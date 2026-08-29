#include "session.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <set>
#include <thread>

#include "http.h"
#include "log.h"
#include "mgs.h"
#include "util.h"
#include "websocket.h"

// Haiku provides the SUSv3 pty interface (posix_openpt/grantpt/unlockpt/ptsname).
#include <stdlib.h>

namespace session {
namespace {

constexpr int kControlConnectTimeoutMs = 20000;
constexpr int kControlRecvPollMs = 1000;    // wake to check *stop and send pings
constexpr int kDataRecvPollMs = 200;
constexpr int kPingIntervalSeconds = 45;    // < the 54 s the Go agent uses, safely under pong wait
constexpr int kHandshakeTimeoutSeconds = 20;
// A shell that produces this much output between reads still yields regularly.
constexpr size_t kPtyReadChunk = 8192;

std::atomic<uint64_t> g_seq_seed{0};

// Live interactive sessions, so shutdown can wait for their detached worker
// threads to finish before main() tears down the shared credential provider
// (a session thread captures pointers into main's stack).
std::atomic<int> g_active_sessions{0};

// One outbound stream-data message: masked binary AgentMessage with an
// incrementing per-channel sequence number (SendStreamDataMessage).
bool send_stream(ws::Client& ws, uint32_t payload_type, const std::string& data, int64_t& seq,
                 std::string& err) {
    mgs::AgentMessage m;
    m.message_type = mgs::kMsgOutputStreamData;
    m.schema_version = 1;
    m.created_ms = static_cast<uint64_t>(util::now_epoch_ms());
    m.sequence = seq;
    m.flags = (seq == 0) ? 1 : 0;  // SYN on the first
    m.message_id = util::uuid4();
    m.payload_type = payload_type;
    m.payload = data;
    seq++;
    return ws.send(ws::kOpBinary, mgs::serialize(m), err);
}

// A JSON control message on the data channel (acknowledge, agent_session_state).
bool send_control(ws::Client& ws, const std::string& message_type, const std::string& json_payload,
                  std::string& err) {
    mgs::AgentMessage m;
    m.message_type = message_type;
    m.schema_version = 1;
    m.created_ms = static_cast<uint64_t>(util::now_epoch_ms());
    m.sequence = 0;
    m.flags = 3;  // messageFlags in the Go agent for these
    m.message_id = util::uuid4();
    m.payload_type = 0;
    m.payload = json_payload;
    return ws.send(ws::kOpBinary, mgs::serialize(m), err);
}

void send_ack(ws::Client& ws, const mgs::AgentMessage& in) {
    json::Value ack = json::obj();
    ack.object["AcknowledgedMessageType"] = json::str(in.message_type);
    ack.object["AcknowledgedMessageId"] = json::str(in.message_id);
    ack.object["AcknowledgedMessageSequenceNumber"] = json::num(static_cast<double>(in.sequence));
    ack.object["IsSequentialMessage"] = json::boolean(true);
    std::string err;
    send_control(ws, mgs::kMsgAcknowledge, json::dump(ack), err);
}

// ---- pty-backed shell ----

struct Pty {
    int master = -1;
    pid_t pid = -1;
    bool ok() const { return master >= 0 && pid > 0; }
};

Pty spawn_shell(const std::string& commands, bool run_as, const std::string& user,
                std::string& err) {
    Pty p;
    int m = ::posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0) {
        err = std::string("posix_openpt: ") + std::strerror(errno);
        return p;
    }
    if (::grantpt(m) != 0 || ::unlockpt(m) != 0) {
        err = std::string("grantpt/unlockpt: ") + std::strerror(errno);
        ::close(m);
        return p;
    }
    const char* slave_name = ::ptsname(m);
    if (!slave_name) {
        err = "ptsname failed";
        ::close(m);
        return p;
    }
    std::string slave_path = slave_name;

    pid_t pid = ::fork();
    if (pid < 0) {
        err = std::string("fork: ") + std::strerror(errno);
        ::close(m);
        return p;
    }
    if (pid == 0) {
        // ---- child: become session leader with the pty as controlling tty ----
        ::setsid();
        int s = ::open(slave_path.c_str(), O_RDWR);
        if (s < 0) ::_exit(127);
        ::dup2(s, STDIN_FILENO);
        ::dup2(s, STDOUT_FILENO);
        ::dup2(s, STDERR_FILENO);
        if (s > STDERR_FILENO) ::close(s);
        ::close(m);

        ::setenv("TERM", "xterm-256color", 1);
        // run-as is best-effort: switch users only when asked and possible.
        if (run_as && !user.empty()) {
            std::string cmd = "exec su - '" + user + "'";
            if (!commands.empty()) cmd += " -c '" + commands + "'";
            ::execl("/bin/sh", "sh", "-c", cmd.c_str(), static_cast<char*>(nullptr));
        } else if (!commands.empty()) {
            ::execl("/bin/sh", "sh", "-c", commands.c_str(), static_cast<char*>(nullptr));
        } else {
            ::execl("/bin/sh", "-sh", static_cast<char*>(nullptr));  // login-ish interactive shell
        }
        ::_exit(127);
    }

    p.master = m;
    p.pid = pid;
    return p;
}

void set_pty_size(int master, uint32_t cols, uint32_t rows) {
#ifdef TIOCSWINSZ
    struct winsize ws {};
    ws.ws_col = static_cast<unsigned short>(cols);
    ws.ws_row = static_cast<unsigned short>(rows);
    ::ioctl(master, TIOCSWINSZ, &ws);
#else
    (void)master;
    (void)cols;
    (void)rows;
#endif
}

// Decrements the live-session count when a session worker returns by any path.
struct SessionGuard {
    ~SessionGuard() { g_active_sessions.fetch_sub(1); }
};

// One interactive session: data channel + pty bridge. Runs on its own thread.
void run_session(const Options& opts, const StartRequest& sr) {
    SessionGuard guard;  // paired with the increment in run() before the spawn
    logging::logf(logging::Info, "session %s: starting (type=%s)", sr.session_id.c_str(),
                  sr.session_type.c_str());

    std::string token;
    std::string err;
    if (!mgs::create_channel(*opts.creds, opts.region, "data-channel", sr.session_id, token, err)) {
        logging::logf(logging::Error, "session %s: CreateDataChannel failed: %s",
                      sr.session_id.c_str(), err.c_str());
        return;
    }

    aws::Credentials c;
    if (!opts.creds->get(c)) {
        logging::logf(logging::Error, "session %s: no credentials for data channel",
                      sr.session_id.c_str());
        return;
    }

    const std::string host = mgs::endpoint(opts.region);
    const std::string path = "/v1/data-channel/" + sr.session_id;
    const std::string query = "role=publish_subscribe";
    ws::Client ws;
    if (!ws.connect(host, 443, true, path + "?" + query,
                    mgs::ws_upgrade_headers(c, opts.region, host, path, query),
                    kControlConnectTimeoutMs, err)) {
        logging::logf(logging::Error, "session %s: data channel upgrade failed: %s",
                      sr.session_id.c_str(), err.c_str());
        return;
    }

    // OpenDataChannel handshake message on the fresh socket.
    {
        json::Value open = json::obj();
        open.object["MessageSchemaVersion"] = json::str("1.0");
        open.object["RequestId"] = json::str(util::uuid4());
        open.object["TokenValue"] = json::str(token);
        open.object["ClientInstanceId"] = json::str(opts.instance_id);
        open.object["ClientId"] = json::str(util::uuid4());
        if (!ws.send(ws::kOpText, json::dump(open), err)) {
            logging::logf(logging::Error, "session %s: OpenDataChannel send failed: %s",
                          sr.session_id.c_str(), err.c_str());
            return;
        }
    }
    ws.set_recv_timeout(kDataRecvPollMs);

    // Announce Connected, then run the plugin handshake (SessionType action).
    {
        json::Value st = json::obj();
        st.object["SchemaVersion"] = json::num(1);
        st.object["SessionState"] = json::str("Connected");
        st.object["SessionId"] = json::str(sr.session_id);
        send_control(ws, mgs::kMsgAgentSessionState, json::dump(st), err);
    }

    int64_t out_seq = 0;
    {
        json::Value props = json::obj();
        std::string hs = build_handshake_request(opts.agent_version, sr.session_type, props);
        if (!send_stream(ws, mgs::kPayloadHandshakeRequest, hs, out_seq, err)) {
            logging::logf(logging::Error, "session %s: handshake request failed: %s",
                          sr.session_id.c_str(), err.c_str());
            return;
        }
    }

    // Wait for the HandshakeResponse before spawning the shell.
    bool handshake_done = false;
    // The HandshakeResponse is itself an inbound stream-data message and shares
    // the ExpectedSequenceNumber space with subsequent keystrokes. We must carry
    // its sequence forward, or the first real input frame is rejected as
    // out-of-order and every keystroke after it is dropped.
    int64_t handshake_seq = -1;
    const int64_t hs_deadline = util::now_epoch() + kHandshakeTimeoutSeconds;
    while (!handshake_done && (!opts.stop || !opts.stop->load())) {
        if (util::now_epoch() > hs_deadline) {
            logging::logf(logging::Warn, "session %s: handshake timed out", sr.session_id.c_str());
            return;
        }
        ws::Frame f;
        int rc = ws.recv(f, err);
        if (rc < 0) {
            logging::logf(logging::Warn, "session %s: channel closed during handshake: %s",
                          sr.session_id.c_str(), err.c_str());
            return;
        }
        if (rc == 0) continue;
        mgs::AgentMessage m;
        std::string derr;
        if (!mgs::deserialize(f.payload, m, derr)) continue;
        if (m.message_type == mgs::kMsgInputStreamData &&
            m.payload_type == mgs::kPayloadHandshakeResponse) {
            send_ack(ws, m);
            std::string client_version, herr;
            if (!handshake_response_ok(m.payload, client_version, herr)) {
                logging::logf(logging::Error, "session %s: handshake rejected: %s",
                              sr.session_id.c_str(), herr.c_str());
                return;
            }
            handshake_seq = m.sequence;
            handshake_done = true;
        } else if (m.message_type == mgs::kMsgChannelClosed) {
            return;
        } else {
            send_ack(ws, m);  // ack anything else so MGS stops resending
        }
    }
    if (!handshake_done) return;

    // Send HandshakeComplete, then start the shell.
    {
        json::Value done = json::obj();
        done.object["HandshakeTimeToComplete"] = json::num(0);
        done.object["CustomerMessage"] = json::str("");
        send_stream(ws, mgs::kPayloadHandshakeComplete, json::dump(done), out_seq, err);
    }

    Pty pty = spawn_shell(sr.shell_commands, sr.run_as_enabled, sr.run_as_user, err);
    if (!pty.ok()) {
        logging::logf(logging::Error, "session %s: could not start shell: %s",
                      sr.session_id.c_str(), err.c_str());
        std::string derr;
        send_stream(ws, mgs::kPayloadStdErr, "Failed to start shell: " + err + "\r\n", out_seq, derr);
        return;
    }
    logging::logf(logging::Info, "session %s: shell running (pid %d)", sr.session_id.c_str(),
                  static_cast<int>(pty.pid));

    ::fcntl(pty.master, F_SETFL, O_NONBLOCK);
    // Continue the inbound sequence after the handshake response (seq 0 in
    // practice, since it is the first inbound stream-data message).
    int64_t next_expected = handshake_seq + 1;
    bool running = true;
    while (running && (!opts.stop || !opts.stop->load())) {
        // 1. Drain all currently-available pty output to the customer, so a
        //    chatty command is not throttled to one chunk per recv timeout.
        bool sent_output = false;
        while (true) {
            char buf[kPtyReadChunk];
            ssize_t n = ::read(pty.master, buf, sizeof(buf));
            if (n > 0) {
                sent_output = true;
                std::string derr;
                if (!send_stream(ws, mgs::kPayloadOutput,
                                 std::string(buf, static_cast<size_t>(n)), out_seq, derr)) {
                    logging::logf(logging::Warn, "session %s: output send failed: %s",
                                  sr.session_id.c_str(), derr.c_str());
                    running = false;
                }
                continue;
            }
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                running = false;  // shell exited or pty error
            break;  // no more data ready right now
        }
        if (!running) break;

        // 2. Handle one inbound frame (bounded by the short data-channel
        //    timeout). Skip the wait when we just flushed output so keystroke
        //    echo stays responsive during heavy output.
        if (sent_output) ws.set_recv_timeout(1);
        else ws.set_recv_timeout(kDataRecvPollMs);
        ws::Frame f;
        int rc = ws.recv(f, err);
        if (rc < 0) {
            logging::logf(logging::Info, "session %s: data channel closed: %s",
                          sr.session_id.c_str(), err.c_str());
            break;
        }
        if (rc == 0) continue;

        mgs::AgentMessage m;
        std::string derr;
        if (!mgs::deserialize(f.payload, m, derr)) continue;

        if (m.message_type == mgs::kMsgChannelClosed) {
            logging::logf(logging::Info, "session %s: terminate requested", sr.session_id.c_str());
            break;
        }
        if (m.message_type == mgs::kMsgAcknowledge) continue;  // client acking our output
        if (m.message_type != mgs::kMsgInputStreamData) {
            send_ack(ws, m);
            continue;
        }

        // Ordered input: ack always, apply only when in-order (a resend of an
        // already-applied sequence would double-type otherwise).
        send_ack(ws, m);
        if (m.sequence != next_expected) continue;
        next_expected++;

        if (m.payload_type == mgs::kPayloadSize) {
            std::string jerr;
            json::Value sz = json::parse(m.payload, &jerr);
            if (jerr.empty())
                set_pty_size(pty.master, static_cast<uint32_t>(sz.num_at("cols", 80)),
                             static_cast<uint32_t>(sz.num_at("rows", 24)));
        } else if (m.payload_type == mgs::kPayloadOutput) {
            // Customer keystrokes: write them to the shell.
            size_t written = 0;
            while (written < m.payload.size()) {
                ssize_t w = ::write(pty.master, m.payload.data() + written,
                                    m.payload.size() - written);
                if (w > 0) {
                    written += static_cast<size_t>(w);
                } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                    continue;
                } else {
                    running = false;
                    break;
                }
            }
        }
    }

    // Tear down: kill the shell, tell MGS we are terminating, close.
    ::kill(-pty.pid, SIGKILL);
    int status = 0;
    ::waitpid(pty.pid, &status, 0);
    ::close(pty.master);

    std::string derr;
    const int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    send_stream(ws, mgs::kPayloadExitCode, std::to_string(exit_code), out_seq, derr);
    json::Value st = json::obj();
    st.object["SchemaVersion"] = json::num(1);
    st.object["SessionState"] = json::str("Terminating");
    st.object["SessionId"] = json::str(sr.session_id);
    send_control(ws, mgs::kMsgAgentSessionState, json::dump(st), derr);
    ws.close();
    logging::logf(logging::Info, "session %s: ended (exit %d)", sr.session_id.c_str(), exit_code);
}

}  // namespace

StartRequest parse_start_request(const std::string& mgs_payload) {
    StartRequest sr;
    std::string err;
    json::Value envelope = json::parse(mgs_payload, &err);
    if (!err.empty() || !envelope.is_obj()) {
        sr.error = "interactive_shell payload is not JSON: " + err;
        return sr;
    }
    // The real AgentTaskPayload is a *stringified* JSON in "Content".
    const std::string inner = envelope.str_at("Content");
    json::Value task = json::parse(inner, &err);
    if (!err.empty() || !task.is_obj()) {
        sr.error = "interactive_shell Content is not JSON: " + err;
        return sr;
    }

    sr.session_id = task.str_at("SessionId");
    sr.document_name = task.str_at("DocumentName");
    const json::Value* doc = task.find("DocumentContent");
    if (doc && doc->is_obj()) {
        sr.session_type = doc->str_at("sessionType");
        const json::Value* inputs = doc->find("inputs");
        if (inputs && inputs->is_obj()) {
            sr.kms_key_id = inputs->str_at("kmsKeyId");
            const json::Value* rae = inputs->find("runAsEnabled");
            if (rae) sr.run_as_enabled = rae->bl(false);
            sr.run_as_user = inputs->str_at("runAsDefaultUser");
            const json::Value* profile = inputs->find("shellProfile");
            if (profile && profile->is_obj()) sr.shell_commands = profile->str_at("linux");
        }
    }
    if (sr.session_id.empty()) sr.error = "interactive_shell payload has no SessionId";
    return sr;
}

std::string build_handshake_request(const std::string& agent_version,
                                    const std::string& session_type,
                                    const json::Value& properties) {
    json::Value action = json::obj();
    action.object["ActionType"] = json::str("SessionType");
    json::Value params = json::obj();
    params.object["SessionType"] = json::str(session_type);
    params.object["Properties"] = properties;
    action.object["ActionParameters"] = params;

    json::Value actions = json::arr();
    actions.array.push_back(action);

    json::Value req = json::obj();
    req.object["AgentVersion"] = json::str(agent_version);
    req.object["RequestedClientActions"] = actions;
    return json::dump(req);
}

bool handshake_response_ok(const std::string& response_json, std::string& client_version,
                           std::string& err) {
    std::string jerr;
    json::Value v = json::parse(response_json, &jerr);
    if (!jerr.empty() || !v.is_obj()) {
        err = "handshake response is not JSON: " + jerr;
        return false;
    }
    client_version = v.str_at("ClientVersion");
    const json::Value* actions = v.find("ProcessedClientActions");
    if (!actions || !actions->is_arr()) {
        err = "handshake response has no ProcessedClientActions";
        return false;
    }
    for (const json::Value& a : actions->array) {
        const std::string status = a.str_at("ActionStatus");
        // ActionStatus is an int enum in the Go agent (Success=1); accept the
        // numeric and string spellings.
        if (status != "1" && util::lower(status) != "success" && a.num_at("ActionStatus", 0) != 1) {
            err = a.str_at("ActionType") + " failed on client: " + a.str_at("Error");
            return false;
        }
    }
    return true;
}

bool run(const Options& opts) {
    (void)g_seq_seed;
    std::string token;
    std::string err;
    // ChannelId for the control channel is the instance id (the Go agent uses
    // "<instanceId>" for CreateControlChannel).
    const std::string channel_id = opts.instance_id;
    if (!mgs::create_channel(*opts.creds, opts.region, "control-channel", channel_id, token, err)) {
        logging::logf(logging::Warn, "control channel: CreateControlChannel failed: %s",
                      err.c_str());
        return false;
    }

    aws::Credentials c;
    if (!opts.creds->get(c)) {
        logging::warn("control channel: no credentials");
        return false;
    }

    const std::string host = mgs::endpoint(opts.region);
    const std::string path = "/v1/control-channel/" + channel_id;
    const std::string query = "role=subscribe&stream=input";  // Set(stream,input) + Add(role)
    ws::Client ws;
    if (!ws.connect(host, 443, true, path + "?" + query,
                    mgs::ws_upgrade_headers(c, opts.region, host, path, query),
                    kControlConnectTimeoutMs, err)) {
        logging::logf(logging::Warn, "control channel: upgrade failed: %s", err.c_str());
        return false;
    }

    // OpenControlChannel input on the fresh socket.
    {
        json::Value open = json::obj();
        open.object["MessageSchemaVersion"] = json::str("1.0");
        open.object["RequestId"] = json::str(util::uuid4());
        open.object["TokenValue"] = json::str(token);
        open.object["AgentVersion"] = json::str(opts.agent_version);
        open.object["PlatformType"] = json::str("Linux");  // closed enum; matches UpdateInstanceInformation
        if (!ws.send(ws::kOpText, json::dump(open), err)) {
            logging::logf(logging::Warn, "control channel: OpenControlChannel send failed: %s",
                          err.c_str());
            return false;
        }
    }
    ws.set_recv_timeout(kControlRecvPollMs);
    logging::info("control channel open; waiting for sessions");

    std::set<std::string> seen_sessions;  // dedup StartSession redeliveries
    int64_t next_ping = util::now_epoch() + kPingIntervalSeconds;
    while (!opts.stop || !opts.stop->load()) {
        if (util::now_epoch() >= next_ping) {
            std::string perr;
            ws.send(ws::kOpPing, "", perr);
            next_ping = util::now_epoch() + kPingIntervalSeconds;
        }

        ws::Frame f;
        int rc = ws.recv(f, err);
        if (rc < 0) {
            logging::logf(logging::Warn, "control channel closed: %s", err.c_str());
            return false;  // caller reconnects
        }
        if (rc == 0) continue;

        mgs::AgentMessage m;
        std::string derr;
        if (!mgs::deserialize(f.payload, m, derr)) {
            logging::logf(logging::Warn, "control channel: bad AgentMessage: %s", derr.c_str());
            continue;
        }

        if (m.message_type == mgs::kMsgInteractiveShell) {
            StartRequest sr = parse_start_request(m.payload);
            if (!sr.error.empty()) {
                logging::logf(logging::Error, "control channel: %s", sr.error.c_str());
                continue;
            }
            // Only interactive standard shells are supported.
            if (!sr.session_type.empty() && sr.session_type != "Standard_Stream") {
                logging::logf(logging::Warn,
                              "session %s: unsupported session type '%s' on Haiku; ignoring",
                              sr.session_id.c_str(), sr.session_type.c_str());
                continue;
            }
            // Refuse rather than silently downgrade: KMS session encryption is
            // not implemented, so a session that asked for it must not run in
            // plaintext (that would be a security regression, not a feature gap).
            if (!sr.kms_key_id.empty()) {
                logging::logf(logging::Warn,
                              "session %s: KMS encryption requested but unsupported; refusing",
                              sr.session_id.c_str());
                continue;
            }
            // MGS redelivers an unacknowledged control message; dedup by
            // SessionId so a redelivery storm cannot spawn a second pty/shell
            // for the same session (mirrors Run Command's CommandId dedup).
            if (!seen_sessions.insert(sr.session_id).second) {
                logging::logf(logging::Info, "session %s: duplicate StartSession; ignoring",
                              sr.session_id.c_str());
                continue;
            }
            g_active_sessions.fetch_add(1);  // paired with SessionGuard in run_session
            std::thread(run_session, opts, sr).detach();
        } else if (m.message_type == mgs::kMsgChannelClosed) {
            logging::info("control channel: server requested close");
            return true;
        } else if (m.message_type == mgs::kMsgAgentJob) {
            // Run Command over MGS is not used here; MDS carries jobs.
            logging::logf(logging::Debug, "control channel: ignoring agent_job %s",
                          m.message_id.c_str());
        }
    }
    ws.close();

    // Shutdown (opts.stop set): wait for detached session workers to finish
    // before returning, so main() does not free the credential provider they
    // still hold. Sessions notice opts.stop within one data-channel poll (~1 s);
    // bound the wait so a wedged pty cannot hang shutdown forever.
    const int64_t drain_deadline = util::now_epoch() + 15;
    while (g_active_sessions.load() > 0 && util::now_epoch() < drain_deadline) ::usleep(100000);
    if (g_active_sessions.load() > 0)
        logging::logf(logging::Warn, "%d session(s) still active at shutdown drain timeout",
                      g_active_sessions.load());
    return true;
}

}  // namespace session
