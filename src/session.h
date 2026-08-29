// session.h -- Session Manager (F6): control channel + interactive shell.
//
// Runs a control-channel WebSocket to MGS, and for each StartSession
// (interactive_shell) message spins up a data-channel WebSocket, performs the
// plugin handshake, and bridges a /bin/sh pty to the customer. Standard
// (Standard_Stream) shell sessions only; port forwarding and NonInteractive
// run-command over MGS are out of scope (BRIEF.md-style: MDS still carries
// Run Command).
//
// Threading: run() owns the control channel on its own thread; each session
// gets a worker thread with its data channel and pty. This mirrors the poll
// loop / worker split already used for Run Command.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <string>

#include "aws.h"
#include "json.h"

namespace session {

// Retransmission buffer for outbound stream-data, mirroring the reference
// agent's ResendStreamDataMessageScheduler (datachannel.go): MGS silently drops
// a stream-data frame that arrives before the peer's channel is bridged (most
// importantly the very first message, the HandshakeRequest), and only resends
// get it through. We buffer each sent frame until the client acknowledges its
// sequence, resend the oldest unacked on a timer, and treat a frame that goes
// unacked past a ceiling as a dead peer (client gone) so the session can be
// reaped instead of leaking a shell. Pure logic, host-testable.
class Outbox {
public:
    // Resend the oldest unacked frame no more often than this.
    static constexpr int64_t kResendIntervalMs = 250;
    // Declare the peer dead after this many resends of the oldest frame with no
    // ack (~60 s at the interval above).
    static constexpr int kMaxResends = 240;
    // Bound memory if a client acks far slower than the shell produces output:
    // evict the oldest rather than grow without limit.
    static constexpr size_t kMaxBuffered = 8192;

    void add(int64_t seq, std::string frame, int64_t now_ms);
    // Ordered delivery: an ack of `seq` clears that frame and any older.
    void ack(int64_t seq);
    bool empty() const { return buf_.empty(); }
    size_t size() const { return buf_.size(); }

    // If the oldest unacked frame is due for resend at now_ms, return its bytes
    // and record the resend; otherwise nullptr. Sets `dead` when the oldest has
    // exceeded kMaxResends (peer is not acknowledging -> gone).
    const std::string* due_resend(int64_t now_ms, bool& dead);

private:
    struct Entry {
        int64_t seq;
        std::string frame;
        int64_t last_sent_ms;
        int resends;
    };
    std::deque<Entry> buf_;
};

// Parsed from the interactive_shell AgentMessage payload. The MGS payload is a
// JSON envelope ("Content" holds a stringified AgentTaskPayload) -- see
// agentmessage.go deserializeAgentTaskPayload.
struct StartRequest {
    std::string session_id;
    std::string document_name;
    std::string session_type;   // e.g. "Standard_Stream"
    std::string kms_key_id;      // non-empty => session requested encryption
    bool run_as_enabled = false;
    std::string run_as_user;
    std::string shell_commands;  // ShellProfile Linux commands, if any
    std::string error;           // non-empty => reject
};

// Pulls the inner AgentTaskPayload out of the MGS envelope and reads the shell
// session fields. Host-testable.
StartRequest parse_start_request(const std::string& mgs_payload);

// Handshake request payload (SessionType action), matching
// buildHandshakeRequestPayload. Host-testable so the JSON shape is pinned.
std::string build_handshake_request(const std::string& agent_version,
                                    const std::string& session_type,
                                    const json::Value& properties);

// True if the client's HandshakeResponse reports every action succeeded.
bool handshake_response_ok(const std::string& response_json, std::string& client_version,
                           std::string& err);

struct Options {
    aws::CredentialProvider* creds = nullptr;
    std::string region;
    std::string instance_id;
    std::string agent_version;
    std::atomic<bool>* stop = nullptr;  // set on shutdown
};

// Opens the control channel and services sessions until *stop is set or the
// channel fails. Returns false if the control channel could not be opened.
// Reconnection/backoff is the caller's job (mirrors the MDS poll loop).
bool run(const Options& opts);

}  // namespace session
