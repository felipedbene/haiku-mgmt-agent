// mgs.h -- Message Gateway Service wire protocol (F6: Session Manager).
//
// Layouts and constants mirror the Apache-2.0 Go agent:
//   agent/session/contracts/agentmessage.go  (binary AgentMessage framing)
//   agent/session/contracts/model.go         (message types, payload types)
//   agent/session/service/service.go         (CreateControlChannel/CreateDataChannel)
//   agent/session/communicator/websocketchannel.go (signed WS upgrade URL)
#pragma once

#include <cstdint>
#include <string>

#include "aws.h"
#include "json.h"

namespace mgs {

// Message types (model.go).
extern const char* kMsgInteractiveShell;    // MGS -> agent: StartSession document
extern const char* kMsgAgentJob;            // MGS -> agent: run-command job (unused; MDS carries jobs)
extern const char* kMsgChannelClosed;       // MGS -> agent: channel/session is closing
extern const char* kMsgAcknowledge;         // both ways on the data channel
extern const char* kMsgAgentSessionState;   // agent -> MGS: Connected / Terminating
extern const char* kMsgInputStreamData;     // MGS -> agent: keystrokes, resize
extern const char* kMsgOutputStreamData;    // agent -> MGS: shell output
extern const char* kMsgPausePublication;
extern const char* kMsgStartPublication;
extern const char* kMsgTaskComplete;        // agent -> MGS (control channel)
extern const char* kMsgTaskAcknowledge;     // MGS -> agent: ack of TaskComplete

// Payload types (model.go PayloadType).
constexpr uint32_t kPayloadOutput = 1;
constexpr uint32_t kPayloadError = 2;
constexpr uint32_t kPayloadSize = 3;
constexpr uint32_t kPayloadHandshakeRequest = 5;
constexpr uint32_t kPayloadHandshakeResponse = 6;
constexpr uint32_t kPayloadHandshakeComplete = 7;
constexpr uint32_t kPayloadFlag = 10;
constexpr uint32_t kPayloadStdErr = 11;
constexpr uint32_t kPayloadExitCode = 12;

// The binary frame exchanged over both channels (agentmessage.go). Header is
// 116 bytes + 4-byte payload length; all integers big-endian; MessageType is
// space-padded to 32 bytes; the UUID is written LSB-half first (putUuid).
struct AgentMessage {
    std::string message_type;
    uint32_t schema_version = 1;
    uint64_t created_ms = 0;
    int64_t sequence = 0;
    uint64_t flags = 0;
    std::string message_id;  // canonical text form ("xxxxxxxx-xxxx-...")
    uint32_t payload_type = 0;
    std::string payload;
};

// ---- pure, host-testable ----

std::string serialize(const AgentMessage& m);
// Verifies structure and the SHA-256 payload digest.
bool deserialize(const std::string& raw, AgentMessage& out, std::string& err);

// UUID text <-> the Go agent's on-wire byte order (least-significant half first).
bool uuid_to_wire(const std::string& uuid_text, unsigned char out[16]);
std::string uuid_from_wire(const unsigned char in[16]);

// ---- service calls ----

// POST https://ssmmessages.<region>.amazonaws.com/v1/<channel-type>/<id>
// SigV4-signed (service "ssmmessages"); 201 + TokenValue on success. The Go
// agent parses the response as XML, so accept both JSON and XML shapes.
bool create_channel(aws::CredentialProvider& creds, const std::string& region,
                    const std::string& channel_type,  // "control-channel" | "data-channel"
                    const std::string& channel_id, std::string& token, std::string& err);

// Signed wss:// upgrade headers for /v1/<channel-type>/<id>?<query>.
std::vector<std::pair<std::string, std::string>> ws_upgrade_headers(
    const aws::Credentials& creds, const std::string& region, const std::string& host,
    const std::string& path, const std::string& query);

std::string endpoint(const std::string& region);  // ssmmessages.<region>.amazonaws.com

}  // namespace mgs
