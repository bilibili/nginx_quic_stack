#include "src/tQuicDispatcher.hh"
#include "src/tQuicServerSession.hh"

using namespace quic;

namespace nginx {

tQuicDispatcher::tQuicDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    uint8_t expected_server_connection_id_length,
    tQuicStackContext stack_ctx,
    tQuicRequestCallback cb,
    tQuicServerIdentifyManager* qsi_ptr)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::move(helper),
                     std::move(session_helper),
                     std::move(alarm_factory),
                     expected_server_connection_id_length),
      stack_ctx_(stack_ctx),
      callback_(cb),
      qsi_mgr_(qsi_ptr) {
  write_blocked_cb_.OnCanWriteCallback = nullptr;
  write_blocked_cb_.OnCanWriteContext  = nullptr;
}

tQuicDispatcher::~tQuicDispatcher() {}

void tQuicDispatcher::SetWriteBlockedCallback(tQuicOnCanWriteCallback write_blocked_cb) {
  write_blocked_cb_ = write_blocked_cb;
}

void tQuicDispatcher::OnWriteBlocked(quic::QuicBlockedWriterInterface* blocked_writer) {
  quic::QuicDispatcher::OnWriteBlocked(blocked_writer);

  if (write_blocked_cb_.OnCanWriteCallback) {
      write_blocked_cb_.OnCanWriteCallback(write_blocked_cb_.OnCanWriteContext);
  }
}

int tQuicDispatcher::GetRstErrorCount(
    QuicRstStreamErrorCode error_code) const {
  auto it = rst_error_map_.find(error_code);
  if (it == rst_error_map_.end()) {
    return 0;
  }
  return it->second;
}

void tQuicDispatcher::OnRstStreamReceived(
    const QuicRstStreamFrame& frame) {
  auto it = rst_error_map_.find(frame.error_code);
  if (it == rst_error_map_.end()) {
    rst_error_map_.insert(std::make_pair(frame.error_code, 1));
  } else {
    it->second++;
  }
}

std::unique_ptr<quic::QuicSession> tQuicDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
	const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    absl::string_view /*alpn*/,
    const ParsedQuicVersion& version,
    const ParsedClientHello& /*parsed_chlo*/) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  QuicConnection* connection = new QuicConnection(
      connection_id, self_address, peer_address, helper(), alarm_factory(), writer(),
      /* owns_writer= */ false, Perspective::IS_SERVER,
      ParsedQuicVersionVector{version});

  std::unique_ptr<tQuicServerSession> session = std::make_unique<tQuicServerSession> (
      config(), GetSupportedVersions(), connection, this, session_helper(),
      crypto_config(), compressed_certs_cache(), stack_ctx_, callback_, qsi_mgr_);
  session->Initialize();
  return session;
}

}  // namespace nginx
