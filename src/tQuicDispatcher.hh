// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack packet dispatcher class.

#ifndef _NGINX_T_QUIC_DISPATCH_H_
#define _NGINX_T_QUIC_DISPATCH_H_

#include "quic/core/http/quic_server_session_base.h"
#include "quic/core/quic_crypto_server_stream.h"
#include "quic/core/quic_dispatcher.h"
#include "quic/core/quic_types.h"
#include "src/quic_stack_api.h"
#include "src/tQuicServerStream.hh"

namespace nginx {

class tQuicDispatcher : public quic::QuicDispatcher {
 public:
  tQuicDispatcher(
      const quic::QuicConfig* config,
      const quic::QuicCryptoServerConfig* crypto_config,
      quic::QuicVersionManager* version_manager,
      std::unique_ptr<quic::QuicConnectionHelperInterface> helper,
      std::unique_ptr<quic::QuicCryptoServerStream::Helper> session_helper,
      std::unique_ptr<quic::QuicAlarmFactory> alarm_factory,
      uint8_t expected_server_connection_id_length,
      tQuicStackContext stack_ctx,
      tQuicRequestCallback cb,
      tQuicServerIdentifyManager* qsi_ptr);
  ~tQuicDispatcher() override;

  int GetRstErrorCount(quic::QuicRstStreamErrorCode rst_error_code) const;

  void OnRstStreamReceived(const quic::QuicRstStreamFrame& frame) override;

  void SetWriteBlockedCallback(tQuicOnCanWriteCallback write_blocked_cb);

  void OnWriteBlocked(quic::QuicBlockedWriterInterface* blocked_writer) override;

 protected:
  std::unique_ptr<quic::QuicSession> CreateQuicSession(
      quic::QuicConnectionId server_connection_id,
      const quic::QuicSocketAddress& self_address,
      const quic::QuicSocketAddress& peer_address,
      absl::string_view alpn,
      const quic::ParsedQuicVersion& version,
      const quic::ParsedClientHello& parsed_chlo) override;

 private:
  // The map of the reset error code with its counter.
  std::map<quic::QuicRstStreamErrorCode, int> rst_error_map_;
  tQuicStackContext    stack_ctx_;
  tQuicRequestCallback callback_;
  tQuicServerIdentifyManager* qsi_mgr_;
  tQuicOnCanWriteCallback  write_blocked_cb_;
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_DISPATCH_H_
