// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack server session class.

#ifndef _NGINX_T_QUIC_SERVER_SESSION_H_
#define _NGINX_T_QUIC_SERVER_SESSION_H_

#include <stdint.h>

#include <list>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "quic/core/http/quic_server_session_base.h"
#include "quic/core/http/quic_spdy_session.h"
#include "quic/core/quic_crypto_server_stream.h"
#include "quic/core/quic_packets.h"
#include "quic/platform/api/quic_containers.h"
#include "src/tQuicServerStream.hh"
#include "src/quic_stack_api.h"

namespace nginx {

class tQuicServerSession : public quic::QuicServerSessionBase {
 public:
  // Takes ownership of |connection|.
  tQuicServerSession(const quic::QuicConfig& config,
                     const quic::ParsedQuicVersionVector& supported_versions,
                     quic::QuicConnection* connection,
                     quic::QuicSession::Visitor* visitor,
                     quic::QuicCryptoServerStream::Helper* helper,
                     const quic::QuicCryptoServerConfig* crypto_config,
                     quic::QuicCompressedCertsCache* compressed_certs_cache,
                     tQuicStackContext    stack_ctx,
                     tQuicRequestCallback cb,
                     tQuicServerIdentifyManager* qsi_ptr);
  tQuicServerSession(const tQuicServerSession&) = delete;
  tQuicServerSession& operator=(const tQuicServerSession&) = delete;

  ~tQuicServerSession() override;

  tQuicServerStream* GetStream(const quic::QuicStreamId stream_id);
  
  //only for GQUIC
  void SetDefaultEncryptionLevel(quic::EncryptionLevel level) override;
  //only for IQUIC
  void OnTlsHandshakeComplete() override;

 protected:
  // QuicSession methods:
  quic::QuicSpdyStream* CreateIncomingStream(quic::QuicStreamId id) override;
  quic::QuicSpdyStream* CreateIncomingStream(quic::PendingStream* pending) override;
  tQuicServerStream* CreateOutgoingBidirectionalStream() override;
  tQuicServerStream* CreateOutgoingUnidirectionalStream() override;

  // QuicServerSessionBaseMethod:
  virtual std::unique_ptr<quic::QuicCryptoServerStreamBase>  
  CreateQuicCryptoServerStream(
      const quic::QuicCryptoServerConfig* crypto_config,
      quic::QuicCompressedCertsCache* compressed_certs_cache) override;

private:
  tQuicStackContext            stack_ctx_;
  tQuicRequestCallback         callback_;
  tQuicServerIdentifyManager*  qsi_mgr_;
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_SERVER_SESSION_H_
