// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack server crypto stream class.

#ifndef _NGINX_T_QUIC_CRYPTO_SERVER_STREAM_H_
#define _NGINX_T_QUIC_CRYPTO_SERVER_STREAM_H_

#include "quic/core/crypto/quic_random.h"
#include "quic/core/quic_crypto_server_stream.h"

namespace nginx {

// Simple helper for server crypto streams which generates a new random
// connection ID for rejects.
class tQuicCryptoServerStream
    : public quic::QuicCryptoServerStream::Helper {
 public:
  ~tQuicCryptoServerStream() override;

  bool CanAcceptClientHello(const quic::CryptoHandshakeMessage& message,
                            const quic::QuicSocketAddress& client_address,
                            const quic::QuicSocketAddress& peer_address,
                            const quic::QuicSocketAddress& self_address,
                            std::string* error_details) const override;
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_CRYPTO_SERVER_STREAM_H_
