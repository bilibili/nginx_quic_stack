#include "quic/core/quic_utils.h"
#include "src/tQuicCryptoServerStream.hh"

using namespace quic;

namespace nginx {

tQuicCryptoServerStream::~tQuicCryptoServerStream() {}

bool tQuicCryptoServerStream::CanAcceptClientHello(
    const CryptoHandshakeMessage& /*message*/,
    const QuicSocketAddress& /*client_address*/,
    const QuicSocketAddress& /*peer_address*/,
    const QuicSocketAddress& /*self_address*/,
    std::string* /*error_details*/) const {
  return true;
}

}  // namespace nginx
