#include <utility>

#include "quic/core/quic_connection.h"
#include "quic/core/quic_utils.h"
#include "quic/core/quic_session.h"
#include "quic/platform/api/quic_flags.h"
#include "quic/platform/api/quic_logging.h"
#include "src/tQuicServerSession.hh"
#include "src/tQuicServerStream.hh"

using namespace quic;

namespace nginx {

tQuicServerSession::tQuicServerSession(
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection,
    QuicSession::Visitor* visitor,
    QuicCryptoServerStream::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    tQuicStackContext    stack_ctx,
    tQuicRequestCallback cb,
    tQuicServerIdentifyManager* qsi_ptr)
    : QuicServerSessionBase(config,
                            supported_versions,
                            connection,
                            visitor,
                            helper,
                            crypto_config,
                            compressed_certs_cache),
      stack_ctx_(stack_ctx),
      callback_(cb),
      qsi_mgr_(qsi_ptr) {
}

tQuicServerSession::~tQuicServerSession() {
  delete connection();
}

void tQuicServerSession::SetDefaultEncryptionLevel(EncryptionLevel level) {
  QuicSession::SetDefaultEncryptionLevel(level);
}

void tQuicServerSession::OnTlsHandshakeComplete()
{
  QuicSession::OnTlsHandshakeComplete();
}

tQuicServerStream* tQuicServerSession::GetStream(const QuicStreamId stream_id)
{
  QuicStream* stream = QuicSession::GetActiveStream(stream_id);
  if (stream == nullptr) {
    return nullptr;
  }
  return static_cast<tQuicServerStream*>(stream);
}

std::unique_ptr<QuicCryptoServerStreamBase>
tQuicServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                    stream_helper());
}

QuicSpdyStream* tQuicServerSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicSpdyStream* stream = new tQuicServerStream(
      id, this, BIDIRECTIONAL, stack_ctx_, callback_, qsi_mgr_);
  ActivateStream(absl::WrapUnique(stream));
  return stream;
}

QuicSpdyStream* tQuicServerSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicSpdyStream* stream = new tQuicServerStream(
      pending, this, stack_ctx_, callback_, qsi_mgr_);
  ActivateStream(absl::WrapUnique(stream));
  return stream;
}

tQuicServerStream*
tQuicServerSession::CreateOutgoingBidirectionalStream() {
  QUICHE_DCHECK(false);
  return nullptr;
}

tQuicServerStream*
tQuicServerSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  tQuicServerStream* stream = new tQuicServerStream(
      GetNextOutgoingUnidirectionalStreamId(), this, WRITE_UNIDIRECTIONAL, stack_ctx_, callback_, qsi_mgr_);
  ActivateStream(absl::WrapUnique(stream));
  return stream;
}

}  // namespace nginx
