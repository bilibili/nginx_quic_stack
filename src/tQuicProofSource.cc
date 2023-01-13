#include "src/tQuicProofSource.hh"

#include "base/strings/pattern.h"
#include "base/strings/string_number_conversions.h"
#include "base/files/file_util.h"
#include "base/files/file_path.h"
#include "quic/core/quic_clock.h"
#include "quic/core/quic_data_writer.h"
#include "quic/core/crypto/crypto_protocol.h"
#include "quic/core/crypto/certificate_view.h"
#include "quic/core/crypto/proof_source_x509.h"
#include "quic/platform/api/quic_bug_tracker.h"
#include "quic/tools/simple_ticket_crypter.h"
#include "openssl/digest.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/base.h"
#include "openssl/crypto.h"

using std::string;
using namespace quic;

namespace nginx {

tQuicProofSource::tQuicProofSource(tQuicClock* clock) {
 quic::QuicClock* quic_clock = static_cast<quic::QuicClock*>(clock);
 SetTicketCrypter(std::make_unique<quic::SimpleTicketCrypter>(quic_clock));
}

tQuicProofSource::~tQuicProofSource() {}

bool tQuicProofSource::AddCertificateChainFromPath(
  const base::FilePath& cert_path,
  const base::FilePath& key_path) {
  CRYPTO_library_init();

  std::string cert_data;
  if (!base::ReadFileToString(cert_path, &cert_data)) {
    QUIC_BUG(-1) << "Unable to read certificates.";
    return false;
  }

  std::stringstream cert_stream(cert_data);
  std::vector<std::string> certs =
       quic::CertificateView::LoadPemFromStream(&cert_stream);

  quic::QuicReferenceCountedPointer<quic::ProofSource::Chain> chain(new quic::ProofSource::Chain(certs));

  std::string key_data;
  if (!base::ReadFileToString(key_path, &key_data)) {
    QUIC_BUG(-1) << "Unable to read key.";
    return false;
  }

  std::stringstream key_stream(key_data);
  std::unique_ptr<quic::CertificatePrivateKey> private_key = quic::CertificatePrivateKey::LoadPemFromStream(&key_stream);
  if (private_key == nullptr) {
    QUIC_BUG(-1) << "default key is null.";
  }

  return AddCertificateChain(chain, std::move(*private_key));
}

absl::InlinedVector<uint16_t, 8>
tQuicProofSource::SupportedTlsSignatureAlgorithms() const {
  // Let ComputeTlsSignature() report an error if a bad signature algorithm is
  // requested.
  return {};
}

void tQuicProofSource::GetProof(
    const quic::QuicSocketAddress& /*server_address*/,
    const quic::QuicSocketAddress& /*client_address*/,
    const std::string& hostname,
    const std::string& server_config,
    quic::QuicTransportVersion /*transport_version*/,
    quiche::QuicheStringPiece chlo_hash,
    std::unique_ptr<ProofSource::Callback> callback) {
  quic::QuicCryptoProof proof;

  size_t payload_size = sizeof(kProofSignatureLabel) + sizeof(uint32_t) +
                        chlo_hash.size() + server_config.size();
  auto payload = std::make_unique<char[]>(payload_size);
  QuicDataWriter payload_writer(payload_size, payload.get(),
                                quiche::Endianness::HOST_BYTE_ORDER);
  bool success = payload_writer.WriteBytes(kProofSignatureLabel,
                                           sizeof(kProofSignatureLabel)) &&
                 payload_writer.WriteUInt32(chlo_hash.size()) &&
                 payload_writer.WriteStringPiece(chlo_hash) &&
                 payload_writer.WriteStringPiece(server_config);
  if (!success) {
    callback->Run(/*ok=*/false, nullptr, proof, nullptr);
    return;
  }

  Certificate* certificate = GetCertificate(hostname);
  proof.signature = certificate->key.Sign(
      quiche::QuicheStringPiece(payload.get(), payload_size),
      SSL_SIGN_RSA_PSS_RSAE_SHA256);
  callback->Run(/*ok=*/!proof.signature.empty(), certificate->chain, proof,
                nullptr);
}

QuicReferenceCountedPointer<ProofSource::Chain> tQuicProofSource::GetCertChain(
    const quic::QuicSocketAddress& /*server_address*/,
    const quic::QuicSocketAddress& /*client_address*/,
    const std::string& hostname,
    bool* /*cert_matched_sni*/) {
  return GetCertificate(hostname)->chain;
}

void tQuicProofSource::ComputeTlsSignature(
    const quic::QuicSocketAddress& /*server_address*/,
    const quic::QuicSocketAddress& /*client_address*/,
    const std::string& hostname,
    uint16_t signature_algorithm,
    quiche::QuicheStringPiece in,
    std::unique_ptr<ProofSource::SignatureCallback> callback) {
  std::string signature =
      GetCertificate(hostname)->key.Sign(in, signature_algorithm);
  callback->Run(/*ok=*/!signature.empty(), signature, nullptr);
}

bool tQuicProofSource::AddCertificateChain(
    QuicReferenceCountedPointer<Chain> chain,
    CertificatePrivateKey key) {
  if (chain->certs.empty()) {
    QUIC_BUG(-1) << "Empty certificate chain supplied.";
    return false;
  }

  std::unique_ptr<CertificateView> leaf =
      CertificateView::ParseSingleCertificate(chain->certs[0]);
  if (leaf == nullptr) {
    QUIC_BUG(-1) << "Unable to parse X.509 leaf certificate in the supplied chain.";
    return false;
  }
  if (!key.MatchesPublicKey(*leaf)) {
    QUIC_BUG(-1) << "Private key does not match the leaf certificate.";
    return false;
  }

  certificates_.push_front(Certificate{
      chain,
      std::move(key),
  });
  Certificate* certificate = &certificates_.front();

  for (quiche::QuicheStringPiece host : leaf->subject_alt_name_domains()) {
    certificate_map_[std::string(host)] = certificate;
  }
  return true;
}

tQuicProofSource::Certificate* tQuicProofSource::GetCertificate(
    const std::string& hostname) {
  auto it = certificate_map_.find(hostname);
  if (it != certificate_map_.end()) {
    return it->second;
  }
  auto dot_pos = hostname.find('.');
  if (dot_pos != std::string::npos) {
    std::string wildcard = absl::StrCat("*", hostname.substr(dot_pos));
    it = certificate_map_.find(wildcard);
    if (it != certificate_map_.end()) {
      return it->second;
    }
  }
  return &certificates_.front();
}

void tQuicProofSource::SetTicketCrypter(
  std::unique_ptr<quic::ProofSource::TicketCrypter> ticket_crypter) {
  ticket_crypter_ = std::move(ticket_crypter);
}

quic::ProofSource::TicketCrypter* tQuicProofSource::GetTicketCrypter() {
  return ticket_crypter_.get();
}

}  // namespace nginx