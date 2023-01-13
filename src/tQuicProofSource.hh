// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack proof source class.

#ifndef _NGINX_T_QUIC_PROOF_SOURCE_H_
#define _NGINX_T_QUIC_PROOF_SOURCE_H_

#include <string>
#include <vector>

#include "src/tQuicClock.hh"
#include "googleurl/base/compiler_specific.h"
#include "googleurl/base/macros.h"
#include "base/files/file_util.h"
#include "quic/core/crypto/certificate_view.h"
#include "quic/core/crypto/proof_source.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "platform/quic_platform_impl/quic_containers_impl.h"
namespace nginx {

class tQuicProofSource : public quic::ProofSource {
 public:
  tQuicProofSource(tQuicClock* clock);
  ~tQuicProofSource() override;

  // Initializes this object based on the certificate chain in |cert_path|,
  // and the PKCS#8 RSA private key in |key_path|. Signed certificate
  // timestamp may be loaded from |sct_path| if it is non-empty.
  bool AddCertificateChainFromPath(const base::FilePath& cert_path,
                                   const base::FilePath& key_path);

  ProofSource::TicketCrypter* GetTicketCrypter() override;

  // ProofSource implementation.
  void GetProof(const quic::QuicSocketAddress& server_address,
                const quic::QuicSocketAddress& client_address,
                const std::string& hostname,
                const std::string& server_config,
                quic::QuicTransportVersion transport_version,
                quiche::QuicheStringPiece chlo_hash,
                std::unique_ptr<Callback> callback) override;
  quic::QuicReferenceCountedPointer<Chain> GetCertChain(
      const quic::QuicSocketAddress& server_address,
      const quic::QuicSocketAddress& client_address,
      const std::string& hostname,
      bool* cert_matched_sni) override;
  void ComputeTlsSignature(
      const quic::QuicSocketAddress& server_address,
      const quic::QuicSocketAddress& client_address,
      const std::string& hostname,
      uint16_t signature_algorithm,
      quiche::QuicheStringPiece in,
      std::unique_ptr<SignatureCallback> callback) override;

  // Adds a certificate chain to the verifier.  Returns false if the chain is
  // not valid.  Newer certificates will override older certificates with the
  // same SubjectAltName value.
  ABSL_MUST_USE_RESULT bool AddCertificateChain(
      quic::QuicReferenceCountedPointer<Chain> chain,
      quic::CertificatePrivateKey key);

 private:
  struct Certificate {
    quic::QuicReferenceCountedPointer<Chain> chain;
    quic::CertificatePrivateKey key;
  };

  // Looks up certficiate for hostname, returns the default if no certificate is
  // found.
  Certificate* GetCertificate(const std::string& hostname);

  absl::InlinedVector<uint16_t, 8> SupportedTlsSignatureAlgorithms() const override;

  std::forward_list<Certificate> certificates_;
  absl::node_hash_map<std::string, Certificate*, absl::Hash<std::string>> certificate_map_;
  void SetTicketCrypter(std::unique_ptr<quic::ProofSource::TicketCrypter> ticket_crypter);

  std::unique_ptr<ProofSource::TicketCrypter> ticket_crypter_;

  DISALLOW_COPY_AND_ASSIGN(tQuicProofSource);
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_PROOF_SOURCE_H_
