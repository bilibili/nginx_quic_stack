#include "net/cert/x509_certificate.h"
#include "net/cert/pem.h"
#include "net/der/input.h"

namespace bvc {
namespace {
// Indicates the order to use when trying to decode binary data, which is
// based on (speculation) as to what will be most common -> least common
const X509Certificate::Format kFormatDecodePriority[] = {
  X509Certificate::FORMAT_SINGLE_CERTIFICATE,
  X509Certificate::FORMAT_PKCS7
};

// The PEM block header used for DER certificates
const char kCertificateHeader[] = "CERTIFICATE";
// The PEM block header used for PKCS#7 data
const char kPKCS7Header[] = "PKCS7";
} // namespace

// static
CertificateList X509Certificate::CreateCertificateListFromBytes(
    const char* data,
    size_t length,
    int format) {
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> certificates;

  // Check to see if it is in a PEM-encoded form. This check is performed
  // first, as both OS X and NSS will both try to convert if they detect
  // PEM encoding, except they don't do it consistently between the two.
  gurl_base::StringPiece data_string(data, length);
  std::vector<std::string> pem_headers;

  // To maintain compatibility with NSS/Firefox, CERTIFICATE is a universally
  // valid PEM block header for any format.
  pem_headers.push_back(kCertificateHeader);
  if (format & FORMAT_PKCS7)
    pem_headers.push_back(kPKCS7Header);

  PEMTokenizer pem_tokenizer(data_string, pem_headers);
  while (pem_tokenizer.GetNext()) {
    std::string decoded(pem_tokenizer.data());

    bssl::UniquePtr<CRYPTO_BUFFER> handle;
    if (format & FORMAT_PEM_CERT_SEQUENCE)
      handle = CreateCertBufferFromBytes(decoded.c_str(), decoded.size());
    if (handle) {
      // Parsed a DER encoded certificate. All PEM blocks that follow must
      // also be DER encoded certificates wrapped inside of PEM blocks.
      format = FORMAT_PEM_CERT_SEQUENCE;
      certificates.push_back(std::move(handle));
      continue;
    }

    // If the first block failed to parse as a DER certificate, and
    // formats other than PEM are acceptable, check to see if the decoded
    // data is one of the accepted formats.
    if (format & ~FORMAT_PEM_CERT_SEQUENCE) {
      for (size_t i = 0;
           certificates.empty() && i < base::size(kFormatDecodePriority); ++i) {
        if (format & kFormatDecodePriority[i]) {
          certificates = CreateCertBuffersFromBytes(
              decoded.c_str(), decoded.size(), kFormatDecodePriority[i]);
        }
      }
    }

    // Stop parsing after the first block for any format but a sequence of
    // PEM-encoded DER certificates. The case of FORMAT_PEM_CERT_SEQUENCE
    // is handled above, and continues processing until a certificate fails
    // to parse.
    break;
  }

  // Try each of the formats, in order of parse preference, to see if |data|
  // contains the binary representation of a Format, if it failed to parse
  // as a PEM certificate/chain.
  for (size_t i = 0;
       certificates.empty() && i < base::size(kFormatDecodePriority); ++i) {
    if (format & kFormatDecodePriority[i])
      certificates =
          CreateCertBuffersFromBytes(data, length, kFormatDecodePriority[i]);
  }

  CertificateList results;
  // No certificates parsed.
  if (certificates.empty())
    return results;

  for (auto& it : certificates) {
    scoped_refptr<X509Certificate> cert = CreateFromBuffer(std::move(it), {});
    if (cert)
      results.push_back(std::move(cert));
  }

  return results;
}

// static
bssl::UniquePtr<CRYPTO_BUFFER> X509Certificate::CreateCertBufferFromBytes(
    const char* data,
    size_t length) {
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  // Do a bare minimum of DER parsing here to make sure the input is not
  // completely crazy. (This is required for at least
  // CreateCertificateListFromBytes with FORMAT_AUTO, if not more.)
  if (!ParseCertificate(
          der::Input(reinterpret_cast<const uint8_t*>(data), length),
          &tbs_certificate_tlv, &signature_algorithm_tlv, &signature_value,
          nullptr)) {
    return nullptr;
  }

  return x509_util::CreateCryptoBuffer(reinterpret_cast<const uint8_t*>(data),
                                       length);
}
} // namespace bvc
