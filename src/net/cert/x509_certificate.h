#ifndef BVC_NET_CERT_X509_CERTIFICATE_H_
#define BVC_NET_CERT_X509_CERTIFICATE_H_

#include "boringssl/include/openssl/base.h"

namespace bvc {

class X509Certificate {
 public:

  // Parses all of the certificates possible from |data|. |format| is a
  // bit-wise OR of Format, indicating the possible formats the
  // certificates may have been serialized as. If an error occurs, an empty
  // collection will be returned.
  static CertificateList CreateCertificateListFromBytes(const char* data,
                                                        size_t length,
                                                        int format);
/*
    // Construct an X509Certificate from a CRYPTO_BUFFER containing the
  // DER-encoded representation.
  X509Certificate(bssl::UniquePtr<CRYPTO_BUFFER> cert_buffer,
                  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates);
  X509Certificate(bssl::UniquePtr<CRYPTO_BUFFER> cert_buffer,
                  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates,
                  UnsafeCreateOptions options);

  ~X509Certificate();
*/
  // Creates a CRYPTO_BUFFER from the DER-encoded representation. Unlike
  // creating a CRYPTO_BUFFER directly, this function does some minimal
  // checking to reject obviously invalid inputs.
  // Returns NULL on failure.
  static bssl::UniquePtr<CRYPTO_BUFFER> CreateCertBufferFromBytes(
      const char* data,
      size_t length);

};

} // namespace bvc
#endif //BVC_NET_CERT_X509_CERTIFICATE_H_