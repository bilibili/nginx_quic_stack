
#ifndef BVC_NET_CERT_INTERNAL_PARSE_CERTIFICATE_H_
#define BVC_NET_CERT_INTERNAL_PARSE_CERTIFICATE_H_

#include "googleurl/base/compiler_specific.h"

namespace bvc {

class CertErrors;

// Parses a DER-encoded "Certificate" as specified by RFC 5280. Returns true on
// success and sets the results in the |out_*| parameters. On both the failure
// and success case, if |out_errors| was non-null it may contain extra error
// information.
//
// Note that on success the out parameters alias data from the input
// |certificate_tlv|.  Hence the output values are only valid as long as
// |certificate_tlv| remains valid.
//
// On failure the out parameters have an undefined state, except for
// out_errors. Some of them may have been updated during parsing, whereas
// others may not have been changed.
//
// The out parameters represent each field of the Certificate SEQUENCE:
//       Certificate  ::=  SEQUENCE  {
//
// The |out_tbs_certificate_tlv| parameter corresponds with "tbsCertificate"
// from RFC 5280:
//         tbsCertificate       TBSCertificate,
//
// This contains the full (unverified) Tag-Length-Value for a SEQUENCE. No
// guarantees are made regarding the value of this SEQUENCE.
// This can be further parsed using ParseTbsCertificate().
//
// The |out_signature_algorithm_tlv| parameter corresponds with
// "signatureAlgorithm" from RFC 5280:
//         signatureAlgorithm   AlgorithmIdentifier,
//
// This contains the full (unverified) Tag-Length-Value for a SEQUENCE. No
// guarantees are made regarding the value of this SEQUENCE.
// This can be further parsed using SignatureValue::Create().
//
// The |out_signature_value| parameter corresponds with "signatureValue" from
// RFC 5280:
//         signatureValue       BIT STRING  }
//
// Parsing guarantees that this is a valid BIT STRING.
bool ParseCertificate(const der::Input& certificate_tlv,
                                 der::Input* out_tbs_certificate_tlv,
                                 der::Input* out_signature_algorithm_tlv,
                                 der::BitString* out_signature_value,
                                 CertErrors* out_errors) WARN_UNUSED_RESULT;

} // namespace bvc

#endif //BVC_NET_CERT_INTERNAL_PARSE_CERTIFICATE_H_