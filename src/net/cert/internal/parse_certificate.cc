#include "net/cert/internal/parse_certificate.h"

#include "net/cert/internal/cert_errors.h"

namespace bvc {
namespace {
// Returns true if |input| is a SEQUENCE and nothing else.
WARN_UNUSED_RESULT bool IsSequenceTLV(const der::Input& input) {
  der::Parser parser(input);
  der::Parser unused_sequence_parser;
  if (!parser.ReadSequence(&unused_sequence_parser))
    return false;
  // Should by a single SEQUENCE by definition of the function.
  return !parser.HasMore();
}

// Reads a SEQUENCE from |parser| and writes the full tag-length-value into
// |out|. On failure |parser| may or may not have been advanced.
WARN_UNUSED_RESULT bool ReadSequenceTLV(der::Parser* parser, der::Input* out) {
  return parser->ReadRawTLV(out) && IsSequenceTLV(*out);
}
} // namespace

bool ParseCertificate(const der::Input& certificate_tlv,
                      der::Input* out_tbs_certificate_tlv,
                      der::Input* out_signature_algorithm_tlv,
                      der::BitString* out_signature_value,
                      CertErrors* out_errors) {
  // |out_errors| is optional. But ensure it is non-null for the remainder of
  // this function.
  if (!out_errors) {
    CertErrors unused_errors;
    return ParseCertificate(certificate_tlv, out_tbs_certificate_tlv,
                            out_signature_algorithm_tlv, out_signature_value,
                            &unused_errors);
  }

  der::Parser parser(certificate_tlv);

  //   Certificate  ::=  SEQUENCE  {
  der::Parser certificate_parser;
  if (!parser.ReadSequence(&certificate_parser)) {
    out_errors->AddError(kCertificateNotSequence);
    return false;
  }

  //        tbsCertificate       TBSCertificate,
  if (!ReadSequenceTLV(&certificate_parser, out_tbs_certificate_tlv)) {
    out_errors->AddError(kTbsCertificateNotSequence);
    return false;
  }

  //        signatureAlgorithm   AlgorithmIdentifier,
  if (!ReadSequenceTLV(&certificate_parser, out_signature_algorithm_tlv)) {
    out_errors->AddError(kSignatureAlgorithmNotSequence);
    return false;
  }

  //        signatureValue       BIT STRING  }
  if (!certificate_parser.ReadBitString(out_signature_value)) {
    out_errors->AddError(kSignatureValueNotBitString);
    return false;
  }

  // There isn't an extension point at the end of Certificate.
  if (certificate_parser.HasMore()) {
    out_errors->AddError(kUnconsumedDataInsideCertificateSequence);
    return false;
  }

  // By definition the input was a single Certificate, so there shouldn't be
  // unconsumed data.
  if (parser.HasMore()) {
    out_errors->AddError(kUnconsumedDataAfterCertificateSequence);
    return false;
  }

  return true;
}
} // namespace bvc
