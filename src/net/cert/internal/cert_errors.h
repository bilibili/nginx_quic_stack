// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// ----------------------------
// Overview of error design
// ----------------------------
//
// Certificate path building/validation/parsing may emit a sequence of errors
// and warnings.
//
// Each individual error/warning entry (CertError) is comprised of:
//
//   * A unique identifier.
//
//     This serves similarly to an error code, and is used to query if a
//     particular error/warning occurred.
//
//   * [optional] A parameters object.
//
//     Nodes may attach a heap-allocated subclass of CertErrorParams to carry
//     extra information that is used when reporting the error. For instance
//     a parsing error may describe where in the DER the failure happened, or
//     what the unexpected value was.
//
// A collection of errors is represented by the CertErrors object. This may be
// used to group errors that have a common context, such as all the
// errors/warnings that apply to a specific certificate.
//
// Lastly, CertPathErrors composes multiple CertErrors -- one for each
// certificate in the verified chain.
//
// ----------------------------
// Defining new errors
// ----------------------------
//
// The error IDs are extensible and do not need to be centrally defined.
//
// To define a new error use the macro DEFINE_CERT_ERROR_ID() in a .cc file.
// If consumers are to be able to query for this error then the symbol should
// also be exposed in a header file.
//
// Error IDs are in truth string literals, whose pointer value will be unique
// per process.

#ifndef BVC_NET_CERT_INTERNAL_CERT_ERRORS_H_
#define BVC_NET_CERT_INTERNAL_CERT_ERRORS_H_

#include <memory>
#include <vector>

#include "net/cert/internal/cert_error_id.h"

namespace bvc {

class CertErrorParams;

// CertError represents either an error or a warning.
struct CertError {
  enum Severity {
    SEVERITY_HIGH,
    SEVERITY_WARNING,
  };

  CertError();
  CertError(Severity severity,
            CertErrorId id,
            std::unique_ptr<CertErrorParams> params);
  CertError(CertError&& other);
  CertError& operator=(CertError&&);
  ~CertError();

  // Pretty-prints the error and its parameters.
  std::string ToDebugString() const;

  Severity severity;
  CertErrorId id;
  std::unique_ptr<CertErrorParams> params;
};

// CertErrors is a collection of CertError, along with convenience methods to
// add and inspect errors.
class NET_EXPORT CertErrors {
 public:
  CertErrors();
  CertErrors(CertErrors&& other);
  CertErrors& operator=(CertErrors&&);
  ~CertErrors();

  // Adds an error/warning. |params| may be null.
  void Add(CertError::Severity severity,
           CertErrorId id,
           std::unique_ptr<CertErrorParams> params);

  // Adds a high severity error.
  void AddError(CertErrorId id, std::unique_ptr<CertErrorParams> params);
  void AddError(CertErrorId id);

  // Adds a low severity error.
  void AddWarning(CertErrorId id, std::unique_ptr<CertErrorParams> params);
  void AddWarning(CertErrorId id);

  // Dumps a textual representation of the errors for debugging purposes.
  std::string ToDebugString() const;

  // Returns true if the error |id| was added to this CertErrors (of any
  // severity).
  bool ContainsError(CertErrorId id) const;

  // Returns true if this contains any errors of the given severity level.
  bool ContainsAnyErrorWithSeverity(CertError::Severity severity) const;

 private:
  std::vector<CertError> nodes_;
};

}  // namespace bvc

#endif  // BVC_NET_CERT_INTERNAL_CERT_ERRORS_H_