// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_errors.h"

#include "googleurl/base/strings/strcat.h"
#include "googleurl/base/strings/string_split.h"
#include "googleurl/base/strings/stringprintf.h"
#include "net/cert/internal/cert_error_params.h"
#include "net/cert/internal/parse_name.h"
#include "net/cert/internal/parsed_certificate.h"

namespace bvc {

namespace {

void AppendLinesWithIndentation(const std::string& text,
                                const std::string& indentation,
                                std::string* out) {
  std::vector<gurl_base::StringPiece> lines = gurl_base::SplitStringPieceUsingSubstr(
      text, "\n", gurl_base::KEEP_WHITESPACE, gurl_base::SPLIT_WANT_ALL);

  for (const auto& line : lines) {
    gurl_base::StrAppend(out, {indentation, line, "\n"});
  }
}

}  // namespace

CertError::CertError() = default;

CertError::CertError(Severity severity,
                     CertErrorId id,
                     std::unique_ptr<CertErrorParams> params)
    : severity(severity), id(id), params(std::move(params)) {}

CertError::CertError(CertError&& other) = default;

CertError& CertError::operator=(CertError&&) = default;

CertError::~CertError() = default;

std::string CertError::ToDebugString() const {
  std::string result;
  switch (severity) {
    case SEVERITY_WARNING:
      result += "WARNING: ";
      break;
    case SEVERITY_HIGH:
      result += "ERROR: ";
      break;
  }
  result += CertErrorIdToDebugString(id);
  result += +"\n";

  if (params)
    AppendLinesWithIndentation(params->ToDebugString(), "  ", &result);

  return result;
}

CertErrors::CertErrors() = default;
CertErrors::CertErrors(CertErrors&& other) = default;
CertErrors& CertErrors::operator=(CertErrors&&) = default;
CertErrors::~CertErrors() = default;

void CertErrors::Add(CertError::Severity severity,
                     CertErrorId id,
                     std::unique_ptr<CertErrorParams> params) {
  nodes_.push_back(CertError(severity, id, std::move(params)));
}

void CertErrors::AddError(CertErrorId id,
                          std::unique_ptr<CertErrorParams> params) {
  Add(CertError::SEVERITY_HIGH, id, std::move(params));
}

void CertErrors::AddError(CertErrorId id) {
  AddError(id, nullptr);
}

void CertErrors::AddWarning(CertErrorId id,
                            std::unique_ptr<CertErrorParams> params) {
  Add(CertError::SEVERITY_WARNING, id, std::move(params));
}

void CertErrors::AddWarning(CertErrorId id) {
  AddWarning(id, nullptr);
}

std::string CertErrors::ToDebugString() const {
  std::string result;
  for (const CertError& node : nodes_)
    result += node.ToDebugString();

  return result;
}

bool CertErrors::ContainsError(CertErrorId id) const {
  for (const CertError& node : nodes_) {
    if (node.id == id)
      return true;
  }
  return false;
}

bool CertErrors::ContainsAnyErrorWithSeverity(
    CertError::Severity severity) const {
  for (const CertError& node : nodes_) {
    if (node.severity == severity)
      return true;
  }
  return false;
}

}  // namespace bvc