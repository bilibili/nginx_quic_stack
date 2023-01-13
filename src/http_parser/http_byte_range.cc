// Copyright (c) 2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "common/platform/api/quiche_logging.h"
#include "http_parser/http_byte_range.h"
#include "absl/strings/str_format.h"

namespace {
const int64_t kPositionNotSpecified = -1;
}  // namespace

namespace bvc {
HttpByteRange::HttpByteRange()
    : first_byte_position_(kPositionNotSpecified),
      last_byte_position_(kPositionNotSpecified),
      suffix_length_(kPositionNotSpecified),
      has_computed_bounds_(false) {
}
// static
HttpByteRange HttpByteRange::Bounded(int64_t first_byte_position,
                                     int64_t last_byte_position) {
  HttpByteRange range;
  range.set_first_byte_position(first_byte_position);
  range.set_last_byte_position(last_byte_position);
  return range;
}
// static
HttpByteRange HttpByteRange::RightUnbounded(int64_t first_byte_position) {
  HttpByteRange range;
  range.set_first_byte_position(first_byte_position);
  return range;
}
// static
HttpByteRange HttpByteRange::Suffix(int64_t suffix_length) {
  HttpByteRange range;
  range.set_suffix_length(suffix_length);
  return range;
}
bool HttpByteRange::IsSuffixByteRange() const {
  return suffix_length_ != kPositionNotSpecified;
}
bool HttpByteRange::HasFirstBytePosition() const {
  return first_byte_position_ != kPositionNotSpecified;
}
bool HttpByteRange::HasLastBytePosition() const {
  return last_byte_position_ != kPositionNotSpecified;
}
bool HttpByteRange::IsValid() const {
  if (suffix_length_ > 0)
    return true;
  return (first_byte_position_ >= 0 &&
          (last_byte_position_ == kPositionNotSpecified ||
           last_byte_position_ >= first_byte_position_));
}
std::string HttpByteRange::GetHeaderValue() const {
  QUICHE_DCHECK(IsValid());
  if (IsSuffixByteRange())
    return absl::StrFormat("bytes=-%d", suffix_length());
  QUICHE_DCHECK(HasFirstBytePosition());
  if (!HasLastBytePosition())
    return absl::StrFormat("bytes=%d-", first_byte_position());
  return absl::StrFormat("bytes=%d-%d", first_byte_position(), last_byte_position());
}
bool HttpByteRange::ComputeBounds(int64_t size) {
  if (size < 0)
    return false;
  if (has_computed_bounds_)
    return false;
  has_computed_bounds_ = true;
  // Empty values.
  if (!HasFirstBytePosition() &&
      !HasLastBytePosition() &&
      !IsSuffixByteRange()) {
    first_byte_position_ = 0;
    last_byte_position_ = size - 1;
    return true;
  }
  if (!IsValid())
    return false;
  if (IsSuffixByteRange()) {
    first_byte_position_ = size - std::min(size, suffix_length_);
    last_byte_position_ = size - 1;
    return true;
  }
  if (first_byte_position_ < size) {
    if (HasLastBytePosition())
      last_byte_position_ = std::min(size - 1, last_byte_position_);
    else
      last_byte_position_ = size - 1;
    return true;
  }
  return false;
}
}  // namespace bvc
