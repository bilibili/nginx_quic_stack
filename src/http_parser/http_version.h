// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BVC_HTTP_PARSER_HTTP_VERSION_H_
#define BVC_HTTP_PARSER_HTTP_VERSION_H_
#pragma once

namespace bvc {

// Wrapper for an HTTP (major,minor) version pair.
class HttpVersion {
 public:
  // Default constructor (major=0, minor=0).
  HttpVersion() : value_(0) { }

  // Build from unsigned major/minor pair.
  HttpVersion(uint16_t major, uint16_t minor) : value_(major << 16 | minor) { }

  // Major version number.
  uint16_t major_value() const {
    return value_ >> 16;
  }

  // Minor version number.
  uint16_t minor_value() const {
    return value_ & 0xffff;
  }

  // Overloaded operators:

  bool operator==(const HttpVersion& v) const {
    return value_ == v.value_;
  }
  bool operator!=(const HttpVersion& v) const {
    return value_ != v.value_;
  }
  bool operator>(const HttpVersion& v) const {
    return value_ > v.value_;
  }
  bool operator>=(const HttpVersion& v) const {
    return value_ >= v.value_;
  }
  bool operator<(const HttpVersion& v) const {
    return value_ < v.value_;
  }
  bool operator<=(const HttpVersion& v) const {
    return value_ <= v.value_;
  }

 private:
  uint32_t value_; // Packed as <major>:<minor>
};

}  // namespace bvc

#endif  // BVC_HTTP_PARSER_HTTP_VERSION_H_
