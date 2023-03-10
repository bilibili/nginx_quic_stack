// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/pem.h"
#include "base/base64.h"
#include "common/platform/api/quiche_text_utils.h"
#include "common/platform/api/quiche_optional.h"
#include "googleurl/base/strings/string_util.h"
#include "googleurl/base/strings/stringprintf.h"

namespace {

const char kPEMSearchBlock[] = "-----BEGIN ";
const char kPEMBeginBlock[] = "-----BEGIN %s-----";
const char kPEMEndBlock[] = "-----END %s-----";

}  // namespace

namespace bvc {

using gurl_base::StringPiece;

struct PEMTokenizer::PEMType {
  std::string type;
  std::string header;
  std::string footer;
};

PEMTokenizer::PEMTokenizer(
    const StringPiece& str,
    const std::vector<std::string>& allowed_block_types) {
  Init(str, allowed_block_types);
}

PEMTokenizer::~PEMTokenizer() = default;

bool PEMTokenizer::GetNext() {
  while (pos_ != StringPiece::npos) {
    // Scan for the beginning of the next PEM encoded block.
    pos_ = str_.find(kPEMSearchBlock, pos_);
    if (pos_ == StringPiece::npos)
      return false;  // No more PEM blocks

    std::vector<PEMType>::const_iterator it;
    // Check to see if it is of an acceptable block type.
    for (it = block_types_.begin(); it != block_types_.end(); ++it) {
      if (!base::StartsWith(str_.substr(pos_), it->header))
        continue;

      // Look for a footer matching the header. If none is found, then all
      // data following this point is invalid and should not be parsed.
      StringPiece::size_type footer_pos = str_.find(it->footer, pos_);
      if (footer_pos == StringPiece::npos) {
        pos_ = StringPiece::npos;
        return false;
      }

      // Chop off the header and footer and parse the data in between.
      StringPiece::size_type data_begin = pos_ + it->header.size();
      pos_ = footer_pos + it->footer.size();
      block_type_ = it->type;

      StringPiece encoded = str_.substr(data_begin, footer_pos - data_begin);
      QuicheOptional<std::string> data = quiche::QuicheTextUtils::Base64Decode(
          gurl_base::CollapseWhitespaceASCII(encoded.as_string(), true));
      if (!data.has_value()) {
        break;
      }
      return true;
    }

    // If the block did not match any acceptable type, move past it and
    // continue the search. Otherwise, |pos_| has been updated to the most
    // appropriate search position to continue searching from and should not
    // be adjusted.
    if (it == block_types_.end())
      pos_ += sizeof(kPEMSearchBlock);
  }

  return false;
}

void PEMTokenizer::Init(const StringPiece& str,
                        const std::vector<std::string>& allowed_block_types) {
  str_ = str;
  pos_ = 0;

  // Construct PEM header/footer strings for all the accepted types, to
  // reduce parsing later.
  for (auto it = allowed_block_types.begin(); it != allowed_block_types.end();
       ++it) {
    PEMType allowed_type;
    allowed_type.type = *it;
    allowed_type.header = gurl_base::StringPrintf(kPEMBeginBlock, it->c_str());
    allowed_type.footer = gurl_base::StringPrintf(kPEMEndBlock, it->c_str());
    block_types_.push_back(allowed_type);
  }
}

std::string PEMEncode(StringPiece data, const std::string& type) {
  std::string b64_encoded;
  quiche::QuicheTextUtils::Base64Encode(data.data(), data.size(), &b64_encoded);

  // Divide the Base-64 encoded data into 64-character chunks, as per
  // 4.3.2.4 of RFC 1421.
  static const size_t kChunkSize = 64;
  size_t chunks = (b64_encoded.size() + (kChunkSize - 1)) / kChunkSize;

  std::string pem_encoded;
  pem_encoded.reserve(
      // header & footer
      17 + 15 + type.size() * 2 +
      // encoded data
      b64_encoded.size() +
      // newline characters for line wrapping in encoded data
      chunks);

  pem_encoded = "-----BEGIN ";
  pem_encoded.append(type);
  pem_encoded.append("-----\n");

  for (size_t i = 0, chunk_offset = 0; i < chunks;
       ++i, chunk_offset += kChunkSize) {
    pem_encoded.append(b64_encoded, chunk_offset, kChunkSize);
    pem_encoded.append("\n");
  }

  pem_encoded.append("-----END ");
  pem_encoded.append(type);
  pem_encoded.append("-----\n");
  return pem_encoded;
}

}  // namespace bvc
