// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/base/escape.h"
#include "platform/quiche_platform_impl/quiche_logging_impl.h"
#include "common/platform/api/quiche_logging.h"
#include "googleurl/base/stl_util.h"
#include "googleurl/base/strings/string_util.h"
#include "googleurl/base/strings/utf_string_conversion_utils.h"
#include "googleurl/base/strings/utf_string_conversions.h"
#include "googleurl/base/third_party/icu/icu_utf.h"

namespace bvc {
namespace {
const char kHexString[] = "0123456789ABCDEF";
inline char IntToHex(int i) {
  QUICHE_DCHECK_GE(i, 0) << i << " not a hex value";
  QUICHE_DCHECK_LE(i, 15) << i << " not a hex value";
  return kHexString[i];
}

// A fast bit-vector map for ascii characters.
//
// Internally stores 256 bits in an array of 8 ints.
// Does quick bit-flicking to lookup needed characters.
struct Charmap {
  bool Contains(unsigned char c) const {
    return ((map[c >> 5] & (1 << (c & 31))) != 0);
  }
  uint32_t map[8];
};

// Given text to escape and a Charmap defining which values to escape,
// return an escaped string.  If use_plus is true, spaces are converted
// to +, otherwise, if spaces are in the charmap, they are converted to
// %20. And if keep_escaped is true, %XX will be kept as it is, otherwise, if
// '%' is in the charmap, it is converted to %25.
std::string Escape(gurl_base::StringPiece text,
                   const Charmap& charmap,
                   bool use_plus,
                   bool keep_escaped = false) {
  std::string escaped;
  escaped.reserve(text.length() * 3);
  for (unsigned int i = 0; i < text.length(); ++i) {
    unsigned char c = static_cast<unsigned char>(text[i]);
    if (use_plus && ' ' == c) {
      escaped.push_back('+');
    } else if (keep_escaped && '%' == c && i + 2 < text.length() &&
               gurl_base::IsHexDigit(text[i + 1]) && gurl_base::IsHexDigit(text[i + 2])) {
      escaped.push_back('%');
    } else if (charmap.Contains(c)) {
      escaped.push_back('%');
      escaped.push_back(IntToHex(c >> 4));
      escaped.push_back(IntToHex(c & 0xf));
    } else {
      escaped.push_back(c);
    }
  }
  return escaped;
}

// Convert a character |c| to a form that will not be mistaken as HTML.
template <class str>
void AppendEscapedCharForHTMLImpl(typename str::value_type c, str* output) {
  static constexpr struct {
    char key;
    gurl_base::StringPiece replacement;
  } kCharsToEscape[] = {
      {'<', "&lt;"},   {'>', "&gt;"},   {'&', "&amp;"},
      {'"', "&quot;"}, {'\'', "&#39;"},
  };
  for (const auto& char_to_escape : kCharsToEscape) {
    if (c == char_to_escape.key) {
      output->append(std::begin(char_to_escape.replacement),
                     std::end(char_to_escape.replacement));
      return;
    }
  }
  output->push_back(c);
}

// Convert |input| string to a form that will not be interpreted as HTML.
template <class str>
str EscapeForHTMLImpl(gurl_base::BasicStringPiece<str> input) {
  str result;
  result.reserve(input.size());  // Optimize for no escaping.
  for (auto c : input) {
    AppendEscapedCharForHTMLImpl(c, &result);
  }
  return result;
}

// Everything except alphanumerics and -._~
// See RFC 3986 for the list of unreserved characters.
static const Charmap kUnreservedCharmap = {
    {0xffffffffL, 0xfc009fffL, 0x78000001L, 0xb8000001L, 0xffffffffL,
     0xffffffffL, 0xffffffffL, 0xffffffffL}};

// Everything except alphanumerics and !'()*-._~
// See RFC 2396 for the list of reserved characters.
static const Charmap kQueryCharmap = {{
  0xffffffffL, 0xfc00987dL, 0x78000001L, 0xb8000001L,
  0xffffffffL, 0xffffffffL, 0xffffffffL, 0xffffffffL
}};

// non-printable, non-7bit, and (including space)  "#%:<>?[\]^`{|}
static const Charmap kPathCharmap = {{
  0xffffffffL, 0xd400002dL, 0x78000000L, 0xb8000001L,
  0xffffffffL, 0xffffffffL, 0xffffffffL, 0xffffffffL
}};

#if defined(OS_APPLE)
// non-printable, non-7bit, and (including space)  "#%<>[\]^`{|}
static const Charmap kNSURLCharmap = {{
  0xffffffffL, 0x5000002dL, 0x78000000L, 0xb8000001L,
  0xffffffffL, 0xffffffffL, 0xffffffffL, 0xffffffffL
}};
#endif  // defined(OS_APPLE)

// non-printable, non-7bit, and (including space) ?>=<;+'&%$#"![\]^`{|}
static const Charmap kUrlEscape = {{
  0xffffffffL, 0xf80008fdL, 0x78000001L, 0xb8000001L,
  0xffffffffL, 0xffffffffL, 0xffffffffL, 0xffffffffL
}};

// non-7bit, as well as %.
static const Charmap kNonASCIICharmapAndPercent = {
    {0x00000000L, 0x00000020L, 0x00000000L, 0x00000000L, 0xffffffffL,
     0xffffffffL, 0xffffffffL, 0xffffffffL}};

// non-7bit
static const Charmap kNonASCIICharmap = {{0x00000000L, 0x00000000L, 0x00000000L,
                                          0x00000000L, 0xffffffffL, 0xffffffffL,
                                          0xffffffffL, 0xffffffffL}};

// Everything except alphanumerics, the reserved characters(;/?:@&=+$,) and
// !'()*-._~#[]
static const Charmap kExternalHandlerCharmap = {{
  0xffffffffL, 0x50000025L, 0x50000000L, 0xb8000001L,
  0xffffffffL, 0xffffffffL, 0xffffffffL, 0xffffffffL
}};
}  // namespace

std::string EscapeAllExceptUnreserved(gurl_base::StringPiece text) {
  return Escape(text, kUnreservedCharmap, false);
}
std::string EscapeQueryParamValue(gurl_base::StringPiece text, bool use_plus) {
  return Escape(text, kQueryCharmap, use_plus);
}
std::string EscapePath(gurl_base::StringPiece path) {
  return Escape(path, kPathCharmap, false);
}

#if defined(OS_APPLE)
std::string EscapeNSURLPrecursor(gurl_base::StringPiece precursor) {
  return Escape(precursor, kNSURLCharmap, false, true);
}
#endif  // defined(OS_APPLE)

std::string EscapeUrlEncodedData(gurl_base::StringPiece path, bool use_plus) {
  return Escape(path, kUrlEscape, use_plus);
}
std::string EscapeNonASCIIAndPercent(gurl_base::StringPiece input) {
  return Escape(input, kNonASCIICharmapAndPercent, false);
}
std::string EscapeNonASCII(gurl_base::StringPiece input) {
  return Escape(input, kNonASCIICharmap, false);
}
std::string EscapeExternalHandlerValue(gurl_base::StringPiece text) {
  return Escape(text, kExternalHandlerCharmap, false, true);
}
void AppendEscapedCharForHTML(char c, std::string* output) {
  AppendEscapedCharForHTMLImpl(c, output);
}
std::string EscapeForHTML(gurl_base::StringPiece input) {
  return EscapeForHTMLImpl(input);
}
gurl_base::string16 EscapeForHTML(gurl_base::StringPiece16 input) {
  return EscapeForHTMLImpl(input);
}

// TODO(crbug/1100760): Move functions from net/base/escape to
// base/strings/escape.
std::string UnescapeURLComponent(gurl_base::StringPiece escaped_text,
                                 UnescapeRule::Type rules) {
  return gurl_base::UnescapeURLComponent(escaped_text, rules);
}
gurl_base::string16 UnescapeAndDecodeUTF8URLComponentWithAdjustments(
    gurl_base::StringPiece text,
    UnescapeRule::Type rules,
    gurl_base::OffsetAdjuster::Adjustments* adjustments) {
  return gurl_base::UnescapeAndDecodeUTF8URLComponentWithAdjustments(text, rules,
                                                                adjustments);
}
std::string UnescapeBinaryURLComponent(gurl_base::StringPiece escaped_text,
                                       UnescapeRule::Type rules) {
  return gurl_base::UnescapeBinaryURLComponent(escaped_text, rules);
}
bool UnescapeBinaryURLComponentSafe(gurl_base::StringPiece escaped_text,
                                    bool fail_on_path_separators,
                                    std::string* unescaped_text) {
  return gurl_base::UnescapeBinaryURLComponentSafe(
      escaped_text, fail_on_path_separators, unescaped_text);
}

gurl_base::string16 UnescapeForHTML(gurl_base::StringPiece16 input) {
  static const struct {
    const char* ampersand_code;
    const char replacement;
  } kEscapeToChars[] = {
      {"&lt;", '<'},   {"&gt;", '>'},   {"&amp;", '&'},
      {"&quot;", '"'}, {"&#39;", '\''},
  };
  constexpr size_t kEscapeToCharsCount = gurl_base::size(kEscapeToChars);
  if (input.find(gurl_base::ASCIIToUTF16("&")) == std::string::npos)
    return gurl_base::string16(input);
  gurl_base::string16 ampersand_chars[kEscapeToCharsCount];
  gurl_base::string16 text(input);
  for (gurl_base::string16::iterator iter = text.begin();
       iter != text.end(); ++iter) {
    if (*iter == '&') {
      // Potential ampersand encode char.
      size_t index = iter - text.begin();
      for (size_t i = 0; i < gurl_base::size(kEscapeToChars); i++) {
        if (ampersand_chars[i].empty()) {
          ampersand_chars[i] =
              gurl_base::ASCIIToUTF16(kEscapeToChars[i].ampersand_code);
        }
        if (text.find(ampersand_chars[i], index) == index) {
          text.replace(iter, iter + ampersand_chars[i].length(),
                       1, kEscapeToChars[i].replacement);
          break;
        }
      }
    }
  }
  return text;
}

bool ContainsEncodedBytes(gurl_base::StringPiece escaped_text,
                          const std::set<unsigned char>& bytes) {
  return gurl_base::ContainsEncodedBytes(escaped_text, bytes);
}
}  // namespace bvc
