// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef BVC_NET_BASE_ESCAPE_H_
#define BVC_NET_BASE_ESCAPE_H_

#include <stdint.h>
#include <set>
#include <string>
#include "googleurl/base/strings/escape.h"
#include "googleurl/base/strings/string16.h"
#include "googleurl/base/strings/string_piece.h"
#include "googleurl/base/strings/utf_offset_string_conversions.h"

namespace bvc {
// Escaping --------------------------------------------------------------------
// Escapes all characters except unreserved characters. Unreserved characters,
// as defined in RFC 3986, include alphanumerics and -._~
std::string EscapeAllExceptUnreserved(gurl_base::StringPiece text);

// Escapes characters in text suitable for use as a query parameter value.
// We %XX everything except alphanumerics and -_.!~*'()
// Spaces change to "+" unless you pass usePlus=false.
// This is basically the same as encodeURIComponent in javascript.
std::string EscapeQueryParamValue(gurl_base::StringPiece text,
                                             bool use_plus);

// Escapes a partial or complete file/pathname.  This includes:
// non-printable, non-7bit, and (including space)  "#%:<>?[\]^`{|}
std::string EscapePath(gurl_base::StringPiece path);

#if defined(OS_APPLE)
// Escapes characters as per expectations of NSURL. This includes:
// non-printable, non-7bit, and (including space)  "#%<>[\]^`{|}
std::string EscapeNSURLPrecursor(gurl_base::StringPiece precursor);
#endif  // defined(OS_APPLE)

// Escapes application/x-www-form-urlencoded content.  This includes:
// non-printable, non-7bit, and (including space)  ?>=<;+'&%$#"![\]^`{|}
// Space is escaped as + (if use_plus is true) and other special characters
// as %XX (hex).
std::string EscapeUrlEncodedData(gurl_base::StringPiece path,
                                            bool use_plus);
// Escapes all non-ASCII input, as well as escaping % to %25.
std::string EscapeNonASCIIAndPercent(gurl_base::StringPiece input);

// Escapes all non-ASCII input. Note this function leaves % unescaped, which
// means the unescaping the resulting string will not give back the original
// input.
std::string EscapeNonASCII(gurl_base::StringPiece input);

// Escapes characters in text suitable for use as an external protocol handler
// command.
// We %XX everything except alphanumerics and -_.!~*'() and the restricted
// characters (;/?:@&=+$,#[]) and a valid percent escape sequence (%XX).
std::string EscapeExternalHandlerValue(gurl_base::StringPiece text);

// Appends the given character to the output string, escaping the character if
// the character would be interpreted as an HTML delimiter.
void AppendEscapedCharForHTML(char c, std::string* output);

// Escapes chars that might cause this text to be interpreted as HTML tags.
std::string EscapeForHTML(gurl_base::StringPiece text);

gurl_base::string16 EscapeForHTML(gurl_base::StringPiece16 text);

// Unescaping ------------------------------------------------------------------
// TODO(crbug/1100760): Migrate callers to call functions in
// base/strings/escape.
using UnescapeRule = gurl_base::UnescapeRule;

// Unescapes |escaped_text| and returns the result.
// Unescaping consists of looking for the exact pattern "%XX", where each X is
// a hex digit, and converting to the character with the numerical value of
// those digits. Thus "i%20=%203%3b" unescapes to "i = 3;", if the
// "UnescapeRule::SPACES" used.
//
// This method does not ensure that the output is a valid string using any
// character encoding. However, it does leave escaped certain byte sequences
// that would be dangerous to display to the user, because if interpreted as
// UTF-8, they could be used to mislead the user. Callers that want to
// unconditionally unescape everything for uses other than displaying data to
// the user should use UnescapeBinaryURLComponent().
std::string UnescapeURLComponent(gurl_base::StringPiece escaped_text,
                                            UnescapeRule::Type rules);

// Unescapes the given substring as a URL, and then tries to interpret the
// result as being encoded as UTF-8. If the result is convertible into UTF-8, it
// will be returned as converted. If it is not, the original escaped string will
// be converted into a gurl_base::string16 and returned.  |adjustments| provides
// information on how the original string was adjusted to get the string
// returned.
gurl_base::string16 UnescapeAndDecodeUTF8URLComponentWithAdjustments(
    gurl_base::StringPiece text,
    UnescapeRule::Type rules,
    gurl_base::OffsetAdjuster::Adjustments* adjustments);

// Unescapes a component of a URL for use as binary data. Unlike
// UnescapeURLComponent, leaves nothing unescaped, including nulls, invalid
// characters, characters that are unsafe to display, etc. This should *not*
// be used when displaying the decoded data to the user.
//
// Only the NORMAL and REPLACE_PLUS_WITH_SPACE rules are allowed.
std::string UnescapeBinaryURLComponent(
    gurl_base::StringPiece escaped_text,
    UnescapeRule::Type rules = UnescapeRule::NORMAL);

// Variant of UnescapeBinaryURLComponent().  Writes output to |unescaped_text|.
// Returns true on success, returns false and clears |unescaped_text| on
// failure. Fails on characters escaped that are unsafe to unescape in some
// contexts, which are defined as characters "\0" through "\x1F" (Which includes
// CRLF but not space), and optionally path separators. Path separators include
// both forward and backward slashes on all platforms. Does not fail if any of
// those characters appear unescaped in the input string.
bool UnescapeBinaryURLComponentSafe(gurl_base::StringPiece escaped_text,
                                               bool fail_on_path_separators,
                                               std::string* unescaped_text);

// Unescapes the following ampersand character codes from |text|:
// &lt; &gt; &amp; &quot; &#39;
gurl_base::string16 UnescapeForHTML(gurl_base::StringPiece16 text);
}  // namespace bvc

#endif  // BVC_NET_BASE_ESCAPE_H_
