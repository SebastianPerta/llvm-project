//===-- CharSet.cpp - Utility class to convert between char sets --*- C++ -*-=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file provides utility classes to convert between different character
/// set encoding.
///
//===----------------------------------------------------------------------===//

#include "llvm/Support/CharSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include <algorithm>
#include <limits>
#include <system_error>

#if LLVM_ENABLE_ICONV
#include <iconv.h>
#endif

using namespace llvm;

namespace {

// Normalize the charset name with the charset alias matching algorithm proposed
// in https://www.unicode.org/reports/tr22/tr22-8.html#Charset_Alias_Matching.
void normalizeCharSetName(StringRef CSName, SmallVectorImpl<char> &Normalized) {
  bool PrevDigit = false;
  for (auto Ch : CSName) {
    if (isAlnum(Ch)) {
      Ch = toLower(Ch);
      if (Ch != '0' || PrevDigit) {
        PrevDigit = isDigit(Ch);
        Normalized.push_back(Ch);
      }
    }
  }
}

// Maps the charset name to enum constant if possible.
std::optional<text_encoding::id> getKnownCharSet(StringRef CSName) {
  SmallString<16> Normalized;
  normalizeCharSetName(CSName, Normalized);
#define CSNAME(CS, STR)                                                        \
  if (Normalized.equals(STR))                                                  \
  return CS
  CSNAME(text_encoding::id::UTF8, "utf8");
  CSNAME(text_encoding::id::ISOLatin1, "iso88591");
  CSNAME(text_encoding::id::IBM1047, "ibm1047");
#undef CSNAME
  return std::nullopt;
}

// Character conversion between Enhanced ASCII and EBCDIC (IBM-1047).
const unsigned char ISO88591ToIBM1047[256] = {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x15, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26,
    0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f, 0x40, 0x5a, 0x7f, 0x7b,
    0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e,
    0x4c, 0x7e, 0x6e, 0x6f, 0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x5f, 0x6d,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92,
    0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
    0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
    0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b,
    0x04, 0x14, 0x3e, 0xff, 0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5,
    0xbb, 0xb4, 0x9a, 0x8a, 0xb0, 0xca, 0xaf, 0xbc, 0x90, 0x8f, 0xea, 0xfa,
    0xbe, 0xa0, 0xb6, 0xb3, 0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab,
    0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, 0x74, 0x71, 0x72, 0x73,
    0x78, 0x75, 0x76, 0x77, 0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf,
    0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xba, 0xae, 0x59, 0x44, 0x45, 0x42, 0x46,
    0x43, 0x47, 0x9c, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
    0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, 0x70, 0xdd, 0xde, 0xdb,
    0xdc, 0x8d, 0x8e, 0xdf};

const unsigned char IBM1047ToISO88591[256] = {
    0x00, 0x01, 0x02, 0x03, 0x9c, 0x09, 0x86, 0x7f, 0x97, 0x8d, 0x8e, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x9d, 0x0a, 0x08, 0x87,
    0x18, 0x19, 0x92, 0x8f, 0x1c, 0x1d, 0x1e, 0x1f, 0x80, 0x81, 0x82, 0x83,
    0x84, 0x85, 0x17, 0x1b, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07,
    0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9a, 0x9b,
    0x14, 0x15, 0x9e, 0x1a, 0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5,
    0xe7, 0xf1, 0xa2, 0x2e, 0x3c, 0x28, 0x2b, 0x7c, 0x26, 0xe9, 0xea, 0xeb,
    0xe8, 0xed, 0xee, 0xef, 0xec, 0xdf, 0x21, 0x24, 0x2a, 0x29, 0x3b, 0x5e,
    0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, 0xc7, 0xd1, 0xa6, 0x2c,
    0x25, 0x5f, 0x3e, 0x3f, 0xf8, 0xc9, 0xca, 0xcb, 0xc8, 0xcd, 0xce, 0xcf,
    0xcc, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22, 0xd8, 0x61, 0x62, 0x63,
    0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1,
    0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xaa, 0xba,
    0xe6, 0xb8, 0xc6, 0xa4, 0xb5, 0x7e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0x5b, 0xde, 0xae, 0xac, 0xa3, 0xa5, 0xb7,
    0xa9, 0xa7, 0xb6, 0xbc, 0xbd, 0xbe, 0xdd, 0xa8, 0xaf, 0x5d, 0xb4, 0xd7,
    0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xad, 0xf4,
    0xf6, 0xf2, 0xf3, 0xf5, 0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff, 0x5c, 0xf7, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xb3, 0xdb,
    0xdc, 0xd9, 0xda, 0x9f};

enum { NoUTF8 = 0x0, SrcIsUTF8 = 0x1, DstIsUTF8 = 0x2 };

std::error_code convertWithTable(const unsigned char *Table, unsigned Flags,
                                 StringRef Source,
                                 SmallVectorImpl<char> &Result) {
  const unsigned char *Ptr =
      reinterpret_cast<const unsigned char *>(Source.data());
  size_t Length = Source.size();
  Result.truncate(0);
  while (Length--) {
    unsigned char Ch = *Ptr++;
    // Handle UTF-8 2-byte-sequences in input.
    if (Flags & SrcIsUTF8) {
      if (Ch >= 128) {
        // Only valid sequences encoding UCS scalar values in the range [U+0080,
        // U+00FF] can be decoded.
        if (Ch != 0xc2 && Ch != 0xc3)
          return std::make_error_code(std::errc::illegal_byte_sequence);
        // Is buffer truncated?
        if (!Length)
          return std::make_error_code(std::errc::invalid_argument);
        unsigned char Ch2 = *Ptr++;
        // Is second byte well-formed?
        if ((Ch2 & 0xc0) != 0x80)
          return std::make_error_code(std::errc::illegal_byte_sequence);
        Ch = Ch2 | (Ch << 6);
        --Length;
      }
    }
    // Translate the character.
    Ch = Table ? Table[Ch] : Ch;
    // Handle UTF-8 2-byte-sequences in output.
    if (Flags & DstIsUTF8) {
      if (Ch >= 128) {
        // First byte prefixed with either 0xc2 or 0xc3.
        Result.push_back(static_cast<char>(0xc0 | (Ch >> 6)));
        // Second byte is either the same as the ASCII byte or ASCII byte -64.
        Ch = Ch & 0xbf;
      }
    }
    Result.push_back(static_cast<char>(Ch));
  }
  return std::error_code();
}

#if LLVM_ENABLE_ICONV
std::error_code convertWithIconv(iconv_t ConvDesc, StringRef Source,
                                 SmallVectorImpl<char> &Result) {
  // Setup the input. Use nullptr to reset iconv state if input length is zero.
  size_t InputLength = Source.size();
  char *Input = InputLength ? const_cast<char *>(Source.data()) : nullptr;
  // Setup the output. We directly write into the SmallVector.
  size_t Capacity = Result.capacity();
  Result.resize(Capacity);
  char *Output = InputLength ? static_cast<char *>(Result.data()) : nullptr;
  size_t OutputLength = Capacity;

  size_t Ret;

  // Handle errors returned from iconv().
  auto HandleError = [&Capacity, &Output, &OutputLength, &Result](size_t Ret) {
    if (Ret == static_cast<size_t>(-1)) {
      // An error occured. Check if we can gracefully handle it.
      if (errno == E2BIG && Capacity < std::numeric_limits<size_t>::max()) {
        // No space left in output buffer. Double the size of the underlying
        // memory in the SmallVectorImpl, adjust pointer and length and continue
        // the conversion.
        const size_t Used = Capacity - OutputLength;
        Capacity = (Capacity < std::numeric_limits<size_t>::max() / 2)
                       ? 2 * Capacity
                       : std::numeric_limits<size_t>::max();
        Result.resize(Capacity);
        Output = static_cast<char *>(Result.data()) + Used;
        OutputLength = Capacity - Used;
        return std::error_code();
      } else {
        // Some other error occured.
        return std::error_code(errno, std::generic_category());
      }
    } else {
      // A positive return value indicates that some characters were converted
      // in a nonreversible way, that is, replaced with a SUB symbol. Returning
      // an error in this case makes sure that both conversion routines behave
      // in the same way.
      return std::make_error_code(std::errc::illegal_byte_sequence);
    }
  };

  // Convert the string. After all input characters are consumed, call iconv()
  // with the input parameter set to nullptr, to flush out any partially
  // converted input characters.
  while ((Ret = iconv(ConvDesc, &Input, &InputLength, &Output, &OutputLength)))
    if (auto EC = HandleError(Ret))
      return EC;
  while ((Ret = iconv(ConvDesc, nullptr, nullptr, &Output, &OutputLength)))
    if (auto EC = HandleError(Ret))
      return EC;

  // Re-adjust size to actual size.
  Result.resize(Capacity - OutputLength);
  return std::error_code();
}
#endif
} // end anonymous namespace

CharSetConverter CharSetConverter::create(text_encoding::id CSFrom,
                                          text_encoding::id CSTo) {
  // Special case: identity transformation.
  if (CSFrom == CSTo)
    return CharSetConverter{
        [](StringRef Source, SmallVectorImpl<char> &Result) {
          Result.assign(Source.begin(), Source.end());
          return std::error_code();
        },
        nullptr};

  unsigned Flags = NoUTF8;
  if (CSFrom == text_encoding::id::UTF8)
    Flags |= SrcIsUTF8;
  if (CSTo == text_encoding::id::UTF8)
    Flags |= DstIsUTF8;
  const unsigned char *Table = nullptr;
  if (CSFrom == text_encoding::id::IBM1047)
    Table = IBM1047ToISO88591;
  if (CSTo == text_encoding::id::IBM1047)
    Table = ISO88591ToIBM1047;
  return CharSetConverter{
      [Table, Flags](StringRef Source, SmallVectorImpl<char> &Result) {
        return convertWithTable(Table, Flags, Source, Result);
      },
      nullptr};
}

ErrorOr<CharSetConverter> CharSetConverter::create(StringRef CSFrom,
                                                   StringRef CSTo) {
  std::optional<text_encoding::id> From = getKnownCharSet(CSFrom);
  std::optional<text_encoding::id> To = getKnownCharSet(CSTo);
  if (From && To &&
      (From == text_encoding::id::IBM1047 || To == text_encoding::id::IBM1047))
    return create(*From, *To);
#if LLVM_ENABLE_ICONV
  iconv_t ConvDesc = iconv_open((CSTo.str()).c_str(), CSFrom.str().c_str());
  if (ConvDesc == (iconv_t)-1)
    return std::error_code(errno, std::generic_category());
  return CharSetConverter{
      [ConvDesc](StringRef Source, SmallVectorImpl<char> &Result) {
        return convertWithIconv(ConvDesc, Source, Result);
      },
      [ConvDesc]() { iconv_close(ConvDesc); }};
#endif
  return std::make_error_code(std::errc::invalid_argument);
}
