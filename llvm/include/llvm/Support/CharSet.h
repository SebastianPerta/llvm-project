//===-- CharSet.h - Utility class to convert between char sets ----*- C++ -*-=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file provides a utility class to convert between different character
/// set encodings.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_CHARSET_H
#define LLVM_SUPPORT_CHARSET_H

#include "llvm/ADT/StringRef.h"
#include "llvm/Config/config.h"
#include "llvm/Support/ErrorOr.h"

#include <functional>
#include <string>
#include <system_error>

namespace llvm {

template <typename T> class SmallVectorImpl;

// Names inspired by https://wg21.link/p1885.
namespace text_encoding {
enum class id {
  /// UTF-8 character set encoding.
  UTF8,

  /// ISO 8859-1 (Latin-1) character set encoding.
  ISOLatin1,

  /// IBM EBCDIC 1047 character set encoding.
  IBM1047
};
} // end namespace text_encoding

/// Utility class to convert between different character set encodings.
/// The class always supports converting between EBCDIC 1047 and Latin-1/UTF-8.
/// If the iconv library is available, then arbitrary conversions are supported.
/// TODO Add Windows support.
class CharSetConverter {
public:
  using ConverterFunc =
      std::function<std::error_code(StringRef, SmallVectorImpl<char> &)>;
  using CleanupFunc = std::function<void(void)>;

private:
  ConverterFunc Convert;
  CleanupFunc Cleanup;

  CharSetConverter(ConverterFunc Convert, CleanupFunc Cleanup)
      : Convert(Convert), Cleanup(Cleanup) {}

public:
  /// Creates a CharSetConverter instance.
  /// \param[in] CSFrom name of the source character encoding
  /// \param[in] CSTo name of the target character encoding
  /// \return a CharSetConverter instance
  static CharSetConverter create(text_encoding::id CSFrom,
                                 text_encoding::id CSTo);

  /// Creates a CharSetConverter instance.
  /// Returns std::errc::invalid_argument in case the requested conversion is
  /// not supported.
  /// \param[in] CSFrom name of the source character encoding
  /// \param[in] CSTo name of the target character encoding
  /// \return a CharSetConverter instance or an error code
  ///
  /// The following error codes can occur, among others:
  ///   - std::errc::invalid_argument: The requested conversion is not
  ///     supported.
  static ErrorOr<CharSetConverter> create(StringRef CSFrom, StringRef CSTo);

  CharSetConverter(const CharSetConverter &) = delete;
  CharSetConverter &operator=(const CharSetConverter &) = delete;

  CharSetConverter(CharSetConverter &&Other) {
    this->Convert = Other.Convert;
    this->Cleanup = Other.Cleanup;
    Other.Cleanup = nullptr;
  }

  CharSetConverter &operator=(CharSetConverter &&Other) {
    if (this->Cleanup)
      this->Cleanup();
    this->Convert = Other.Convert;
    this->Cleanup = Other.Cleanup;
    Other.Cleanup = nullptr;
    return *this;
  }

  ~CharSetConverter() {
    if (Cleanup)
      Cleanup();
  }

  /// Converts a string.
  /// \param[in] Source source string
  /// \param[in,out] Result container for converted string
  /// \return error code in case something went wrong
  ///
  /// The following error codes can occur, among others:
  ///   - std::errc::argument_list_too_long: The result requires more than
  ///     std::numeric_limits<size_t>::max() bytes.
  ///   - std::errc::illegal_byte_sequence: The input contains an invalid
  ///     multibyte sequence.
  ///   - std::errc::invalid_argument: The input contains an incomplete
  ///     multibyte sequence.
  ///
  /// In case of an error, the result string contains the successfully converted
  /// part of the input string.
  ///
  /// If the Source parameter has a zero length, then no conversion is
  /// performed. Instead, the internal conversation state of iconv is reset to
  /// the initial state if iconv is used for the conversion. Otherwise it is a
  /// no-op.
  std::error_code convert(StringRef Source,
                          SmallVectorImpl<char> &Result) const {
    return Convert(Source, Result);
  }

  /// Converts a string.
  /// \param[in] Source source string
  /// \param[in,out] Result container for converted string
  /// \return error code in case something went wrong
  ///
  /// Behavior in case of error is similar to convert(StringRef,
  /// SmallVectorImpl<char> &).
  std::error_code convert(const std::string &Source,
                          SmallVectorImpl<char> &Result) const {
    return convert(StringRef(Source), Result);
  }
};

} // end namespace llvm

#endif
