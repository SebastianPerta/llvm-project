//===- unittests/Support/CharSetTest.cpp - Charset conversion tests -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Support/CharSet.h"
#include "llvm/ADT/SmallString.h"
#include "gtest/gtest.h"
using namespace llvm;

namespace {

// String "Hello World!"
static const char HelloA[] =
    "\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64\x21\x0a";
static const char HelloE[] =
    "\xC8\x85\x93\x93\x96\x40\xE6\x96\x99\x93\x84\x5A\x15";

// String "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
static const char ABCStrA[] =
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52"
    "\x53\x54\x55\x56\x57\x58\x59\x5A\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A"
    "\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A";
static const char ABCStrE[] =
    "\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9"
    "\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\x81\x82\x83\x84\x85\x86\x87\x88\x89\x91"
    "\x92\x93\x94\x95\x96\x97\x98\x99\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9";

// String "¡¢£AÄÅÆEÈÉÊaàáâãäeèéêë"
static const char AccentUTF[] =
    "\xc2\xa1\xc2\xa2\xc2\xa3\x41\xc3\x84\xc3\x85\xc3\x86\x45\xc3\x88\xc3\x89"
    "\xc3\x8a\x61\xc3\xa0\xc3\xa1\xc3\xa2\xc3\xa3\xc3\xa4\x65\xc3\xa8\xc3\xa9"
    "\xc3\xaa\xc3\xab";
static const char AccentE[] = "\xaa\x4a\xb1\xc1\x63\x67\x9e\xc5\x74\x71\x72"
                              "\x81\x44\x45\x42\x46\x43\x85\x54\x51\x52\x53";

// String with Cyrillic character ya.
static const char CyrillicUTF[] = "\xd0\xaf";

template<unsigned int N>
static std::string SmallStringToString(SmallString<N> SM) {
  std::string s = "";
  for(int i = 0; i < N; i++)
    s += SM[i];
  return s;
}

TEST(CharSet, FromASCII) {
  // Hello string.
  StringRef Src(HelloA);
  SmallString<64> Dst;

  CharSetConverter Conv = CharSetConverter::create(text_encoding::id::ISOLatin1,
                                                   text_encoding::id::IBM1047);
  std::error_code EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(HelloE, SmallStringToString(Dst).c_str());

  // ABC string.
  Src = ABCStrA;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(ABCStrE, SmallStringToString(Dst).c_str());
}

TEST(CharSet, ToASCII) {
  // Hello string.
  StringRef Src(HelloE);
  SmallString<64> Dst;

  CharSetConverter Conv = CharSetConverter::create(
      text_encoding::id::IBM1047, text_encoding::id::ISOLatin1);
  std::error_code EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(HelloA, SmallStringToString(Dst).c_str());

  // ABC string.
  Src = ABCStrE;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(ABCStrA, SmallStringToString(Dst).c_str());
}

TEST(CharSet, FromUTF8) {
  // Hello string.
  StringRef Src(HelloA);
  SmallString<64> Dst;

  CharSetConverter Conv = CharSetConverter::create(text_encoding::id::UTF8,
                                                   text_encoding::id::IBM1047);
  std::error_code EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(HelloE, SmallStringToString(Dst).c_str());

  // ABC string.
  Src = ABCStrA;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(ABCStrE, SmallStringToString(Dst).c_str());

  // Accent string.
  Src = AccentUTF;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(AccentE, SmallStringToString(Dst).c_str());

  // Cyrillic string. Results in error because not representable in 1047.
  Src = CyrillicUTF;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_EQ(EC, std::errc::illegal_byte_sequence);
}

TEST(CharSet, ToUTF8) {
  // Hello string.
  StringRef Src(HelloE);
  SmallString<64> Dst;

  CharSetConverter Conv = CharSetConverter::create(text_encoding::id::IBM1047,
                                                   text_encoding::id::UTF8);
  std::error_code EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(HelloA, SmallStringToString(Dst).c_str());

  // ABC string.
  Src = ABCStrE;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(ABCStrA, SmallStringToString(Dst).c_str());

  // Accent string.
  Src = AccentE;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(AccentUTF, SmallStringToString(Dst).c_str());
}

TEST(CharSet, Identity) {
  // Hello string.
  StringRef Src(HelloA);
  SmallString<64> Dst;

  CharSetConverter Conv = CharSetConverter::create(
      text_encoding::id::ISOLatin1, text_encoding::id::ISOLatin1);
  std::error_code EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(HelloA, SmallStringToString(Dst).c_str());

  // ABC string.
  Src = ABCStrA;
  Dst.clear();
  EC = Conv.convert(Src, Dst);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(ABCStrA, SmallStringToString(Dst).c_str());
}

TEST(CharSet, RoundTrip) {
  ErrorOr<CharSetConverter> ConvToUTF16 =
      CharSetConverter::create("IBM-1047", "UTF-16");
  // Stop test if conversion is not supported (no underlying iconv support).
  if (!ConvToUTF16) {
    ASSERT_EQ(ConvToUTF16.getError(),
              std::make_error_code(std::errc::invalid_argument));
    return;
  }
  ErrorOr<CharSetConverter> ConvToUTF32 =
      CharSetConverter::create("UTF-16", "UTF-32");
  // Stop test if conversion is not supported (no underlying iconv support).
  if (!ConvToUTF32) {
    ASSERT_EQ(ConvToUTF32.getError(),
              std::make_error_code(std::errc::invalid_argument));
    return;
  }
  ErrorOr<CharSetConverter> ConvToEBCDIC =
      CharSetConverter::create("UTF-32", "IBM-1047");
  // Stop test if conversion is not supported (no underlying iconv support).
  if (!ConvToEBCDIC) {
    ASSERT_EQ(ConvToEBCDIC.getError(),
              std::make_error_code(std::errc::invalid_argument));
    return;
  }

  // Setup source string.
  char SrcStr[256];
  for (size_t I = 0; I < 256; ++I)
    SrcStr[I] = (I + 1) % 256;

  SmallString<99> Dst1Str, Dst2Str, Dst3Str;

  std::error_code EC = ConvToUTF16->convert(StringRef(SrcStr), Dst1Str);
  EXPECT_TRUE(!EC);
  EC = ConvToUTF32->convert(Dst1Str, Dst2Str);
  EXPECT_TRUE(!EC);
  EC = ConvToEBCDIC->convert(Dst2Str, Dst3Str);
  EXPECT_TRUE(!EC);
  EXPECT_STREQ(SrcStr, SmallStringToString(Dst3Str).c_str());
}

} // namespace
