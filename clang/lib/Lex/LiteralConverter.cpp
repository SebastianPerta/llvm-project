//===--- LiteralConverter.cpp - Translator for String Literals -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/Lex/LiteralConverter.h"
#include "clang/Basic/DiagnosticDriver.h"

using namespace llvm;

static std::string CreateKey(llvm::StringRef From, llvm::StringRef To) {
  return std::string(From) + " " + std::string(To);
}

llvm::CharSetConverter *LiteralConverter::getConverter(const char *Codepage) {
  auto Iter = CharsetConverters.find(Codepage);
  if (Iter != CharsetConverters.end())
    return &Iter->second;
  return nullptr;
}

llvm::CharSetConverter *
LiteralConverter::getConverter(ConversionAction Action) {
  StringRef From;
  StringRef To;
  if (Action == ToInternalCharset) {
    From = InputCharset;
    To = InternalCharset;
  } else if (Action == ToExecCharset) {
    From = InternalCharset;
    To = ExecCharset;
  } else
    return nullptr;
  return getConverter(CreateKey(From, To).c_str());
}

llvm::CharSetConverter *
LiteralConverter::createAndInsertCharConverter(llvm::StringRef From,
                                               llvm::StringRef To) {
  std::string Key = CreateKey(From, To);
  llvm::CharSetConverter *Converter = getConverter(Key.c_str());
  if (Converter)
    return Converter;

  ErrorOr<CharSetConverter> ErrorOrConverter =
      llvm::CharSetConverter::create(From, To);
  if (!ErrorOrConverter)
    return nullptr;
  CharsetConverters.insert_or_assign(StringRef(Key),
                                     std::move(*ErrorOrConverter));
  return getConverter(Key.c_str());
}

void LiteralConverter::setConvertersFromOptions(
    const clang::LangOptions &Opts, const clang::TargetInfo &TInfo,
    clang::DiagnosticsEngine &Diags) {
  using namespace llvm;
  InternalCharset = "UTF-8";
  InputCharset =
      Opts.InputCharset.empty() ? InternalCharset : StringRef(Opts.InputCharset);
  ExecCharset = Opts.ExecCharset.empty() ? InternalCharset : StringRef(Opts.ExecCharset);
  // Create converter between input and internal charset
  if (!InternalCharset.equals(InputCharset))
    if (!createAndInsertCharConverter(InputCharset, InternalCharset)) {
      Diags.Report(clang::diag::err_drv_invalid_value)
          << "-finput-charset" << InputCharset;
    }

  // Create converter between internal and exec charset specified
  // in fexec-charset option.
  if (InternalCharset.equals(ExecCharset))
    return;
  if (!createAndInsertCharConverter(InternalCharset.data(),
                                    ExecCharset.data())) {
    Diags.Report(clang::diag::err_drv_invalid_value)
        << "-fexec-charset" << ExecCharset;
  }
}
