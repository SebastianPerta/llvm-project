//===--- RL78.cpp - Implement RL78 target feature support ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements RL78 TargetInfo objects.
//
//===----------------------------------------------------------------------===//

#include "RL78.h"
#include "clang/Basic/TargetBuiltins.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace clang::targets;

static constexpr Builtin::Info BuiltinInfo[] = {
#define BUILTIN(ID, TYPE, ATTRS)                                               \
  {#ID, TYPE, ATTRS, nullptr, HeaderDesc::NO_HEADER, ALL_LANGUAGES},
#define TARGET_BUILTIN(ID, TYPE, ATTRS, FEATURE)                               \
  {#ID, TYPE, ATTRS, FEATURE, HeaderDesc::NO_HEADER, ALL_LANGUAGES},
#include "clang/Basic/BuiltinsRL78.def"
};

ArrayRef<Builtin::Info> RL78TargetInfo::getTargetBuiltins() const {
  return llvm::ArrayRef(BuiltinInfo, clang::RL78::LastTSBuiltin -
                                             Builtin::FirstTSBuiltin);
}

const char *const RL78TargetInfo::GCCRegNames[] = {
    "rp0", "rp2", "rp4", "rp6", "r0", "r1",  "r2", "r3", "r4",
    "r5",  "r6",  "r7",  "sp",  "ap", "psw", "es", "cs"};

const LangASMap RL78TargetInfo::RL78AddrSpaceMap = {  
  0, // Default
  0, // opencl_global
  0, // opencl_local
  0, // opencl_constant
  0, // opencl_private
  0, // opencl_generic
  0, // opencl_global_device
  0, // opencl_global_host
  0, // cuda_device
  0, // cuda_constant
  0, // cuda_shared
  0, // sycl_global
  0, // sycl_global_device
  0, // sycl_global_host
  0, // sycl_local
  0, // sycl_private
  0, // ptr32_sptr
  0, // ptr32_uptr
  0, // ptr64
  0, // hlsl_groupshared
  0, // wasm_funcref
  1, // __near
  2, // __far_data
  3, // __far_code
};

ArrayRef<const char *> RL78TargetInfo::getGCCRegNames() const {
  return llvm::makeArrayRef(GCCRegNames);
}

const TargetInfo::GCCRegAlias RL78TargetInfo::GCCRegAliases[] = {
    {{"ax"}, "rp0"}, {{"bc"}, "rp2"}, {{"de"}, "rp4"}, {{"hl"}, "rp6"},
    {{"a"}, "r1"},   {{"x"}, "r0"},   {{"b"}, "r3"},   {{"c"}, "r2"},
    {{"d"}, "r5"},   {{"e"}, "r4"},   {{"h"}, "r7"},   {{"l"}, "r6"}};

ArrayRef<TargetInfo::GCCRegAlias> RL78TargetInfo::getGCCRegAliases() const {
  return llvm::makeArrayRef(GCCRegAliases);
}

RL78TargetInfo::RL78TargetInfo(const llvm::Triple &Triple,
                               const TargetOptions &Opts)
    : TargetInfo(Triple) {

  has64BitDoubles = false;
  farCodeModel = false;
  farDataModel = false;
  isMDADisabled = false;
  for (auto &I : Opts.FeaturesAsWritten) {
    if (I == "+64bit-doubles")
      has64BitDoubles = true;
    if (I == "+disable-mda")
      isMDADisabled = true;
    if (I == "+far-code")
      farCodeModel = true;
    if (I == "+near-code")
      farCodeModel = false;
    if (I == "+far-data")
      farDataModel = true;
    if (I == "+near-data")
      farDataModel = false;
  }

  std::string ABI{farCodeModel ? "fc" : "nc"};
  ABI += (farDataModel ? "_fd" : "_nd");
  ABI += (has64BitDoubles ? "_d64" : "_d32");
  if (Opts.CPU == "RL78_S2")
    ABI += ((isMDADisabled ? "_nomda" : "_mda"));
  setABI(ABI);

  TLSSupported = false;
  IntWidth = 16;
  IntAlign = 16;
  LongWidth = 32;
  LongLongWidth = 64;
  LongAlign = LongLongAlign = 16;
  if (!has64BitDoubles) {
    DoubleWidth = 32;
    DoubleFormat = &llvm::APFloat::IEEEsingle();
    LongDoubleWidth = 32;
    LongDoubleFormat = &llvm::APFloat::IEEEsingle();
  } else {
    DoubleWidth = 64;
    DoubleFormat = &llvm::APFloat::IEEEdouble();
    LongDoubleWidth = 64;
    LongDoubleFormat = &llvm::APFloat::IEEEdouble();
  }
  Char32Type = UnsignedLong;
  WCharType = UnsignedInt;
  WIntType = UnsignedInt;
  FloatAlign = 16;
  DoubleAlign = 16;
  LongDoubleAlign = 16;
  PointerWidth = farDataModel ? 32 : 16;
  PointerAlign = 16;
  SuitableAlign = 16;
  SizeType = UnsignedInt;
  IntMaxType = SignedLongLong;
  IntPtrType = farDataModel ? SignedLong : SignedInt;
  PtrDiffType = SignedInt;
  SigAtomicType = SignedLong;

  // TODO: see https://llvm.org/docs/LangRef.html#data-layout
  std::string DL;
  llvm::raw_string_ostream SS(DL);

  // NOTE: keep in sync with def from llvm/lib/Target/RL78/RL78TargetMachine.cpp
  SS << "e"               // little endian
        "-m:o";           // Mach-O mangling: Private symbols get L prefix.
                          // Other symbols get a _ prefix.
  if (farDataModel) {
    SS << "-p0:32:16:16"  // default: 32 bit width, 16 bit aligned
          "-A1";          // near allocas
  } else {
    SS << "-p0:16:16:16"; // default: 16 bit width, 16 bit aligned
  }

  SS << "-p1:16:16:16" // Near pointers: 16 bit width, 16 bit aligned.
        "-p2:32:16:16" // Far data pointers: 32 bit width, 16 bit aligned.
        "-p3:32:16:16" // Far code pointers: 32 bit width, 16 bit aligned.
        "-i32:16-i64:16-f32:16-f64:16-a:8" // TODO: explain
        "-n8:8"                            // 8 bit native integer width
        "-n16:16"                          // 16 bit native integer width
        "-S16";                            // 16 bit natural stack alignment

  if (farCodeModel)
    SS << "-P3";                           // Use far pointers for functions.

  SS.flush();

  resetDataLayout(DL, "_"); // '_' is to be consistent with Mach-O prefixing.

  AddrSpaceMap = &RL78AddrSpaceMap;
}

void RL78TargetInfo::adjust(DiagnosticsEngine &Diags, LangOptions &Opts) {
  TargetInfo::adjust(Diags, Opts);
  // Turn off POSIXThreads and ThreadModel so that we don't predefine _REENTRANT
  // or __STDCPP_THREADS__ if we will eventually end up stripping atomics
  // because they are unsupported.
  Opts.POSIXThreads = false;
  Opts.setThreadModel(LangOptions::ThreadModelKind::Single);
  Opts.ThreadsafeStatics = false;
}