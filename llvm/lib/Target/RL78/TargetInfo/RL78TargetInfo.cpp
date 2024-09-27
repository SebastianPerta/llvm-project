//===-- RL78TargetInfo.cpp - RL78 Target Implementation -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "TargetInfo/RL78TargetInfo.h"
#include "llvm/MC/TargetRegistry.h"

using namespace llvm;

Target &llvm::getTheRL78Target() {
  static Target TheRL78Target;
  return TheRL78Target;
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeRL78TargetInfo() {
  RegisterTarget<Triple::RL78, /*HasJIT=*/false> X(getTheRL78Target(), "RL78",
                                                   "RL78", "RL78");
}
