//===-- RL78TargetInfo.h - RL78 Target Implementation ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_TARGETINFO_RL78TARGETINFO_H
#define LLVM_LIB_TARGET_RL78_TARGETINFO_RL78TARGETINFO_H

namespace llvm {

class Target;

Target &getTheRL78Target();

} // end namespace llvm

#endif // LLVM_LIB_TARGET_RL78_TARGETINFO_RL78TARGETINFO_H
