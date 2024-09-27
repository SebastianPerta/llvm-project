//===-- RL78TargetObjectFile.h - RL78 Object Info -------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78TARGETOBJECTFILE_H
#define LLVM_LIB_TARGET_RL78_RL78TARGETOBJECTFILE_H

#include "llvm/CodeGen/TargetLoweringObjectFileImpl.h"

namespace llvm {

class MCContext;
class TargetMachine;

class RL78ELFTargetObjectFile : public TargetLoweringObjectFileELF {
public:
  RL78ELFTargetObjectFile() : TargetLoweringObjectFileELF() {}

  void Initialize(MCContext &Ctx, const TargetMachine &TM) override;

  std::string getSectionPrefixForGlobal(SectionKind Kind,
                                        const GlobalObject *GO) const override;
};

} // end namespace llvm

#endif
