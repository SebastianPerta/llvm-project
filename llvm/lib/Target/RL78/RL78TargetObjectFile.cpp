//===------- RL78TargetObjectFile.cpp - RL78 Object Info Impl -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RL78TargetObjectFile.h"
#include "RL78.h"

using namespace llvm;

void RL78ELFTargetObjectFile::Initialize(MCContext &Ctx,
                                         const TargetMachine &TM) {
  TargetLoweringObjectFileELF::Initialize(Ctx, TM);
  InitializeELF(TM.Options.UseInitArray);
}

std::string RL78ELFTargetObjectFile::getSectionPrefixForGlobal(
    SectionKind Kind, const GlobalObject *GO) const {
  bool isFar = false;
  bool useRenesasNaming = false;
  bool isSaddr = false;
  if (GO) {
    const GlobalVariable *GV = dyn_cast<GlobalVariable>(GO);
    const Function *GF = dyn_cast<Function>(GO);
    if (GV) {
      useRenesasNaming = GV->getAttributes().hasAttribute("use-renesas-naming");
      isSaddr = GV->getAttributes().hasAttribute("saddr");
      // this works also for the default AS which is far with -mfar-data
      isFar = GV->getParent()->getDataLayout().getPointerSizeInBits(
                  GV->getAddressSpace()) == 32;
    } else if (GF) {
      isFar = GF->getAddressSpace() == RL78AS::FarCode ||
              GF->getAddressSpace() == RL78AS::FarData;
    }
  }

  if (Kind.isText())
    return isFar ? ".textf" : ".text";
  if (Kind.isReadOnly()) {
    if (useRenesasNaming) {
      return isFar ? ".constf" : ".const";
    } else {
      return isFar ? ".frodata" : ".rodata";
    }
  }

  if (isSaddr) {
    return Kind.isData() ? ".sdata" : ".sbss";
  }

  if (Kind.isBSS() || Kind.isThreadBSS()) {
    return isFar ? ".bssf" : ".bss";
  }

  if (Kind.isData() || Kind.isThreadData())
    return isFar ? ".dataf" : ".data";
  assert(Kind.isReadOnlyWithRel() && "Unknown section kind");
  return ".data.rel.ro";
}
