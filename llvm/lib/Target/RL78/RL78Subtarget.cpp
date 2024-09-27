//===-- RL78Subtarget.cpp - RL78 Subtarget Information ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the RL78 specific subclass of TargetSubtargetInfo.
//
//===----------------------------------------------------------------------===//

#include "RL78Subtarget.h"

using namespace llvm;

#define DEBUG_TYPE "RL78-subtarget"

#define GET_SUBTARGETINFO_TARGET_DESC
#define GET_SUBTARGETINFO_CTOR
#include "RL78GenSubtargetInfo.inc"

void RL78Subtarget::anchor() {}

RL78Subtarget &
RL78Subtarget::initializeSubtargetDependencies(const Triple &TT, StringRef CPU,
                                                StringRef TuneCPU, StringRef FS,
                                                StringRef ABIName) {
  coreType = RL78_S3;
  has64BitDoubles = false;
  mirrorSource = (unsigned char)RL78MirrorSource::Zero;
  hasFarCodeModel = false;
  hasFarDataModel = false;
  romModel = (unsigned char)RL78RomModel::Near;
  disableMDA = false;
  callingConvention = CCRL;

  // Determine default and user specified characteristics.
  if (CPU.empty())
    CPU = "RL78_S3";
  else if (CPU == "RL78_S1")
    coreType = RL78_S1;
  else if (CPU == "RL78_S2")
    coreType = RL78_S2;

  if (TuneCPU.empty())
    TuneCPU = CPU;

  // Parse features string.
  ParseSubtargetFeatures(CPU, TuneCPU, FS);

  return *this;
}

RL78Subtarget::RL78Subtarget(const Triple &TT, StringRef CPU, StringRef TuneCPU,
                StringRef FS, StringRef ABIName,
                const TargetMachine &TM)
    : RL78GenSubtargetInfo(TT, CPU, TuneCPU, FS), TargetTriple(TT),
      InstrInfo(initializeSubtargetDependencies(TT, CPU, TuneCPU, FS, ABIName)), TLInfo(TM, *this),
      FrameLowering(*this) {}
