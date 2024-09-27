//===-- RL78MCTargetDesc.h - RL78 Target Descriptions ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides RL78 specific target descriptions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78MCTARGETDESC_H
#define LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78MCTARGETDESC_H

#include <memory>

namespace llvm {
class MCAsmBackend;
class MCCodeEmitter;
class MCContext;
class MCInstrInfo;
class MCObjectTargetWriter;
class MCRegisterInfo;
class MCSubtargetInfo;
class MCTargetOptions;
class Target;
class Triple;
class StringRef;
class raw_pwrite_stream;
class raw_ostream;

MCCodeEmitter *createRL78MCCodeEmitter(const MCInstrInfo &MCII,
                                       MCContext &Ctx);
MCAsmBackend *createRL78AsmBackend(const Target &T, const MCSubtargetInfo &STI,
                                   const MCRegisterInfo &MRI,
                                   const MCTargetOptions &Options);
std::unique_ptr<MCObjectTargetWriter> createRL78ELFObjectWriter(bool Is64Bit,
                                                                uint8_t OSABI);
} // end namespace llvm

// Defines symbolic names for RL78 registers.  This defines a mapping from
// register name to register number.
//
#define GET_REGINFO_ENUM
#include "RL78GenRegisterInfo.inc"

// Defines symbolic names for the RL78 instructions.
//
#define GET_INSTRINFO_ENUM
#include "RL78GenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "RL78GenSubtargetInfo.inc"

#endif
