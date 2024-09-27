//===-- RL78MCTargetDesc.cpp - RL78 Target Descriptions -----------------===//
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

#include "RL78InstPrinter.h"
#include "RL78MCAsmInfo.h"
#include "RL78TargetStreamer.h"
#include "TargetInfo/RL78TargetInfo.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/TargetRegistry.h"

using namespace llvm;

#define GET_INSTRINFO_MC_DESC
#define ENABLE_INSTR_PREDICATE_VERIFIER
#include "RL78GenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "RL78GenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "RL78GenRegisterInfo.inc"

static MCAsmInfo *createRL78MCAsmInfo(const MCRegisterInfo &MRI,
                                      const Triple &TT,
                                      const MCTargetOptions &Options) {
  MCAsmInfo *MAI = new RL78ELFMCAsmInfo(TT);
  unsigned Reg = MRI.getDwarfRegNum(RL78::SPreg, false);
  MCCFIInstruction Inst = MCCFIInstruction::cfiDefCfa(nullptr, Reg, 4);
  MAI->addInitialFrameState(Inst);
  Reg = MRI.getDwarfRegNum(RL78::PCreg, false);
  Inst = MCCFIInstruction::createOffset(nullptr, Reg, -4);
  MAI->addInitialFrameState(Inst);
  return MAI;
}

static MCInstrInfo *createRL78MCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitRL78MCInstrInfo(X);
  return X;
}

static MCRegisterInfo *createRL78MCRegisterInfo(const Triple &TT) {
  MCRegisterInfo *X = new MCRegisterInfo();
  // OBS. Return address is saved on the stack (CFA-4) however:
  // 1. we set RA = PCreg just like GCC so we don't need to make changes in GDB.
  // 2. we emit a DW_CFA_offset: r37 at cfa-4 in the CIE (see above).
  InitRL78MCRegisterInfo(X, RL78::PCreg);
  return X;
}

static MCSubtargetInfo *createRL78MCSubtargetInfo(const Triple &TT,
                                                  StringRef CPU, StringRef FS) {
  if (CPU.empty())
    CPU = "RL78_S3";
  return createRL78MCSubtargetInfoImpl(TT, CPU, /*TuneCPU=*/CPU, FS);
}

static MCTargetStreamer *
createObjectTargetStreamer(MCStreamer &S, const MCSubtargetInfo &STI) {
  return new RL78TargetELFStreamer(S, STI);
}

MCStreamer *createELFStreamer(const Triple &T, MCContext &Ctx,
                              std::unique_ptr<MCAsmBackend> &&TAB,
                              std::unique_ptr<MCObjectWriter> &&OW,
                              std::unique_ptr<MCCodeEmitter> &&Emitter,
                              bool RelaxAll) {
  return new RL78ELFStreamer(Ctx, std::move(TAB), std::move(OW),
                             std::move(Emitter));
}

static MCTargetStreamer *createTargetAsmStreamer(MCStreamer &S,
                                                 formatted_raw_ostream &OS,
                                                 MCInstPrinter *InstPrint,
                                                 bool isVerboseAsm) {
  return new RL78TargetAsmStreamer(S, OS);
}

static MCInstPrinter *createRL78MCInstPrinter(const Triple &T,
                                              unsigned SyntaxVariant,
                                              const MCAsmInfo &MAI,
                                              const MCInstrInfo &MII,
                                              const MCRegisterInfo &MRI) {
  return new RL78InstPrinter(MAI, MII, MRI);
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeRL78TargetMC() {
  // Register the MC asm info.
  RegisterMCAsmInfoFn X(getTheRL78Target(), createRL78MCAsmInfo);

  for (Target *T : {&getTheRL78Target()}) {
    // Register the MC instruction info.
    TargetRegistry::RegisterMCInstrInfo(*T, createRL78MCInstrInfo);

    // Register the MC register info.
    TargetRegistry::RegisterMCRegInfo(*T, createRL78MCRegisterInfo);

    // Register the MC subtarget info.
    TargetRegistry::RegisterMCSubtargetInfo(*T, createRL78MCSubtargetInfo);

    // Register the MC Code Emitter.
    TargetRegistry::RegisterMCCodeEmitter(*T, createRL78MCCodeEmitter);

    // Register the asm backend.
    TargetRegistry::RegisterMCAsmBackend(*T, createRL78AsmBackend);

    // Register the object target streamer.
    TargetRegistry::RegisterObjectTargetStreamer(*T,
                                                 createObjectTargetStreamer);

    // Register the object target streamer.
    TargetRegistry::RegisterELFStreamer(*T, createELFStreamer);

    // Register the asm streamer.
    TargetRegistry::RegisterAsmTargetStreamer(*T, createTargetAsmStreamer);

    // Register the MCInstPrinter.
    TargetRegistry::RegisterMCInstPrinter(*T, createRL78MCInstPrinter);
  }
}
