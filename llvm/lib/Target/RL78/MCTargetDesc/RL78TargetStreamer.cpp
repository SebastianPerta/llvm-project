//===-- RL78TargetStreamer.cpp - RL78 Target Streamer Methods -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides RL78 specific target streamer methods.
//
//===----------------------------------------------------------------------===//

#include "RL78TargetStreamer.h"
#include "RL78InstPrinter.h"
#include "RL78MCExpr.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Support/FormattedStream.h"

using namespace llvm;

// Pin vtable to this file.
RL78TargetStreamer::RL78TargetStreamer(MCStreamer &S) : MCTargetStreamer(S) {}

void RL78TargetStreamer::anchor() {}

RL78TargetAsmStreamer::RL78TargetAsmStreamer(MCStreamer &S,
                                             formatted_raw_ostream &OS)
    : RL78TargetStreamer(S), OS(OS) {}

void RL78TargetAsmStreamer::emitRL78RegisterName(unsigned reg) {
  OS << StringRef(RL78InstPrinter::getRegisterName(MCRegister(reg))).lower() << " ";
}

bool isS1CoreType(const MCSubtargetInfo &STI) {
  return STI.getCPU() == "RL78_S1";
}

bool isS2CoreType(const MCSubtargetInfo &STI) {
  return STI.getCPU() == "RL78_S2";
}

bool isS3CoreType(const MCSubtargetInfo &STI) {
  return STI.getCPU() == "RL78_S3";
}

RL78TargetELFStreamer::RL78TargetELFStreamer(MCStreamer &S,
                                             const MCSubtargetInfo &STI)
    : RL78TargetStreamer(S) {
  MCAssembler &MCA = getStreamer().getAssembler();
  const FeatureBitset &Features = STI.getFeatureBits();
  unsigned int EFlags = MCA.getELFHeaderEFlags();

  EFlags |= isS2CoreType(STI) && !Features[RL78::FeatureDisableMDA]
                ? ELF::EF_RL78_FU_EXIST
                : 0x0;

  EFlags |= isS3CoreType(STI) ? ELF::EF_RL78_EI_EXIST : 0x0;

  if (Features[RL78::FeatureMirrorSourceCommon])
    EFlags |= 0;
  else if (Features[RL78::FeatureMirrorSourceOne])
    EFlags |= ELF::EF_RL78_MAA_1;
  else
    EFlags |= ELF::EF_RL78_MAA_0;

  EFlags |= isS1CoreType(STI) ? ELF::EF_RL78_CPU_8BIT : ELF::EF_RL78_CPU_16BIT;

  EFlags |= Features[RL78::Feature64bitDoubles] ? ELF::EF_RL78_DOUBLE_8
                                                : ELF::EF_RL78_DOUBLE_4;

  EFlags |= Features[RL78::FeatureFarCode] ? ELF::EF_RL78_TEXT_FAR
                                           : ELF::EF_RL78_TEXT_NEAR;

  EFlags |= Features[RL78::FeatureFarData] ? ELF::EF_RL78_DATA_FAR
                                           : ELF::EF_RL78_DATA_NEAR;

  if (Features[RL78::FeatureCommonRom])
    EFlags |= 0;
  else if (Features[RL78::FeatureFarRom])
    EFlags |= ELF::EF_RL78_RODATA_FAR;
  else
    EFlags |= ELF::EF_RL78_RODATA_NEAR;

  MCA.setELFHeaderEFlags(EFlags);
}

MCELFStreamer &RL78TargetELFStreamer::getStreamer() {
  return static_cast<MCELFStreamer &>(Streamer);
}

RL78ELFStreamer::RL78ELFStreamer(MCContext &Context,
                                 std::unique_ptr<MCAsmBackend> TAB,
                                 std::unique_ptr<MCObjectWriter> OW,
                                 std::unique_ptr<MCCodeEmitter> Emitter)
    : MCELFStreamer(Context, std::move(TAB), std::move(OW),
                    std::move(Emitter)) {}

void RL78ELFStreamer::initSections(bool NoExecStack, const MCSubtargetInfo &STI) {
  MCContext &Ctx = getContext();
  switchSection(Ctx.getObjectFileInfo()->getTextSection());
  emitCodeAlignment(Align(1), &STI);

  if (NoExecStack)
    switchSection(Ctx.getAsmInfo()->getNonexecutableStackSection(Ctx));
}

// We override to be able to emit multiple fixups for a given value (CC-RL
// style) and to handle binary sub expressions on symbols.
void RL78ELFStreamer::emitValueImpl(const MCExpr *Value, unsigned Size,
                                    SMLoc Loc) {

  if (!RL78MCExpr::isTargetExpr(Value)) {
    MCELFStreamer::emitValueImpl(Value, Size, Loc);
    return;
  }

  MCStreamer::emitValueImpl(Value, Size, Loc);
  MCDataFragment *DF = getOrCreateDataFragment();
  flushPendingLabels(DF, DF->getContents().size());

  MCDwarfLineEntry::make(this, getCurrentSectionOnly());

  size_t FragmentSize = DF->getContents().size();
  RL78MCExpr::createFixupsForExpression(Value, FragmentSize, Size * 8, DF->getFixups(), true, 0, getContext(), Loc);
  DF->getContents().resize(DF->getContents().size() + Size, 0);
}