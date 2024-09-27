//===- RL78MCAsmInfo.cpp - RL78 asm properties --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declarations of the RL78MCAsmInfo properties.
//
//===----------------------------------------------------------------------===//

#include "RL78MCAsmInfo.h"

using namespace llvm;

void RL78ELFMCAsmInfo::anchor() {}

RL78ELFMCAsmInfo::RL78ELFMCAsmInfo(const Triple &TheTriple) {

  Data16bitsDirective = "\t.short\t";
  Data32bitsDirective = "\t.long\t";
  Data64bitsDirective = nullptr;
  ZeroDirective = "\t.skip\t";
  CommentString = ";";
  SupportsDebugInformation = true;

  ExceptionsType = ExceptionHandling::DwarfCFI;

  UsesELFSectionDirectiveForBSS = true;

  UseIntegratedAssembler = true;

  CodePointerSize = 4;

  CalleeSaveStackSlotSize = 2;

  HasRL78Expressions = true;

  AllowAtInName = true;
}

const MCExpr *RL78ELFMCAsmInfo::getExprForPersonalitySymbol(
    const MCSymbol *Sym, unsigned Encoding, MCStreamer &Streamer) const {

  return MCAsmInfo::getExprForPersonalitySymbol(Sym, Encoding, Streamer);
}

const MCExpr *
RL78ELFMCAsmInfo::getExprForFDESymbol(const MCSymbol *Sym, unsigned Encoding,
                                      MCStreamer &Streamer) const {
  return MCAsmInfo::getExprForFDESymbol(Sym, Encoding, Streamer);
}
