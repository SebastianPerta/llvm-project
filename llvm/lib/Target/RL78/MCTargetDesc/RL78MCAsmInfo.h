//===- RL78MCAsmInfo.h - RL78 asm properties -----------------*- C++ -*--===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the RL78MCAsmInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78MCASMINFO_H
#define LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78MCASMINFO_H

#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm {

class Triple;

class RL78ELFMCAsmInfo : public MCAsmInfoELF {
  void anchor() override;

public:
  explicit RL78ELFMCAsmInfo(const Triple &TheTriple);

  const MCExpr *
  getExprForPersonalitySymbol(const MCSymbol *Sym, unsigned Encoding,
                              MCStreamer &Streamer) const override;
  const MCExpr *getExprForFDESymbol(const MCSymbol *Sym, unsigned Encoding,
                                    MCStreamer &Streamer) const override;
};

} // end namespace llvm

#endif // LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78MCASMINFO_H
