//===-- RL78ELFObjectWriter.cpp - RL78 ELF Writer -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/RL78MCExpr.h"
#include "RL78.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCValue.h"

using namespace llvm;

namespace {
class RL78ELFObjectWriter : public MCELFObjectTargetWriter {
public:
  RL78ELFObjectWriter(bool Is64Bit, uint8_t OSABI)
      : MCELFObjectTargetWriter(Is64Bit, OSABI, ELF::EM_RL78,
                                /*HasRelocationAddend*/ true) {}

  ~RL78ELFObjectWriter() override {}

protected:
  unsigned getRelocType(MCContext &Ctx, const MCValue &Target,
                        const MCFixup &Fixup, bool IsPCRel) const override;

  bool needsRelocateWithSymbol(const MCSymbol &Sym,
                               unsigned Type) const override;
};
} // end anonymous namespace

unsigned RL78ELFObjectWriter::getRelocType(MCContext &Ctx,
                                           const MCValue &Target,
                                           const MCFixup &Fixup,
                                           bool IsPCRel) const {

  // We let LLVM fold some SymA - SymB cases so we check for it in particular.
  // FIXME: We could generalze this as there's no CCRL relocation accepting 2
  // symbols.
  if (((unsigned)Fixup.getKind() == RL78::fixup_RL78_OPsub) && Target.getSymB())
    RL78ReportError(false, "Invalid oprands for relocation R_RL78_OPsub.");

  if (IsPCRel) {
    switch ((unsigned)Fixup.getKind()) {
    default:
      llvm_unreachable("Unimplemented fixup -> relocation");
      // TODO:
    case RL78::fixup_RL78_DIR16S_PCREL:
      return ELF::R_RL78_DIR16S_PCREL;
    case RL78::fixup_RL78_DIR8S_PCREL:
      return ELF::R_RL78_DIR8S_PCREL;
      // TODO: this is generated when using exceptions we need to look at this
      // closer.
    case FK_Data_4:
      return ELF::R_RL78_DIR32U;
    }
  }

  switch ((unsigned)Fixup.getKind()) {
  default:
    llvm_unreachable("Unimplemented fixup -> relocation");
  case FK_Data_1:
    return ELF::R_RL78_DIR8U;
  case FK_Data_2:
    return ELF::R_RL78_DIR16U;
  case FK_Data_4:
    return ELF::R_RL78_DIR32U;
  case RL78::fixup_RL78_DIR3U:
    return ELF::R_RL78_DIR3U;
  case RL78::fixup_RL78_DIR8U:
    return ELF::R_RL78_DIR8U;
  case RL78::fixup_RL78_DIR8U_SAD:
    return ELF::R_RL78_DIR8U_SAD;
  case RL78::fixup_RL78_DIR8UW_SAD:
    return ELF::R_RL78_DIR8UW_SAD;
  case RL78::fixup_RL78_DIR16U:
    return ELF::R_RL78_DIR16U;
  case RL78::fixup_RL78_DIR16U_RAM:
    return ELF::R_RL78_DIR16U_RAM;
  case RL78::fixup_RL78_DIR16UW_RAM:
    return ELF::R_RL78_DIR16UW_RAM;
  case RL78::fixup_RL78_DIR20U:
    return ELF::R_RL78_DIR20U;
  case RL78::fixup_RL78_DIR20U_16:
    return ELF::R_RL78_DIR20U_16;
  case RL78::fixup_RL78_DIR20UW_16:
    return ELF::R_RL78_DIR20UW_16;
  case RL78::fixup_RL78_DIR32U:
    return ELF::R_RL78_DIR32U;
  case RL78::fixup_RL78_DIR_CALLT:
    return ELF::R_RL78_DIR_CALLT;
  case RL78::fixup_RL78_SYM:
    return ELF::R_RL78_SYM;
  case RL78::fixup_RL78_OPsctsize:
    return ELF::R_RL78_OPsctsize;
  case RL78::fixup_RL78_OPscttop:
    return ELF::R_RL78_OPscttop;
  case RL78::fixup_RL78_OPsub:
    return ELF::R_RL78_OPsub;
  case RL78::fixup_RL78_OPadd:
    return ELF::R_RL78_OPadd;
  case RL78::fixup_RL78_OPlowH:
    return ELF::R_RL78_OPlowH;
  case RL78::fixup_RL78_OPlowL:
    return ELF::R_RL78_OPlowL;
  case RL78::fixup_RL78_OPhighW:
    return ELF::R_RL78_OPhighW;
  case RL78::fixup_RL78_OPlowW:
    return ELF::R_RL78_OPlowW;
  case RL78::fixup_RL78_OPhighW_MIR:
    return ELF::R_RL78_OPhighW_MIR;
  case RL78::fixup_RL78_OPlowW_MIR:
    return ELF::R_RL78_OPlowW_MIR;
  case RL78::fixup_RL78_OPlowW_SMIR:
    return ELF::R_RL78_OPlowW_SMIR;
  case RL78::fixup_RL78_OPABSlowH:
    return ELF::R_RL78_OPABSlowH;
  case RL78::fixup_RL78_OPABSlowL:
    return ELF::R_RL78_OPABSlowL;
  case RL78::fixup_RL78_OPABShighW:
    return ELF::R_RL78_OPABShighW;
  case RL78::fixup_RL78_OPABSlowW:
    return ELF::R_RL78_OPABSlowW;
  case RL78::fixup_RL78_ABS3U:
    return ELF::R_RL78_ABS3U;
  case RL78::fixup_RL78_ABS8U:
    return ELF::R_RL78_ABS8U;
  case RL78::fixup_RL78_ABS16U:
    return ELF::R_RL78_ABS16U;
  case RL78::fixup_RL78_ABS16UW:
    return ELF::R_RL78_ABS16UW;
  case RL78::fixup_RL78_ABS20U:
    return ELF::R_RL78_ABS20U;
  case RL78::fixup_RL78_ABS32U:
    return ELF::R_RL78_ABS32U;
  }

  return ELF::R_RL78_NONE;
}

bool RL78ELFObjectWriter::needsRelocateWithSymbol(const MCSymbol &Sym,
                                                  unsigned Type) const {
  // switch (Type) {
  // default:
  return Type == ELF::R_RL78_SYM;
  // TODO:
  //}
}

std::unique_ptr<MCObjectTargetWriter>
llvm::createRL78ELFObjectWriter(bool Is64Bit, uint8_t OSABI) {
  return std::make_unique<RL78ELFObjectWriter>(Is64Bit, OSABI);
}
