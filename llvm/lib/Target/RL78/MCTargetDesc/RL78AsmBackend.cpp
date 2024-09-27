//===-- RL78AsmBackend.cpp - RL78 Assembler Backend ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/RL78FixupKinds.h"
#include "MCTargetDesc/RL78MCTargetDesc.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/EndianStream.h"
#include "RL78.h"
using namespace llvm;

static unsigned adjustFixupValue(unsigned Kind, int64_t Value) {
  switch (Kind) {
  default:
    llvm_unreachable("Unknown fixup kind!");

  case FK_Data_1:
  case FK_Data_2:
  case FK_Data_4:
  case FK_Data_8:
    return Value;

  // These fixups are either resolved earlier and shouldn't appear here or will
  // be resolved with relocations, thus the value should be 0
  case RL78::fixup_RL78_OPsctsize:
  case RL78::fixup_RL78_OPscttop:
  case RL78::fixup_RL78_OPsub:
  case RL78::fixup_RL78_OPadd:
  case RL78::fixup_RL78_OPlowH:
  case RL78::fixup_RL78_OPlowL:
  case RL78::fixup_RL78_OPhighW:
  case RL78::fixup_RL78_OPlowW:
  case RL78::fixup_RL78_OPhighW_MIR:
  case RL78::fixup_RL78_OPlowW_MIR:
  case RL78::fixup_RL78_OPlowW_SMIR:
  case RL78::fixup_RL78_OPABSlowH:
  case RL78::fixup_RL78_OPABSlowL:
  case RL78::fixup_RL78_OPABShighW:
  case RL78::fixup_RL78_OPABSlowW:
  case RL78::fixup_RL78_ABS3U:
  case RL78::fixup_RL78_ABS8U:
  case RL78::fixup_RL78_ABS16U:
  case RL78::fixup_RL78_ABS16UW:
  case RL78::fixup_RL78_ABS20U:
  case RL78::fixup_RL78_ABS32U:
    if (Value)
      llvm_unreachable("Unknown fixup kind!");
    else
      return Value;

  case RL78::fixup_RL78_DIR3U:
    RL78ReportError(Value >= -4 && Value < 8,
                    "Instruction using illegal Value.");
    return Value;

  case RL78::fixup_RL78_DIR16U:
  case RL78::fixup_RL78_DIR16U_RAM:
  case RL78::fixup_RL78_DIR16UW_RAM:
    RL78ReportError(Value >= -32768 && Value <= 0xFFFF,
                    "Instruction using illegal Value.");
    return Value;

  case RL78::fixup_RL78_DIR20U:
    RL78ReportError(Value >= -524288 && Value <= 0xFFFFF,
                    "Instruction using illegal Value.");
    return Value;

  case RL78::fixup_RL78_DIR20U_16:
  case RL78::fixup_RL78_DIR20UW_16:
    RL78ReportError(Value >= -32768 && Value <= 0xFFFF,
                    "Instruction using illegal Value.");
    return Value;

  case RL78::fixup_RL78_SYM:
    return Value;

  case RL78::fixup_RL78_DIR8S_PCREL:
    RL78ReportError(Value >= -128 && Value <= 0xFF,
                    "Instruction using illegal Value.");
	return Value - 1;

  case RL78::fixup_RL78_DIR16S_PCREL:
    RL78ReportError(Value >= -32768 && Value <= 0xFFFF,
                    "Instruction using illegal Value.");
    return Value - 2;

  case RL78::fixup_RL78_DIR8U:
  case RL78::fixup_RL78_DIR8U_SAD:
  case RL78::fixup_RL78_DIR8UW_SAD:
    RL78ReportError(Value >= -128 && Value <= 0xFF,
                    "Instruction using illegal Value.");
    return Value;
    
  case RL78::fixup_RL78_DIR_CALLT:
    RL78ReportError(Value >= -16 && Value < 0x20,
                    "Instruction using illegal Value.");
	return Value;
  case RL78::fixup_RL78_DIR32U:
    RL78ReportError(Value >= INT32_MIN && Value <= UINT32_MAX,
                    "Instruction using illegal Value.");
    return Value;
  }
}

namespace {
class RL78AsmBackend : public MCAsmBackend {
protected:
  const Target &TheTarget;

public:
  RL78AsmBackend(const Target &T)
      : MCAsmBackend(support::little), TheTarget(T) {}

  unsigned getNumFixupKinds() const override {
    return RL78::NumTargetFixupKinds;
  }

  const MCFixupKindInfo &getFixupKindInfo(MCFixupKind Kind) const override {
    const static MCFixupKindInfo Infos[RL78::NumTargetFixupKinds] = {
        // Name                    Offset Bits  Flags.
        {"fixup_RL78_DIR8S_PCREL", 0, 8, MCFixupKindInfo::FKF_IsPCRel},
        {"fixup_RL78_DIR16S_PCREL", 0, 16, MCFixupKindInfo::FKF_IsPCRel},
        {"fixup_RL78_DIR3U", 0, 3, 0},
        {"fixup_RL78_DIR8U", 0, 8, 0},
        {"fixup_RL78_DIR8U_SAD", 0, 8, 0},
        {"fixup_RL78_DIR8UW_SAD", 0, 16, 0},
        {"fixup_RL78_DIR16U", 0, 16, 0},
        {"fixup_RL78_DIR16U_RAM", 0, 16, 0},
        {"fixup_RL78_DIR16UW_RAM", 0, 16, 0},
        {"fixup_RL78_DIR20U", 0, 20, 0},
        {"fixup_RL78_DIR20U_16", 0, 16, 0},
        {"fixup_RL78_DIR20UW_16", 0, 16, 0},
        {"fixup_RL78_DIR32U", 0, 32, 0},
        {"fixup_RL78_DIR_CALLT", 0, 5, 0},
        {"fixup_RL78_SYM", 0, 0, 0},
        {"fixup_RL78_OPsctsize", 0, 0, 0},
        {"fixup_RL78_OPscttop", 0, 0, 0},
        {"fixup_RL78_OPsub", 0, 0, 0},
        {"fixup_RL78_OPadd", 0, 0, 0},
        {"fixup_RL78_OPlowH", 0, 0, 0},
        {"fixup_RL78_OPlowL", 0, 0, 0},
        {"fixup_RL78_OPhighW", 0, 0, 0},
        {"fixup_RL78_OPlowW", 0, 0, 0},
        {"fixup_RL78_OPhighW_MIR", 0, 0, 0},
        {"fixup_RL78_OPlowW_MIR", 0, 0, 0},
        {"fixup_RL78_OPlowW_SMIR", 0, 0, 0},
        {"fixup_RL78_OPABSlowH", 0, 0, 0},
        {"fixup_RL78_OPABSlowL", 0, 0, 0},
        {"fixup_RL78_OPABShighW", 0, 0, 0},
        {"fixup_RL78_OPABSlowW", 0, 0, 0},
        {"fixup_RL78_ABS3U", 0, 3, 0},
        {"fixup_RL78_ABS8U", 0, 8, 0},
        {"fixup_RL78_ABS16U", 0, 16, 0},
        {"fixup_RL78_ABS16UW", 0, 16, 0},
        {"fixup_RL78_ABS20U", 0, 20, 0},
        {"fixup_RL78_ABS32U", 0, 32, 0}
    };

    if (Kind < FirstTargetFixupKind)
      return MCAsmBackend::getFixupKindInfo(Kind);

    assert(unsigned(Kind - FirstTargetFixupKind) < getNumFixupKinds() &&
           "Invalid kind!");
    return Infos[Kind - FirstTargetFixupKind];
  }

  bool shouldForceRelocation(const MCAssembler &Asm, const MCFixup &Fixup,
                             const MCValue &Target) override {
    switch ((RL78::Fixups)Fixup.getKind()) {
    default:
      return false;
    case RL78::fixup_RL78_SYM:
    case RL78::fixup_RL78_OPsub:
    case RL78::fixup_RL78_OPadd:
    case RL78::fixup_RL78_OPsctsize:
    case RL78::fixup_RL78_OPscttop:
    case RL78::fixup_RL78_OPlowH:
    case RL78::fixup_RL78_OPlowL:
    case RL78::fixup_RL78_OPhighW:
    case RL78::fixup_RL78_OPlowW:
    case RL78::fixup_RL78_OPhighW_MIR:
    case RL78::fixup_RL78_OPlowW_MIR:
    case RL78::fixup_RL78_OPlowW_SMIR:
    case RL78::fixup_RL78_OPABSlowH:
    case RL78::fixup_RL78_OPABSlowL:
    case RL78::fixup_RL78_OPABShighW:
    case RL78::fixup_RL78_OPABSlowW:
    case RL78::fixup_RL78_ABS3U:
    case RL78::fixup_RL78_ABS8U:
    case RL78::fixup_RL78_ABS16U:
    case RL78::fixup_RL78_ABS16UW:
    case RL78::fixup_RL78_ABS20U:
    case RL78::fixup_RL78_ABS32U:
      return true;
    }
  }

  bool mayNeedRelaxation(const MCInst &Inst,
                         const MCSubtargetInfo &STI) const override {
    // FIXME.
    return false;
  }

  /// fixupNeedsRelaxation - Target specific predicate for whether a given
  /// fixup requires the associated instruction to be relaxed.
  bool fixupNeedsRelaxation(const MCFixup &Fixup, uint64_t Value,
                            const MCRelaxableFragment *DF,
                            const MCAsmLayout &Layout) const override {
    // FIXME.
    llvm_unreachable("fixupNeedsRelaxation() unimplemented");
    return false;
  }
  void relaxInstruction(MCInst &Inst, const MCSubtargetInfo &STI) const override {
    // FIXME.
    llvm_unreachable("relaxInstruction() unimplemented");
  }

  bool writeNopData(raw_ostream &OS, uint64_t Count, const MCSubtargetInfo *STI) const override {

    for (uint64_t i = 0; i != Count; ++i)
      support::endian::write<uint8_t>(OS, 0x00, support::little);

    return true;
  }
};

class ELFRL78AsmBackend : public RL78AsmBackend {
  Triple::OSType OSType;

public:
  ELFRL78AsmBackend(const Target &T, Triple::OSType OSType)
      : RL78AsmBackend(T), OSType(OSType) {}

  void applyFixup(const MCAssembler &Asm, const MCFixup &Fixup,
                  const MCValue &Target, MutableArrayRef<char> Data,
                  uint64_t Value, bool IsResolved,
                  const MCSubtargetInfo *STI) const override {

    Value = adjustFixupValue(Fixup.getKind(), static_cast<int64_t>(Value));
    if (!Value)
      return; // Doesn't change encoding.

    unsigned Offset = Fixup.getOffset();

    // For each byte of the fragment that the fixup touches, mask in the bits
    // from the fixup value. The Value has been "split up" into the
    // appropriate bitfields above.
    for (unsigned i = 0, e = (getFixupKindInfo(Fixup.getKind()).TargetSize / 8);
         i != e; ++i)
      Data[Offset + i] |= uint8_t((Value >> (i * 8)) & 0xff);
  }

  std::unique_ptr<MCObjectTargetWriter>
  createObjectTargetWriter() const override {
    return createRL78ELFObjectWriter(false, ELF::ELFOSABI_NONE);
  }
};

} // end anonymous namespace
MCAsmBackend *llvm::createRL78AsmBackend(const Target &T,
                                         const MCSubtargetInfo &STI,
                                         const MCRegisterInfo &MRI,
                                         const MCTargetOptions &Options) {
  return new ELFRL78AsmBackend(T, STI.getTargetTriple().getOS());
}
