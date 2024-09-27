//===-- RL78MCCodeEmitter.cpp - Convert RL78 code to machine code -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the RL78MCCodeEmitter class.
//
//===----------------------------------------------------------------------===//

#include "RL78.h"
#include "RL78MCExpr.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/EndianStream.h"
#include "llvm/Support/SourceMgr.h"

using namespace llvm;

#define DEBUG_TYPE "mccodeemitter"

STATISTIC(MCNumEmitted, "Number of MC instructions emitted");

// Useful for debugging: enable to see from where RL78ReportError() is called (as there are
// a lot of places with the same error message e.g. "Instruction using illegal register.")
#if 0
static void RL78ReportError_(bool condition, StringRef Reason, const char *file, int line) {
  if (!condition) {
    SmallVector<char, 64> Buffer;
    raw_svector_ostream OS(Buffer);
    OS << file << ':' << line << ' ';
    StringRef MessageStr = OS.str();
    ssize_t written = ::write(2, MessageStr.data(), MessageStr.size());
    (void)written;
    RL78ReportError(condition, Reason);
  }
}
#define RL78ReportError(condition, Reason) RL78ReportError_(condition, Reason, __FILE__, __LINE__)
#endif

namespace {

class RL78MCCodeEmitter : public MCCodeEmitter {
  const MCInstrInfo &MCII;
  MCContext &Ctx;

public:
  RL78MCCodeEmitter(const MCInstrInfo &mcii, MCContext &ctx)
      : MCII(mcii), Ctx(ctx) {}
  RL78MCCodeEmitter(const RL78MCCodeEmitter &) = delete;
  RL78MCCodeEmitter &operator=(const RL78MCCodeEmitter &) = delete;
  ~RL78MCCodeEmitter() override = default;

  void encodeInstruction(const MCInst &MI, raw_ostream &OS,
                         SmallVectorImpl<MCFixup> &Fixups,
                         const MCSubtargetInfo &STI) const override;

  // getBinaryCodeForInstr - TableGen'erated function for getting the
  // binary encoding for an instruction.
  uint64_t getBinaryCodeForInstr(const MCInst &MI,
                                 SmallVectorImpl<MCFixup> &Fixups,
                                 const MCSubtargetInfo &STI) const;

  /// getMachineOpValue - Return binary encoding of operand. If the machine
  /// operand requires relocation, record the relocation and return zero.
  unsigned getMachineOpValue(const MCInst &MI, const MCOperand &MO,
                             SmallVectorImpl<MCFixup> &Fixups,
                             const MCSubtargetInfo &STI) const;

  unsigned
  getTargetOpValue(const MCInst &MI, unsigned OpNo, uint32_t offset,
                   SmallVectorImpl<MCFixup> &Fixups, const MCSubtargetInfo &STI,
                   enum MCFixupKind fixup1) const;

  unsigned getBranchOnRegTargetOpValue(const MCInst &MI, unsigned OpNo,
                                       SmallVectorImpl<MCFixup> &Fixups,
                                       const MCSubtargetInfo &STI) const;

private:
  FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) const;
};

} // end anonymous namespace

static std::map<unsigned, unsigned> sfrRegisterToSfraddr{
    {RL78::SPL, 0xffff8}, {RL78::SPH, 0xffff9}, {RL78::PSW, 0xffffa},
    {RL78::CS, 0xffffc},  {RL78::ES, 0xffffd},  {RL78::PMC, 0xffffe},
    {RL78::MEM, 0xfffff},
};

static void
encode8BitRROperationInstruction(const MCInst &MI, unsigned long long &Bits,
                                 const unsigned short &OpcodeRA,
                                 const unsigned short &OpcodeASaddr) {
  //
  if (MI.getOperand(0).getReg() == RL78::R1) {

    if (MI.getOperand(2).getReg() == RL78::R1)
      Bits = OpcodeRA + MI.getOperand(0).getReg() - RL78::R0;
    // OP A, r.
    else
      Bits += MI.getOperand(2).getReg() - RL78::R0;
  }
  // OP r, A.
  else {
    RL78ReportError(MI.getOperand(2).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    Bits = OpcodeRA + MI.getOperand(0).getReg() - RL78::R0;
  }
}

static void
encode8BitCMPOperationInstruction(const MCInst &MI, unsigned long long &Bits,
                                  const unsigned short &OpcodeRA,
                                  const unsigned short &OpcodeASaddr) {
  //
  if (MI.getOperand(0).getReg() == RL78::R1 &&
      MI.getOperand(1).getReg() != RL78::R1) {
    // OP A, r.
    Bits += MI.getOperand(1).getReg() - RL78::R0;
  }
  // OP r, A.
  else {
    RL78ReportError(MI.getOperand(1).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    Bits = OpcodeRA + MI.getOperand(0).getReg() - RL78::R0;
  }
}
static void encode8BitRMEMRIOperationInstruction(
    const MCInst &MI, unsigned long long &Bits, unsigned &Size,
    const unsigned short &OpcodeShort, const unsigned &OpcodeLong) {
  // OP A, [HL].
  if (MI.getOperand(3).isImm() && MI.getOperand(3).getImm() == 0) {
    Size = 1;
    Bits = OpcodeShort;
  }
  // OP A, [HL+byte].
  else {
    Size = 2;
    Bits = OpcodeLong;
  }
}

static void encodeBitManip1RInstruction(const MCInst &MI,
                                        unsigned long long &Bits,
                                        const unsigned short &Opcode,
                                        const unsigned ImmIndex) {
  // OP A.bit.
  assert(MI.getOperand(0).getReg() == RL78::R1);
  Bits = Opcode;
  RL78ReportError(MI.getOperand(ImmIndex).getImm() >= 0 &&
                      MI.getOperand(ImmIndex).getImm() < 8,
                  "Instruction using operand outside of range 0-7.");
  Bits += MI.getOperand(ImmIndex).getImm() << 4;
}

void RL78MCCodeEmitter::encodeInstruction(const MCInst &MI, raw_ostream &OS,
                                          SmallVectorImpl<MCFixup> &Fixups,
                                          const MCSubtargetInfo &STI) const {
  /* TODO: look into this auto generated pseudo lowerings
  RL78_MC::verifyInstructionPredicates(MI,
                              computeAvailableFeatures(STI.getFeatureBits()));*/
  unsigned long long Bits = getBinaryCodeForInstr(MI, Fixups, STI);
  unsigned Size = MCII.get(MI.getOpcode()).getSize();
  switch (MI.getOpcode()) {
  case RL78::MOV_A_PSW:
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    break;
  case RL78::MOV_PSW_A:
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    break;
  case RL78::MOV_r_imm:
    // MOV r, #byte      5X data (X..H -> 0..7)
    Bits += ((MI.getOperand(0).getReg() - RL78::R0) << 8);
    //
    Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::STORE8_saddr_imm:
    Bits |= (getTargetOpValue(MI, 0, 1, Fixups, STI,
                              (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD) &
             0x00FF)
            << 8;
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::MOV_es_imm:
    // MOV ES, #byte;   41 data.
    Bits = 0x4100;
    Size = 2;
    Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::MOV_cs_imm:
    // MOV CS, #byte ;CE FC data.
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::MOV_es_saddr:
    // MOV ES, saddr;     61 B8 saddr.
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD) &
            0xFF;
    break;
  case RL78::MOV_psw_imm:
    // MOV PSW, #byte ;CE FA data.
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::LOAD8_r_sfr: {
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(1).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::MOV_A_sfrReg:
    // MOV A, sfr ;8E sfr.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    Bits |= sfrRegisterToSfraddr[MI.getOperand(1).getReg()] & 0xFF;
    break;
  case RL78::STORE8_sfr_r: {
    // MOV sfr, A ;9E sfr.
    RL78ReportError(MI.getOperand(1).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::MOV_sfrReg_A:
    // MOV sfr, A ;9E sfr.
    RL78ReportError(MI.getOperand(1).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    Bits |= sfrRegisterToSfraddr[MI.getOperand(0).getReg()] & 0xFF;
    break;
  case RL78::STORE8_sfr_imm: {
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= (immediateValue & 0xFF) << 8;
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  }
  case RL78::MOV_sfrReg_imm:
    Bits |= (sfrRegisterToSfraddr[MI.getOperand(0).getReg()] & 0xFF) << 8;
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::STORE8_abs16_imm: {
    // MOV !addr16, #byte    CF adrl adrh data.
    Bits |= getTargetOpValue(MI, 1, 3, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 16;
    unsigned int uaddr = (0xFF00 & addressValue);
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::STORE8_stack_slot_imm:
    // MOV [SP+byte], #byte	C8 adr data.
    Bits |= (getTargetOpValue(MI, 1, 1, Fixups, STI,
                              (MCFixupKind)RL78::fixup_RL78_DIR8U) &
             0xFF)
            << 8;
    Bits |= getTargetOpValue(MI, 2, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::STORE8_memDEi_imm:
  case RL78::STORE8_memHLi_imm:
  case RL78::STORE8_ri_imm:
  case RL78::STORE8_rbci_imm: {
    unsigned int RegOp = MI.getOperand(0).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Invalid register for Instruction");
    // MOV [DE+byte], #byte	CA adr data.
    // MOV [HL+byte], #byte	CC adr data.
    // TODO: insert asserts here and in similar places.
    if (RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      Size = 3;
      Bits = (RegOp == RL78::RP4) ? 0xCA0000 : 0xCC0000;
      Bits |= (getTargetOpValue(MI, 1, 1, Fixups, STI,
                                (MCFixupKind)RL78::fixup_RL78_DIR8U) &
               0xFF)
              << 8;
      Bits |= getTargetOpValue(MI, 2, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    // MOV word[BC], #byte	39 adrl adrh data.
    // MOV word[B], #byte	19 adrl adrh data.
    // MOV word[C], #byte	38 adrl adrh data.
    else {
      if (RegOp == RL78::RP2)
        Bits = 0x39000000;
      else if (RegOp == RL78::R2)
        Bits = 0x38000000;
      else if (RegOp == RL78::R3)
        Bits = 0x19000000;
      Size = 4;
      unsigned int addressValue = getTargetOpValue(
          MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
      Bits |= (addressValue & 0xFF00) | ((addressValue & 0xFF) << 16);
      Bits |= getTargetOpValue(MI, 2, 3, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::STORE8_abs16_r: {

    // MOV !addr16, A    9F adrl adrh.
    RL78ReportError(MI.getOperand(1).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::MOV_A_r:
    // MOV A, X          60
    // MOV A, C          62
    // MOV A, B          63
    // MOV A, E          64
    // MOV A, D          65
    // MOV A, L          66
    // MOV A, H          67
    Bits |= MI.getOperand(1).getReg() - RL78::R0;
    break;
  case RL78::MOV_r_A:
    // MOV X, A          70
    // MOV C, A          72
    // MOV B, A          73
    // MOV E, A          74
    // MOV D, A          75
    // MOV L, A          76
    // MOV H, A          77
    Bits |= MI.getOperand(0).getReg() - RL78::R0;
    break;
  case RL78::LOAD8_rlo_saddr:
    // MOV A, saddr      8D saddr
    // MOV X, saddr      D8 saddr
    // MOV B, saddr      E8 saddr
    // MOV C, saddr      F8 saddr
    switch (MI.getOperand(0).getReg()) {
    case RL78::R0:
      Bits = 0xD800;
      break;
    case RL78::R3:
      Bits = 0xE800;
      break;
    case RL78::R2:
      Bits = 0xF800;
      break;
    }
    Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD) &
              0xFF;
    break;
  case RL78::STORE8_saddr_A:
    // MOV saddr, A      9D saddr
    if (MI.getOperand(1).getReg() != RL78::R1) {
      // TODO: rewrite reporterror to use loc, like below
      // Or transmit error to RL78AsmParser getStreamer().getAssemblerPtr()->getEmitter()
      Ctx.getSourceManager()->PrintMessage(
          errs(), MI.getLoc(), SourceMgr::DiagKind::DK_Error,
          "Instruction using illegal register.");
      exit(1);
    }
    Bits |= getTargetOpValue(MI, 0, 1, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD) &
            0xFF;
    break;
  case RL78::LOAD8_r_memHL:
  case RL78::LOAD8_r_memDE:
  case RL78::LOAD8_r_memHLi:
  case RL78::LOAD8_r_memDEi:
  case RL78::LOAD8_r_ri:
  case RL78::LOAD8_r_rbci: {
    // MOV A, [DE]       89.
    // MOV A, [HL]       8B.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");

    unsigned int RegOp = MI.getOperand(1).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (MI.getOperand(2).isImm() && MI.getOperand(2).getImm() == 0 &&
        RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      Size = 1;
      Bits = (RegOp == RL78::RP4) ? 0x89 : 0x8B;
    }
    // MOV A, [DE+byte]  8A adr.
    // MOV A, [HL+byte]  8C adr.
    else if (RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      Size = 2;
      Bits = (RegOp == RL78::RP4) ? 0x8A00 : 0x8C00;
      unsigned int addr = getTargetOpValue(MI, 2, 1, Fixups, STI,
                                           (MCFixupKind)RL78::fixup_RL78_DIR8U);
      Bits |= addr & 0xFF;
    }
    // MOV A, word[BC]   49 adrl adrh.
    else {

      if (RegOp == RL78::RP2)
        Bits = 0x490000;
      else if (RegOp == RL78::R2)
        Bits = 0x290000;
      else if (RegOp == RL78::R3)
        Bits = 0x090000;

      unsigned int addressValue = getTargetOpValue(
          MI, 2, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
      unsigned int laddr = (0x00FF & addressValue) << 8;
      unsigned int uaddr = (0xFF00 & addressValue) >> 8;

      Size = 3;
      Bits |= (uaddr | laddr);
    }
    break;
  }
  case RL78::STORE8_memDE_r:
  case RL78::STORE8_memHL_r:
  case RL78::STORE8_memDEi_r:
  case RL78::STORE8_memHLi_r:
  case RL78::STORE8_ri_r:
  case RL78::STORE8_rbci_r: {
    // MOV [DE], A       99.
    // MOV [HL], A       9B.
    RL78ReportError(MI.getOperand(2).getReg() == RL78::R1,
                    "Instruction using illegal register.");

    unsigned int RegOp = MI.getOperand(0).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (MI.getOperand(1).isImm() && MI.getOperand(1).getImm() == 0 &&
        RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      Size = 1;
      Bits = (RegOp == RL78::RP4) ? 0x99 : 0x9B;
    }
    // MOV [DE+byte], A  9A adr.
    // MOV [HL+byte], A  9C adr.
    else if (RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      Size = 2;
      Bits = (RegOp == RL78::RP4) ? 0x9A00 : 0x9C00;
      Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    // MOV word[BC], A   48 adrl adrh.
    else {
      if (RegOp == RL78::RP2)
        Bits = 0x480000;
      else if (RegOp == RL78::R2)
        Bits = 0x280000;
      else if (RegOp == RL78::R3)
        Bits = 0x180000;
      Size = 3;
      unsigned int addressValue = getTargetOpValue(
          MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
      Bits |= ((addressValue & 0xFF00) >> 8) | ((addressValue & 0xFF) << 8);
    }
    break;
  }
  case RL78::LOAD8_r_stack_slot:
    // MOV A, [SP+byte]  88 adr.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::STORE8_stack_slot_r: {
    // MOV [SP+byte], A  98 adr.
    RL78ReportError(MI.getOperand(2).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(MI, 1, 1, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR8U);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::LOAD8_r_memrr:
    // MOV A, [HL+B]     61 C9.
    // MOV A, [HL+C]     61 E9.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::R2 || MI.getOperand(2).getReg() == RL78::R3,
                    "Instruction using illegal register.");
    if (MI.getOperand(2).getReg() == RL78::R2)
      Bits += 0x20;
    break;
  case RL78::STORE8_memrr_r:
    // MOV [HL+B], A     61 D9
    // MOV [HL+C], A     61 F9
    RL78ReportError(MI.getOperand(2).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::R2 || MI.getOperand(1).getReg() == RL78::R3,
                    "Instruction using illegal register.");
    if (MI.getOperand(1).getReg() == RL78::R2)
      Bits += 0x20;
    break;
  case RL78::LOAD8_r_abs16: {
    // MOV A, !addr16    8F adrl adrh.
    // MOV B, !addr16    E9 adrl adrh.
    // MOV C, !addr16    F9 adrl adrh.
    // MOV X, !addr16    D9 adrl adrh.
    switch (MI.getOperand(0).getReg()) {
    case RL78::R0:
      Bits = 0xD90000;
      break;
    case RL78::R1:
      Bits = 0x8F0000;
      break;
    case RL78::R2:
      Bits = 0xF90000;
      break;
    case RL78::R3:
      Bits = 0xE90000;
      break;
    default:
      RL78ReportError(false, "Instruction using illegal register.");
    }
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;

    Size = 3;
    Bits |= (uaddr | laddr);
    break;
  }

  case RL78::MOV_esaddr16_imm: {
    // MOV ES:!addr16, #byte ;11 CF adrl adrh data.
    Bits |= getTargetOpValue(MI, 2, 4, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 16;
    unsigned int uaddr = (0xFF00 & addressValue);
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::MOV_esaddr16_a: {
    // MOV ES:!addr16, A ;11 9F adrl adrh.
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::MOV_r_esaddr16: {
    // MOV A, ES:!addr16 ;11 8F adrl adrh 
    // MOV B, ES:!addr16 ;11 E9 adrl adrh.
    // MOV C, ES:!addr16 ;11 F9 adrl adrh.
    // MOV X, ES:!addr16 ;11 D9 adrl adrh.
    switch (MI.getOperand(0).getReg()) {
    case RL78::R0:
      Bits = 0x11D90000;
      break;
    case RL78::R1:
      Bits = 0x118F0000;
      break;
    case RL78::R2:
      Bits = 0x11F90000;
      break;
    case RL78::R3:
      Bits = 0x11E90000;
      break;
    }
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }

  case RL78::STORE8_esmemDE_r:
  case RL78::STORE8_esmemHL_a:
  case RL78::STORE8_esmemDEi_a:
  case RL78::STORE8_esmemHLi_a:
  case RL78::STORE8_esrborci_r:
  case RL78::STORE8_esrpi_r: {

    RL78ReportError(MI.getOperand(3).getReg() == RL78::R1,
                    "Instruction using illegal register.");

    unsigned int RegOp = MI.getOperand(1).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (MI.getOperand(2).isImm() && MI.getOperand(2).getImm() == 0 &&
        RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      // MOV es:[HL], A         11 9B.
      // MOV es:[DE], A         11 99.
      Bits = (RegOp == RL78::RP4) ? 0x1199 : 0x119B;
      Size = 2;
      break;
    }

    if (RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      // MOV es:[DE+byte], A    11 9A adr.
      // MOV es:[HL+byte], A    11 9C adr.
      Bits = (RegOp == RL78::RP4) ? 0x119A00 : 0x119C00;
      unsigned int addr = getTargetOpValue(MI, 2, 2, Fixups, STI,
                                           (MCFixupKind)RL78::fixup_RL78_DIR8U);
      Bits |= addr & 0xFF;
      Size = 3;
      break;
    } else {

      // MOV es:word[BC], A     11 48 adrl adrh.
      // MOV ES:word[C], A	  11 28 adrl adrh.
      // MOV ES : word[B], A    11 18 adrl adrh.
      if (RegOp == RL78::RP2)
        Bits = 0x11480000;
      else if (RegOp == RL78::R2)
        Bits = 0x11280000;
      else if (RegOp == RL78::R3)
        Bits = 0x11180000;
      Size = 4;
      unsigned int addressValue = getTargetOpValue(
          MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
      unsigned int laddr = (0x00FF & addressValue) << 8;
      unsigned int uaddr = (0xFF00 & addressValue) >> 8;
      Bits |= (uaddr | laddr);
      break;
    }
  }
  case RL78::LOAD8_a_esmemDE:
  case RL78::LOAD8_rp_esmemHL:
  case RL78::LOAD8_a_esmemDEi:
  case RL78::LOAD8_a_esmemHLi:
  case RL78::LOAD8_a_esrborci:
  case RL78::LOAD8_r_esrpi: {

    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");

    unsigned int RegOp = MI.getOperand(2).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (MI.getOperand(3).isImm() && MI.getOperand(3).getImm() == 0 &&
        RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {

      // MOV A, es:[DE]       11 89.
      // MOV A, es:[HL]       11 8B.
      Bits = (RegOp == RL78::RP4) ? 0x1189 : 0x118B;
      Size = 2;
      break;
    }

    if (RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {
      // MOV A, es:[DE+byte]  11 8A adr.
      // MOV A, es:[HL+byte]  11 8C adr.
      Bits = (RegOp == RL78::RP4) ? 0x118A00 : 0x118C00;
      unsigned int addr = getTargetOpValue(MI, 3, 2, Fixups, STI,
                                           (MCFixupKind)RL78::fixup_RL78_DIR8U);
      Bits |= addr & 0xFF;
      Size = 3;
      break;
    }
    if (RegOp == RL78::RP2)
      Bits = 0x11490000;
    else if (RegOp == RL78::R2)
      Bits = 0x11290000;
    else if (RegOp == RL78::R3)
      Bits = 0x11090000;

    Size = 4;
    // MOV A, es:word[BC]   11 49 adrl adrh.
    // MOV A, ES:word[C] ;11 29 adrl adrh.
    // MOV A, ES:word[B] ;11 09 adrl adrh.

    unsigned int addressValue = getTargetOpValue(
        MI, 3, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }

  case RL78::STORE8_esmemDEi_imm:
  case RL78::STORE8_esmemHLi_imm:
  case RL78::STORE8_esmemBorCi_imm:
  case RL78::STORE8_esmemBCi_imm: {
    unsigned int RegOp = MI.getOperand(1).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (RegOp != RL78::RP2 && RegOp != RL78::R2 && RegOp != RL78::R3) {

      // MOV ES:[DE+byte], #byte ;11 CA adr data.
      // MOV ES:[HL+byte], #byte ;11 CC adr data.
      Bits = (RegOp == RL78::RP4) ? 0x11CA0000 : 0x11CC0000;
      unsigned int addr = getTargetOpValue(MI, 2, 3, Fixups, STI,
                                           (MCFixupKind)RL78::fixup_RL78_DIR8U);
      Bits |= (addr & 0xFF) << 8;
      unsigned int data = getTargetOpValue(MI, 3, 2, Fixups, STI,
                                           (MCFixupKind)RL78::fixup_RL78_DIR8U);
      Bits |= (data & 0xFF);
      Size = 4;
      break;
    } else {

      // MOV ES:word[BC], #byte  ;11 39 adrl adrh data.
      // MOV ES:word[B],  #byte  ;11 19 adrl adrh data.
      // MOV ES:word[C],  #byte  ;11 38 adrl adrh data.
      if (RegOp == RL78::RP2)
        Bits = 0x1139000000;
      else if (RegOp == RL78::R2)
        Bits = 0x1138000000;
      else if (RegOp == RL78::R3)
        Bits = 0x1119000000;
      Size = 5;
      unsigned int addressValue = getTargetOpValue(
          MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
      unsigned int laddr = (0x00FF & addressValue) << 16;
      unsigned int uaddr = (0xFF00 & addressValue);
      Bits |= (uaddr | laddr);

      Bits |= getTargetOpValue(MI, 3, 4, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;

      break;
    }
  }
  case RL78::LOAD8_a_esmemRpr: {
    // MOV A, ES:[HL+B] ;11 61 C9.
    // MOV A, ES:[HL+C] ;11 61 E9.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(3).getReg() == RL78::R3) ? 0x1161C9 : 0x1161E9;

    break;
  }
  case RL78::STORE8_esmemRpr_a: {
    // MOV ES:[HL+B], A ;11 61 D9.
    // MOV ES:[HL+C], A ;11 61 F9.
    RL78ReportError(MI.getOperand(3).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(2).getReg() == RL78::R3) ? 0x1161D9 : 0x1161F9;
    break;
  }
  case RL78::XCH_A_X:
  case RL78::XCH_A_r:
    // XCH A, X          08
    // XCH A, C          61 8A
    // XCH A, B          61 8B
    // XCH A, E          61 8C
    // XCH A, D          61 8D
    // XCH A, L          61 8E
    // XCH A, H          61 8F
    if (MI.getOperand(3).getReg() == RL78::R0) {
      Size = 1;
      Bits = 0x08;
    } else
      Bits += (MI.getOperand(3).getReg() - RL78::R2);
    break;
  case RL78::XCH_A_sfr: {
    // XCH A, sfr      61 AB sfr.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(1).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::XCH_A_sfrReg: {
    // XCH A, sfr      61 AB sfr.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    Bits |= (sfrRegisterToSfraddr[MI.getOperand(1).getReg()] & 0xFF);
    break;
  }
  case RL78::XCH_A_saddrabs: {
    // XCH A, saddr      61 A8 saddr.
    unsigned int addr = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::XCH_A_abs16: {
    // XCH A, !addr16    61 AA adrl adrh.
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::XCH_A_memri: {

    // XCH A, [DE]       61 AE.
    // XCH A, [DE+byte]  61 AF adr.
    // XCH A, [HL]       61 AC.
    // XCH A, [HL+byte]  61 AD adr.
    unsigned int RegOp = MI.getOperand(2).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6,
                    "Instruction using illegal register.");

    if (MI.getOperand(3).isImm() && MI.getOperand(3).getImm() == 0) {

      Bits = (RegOp == RL78::RP4) ? 0x61AE : 0x61AC;
      Size = 2;
      break;
    } else {
      Bits = (RegOp == RL78::RP4) ? 0x61AF00 : 0x61AD00;
      unsigned int addr = getTargetOpValue(MI, 3, 2, Fixups, STI,
                                           (MCFixupKind)RL78::fixup_RL78_DIR8U);
      Bits |= addr & 0xFF;
      Size = 3;
      break;
    }
  }
  case RL78::XCH_A_memrr: {
    // XCH A, [HL+B]     61 B9.
    // XCH A, [HL+C]     61 A9.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::R2 || MI.getOperand(3).getReg() == RL78::R3,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(3).getReg() == RL78::R3) ? 0x61B9 : 0x61A9;
    break;
  }
  case RL78::XCH_A_esaddr16: {
    // XCH A, ES:!addr16 ;11 61 AA adrl adrh.
    unsigned int addressValue = getTargetOpValue(
        MI, 3, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::XCH_A_esmemDE:
  case RL78::XCH_A_esmemHL:
  case RL78::XCH_A_esmemRpi: {
    // XCH A, ES:[DE] ;11 61 AE.
    // XCH A, ES:[HL] ;11 61 AC.
    // XCH A, ES:[DE+byte] ;11 61 AF adr.
    // XCH A, ES:[HL+byte] ;11 61 AD adr.
    unsigned int RegOp = MI.getOperand(3).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6,
                    "Instruction using illegal register.");

    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {

      Bits = (RegOp == RL78::RP4) ? 0x1161AE : 0x1161AC;
      Size = 3;
      break;
    } else {
      Bits = (RegOp == RL78::RP4) ? 0x1161AF00 : 0x1161AD00;
      unsigned int addr = getTargetOpValue(MI, 4, 3, Fixups, STI,
                                           (MCFixupKind)RL78::fixup_RL78_DIR8U);
      Bits |= addr & 0xFF;
      Size = 4;
      break;
    }
  }
  case RL78::XCH_A_esmemRpr: {
    // XCH A, ES:[HL+B] ;11 61 B9
    // XCH A, ES:[HL+C] ;11 61 A9
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x1161B9 : 0x1161A9;
    break;
  }
  case RL78::ONEB_r: {
    // ONEB r            EX (X..B -> 0..3)
    Bits += (MI.getOperand(0).getReg() - RL78::R0);
    break;
  }
  case RL78::ONEB_saddr: {

    // ONEB saddr        E4 saddr
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::ONEB_esaddr16: {

    // ONEB ES:!addr16    11 E5 adrl adrh
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CLRB_r: {
    // CLRB r            FX (X..C -> 0..3)
    Bits |= (MI.getOperand(0).getReg() - RL78::R0);
    break;
  }
  case RL78::CLRB_saddr: {

    // CLRB saddr        F4 saddr
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::CLRB_esaddr16: {

    // CLRB ES:!addr16    11 F5 adrl adrh
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::INCW_saddr:
  case RL78::DECW_saddr: {
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8UW_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::DEC_saddr:
  case RL78::INC_saddr: {
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::INC_r:
  case RL78::DEC_r:
    // INC r             80 (X..H -> 0..7)
    // DEC r             90 (X..H -> 0..7)
    Bits += MI.getOperand(0).getReg() - RL78::R0;
    break;
  case RL78::CLRB_abs16:
  case RL78::ONEB_abs16: {
    // CLRB addr16       F5 adrl adrh
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::MOVS_memri_r: {

    // MOVS [HL+byte], X     61 CE adr
    RL78ReportError(MI.getOperand(2).getReg() == RL78::R0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  }
  case RL78::MOVS_Esmemri_r: {

    // MOVS ES:[HL+byte], X ;11 61 CE adr
    RL78ReportError(MI.getOperand(3).getReg() == RL78::R0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 2, 3, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  }
  case RL78::MOVW_rp_imm:
  case RL78::HI16_rp_addr:
    // MOVW AX, #word        30 datal datah
    // MOVW BC, #word        32 datal datah
    // MOVW DE, #word        34 datal datah
    // MOVW HL, #word        36 datal datah
    Bits += (((MI.getOperand(0).getReg() - RL78::RP0) * 2) << 16);
    // Note that fixup_RL78_DIR16U might be replaced with others if TargetFlag
    // says so
    if (MI.getOperand(1).isImm()) {
      unsigned int data = getTargetOpValue(
          MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
      Bits |= ((data & 0xFF00) >> 8) | ((data & 0xFF) << 8);
    } else
      getTargetOpValue(MI, 1, Size - 2, Fixups, STI,
                       (MCFixupKind)RL78::fixup_RL78_DIR16U);
    break;
  case RL78::MOVW_sp_rp:
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    break;
  case RL78::MOVW_sp_imm:
    // MOVW SP, #word    CB F8 datal datah
    if (MI.getOperand(1).isImm()) {
      // Not sure why CCRL does not enforce even values.
      unsigned int data = getTargetOpValue(
          MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
      Bits |= ((data & 0xFF00) >> 8) | ((data & 0xFF) << 8);

    } else {

      getTargetOpValue(MI, 1, Size - 2, Fixups, STI,
                       (MCFixupKind)RL78::fixup_RL78_DIR16U);
    }
    break;
  case RL78::LOAD16_rp_sfrp: {
    // MOVW AX, sfrp ;AE sfr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(1).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00 && immediateValue % 2 == 0,
                    "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::MOVW_AX_sfrpReg: {
    // MOVW AX, sfrp ;AE sfr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    Bits |= sfrRegisterToSfraddr[MI.getOperand(1).getReg()] & 0xFF;
    break;
  }
  case RL78::LOAD16_rp_saddrp: {
    // MOVW AX, saddrp    AD saddr
    switch (MI.getOperand(0).getReg()) {
    case RL78::RP0:
      Bits = 0xAD00;
      break;
    case RL78::RP2:
      Bits = 0xDA00;
      break;
    case RL78::RP4:
      Bits = 0xEA00;
      break;
    case RL78::RP6:
      Bits = 0xFA00;
      break;
    default:
      llvm_unreachable("Invalid register used in MOVW instruction!");
    }
    unsigned int addr = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8UW_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::STORE16_sfrp_rp: {
    // MOVW sfrp, AX ;BE sfr
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00 && immediateValue % 2 == 0,
                    "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::STORE16_saddrp_rp: {
    // MOVW saddrp, AX    BD saddr
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8UW_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::MOVW_sfrpReg_AX: {
    // MOVW sfrp, AX ;BE sfr
    Bits |= sfrRegisterToSfraddr[MI.getOperand(0).getReg()] & 0xFF;
    break;
  }
  case RL78::STORE16_sfrp_imm: {
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00 && immediateValue % 2 == 0,
                    "sfr operand not in range");
    Bits |= (immediateValue & 0xFF) << 16;
    unsigned int data = getTargetOpValue(MI, 1, 2, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned int datal = (0x00FF & data) << 8;
    unsigned int datah = (0xFF00 & data) >> 8;
    Bits |= (datal | datah);
    break;
  }
  case RL78::MOVW_saddrp_imm: {

    // MOVW saddrp, #word    C9 saddr datal datah
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8UW_SAD);
    Bits |= (addr & 0xFF) << 16;
    unsigned int data = getTargetOpValue(MI, 1, 2, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned int datal = (0x00FF & data) << 8;
    unsigned int datah = (0xFF00 & data) >> 8;
    Bits |= (datal | datah);
    break;
  }
  case RL78::MOVW_sfrpReg_imm: {
    // MOVW sfrp,#word ;CB sfr datal datah
    Bits |= (sfrRegisterToSfraddr[MI.getOperand(0).getReg()] & 0xFF) << 16;
    unsigned int data = getTargetOpValue(MI, 1, 2, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned int datal = (0x00FF & data) << 8;
    unsigned int datah = (0xFF00 & data) >> 8;
    Bits |= (datal | datah);
    break;
  }
  case RL78::MOVW_AX_rp:
    // First/Only byte: BC -> 0x13, DE -> 0x15, HL -> 0x17.
    RL78ReportError(MI.getOperand(1).getReg() != MI.getOperand(0).getReg(),
                    "Invalid Instruction.");
    Bits += (MI.getOperand(1).getReg() - RL78::RP2) * 2;
    break;
  case RL78::MOVW_rp_AX:
    // MOVW BC, AX       12
    // MOVW DE, AX       14
    // MOVW HL, AX       16
    RL78ReportError(MI.getOperand(1).getReg() != MI.getOperand(0).getReg(),
                    "Invalid Instruction.");
    Bits += (MI.getOperand(0).getReg() - RL78::RP2) * 2;
    break;
  case RL78::LOAD16_rp_abs16: {
    // MOVW AX, !addr16      AF adrl adrh
    // MOVW BC, !addr16      DB adrl adrh
    // MOVW DE, !addr16      EB adrl adrh
    // MOVW HL, !addr16      FB adrl adrh
    if (MI.getOperand(0).getReg() != RL78::RP0) {
      Bits &= 0x00FFFF;
      Bits |= 0xDB0000 + ((MI.getOperand(0).getReg() - RL78::RP2) << 20);
    }
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits = Bits + laddr + uaddr;
    break;
  }
  case RL78::STORE16_abs16_rp: {
    // MOVW !addr16, AX      BF adrl adrh
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits = Bits + laddr + uaddr;

    break;
  }
  case RL78::LOAD16_rp_esmemDE:
  case RL78::LOAD16_rp_esmemHL:
  case RL78::LOAD16_rp_esmemDEi:
  case RL78::LOAD16_rp_esmemHLi:
  case RL78::LOAD16_rp_esrpi:
  case RL78::LOAD16_rp_esrbci: {
    // MOVW AX, es:[DE]       11 A9
    // MOVW AX, es:[DE+byte]  11 AA adr
    // MOVW AX, es:[HL]       11 AB
    // MOVW AX, es:[HL+byte]  11 AC adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int RegOp = MI.getOperand(2).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (RegOp != RL78::RP2 && RegOp != RL78::R3 && RegOp != RL78::R2) {
      Size = 3;
      // Size is set to 3 update it.
      if (MI.getOperand(3).isImm())
        Size = MI.getOperand(3).getImm() ? 3 : 2;
      else
        Size = 3;

      if (RegOp == RL78::RP4) {
        if (Size == 2) {
          Bits = 0x11A9;
        } else {
          Bits = 0x11AA00;
          Bits |= getTargetOpValue(MI, 3, 2, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }

      else {
        if (Size == 2) {

          Bits = 0x11AB;
        } else {
          Bits = 0x11AC00;
          Bits |= getTargetOpValue(MI, 3, 2, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }

    }
    // MOVW AX, es:word[BC]   11 79 adrl adrh
    else {
      // MOVW AX, es:word[BC]   11 79 adrl adrh
      if (RegOp == RL78::RP2)
        Bits = 0x11790000;
      else if (RegOp == RL78::R2)
        Bits = 0x11690000;
      else if (RegOp == RL78::R3)
        Bits = 0x11590000;
      Size = 4;
      unsigned int addressValue = getTargetOpValue(
          MI, 3, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
      Bits |= (((addressValue)&0xFF00) >> 8) | ((addressValue & 0xFF) << 8);
    }
    break;
  }
  case RL78::LOAD16_rp_memDE:
  case RL78::LOAD16_rp_memHL:
  case RL78::LOAD16_rp_memDEi:
  case RL78::LOAD16_rp_memHLi:
  case RL78::LOAD16_rp_rpi:
  case RL78::LOAD16_rp_rbci: {

    // MOVW AX, [DE]       A9
    // MOVW AX, [DE+byte]  AA adr
    // MOVW AX, [HL]       AB
    // MOVW AX, [HL+byte]  AC adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");

    unsigned int RegOp = MI.getOperand(1).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (RegOp != RL78::RP2 && RegOp != RL78::R3 && RegOp != RL78::R2) {
      // Size is set to 3 update it.
      if (MI.getOperand(2).isImm())
        Size = MI.getOperand(2).getImm() ? 2 : 1;
      else
        Size = 2;

      if (RegOp == RL78::RP4) {
        if (Size == 1) {
          Bits = 0xA9;
        } else {
          Bits = 0xAA00;
          Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }

      else {
        if (Size == 1) {

          Bits = 0xAB;
        } else {
          Bits = 0xAC00;
          Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }
    }
    // MOVW AX, word[BC]   79 adrl adrh
    else {
      if (RegOp == RL78::RP2)
        Bits = 0x790000;
      else if (RegOp == RL78::R2)
        Bits = 0x690000;
      else if (RegOp == RL78::R3)
        Bits = 0x590000;

      Size = 3;
      unsigned int addressValue = getTargetOpValue(
          MI, 2, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
      Bits |= ((addressValue & 0xFF00) >> 8) | ((addressValue & 0xFF) << 8);
    }
    break;
  }
  case RL78::STORE16_memDE_rp:
  case RL78::STORE16_memHL_rp:
  case RL78::STORE16_memDEi_rp:
  case RL78::STORE16_memHLi_rp:
  case RL78::STORE16_rpi_rp:
  case RL78::STORE16_rbci_rp: {
    // MOVW [DE], AX         B9
    // MOVW [DE+byte], AX    BA adr
    // MOVW [HL], AX         BB
    // MOVW [HL+byte], AX    BC adr
    // MOVW word[BC], AX     78 adrl adrh
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int RegOp = MI.getOperand(0).getReg();
    RL78ReportError(RegOp == RL78::RP4 || RegOp == RL78::RP6 ||
                        RegOp == RL78::RP2 || RegOp == RL78::R2 ||
                        RegOp == RL78::R3,
                    "Instruction using illegal register.");

    if (RegOp != RL78::RP2 && RegOp != RL78::R3 && RegOp != RL78::R2) {
      // Size is set to 3 update it.
      if (MI.getOperand(1).isImm())
        Size = MI.getOperand(1).getImm() ? 2 : 1;
      else
        Size = 2;

      if (RegOp == RL78::RP4) {
        if (Size == 1) {
          Bits = 0xB9;
        } else {
          Bits = 0xBA00;
          Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }

      else {
        if (Size == 1) {

          Bits = 0xBB;
        } else {
          Bits = 0xBC00;
          Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }

    }
    // MOVW word[BC], AX     78 adrl adrh
    else {
      if (RegOp == RL78::RP2)
        Bits = 0x780000;
      else if (RegOp == RL78::R2)
        Bits = 0x680000;
      else if (RegOp == RL78::R3)
        Bits = 0x580000;
      Size = 3;
      unsigned int addressValue = getTargetOpValue(
          MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
      Bits |= ((addressValue & 0xFF00) >> 8) | ((addressValue & 0xFF) << 8);
    }
    break;
  }
  case RL78::STORE16_esmemDE_rp:
  case RL78::STORE16_esmemHL_rp:
  case RL78::STORE16_esmemDEi_rp:
  case RL78::STORE16_esmemHLi_rp:
  case RL78::STORE16_esrpi_rp:
  case RL78::STORE16_esrbci_rp:
    // MOVW es:[DE], AX         11 B9
    // MOVW es:[DE+byte], AX    11 BA adr
    // MOVW es:[HL], AX         11 BB
    // MOVW es:[HL+byte], AX    11 BC adr
    // MOVW es:word[BC], AX     11 78 adrl adrh
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    if (MI.getOperand(1).getReg() != RL78::RP2 &&
        MI.getOperand(1).getReg() != RL78::R3 &&
        MI.getOperand(1).getReg() != RL78::R2) {
      // Size is set to 3 update it.
      if (MI.getOperand(2).isImm())
        Size = MI.getOperand(2).getImm() ? 3 : 2;
      else
        Size = 3;

      if (MI.getOperand(1).getReg() == RL78::RP4) {
        if (Size == 2) {
          Bits = 0x11B9;
        } else {
          Bits = 0x11BA00;
          Bits |= getTargetOpValue(MI, 2, 2, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }

      else {
        if (Size == 2) {
          Bits = 0x11BB;
        } else {
          Bits = 0x11BC00;
          Bits |= getTargetOpValue(MI, 2, 2, Fixups, STI,
                                   (MCFixupKind)RL78::fixup_RL78_DIR8U) &
                  0xFF;
        }
      }
    }
    // MOVW es:word[BC], AX     11 78 adrl adrh
    else {
      if (MI.getOperand(1).getReg() == RL78::RP2)
        Bits = 0x11780000;
      else if (MI.getOperand(1).getReg() == RL78::R2)
        Bits = 0x11680000;
      else if (MI.getOperand(1).getReg() == RL78::R3)
        Bits = 0x11580000;
      Size = 4;
      unsigned int addressValue = getTargetOpValue(
          MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
      Bits |= ((addressValue & 0xFF00) >> 8) | ((addressValue & 0xFF) << 8);
    }
    break;
  case RL78::LOAD16_rp_stack_slot:
    // MOVW AX, [SP+byte]    A8 adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::STORE16_stack_slot_rp:
    // MOVW [SP+byte], AX    B8 adr
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::LOAD16_rp_esaddr16: {
    // MOVW AX, ES:!addr16   ;11 AF adrl adrh
    // MOVW BC, ES:!addr16   ;11 DB adrl adrh
    // MOVW DE, ES:!addr16   ;11 EB adrl adrh
    // MOVW HL, ES:!addr16   ;11 FB adrl adrh
    switch (MI.getOperand(0).getReg()) {
    case RL78::RP0:
      break;
    case RL78::RP2:
      Bits = 0x11DB0000;
      break;
    case RL78::RP4:
      Bits = 0x11EB0000;
      break;
    case RL78::RP6:
      Bits = 0x11FB0000;
      break;
    default:
      llvm_unreachable("Invalid register used in MOVW instruction!");
    }
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits = Bits + laddr + uaddr;
    break;
  }
  case RL78::STORE16_esaddr16_rp: {

    // MOVW ES:!addr16, AX   ;11 BF adrl adrh
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20UW_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits = Bits + laddr + uaddr;
    break;
  }
  case RL78::MOVW_AX_sp:
  case RL78::MOVW_rp_sp:
    // MOVW AX, SP       AE F8
    // MOVW BC, SP       DB adrl adrh
    // MOVW DE, SP       EB adrl adrh
    // MOVW HL, SP       FB adrl adrh
    if (MI.getOperand(0).getReg() == RL78::RP0) {
      Size = 2;
      Bits = 0xAEF8;
    } else {
      Bits = 0xDBF8FF;
      Size = 3;
      Bits += (MI.getOperand(0).getReg() - RL78::RP2) << 20;
    }
    break;
  case RL78::ONEW_rp:
  case RL78::CLRW_rp:
    // AX -> x6, BC -> x7.
    Bits |= (MI.getOperand(0).getReg() == RL78::RP0) ? 0 : 1;
    break;
  case RL78::XCHW_AX_rp:
    // XCHW AX, BC   33
    // XCHW AX, DE   35
    // XCHW AX, HL   37
    Bits += (MI.getOperand(1).getReg() - RL78::RP2) * 2;
    break;
  case RL78::BSWAP32_rp:
    // Same as XCHW_AX_rp + 2 x XCH A, X.
    Bits += ((MI.getOperand(1).getReg() - RL78::RP2) * 2) << 8;
    break;
  case RL78::ADD_r_r:
    // ADD A, r          61 0r (X -> 8, C -> A ... H -> F)
    // ADD X, A          61 0r (X -> 0, A -> 1 ... H -> 7)
    encode8BitRROperationInstruction(MI, Bits, 0x6100, 0x0B00);
    break;
  case RL78::ADDC_r_r:
    // ADDC A, r          61 1r (X -> 8, C -> A ... H -> F)
    // ADDC r, A          61 1r (X -> 0, A -> 1 ... H -> 7)
    encode8BitRROperationInstruction(MI, Bits, 0x6110, 0x1B00);
    break;
  case RL78::SUB_r_r:
    // SUB A, r          61 2r (X -> 8, C -> A ... H -> F)
    // SUB X, A          61 2r (X -> 0, A -> 1 ... H -> 7)
    encode8BitRROperationInstruction(MI, Bits, 0x6120, 0x2B00);
    break;
  case RL78::SUBC_r_r:
    // SUBC A, r          61 3r (X -> 8, C -> A ... H -> F)
    // SUBC X, A          61 3r (X -> 0, A -> 1 ... H -> 7)
    encode8BitRROperationInstruction(MI, Bits, 0x6130, 0x3B00);
    break;
  case RL78::AND_r_r:
    // AND A, r          61 5r (X -> 8, C -> A ... H -> F)
    // AND X, A          61 5r (X -> 0, A -> 1 ... H -> 7)
    encode8BitRROperationInstruction(MI, Bits, 0x6150, 0x5B00);
    break;
  case RL78::OR_r_r:
    // OR A, r          61 6r (X -> 8, C -> A ... H -> F)
    // OR X, A          61 6r (X -> 0, A -> 1 ... H -> 7)
    encode8BitRROperationInstruction(MI, Bits, 0x6160, 0x6B00);
    break;
  case RL78::XOR_r_r:
    // XOR A, r          61 7r (X -> 8, C -> A ... H -> F)
    // XOR X, A          61 7r (X -> 0, A -> 1 ... H -> 7)
    encode8BitRROperationInstruction(MI, Bits, 0x6170, 0x7B00);
    break;
  case RL78::CMP_r_r:
    // CMP A, r              61 4r (X -> 8, C -> A ... H -> F)
    // CMP r, A              61 40 (X -> 0, A -> 1 ... H -> 7)
    encode8BitCMPOperationInstruction(MI, Bits, 0x6140, 0x4B00);
    break;
  case RL78::ADD_r_imm:
    // ADD A, #byte      0C data
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::ADDC_A_imm:
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::SUB_r_imm:
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::SUBC_A_imm:
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::AND_r_imm:
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::OR_r_imm:
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
  case RL78::XOR_r_imm:
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::CMP_r_imm:
      Bits |= getTargetOpValue(MI, 1, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::ADD_r_abs16:
  case RL78::ADDC_r_abs16:
  case RL78::SUB_r_abs16:
  case RL78::SUBC_r_abs16:
  case RL78::AND_r_abs16:
  case RL78::OR_r_abs16:
  case RL78::XOR_r_abs16: {
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CMP_r_abs16: {
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }

  case RL78::CMP_abs16_imm: {

    // CMP !addr16, #byte    40 adrl adrh data
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 16;
    unsigned int uaddr = (0xFF00 & addressValue);
    Bits |= (uaddr | laddr);
    Bits |= getTargetOpValue(MI, 1, 3, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  }
  case RL78::ADD_r_memHL:
  case RL78::ADD_r_memri:
    // ADD A, [HL]       0D
    // ADD A, [HL+byte]  0E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    encode8BitRMEMRIOperationInstruction(MI, Bits, Size, 0x0D, 0x0E00);
    if (Size == 2)
      Bits |= getTargetOpValue(MI, 3, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;

    break;
  case RL78::ADDC_r_memHL:
  case RL78::ADDC_r_memri:
    // ADDC A, [HL]       0D
    // ADDC A, [HL+byte]  0E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    encode8BitRMEMRIOperationInstruction(MI, Bits, Size, 0x1D, 0x1E00);
    if (Size == 2)
      Bits |= getTargetOpValue(MI, 3, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::SUB_r_memHL:
  case RL78::SUB_r_memri:
    // SUB A, [HL]       2D
    // SUB A, [HL+byte]  2E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    encode8BitRMEMRIOperationInstruction(MI, Bits, Size, 0x2D, 0x2E00);
    if (Size == 2)
      Bits |= getTargetOpValue(MI, 3, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::SUBC_r_memHL:
  case RL78::SUBC_r_memri:
    // SUBC A, [HL]       3D
    // SUBC A, [HL+byte]  3E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    encode8BitRMEMRIOperationInstruction(MI, Bits, Size, 0x3D, 0x3E00);
    if (Size == 2)
      Bits |= getTargetOpValue(MI, 3, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::AND_r_memHL:
  case RL78::AND_r_memri:
    // AND A, [HL]       5D
    // AND A, [HL+byte]  5E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    encode8BitRMEMRIOperationInstruction(MI, Bits, Size, 0x5D, 0x5E00);
    if (Size == 2)
      Bits |= getTargetOpValue(MI, 3, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::OR_r_memHL:
  case RL78::OR_r_memri:
    // OR A, [HL]        6D
    // OR A, [HL+byte]   6E adr
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    encode8BitRMEMRIOperationInstruction(MI, Bits, Size, 0x6D, 0x6E00);
    if (Size == 2)
      Bits |= getTargetOpValue(MI, 3, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::XOR_r_memHL:
  case RL78::XOR_r_memri:
    // XOR A, [HL]       7D
    // XOR A, [HL+byte]  7E adr
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    encode8BitRMEMRIOperationInstruction(MI, Bits, Size, 0x7D, 0x7E00);
    if (Size == 2)
      Bits |= getTargetOpValue(MI, 3, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    break;
  case RL78::CMP_r_memHL:
  case RL78::CMP_r_memri:
    // CMP A, [HL]           4D.
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    if (MI.getOperand(2).isImm() && MI.getOperand(2).getImm() == 0) {
      Size = 1;
      Bits = 0x4D;
    }
    // CMP A, [HL+byte]      4E adr.
    else {
      Size = 2;
      Bits = 0x4E00;
      Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;

  case RL78::ADD_r_memrr:
  case RL78::ADDC_r_memrr:
  case RL78::SUB_r_memrr:
  case RL78::SUBC_r_memrr:
  case RL78::AND_r_memrr:
  case RL78::OR_r_memrr:
  case RL78::XOR_r_memrr:
    // Opcode is of the form:
    // Op A, [HL+B]  61 X0
    // Op A, [HL+C]  61 X2.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::R2 || MI.getOperand(3).getReg() == RL78::R3,
                    "Instruction using illegal register.");
    if (MI.getOperand(3).getReg() == RL78::R2)
      Bits |= 2;
    break;
  case RL78::CMP_r_memrr:
    // Opcode is of the form:
    // Op A, [HL+B]  61 X0
    // Op A, [HL+C]  61 X2.
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::R2 || MI.getOperand(2).getReg() == RL78::R3,
                    "Instruction using illegal register.");
    if (MI.getOperand(2).getReg() == RL78::R2)
      Bits |= 2;
    break;
  case RL78::SUBC_r_esaddr16:
  case RL78::SUB_r_esaddr16:
  case RL78::AND_r_esaddr16:
  case RL78::OR_r_esaddr16:
  case RL78::XOR_r_esaddr16:
  case RL78::ADDC_r_esaddr16:
  case RL78::ADD_r_esaddr16: {

    // ADD A, ES:!addr16 ;11 0F adrl adrh
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 3, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits = Bits + laddr + uaddr;
    break;
  }
  case RL78::CMP_r_esaddr16: {
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits = Bits + laddr + uaddr;
    break;
  }

  case RL78::CMP0_esaddr16: {
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits = Bits + laddr + uaddr;
    break;
  }
  case RL78::ADD_r_esmemHL:
  case RL78::ADD_r_esmemHLi: {

    // ADD A, ES:[HL] ;11 0D
    // ADD A, ES:[HL+byte] ;11 0E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {
      Bits = 0x110D;
      Size = 2;
    } else {
      Bits = 0x110E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 4, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::ADDC_r_esmemHL:
  case RL78::ADDC_r_esmemHLi: {
    // ADDC A, ES:[HL] ;11 1D
    // ADDC A, ES:[HL+byte] ;11 1E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {
      Bits = 0x111D;
      Size = 2;
    } else {
      Bits = 0x111E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 4, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::SUB_r_esmemHL:
  case RL78::SUB_r_esmemHLi: {

    // SUB A, ES:[HL] ;11 2D
    // SUB A, ES:[HL+byte] ;11 2E adrdr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {
      Bits = 0x112D;
      Size = 2;
    } else {
      Bits = 0x112E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 4, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::SUBC_r_esmemHL:
  case RL78::SUBC_r_esmemHLi: {
    // SUBC A, ES:[HL] ;11 3D
    // SUBC A, ES:[HL+byte] ;11 3E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {
      Bits = 0x113D;
      Size = 2;
    } else {
      Bits = 0x113E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 4, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::AND_r_esmemHL:
  case RL78::AND_r_esmemHLi: {

    // ADD A, ES:[HL] ;11 0D
    // ADD A, ES:[HL+byte] ;11 0E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {
      Bits = 0x115D;
      Size = 2;
    } else {
      Bits = 0x115E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 4, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::OR_r_esmemHL:
  case RL78::OR_r_esmemHLi: {
    // OR A, ES:[HL] ;11 6D
    // OR A, ES:[HL+byte] ;11 6E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {
      Bits = 0x116D;
      Size = 2;
    } else {
      Bits = 0x116E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 4, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::XOR_r_esmemHL:
  case RL78::XOR_r_esmemHLi: {

    // XOR A, ES:[HL] ;11 7D
    // XOR A, ES:[HL+byte] ;11 7E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");

    if (MI.getOperand(4).isImm() && MI.getOperand(4).getImm() == 0) {
      Bits = 0x117D;
      Size = 2;
    } else {
      Bits = 0x117E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 4, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::CMP_r_esmemHL:
  case RL78::CMP_r_esmemHLi: {
    // CMP A, ES:[HL] ;11 4D
    // CMP A, ES:[HL+byte] ;11 4E adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");

    if (MI.getOperand(3).isImm() && MI.getOperand(3).getImm() == 0) {
      Bits = 0x114D;
      Size = 2;
    } else {
      Bits = 0x114E00;
      Size = 3;
      Bits |= getTargetOpValue(MI, 3, 2, Fixups, STI,
                               (MCFixupKind)RL78::fixup_RL78_DIR8U) &
              0xFF;
    }
    break;
  }
  case RL78::CMP_esaddr16_imm: {

    // CMP ES:!addr16, #byte ;11 40 adrl adrh data
    Bits |= getTargetOpValue(MI, 2, 4, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 16;
    unsigned int uaddr = (0xFF00 & addressValue);
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CMPS_rp_memri: {
    // CMPS X, ES:[HL+byte] ;11 61 DE adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(MI, 3, 3, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR8U);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::ADDC_r_esmemRpr:
    // ADDC A, ES:[HL+C] ;11 61 92
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x116190 : 0x116192;
    break;
  case RL78::ADD_r_esmemRpr:
    // ADD A, ES:[HL+C] ;11 61 82
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x116180 : 0x116182;
    break;
  case RL78::SUB_r_esmemRpr:
    // SUB A, ES:[HL+C] ;11 61 A2
    RL78ReportError(MI.getOperand(1).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x1161A0 : 0x1161A2;
    break;
  case RL78::SUBC_r_esmemRpr:
    // SUBC A, ES:[HL+C] ;11 61 B2
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x1161B0 : 0x1161B2;
    break;
  case RL78::AND_r_esmemRpr:
    // AND A, ES:[HL+C] ;11 61 D2
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x1161D0 : 0x1161D2;
    break;
  case RL78::OR_r_esmemRpr:
    // OR A, ES:[HL+C] ;11 61 E2
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x1161E0 : 0x1161E2;
    break;
  case RL78::XOR_r_esmemRpr:
    // XOR A, ES:[HL+C] ;11 61 F2
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(4).getReg() == RL78::R3) ? 0x1161F0 : 0x1161F2;
    break;
  case RL78::CMP_r_esmemRpr:
    // CMP A, ES:[HL+C] ;11 61 C
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits = (MI.getOperand(3).getReg() == RL78::R3) ? 0x1161C0 : 0x1161C2;
    break;
  case RL78::CMP0_r:
    // CMP0 r                DX (X..B -> 0..3)
    RL78ReportError(MI.getOperand(0).getReg() < RL78::R4,
                    "Instruction using illegal register.");
    Bits |= (MI.getOperand(0).getReg() - RL78::R0);
    break;
  case RL78::CMP0_saddr: {
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= (addr & 0xFF);
    break;
  }
  case RL78::CMP0_abs16: {

    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CMPS_r_memri:
    // CMPS X, [HL+byte]     61 DE adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 2, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::ADDW_rp_imm:
  case RL78::SUBW_rp_imm: {
    // SUBW AX, #word        24 datal datah
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
    Bits |= ((addressValue & 0xFF00) >> 8) | ((addressValue & 0xFF) << 8);
    break;
  }
  case RL78::ADDW_rp_rp:
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    // ADDW  AX, AX          01
    // ADDW  AX, BC          03
    // ADDW  AX, DE          05
    // ADDW  AX, HL          07
    Bits += (MI.getOperand(2).getReg() - RL78::RP0) * 2;
    break;
  case RL78::SUBW_rp_rp:
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    // SUBW AX, BC           23
    // SUBW AX, DE           25
    // SUBW AX, HL           27
    Bits += (MI.getOperand(2).getReg() - RL78::RP2) * 2;
    break;
  case RL78::ADDW_rp_abs16:
  case RL78::SUBW_rp_abs16: {
    // ADDW  AX, !addr16     02 adrl adrh
    // SUBW  AX, !addr16     22 adrl adrh
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    // getTargetOpValue(MI, 1, 1, Fixups, STI);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::LowCMPW_rp_abs16: {
    // sknz
    // CMPW  AX, !addr16     42 adrl adrh
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CMPW_rp_abs16: {
    // CMPW  AX, !addr16     42 adrl adrh
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::ADDW_rp_saddr:
  case RL78::SUBW_rp_saddr: {
    // ADDW  AX, saddrp      06 saddr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(
        MI, 2, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8UW_SAD);
    Bits |= (addr & 0xFF);
    break;
  }
  case RL78::LowCMPW_rp_saddr: {
      RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
      unsigned int addr = getTargetOpValue(
        MI, 1, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8UW_SAD);
      Bits |= (addr & 0xFF);
      break;
  }
  case RL78::CMPW_rp_saddr: {
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8UW_SAD);
    Bits |= (addr & 0xFF);
    break;
  }

  case RL78::ADDW_rp_esaddr16:
  case RL78::SUBW_rp_esaddr16: {
    // ADDW AX, ES:!addr16 ;11 02 adrl adrh
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 3, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CMPW_rp_esaddr16: {
    // ADDW AX, ES:!addr16 ;11 02 adrl adrh
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::ADDW_rp_esmemHLi: {
    // ADDW AX, ES:[HL+byte] ;11 61 09 adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(MI, 4, 3, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR8U);
    Bits |= (addr & 0xFF);
    break;
  }
  case RL78::SUBW_rp_esmemHLi: {
    // SUBW AX, ES:[HL+byte]
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(MI, 4, 3, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR8U);
    Bits |= (addr & 0xFF);
    break;
  }
  case RL78::CMPW_rp_esmemHLi: {
    // CMPW AX, ES:[HL+byte] ;11 61 49 adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(MI, 3, 3, Fixups, STI,
                                         (MCFixupKind)RL78::fixup_RL78_DIR8U);
    Bits |= (addr & 0xFF);
    break;
  }
  case RL78::LowCMPW_rp_rp:
       // sknz 61 F8
  case RL78::CMPW_rp_rp:
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() != RL78::RP0,
                    "Instruction using illegal register.");
    // CMPW AX, BC           43
    // CMPW AX, DE           45
    // CMPW AX, HL           47
    Bits += (MI.getOperand(1).getReg() - RL78::RP2) * 2;
    break;
  case RL78::CMPW_rp_imm: {
    // CMPW AX, #word ;44 datal datah

    // Bits |= ((MI.getOperand(1).getImm() & 0xFF00) >> 8) |
    //        ((MI.getOperand(1).getImm() & 0xFF) << 8);
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::ADDW_rp_memri:
  case RL78::SUBW_rp_memri:
    // ADDW  AX, [HL+byte]   61 09 adr
    // SUBW AX, [HL+byte]    61 29 adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 3, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::LowCMPW_rp_memri:
    // sknz
    // CMPW AX, [HL+byte]  61 49 adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 2, 4, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::CMPW_rp_memri:
    // CMPW AX, [HL+byte]  61 49 adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 2, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::INC_abs16:
  case RL78::DEC_abs16: {
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::INCW_abs16:
  case RL78::DECW_abs16: {
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16UW_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::INC_esaddr16:
  case RL78::DEC_esaddr16: {
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::INCW_esaddr16:
  case RL78::DECW_esaddr16: {
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20UW_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }

  case RL78::INC_memri:
  case RL78::DEC_memri:
  case RL78::INCW_memri:
  case RL78::DECW_memri:
    // INC [HL+byte]     61 59 adr
    // DEC [HL+byte]     61 69 adr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::INC_esmemHLi:
  case RL78::DEC_esmemHLi:
  case RL78::INCW_esmemHLi:
  case RL78::DECW_esmemHLi:
    // INC ES:[HL+byte] ;11 61 59 adr
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= getTargetOpValue(MI, 2, 3, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::INCW_rp:
  case RL78::DECW_rp:
    // INCW AX           A1
    // INCW BC           A3
    // INCW DE           A5
    // INCW HL           A7
    // DECW AX           B1
    // DECW BC           B3
    // DECW DE           B5
    // DECW HL           B7
    Bits += (MI.getOperand(0).getReg() - RL78::RP0) * 2;
    break;
  case RL78::SHR_r_i:
  case RL78::SAR_r_i:
    // SHR A, X          31 XA (X -> 1..7)
    // SAR A, X          31 XB (X -> 1..7)
    // Bits +=  getTargetOpValue(MI, 2, 3, Fixups, STI,
    // (MCFixupKind)RL78::fixup_RL78_DIR3U) & 0xFF << 4; //TODO??
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(2).getImm() << 4;
    break;
  case RL78::SHL_r_imm:
    // SHL A, X          31 X9 (X -> 1..7)
    // SHL B, X          31 X8 (X -> 1..7)
    // SHL C, X          31 X7 (X -> 1..7)
    RL78ReportError(MI.getOperand(0).getReg() >= RL78::R1 &&
                        MI.getOperand(0).getReg() <= RL78::R3,
                    "Instruction using illegal register.");
    Bits += (MI.getOperand(2).getImm() - 1) << 4;
    // Second byte: A -> x9, B -> x8, C -> x7.
    if (MI.getOperand(0).getReg() == RL78::R2) {
      Bits -= 2;
    } else if (MI.getOperand(0).getReg() == RL78::R3) {
      Bits -= 1;
    }
    break;
  case RL78::SHLW_rp_imm:
    // SHLW AX, X        31 XD (X -> 1..15)
    // SHLW BC, X        31 XC (X -> 1..15)
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0 ||
                        MI.getOperand(1).getReg() == RL78::RP2,
                    "Instruction using illegal register.");
    Bits += (MI.getOperand(2).getImm() - 1) << 4;
    if (MI.getOperand(0).getReg() == RL78::RP2)
      --Bits;
    break;
  case RL78::SHRW_rp_i:
  case RL78::SARW_rp_i:
    // SHRW AX, 1        31 1E
    // SHRW AX, 2        31 2E
    // SHRW AX, 3        31 3E
    // SHRW AX, 4        31 4E
    // SHRW AX, 5        31 5E
    // SHRW AX, 6        31 6E
    // SHRW AX, 7        31 7E
    // SHRW AX, 8        31 8E
    // SHRW AX, 9        31 9E
    // SHRW AX, 10       31 AE
    // SHRW AX, 11       31 BE
    // SHRW AX, 12       31 CE
    // SHRW AX, 13       31 DE
    // SHRW AX, 14       31 EE
    // SHRW AX, 15       31 FE
    // SARW AX, 1        31 1F
    // SARW AX, 2        31 2F
    // SARW AX, 3        31 3F
    // SARW AX, 4        31 4F
    // SARW AX, 5        31 5F
    // SARW AX, 6        31 6F
    // SARW AX, 7        31 7F
    // SARW AX, 8        31 8F
    // SARW AX, 9        31 9F
    // SARW AX, 10       31 AF
    // SARW AX, 11       31 BF
    // SARW AX, 12       31 CF
    // SARW AX, 13       31 DF
    // SARW AX, 14       31 EF
    // SARW AX, 15       31 FF
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    Bits += (MI.getOperand(2).getImm() - 1) << 4;
    break;
  case RL78::ROLWC_rp_1:
    // ROLWC AX, 1       61 EE
    // ROLWC BC, 1       61 FE
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP0 ||
                        MI.getOperand(1).getReg() == RL78::RP2,
                    "Instruction using illegal register.");
    if (MI.getOperand(0).getReg() == RL78::RP2)
      Bits += 0x10;
    break;
  case RL78::ROR_r_1:
  case RL78::ROL_r_1:
  case RL78::RORC_r_1:
  case RL78::ROLC_r_1:
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    break;
  case RL78::MOV1_r_cy:
    // MOV1 A.X, CY          71 X9 (X -> 0..7 -> 8..F)
    encodeBitManip1RInstruction(MI, Bits, 0x7189, 2);
    break;
  case RL78::SET1_A:
    // SET1 A.X              71 Xa (X -> 0..7 -> 8..F)
    encodeBitManip1RInstruction(MI, Bits, 0x718A, 2);
    break;
  case RL78::CLR1_A:
    // CLR1 A.X              71 XB (X -> 0..7 -> 8..F)
    encodeBitManip1RInstruction(MI, Bits, 0x718B, 2);
    break;
  case RL78::AND1_cy_A:
  case RL78::AND1_cy_r:
    // AND1 CY, A.X          71 XD (X -> 0..7 -> 8..F)
    // AND1 CY, saddr.X      71 X5 saddr (X -> 0..7)
    encodeBitManip1RInstruction(MI, Bits, 0x718D, 1);
    break;
  case RL78::OR1_cy_A:
  case RL78::OR1_cy_r:
    // OR1 CY, A.X           71 XE (X -> 0..7 -> 8..F)
    // OR1  CY, saddr.X      71 X6 saddr (X -> 0..7)
    encodeBitManip1RInstruction(MI, Bits, 0x718E, 1);
    break;
  case RL78::XOR1_cy_A:
  case RL78::XOR1_cy_r:
    // XOR1 CY, A.X        71 XF (X -> 0..7 -> 8..F)
    // XOR1 CY, saddr.X    71 X7 saddr (X -> 0..7)
    encodeBitManip1RInstruction(MI, Bits, 0x718F, 1);
    break;
  case RL78::MOV1_cy_r:
    // MOV1 CY, A.X          71 XC (X -> 0..7 -> 8..F)
    encodeBitManip1RInstruction(MI, Bits, 0x718C, 1);
    break;
  case RL78::AND1_cy_saddrx:
  case RL78::OR1_cy_saddrx:
  case RL78::XOR1_cy_saddrx:
  case RL78::MOV1_cy_saddr: {
    // MOV1 CY, saddr.X      71 X4 saddr (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::MOV1_saddr_cy: {
    // MOV1 saddr.X, CY      71 X1 saddr (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::MOV1_sfr_cy: {
    // MOV1 sfr.x. CY  71 x9 sfr   (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::MOV1_sfrReg_cy: {
    // MOV1 sfr.x. CY  71 x9 sfr   (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    Bits |= sfrRegisterToSfraddr[MI.getOperand(0).getReg()] & 0xFF;
    break;
  }
  case RL78::AND1_cy_sfr:
  case RL78::OR1_cy_sfr:
  case RL78::XOR1_cy_sfr: {
    // XOR1 CY, sfr.X    71 0F sfr (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::AND1_cy_sfrReg:
  case RL78::OR1_cy_sfrReg:
  case RL78::XOR1_cy_sfrReg: {
    // XOR1 CY, sfr.X    71 0F sfr (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    Bits |= sfrRegisterToSfraddr[MI.getOperand(0).getReg()] & 0xFF;
    break;
  }
  case RL78::MOV1_cy_sfr: {
    // MOV1 CY, sfr.x ;71 xC sfr   (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::MOV1_cy_sfrReg: {
    // MOV1 CY, sfr.x ;71 xC sfr   (X -> 0..7)
    Bits |= (MI.getOperand(2).getImm() & 0xF) << 12;
    Bits |= sfrRegisterToSfraddr[MI.getOperand(1).getReg()] & 0xFF;
    break;
  }
  case RL78::MOV1_psw_cy:
  case RL78::MOV1_cy_psw:
    // MOV1 PSW.X, CY		71 X9 FA (X -> 0..7)
    // MOV1 CY, PSW.0		71 XC FA (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    break;

  case RL78::XOR1_cy_PSW:
  case RL78::OR1_cy_PSW:
  case RL78::AND1_cy_PSW:
    // AND1 CY, PSW.0         ;71 0D FA  (X -> 0..7 -> 8..F)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    break;
  case RL78::SET1_PSW:
  case RL78::CLR1_PSW:
    Bits |= (MI.getOperand(2).getImm() & 0xF) << 12;
    break;
  case RL78::SET1_abs16:
  case RL78::CLR1_abs16: {
    // SET1 !addr16.X        71 X0 adrl adrh (X -> 0..7)
    // CLR1 !addr16.X        71 X8 adrl adrh (X -> 0..7)
    Bits += MI.getOperand(1).getImm() << 20;
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U_RAM);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::MOV1_cy_memr:
  case RL78::AND1_cy_memr:
  case RL78::OR1_cy_memr:
  case RL78::XOR1_cy_memr:
    // MOV1 CY, [HL].X       71 X4 (X -> 0..7 -> 8..F)
    // AND1 CY, [HL].X       71 X5 (X -> 0..7 -> 8..F)
    // OR1 CY, [HL].X        71 X6 (X -> 0..7 -> 8..F)
    // XOR1 CY, [HL].X       71 X7 (X -> 0..7 -> 8..F)
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(1).getImm() << 4;
    break;
  case RL78::SET1_memr:
  case RL78::CLR1_memr:
    // SET1 [HL].X           71 X2 (X -> 0..7 -> 8..F)
    // CLR1 [HL].X           71 X3 (X -> 0..7 -> 8..F)
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(1).getImm() << 4;
    break;
  case RL78::MOV1_memr_cy:
    // MOV1 [HL].X, CY       71 X1 (X -> 0..7 -> 8..F)
    RL78ReportError(MI.getOperand(0).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(1).getImm() << 4;
    break;
  case RL78::MOV1_cy_esmemr:
    // MOV1 CY, ES:[HL].0    ;11 71 84
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(3).getImm() << 4;
    break;
  case RL78::MOV1_esmemr_cy:
    // MOV1 ES:[HL].0, CY    ;11 71 81
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(2).getImm() << 4;
    break;
  case RL78::AND1_esmemr:
  case RL78::OR1_esmemr:
  case RL78::XOR1_esmemr:
    // AND1 CY, ES:[HL].0       ;11 71 85
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(3).getImm() << 4;
    break;
  case RL78::SET1_sfr:
  case RL78::CLR1_sfr: {
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    RL78ReportError(MI.getOperand(0).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(0).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= immediateValue & 0xFF;
    break;
  }
  case RL78::SET1_saddr:
  case RL78::CLR1_saddr: {
    // SET1 saddr.X          71 X2 saddr (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::SET1_sfrReg:
  case RL78::CLR1_sfrReg: {
    // SET1 saddr.X          71 X2 saddr (X -> 0..7)
    Bits |= (MI.getOperand(1).getImm() & 0xF) << 12;
    Bits |= sfrRegisterToSfraddr[MI.getOperand(0).getReg()] & 0xFF;
    break;
  }
  case RL78::SET1_esaddr16:
  case RL78::CLR1_esaddr16: {

    // SET1 ES:!addr16.0            ;11 71 x0 adrl adrh
    Bits |= (MI.getOperand(2).getImm() & 0xF) << 20;

    unsigned int addressValue = getTargetOpValue(
        MI, 1, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U_16);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::SET1_esmemr:
  case RL78::CLR1_esmemr:
    // SET1 ES:[HL].0               ;11 71 82
    RL78ReportError(MI.getOperand(1).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits |= (MI.getOperand(2).getImm() & 0xF) << 4;
    break;
  case RL78::CALL_cs_rp:
  case RL78::CALL_rp:
    // CALL AX           61 CA
    // CALL BC           61 DA
    // CALL DE           61 EA
    // CALL HL           61 FA
    Bits += (MI.getOperand(0).getReg() - RL78::RP0) << 4;
    break;
  case RL78::CALL_rp_fp:
    Bits += (unsigned long long)(MI.getOperand(0).getReg() - RL78::RP0) << 36;
    Bits |= (getTargetOpValue(MI, 2, 4, Fixups, STI,
                              (MCFixupKind)RL78::fixup_RL78_DIR8U) &
             0xFF)
            << 8;
    break;
  case RL78::CALL_addr16:
  case RL78::CALL_sym16: {
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CALL_addr16_fp:
  case RL78::CALL_sym16_fp: {
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned long long laddr = (0x00FF & addressValue) << 8;
    unsigned long long uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr) << 32;
    Bits |= (getTargetOpValue(MI, 2, 5, Fixups, STI,
                              (MCFixupKind)RL78::fixup_RL78_DIR8U) &
             0xFF)
            << 8;
    break;
  }
  case RL78::CALL_addr20:
  case RL78::CALL_sym20: {
    // call !!$addr20
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U);
    unsigned int laddr = (0x0000FF & addressValue) << 16;
    unsigned int uaddr = (0x00FF00 & addressValue);
    unsigned int saddr = (0xFF0000 & addressValue) >> 16;
    Bits |= (uaddr | laddr | saddr);
    break;
  }
  case RL78::CALL_addr20_fp:
  case RL78::CALL_sym20_fp: {
    uint64_t addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U);
    uint64_t laddr = (0x0000FF & addressValue) << 16;
    uint64_t uaddr = (0x00FF00 & addressValue);
    uint64_t saddr = (0xFF0000 & addressValue) >> 16;
    Bits |= (uaddr | laddr | saddr) << 32;
    Bits |= (getTargetOpValue(MI, 2, 5, Fixups, STI,
                              (MCFixupKind)RL78::fixup_RL78_DIR8U) &
             0xFF)
            << 8;
    break;
  }
  case RL78::CALL_addr16rel: {
    // call $addr16
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16S_PCREL);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::CALLT_addr5: {
    // CALLT[0080h]; 61 84
    // CALLT[0082h]; 61 94
    // CALLT[008Eh]; 61 F4
    // CALLT[0090h]; 61 85
    // CALLT[009Ch]; 61 E5
    // CALLT[009Eh]; 61 F5
    // CALLT[00A0h]; 61 86
    // CALLT[00ACh]; 61 E6
    // CALLT[00AEh]; 61 F6
    // CALLT[00B0h]; 61 87
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR_CALLT);
    if (addr > 0)
      Bits = 0x6184 + ((((addr - 0x80) & 0x0F) / 2) << 4) +
             (((addr - 0x80) & 0xF0) >> 4);
    break;
  }
  case RL78::ADDW_sp_imm:
  case RL78::SUBW_sp_imm:
    // ADDW SP, #byte    10 data
    // SUBW SP, #byte    20 data
    Bits |= getTargetOpValue(MI, 2, 1, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    break;
  case RL78::B_BC:
  case RL78::B_BNC:
  case RL78::B_BZ:
  case RL78::B_BNZ:
  case RL78::B_cc:
  case RL78::B_BNH:
    // BC $addr20        DC adr
    // BNC $addr20       DE adr
    // BZ $addr20        DD adr
    // BNZ $addr20       DF adr
    if ((MI.getOperand(1).getImm() != RL78CC::RL78CC_H) &&
        (MI.getOperand(1).getImm() != RL78CC::RL78CC_NH)) {
      Size = 2;
      switch (MI.getOperand(1).getImm()) {
      case RL78CC::RL78CC_C:
        Bits = 0xDC00;
        break;
      case RL78CC::RL78CC_NC:
        Bits = 0xDE00;
        break;
      case RL78CC::RL78CC_Z:
        Bits = 0xDD00;
        break;
      case RL78CC::RL78CC_NZ:
        Bits = 0xDF00;
        break;
      }
      unsigned int addr = getTargetOpValue(
          MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
      Bits |= addr & 0xFF;

      break;
    }
    // BH $addr20        61 C3 adr (already set).
    // BNH $addr20       61 D3 adr (chaamge opcode if necesarry).
    else {
      Size = 3;
      if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NH)
        Bits = 0x61D300;
      else
        Bits = 0x61C300;
      unsigned int addr = getTargetOpValue(
          MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
      Bits |= addr & 0xFF;
    }
    break;

  case RL78::SK_cc:
    switch (MI.getOperand(1).getImm()) {
    // SKC               61 C8
    // case RL78CC::RL78CC_C:
    // SKNC              61 D8
    case RL78CC::RL78CC_NC:
      Bits = 0x61D8;
      break;
    // SKZ               61 E8
    case RL78CC::RL78CC_Z:
      Bits = 0x61E8;
      break;
    // SKNZ              61 F8
    case RL78CC::RL78CC_NZ:
      Bits = 0x61F8;
      break;
    // SKH               61 E3
    case RL78CC::RL78CC_H:
      Bits = 0x61E3;
      break;
    // SKNH              61 F3
    case RL78CC::RL78CC_NH:
      Bits = 0x61F3;
      break;
    }
    break;
  case RL78::SK_cc_nodst:
    switch (MI.getOperand(0).getImm()) {
    // SKC               61 C8
    // case RL78CC::RL78CC_C:
    // SKNC              61 D8
    case RL78CC::RL78CC_NC:
      Bits = 0x61D8;
      break;
    // SKZ               61 E8
    case RL78CC::RL78CC_Z:
      Bits = 0x61E8;
      break;
    // SKNZ              61 F8
    case RL78CC::RL78CC_NZ:
      Bits = 0x61F8;
      break;
    // SKH               61 E3
    case RL78CC::RL78CC_H:
      Bits = 0x61E3;
      break;
    // SKNH              61 F3
    case RL78CC::RL78CC_NH:
      Bits = 0x61F3;
      break;
    }
    break;
  case RL78::BR_rel8: {
    // BR $addr20    EF adr
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BR_rel16: {
    // BR $!addr20 EE adrl adrh
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16S_PCREL);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::BR_addr16: {
    // BR !addr16 ED adrl adrh
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
    break;
  }
  case RL78::BR_addr20: {
    // BR !!$addr20
    unsigned int addressValue = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR20U);
    unsigned int laddr = (0x0000FF & addressValue) << 16;
    unsigned int uaddr = (0x00FF00 & addressValue);
    unsigned int saddr = (0xFF0000 & addressValue) >> 16;
    Bits |= (uaddr | laddr | saddr);
    break;
  }
  case RL78::BTBF_A: {
    // BT A.X, $addr20           31 X3 adr (X -> 0..7)
    // BF A.X, $addr20           31 X5 adr (X -> 0..7)
    if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NZ)
      Bits += 0x200;
    Bits += MI.getOperand(3).getImm() << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTCLR_saddr: {
    // BTCLR saddr.X, $addr20    31 X0 saddr adr (X -> 0..7)
    Bits += MI.getOperand(3).getImm() << 20;
    unsigned int addr = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= (addr & 0xFF) << 8;

    addr = getTargetOpValue(MI, 0, 3, Fixups, STI,
                            (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTBF_saddr: {
    // BT saddr.X, $addr20       31 X2 saddr adr (X -> 0..7)
    // BF saddr.X, $addr20       31 X4 saddr adr (X -> 0..7)
    Bits += MI.getOperand(3).getImm() << 20;
    if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NZ)
      Bits += 0x20000;

    unsigned int addr = getTargetOpValue(
        MI, 2, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= (addr & 0xFF) << 8;
    addr = getTargetOpValue(MI, 0, 3, Fixups, STI,
                            (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTBF_PSWi_addr: {
    // BF PSW.0, $addr20 ;31 84 FA adr
    // BT PSW.0, $addr20 ;31 82 FA adr
    Bits += MI.getOperand(3).getImm() << 20;

    if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NZ)
      Bits += 0x20000;
    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTCLR_PSWi_addr: {
    // BTCLR PSW.0, $addr20 ;31 80 FA adr
    Bits += MI.getOperand(2).getImm() << 20;
    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTCLR_memr: {
    // BTCLR [HL].X, $addr20     31 X1 adr (X -> 0..7 -> 8..F)
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(3).getImm() << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTBF_memr: {

    // BT [HL].X, $addr20        31 X3 adr (X -> 0..7 -> 8..F)
    // BF [HL].X, $addr20        31 X5 adr (X -> 0..7 -> 8..F)
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NZ)
      Bits += 0x200;
    Bits += MI.getOperand(3).getImm() << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTBF_esmemr: {
    // BF ES:[HL].0, $addr20 ;11 31 85 adr
    // BT ES:[HL].0, $addr20 ;11 31 83 adr
    RL78ReportError(MI.getOperand(3).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NZ)
      Bits += 0x200;
    Bits += MI.getOperand(4).getImm() << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTCLR_esmemr: {
    // BTCLR ES:[HL].X, $addr20  11 31 X1 adr (X -> 0..7 -> 8..F)
    RL78ReportError(MI.getOperand(2).getReg() == RL78::RP6,
                    "Instruction using illegal register.");
    Bits += MI.getOperand(3).getImm() << 12;
    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTCLR_sfri_addr: {
    // BTCLR sfr.0, $addr20 ;31 80 sfr adr
    Bits += MI.getOperand(2).getImm() << 20;

    RL78ReportError(MI.getOperand(1).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(1).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= (immediateValue & 0xFF) << 8;

    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTCLR_sfrRegi_addr: {
    // BTCLR sfr.0, $addr20 ;31 80 sfr adr
    Bits += MI.getOperand(2).getImm() << 20;
    Bits |= (sfrRegisterToSfraddr[MI.getOperand(1).getReg()] & 0xFF) << 8;
    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTBF_sfri_addr: {
    // BF sfr.0, $addr20 ;31 84 sfr adr
    // BT sfr.0, $addr20 ;31 82 sfr adr
    if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NZ)
      Bits += 0x20000;
    Bits += MI.getOperand(3).getImm() << 20;

    RL78ReportError(MI.getOperand(2).isImm(),
                    "sfr operand can be special register or immediate only");
    int64_t immediateValue = MI.getOperand(2).getImm() & 0xFFFF;
    RL78ReportError(immediateValue >= 0xFF00, "sfr operand not in range");
    Bits |= (immediateValue & 0xFF) << 8;

    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTBF_sfrRegi_addr: {
    // BF sfr.0, $addr20 ;31 84 sfr adr
    // BT sfr.0, $addr20 ;31 82 sfr adr
    if (MI.getOperand(1).getImm() == RL78CC::RL78CC_NZ)
      Bits += 0x20000;
    Bits += MI.getOperand(3).getImm() << 20;
    Bits |= (sfrRegisterToSfraddr[MI.getOperand(2).getReg()] & 0xFF) << 8;
    unsigned int addr = getTargetOpValue(
        MI, 0, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::BTCLR_A: {
    // BTCLR A.X, $addr20        31 X1 adr (X -> 0..7)
    Bits += MI.getOperand(4).getImm() << 12;
    unsigned int addr = getTargetOpValue(
        MI, 1, 2, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8S_PCREL);
    Bits |= addr & 0xFF;
    break;
  }
  case RL78::SEL:
    // SEL RB0           61 CF
    // SEL RB1           61 DF
    // SEL RB2           61 EF
    // SEL RB3           61 FF
    Bits += MI.getOperand(0).getImm() << 4;
    break;
  case RL78::PUSH_rp:
  case RL78::POP_rp:
    // PUSH AX           C1
    // PUSH BC           C3
    // PUSH DE           C5
    // PUSH HL           C7
    // POP AX            C0
    // POP BC            C2
    // POP DE            C4
    // POP HL            C6
    Bits += (MI.getOperand(0).getReg() - RL78::RP0) * 2;
    break;
  case RL78::ADD_r_saddr:
  case RL78::ADDC_r_saddrabs:
  case RL78::SUB_r_saddr:
  case RL78::SUBC_r_saddr:
  case RL78::AND_r_saddr:
  case RL78::OR_r_saddr:
  case RL78::XOR_r_saddr: {
    // XOR A, saddr      7B saddr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(
        MI, 2, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= (addr & 0xFF);
    break;
  }
  case RL78::CMP_r_saddr: {
    // CMP A, saddr          4B saddr
    RL78ReportError(MI.getOperand(0).getReg() == RL78::R1,
                    "Instruction using illegal register.");
    unsigned int addr = getTargetOpValue(
        MI, 1, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= (addr & 0xFF);
    break;
  }
  case RL78::CMP_saddr_imm:
  case RL78::XOR_saddr_imm:
  case RL78::OR_saddr_imm:
  case RL78::AND_saddr_imm:
  case RL78::ADD_saddr_imm:
  case RL78::SUB_saddr_imm:
  case RL78::SUBC_saddr_imm:
  case RL78::ADDC_saddrabs_imm: {
    // ADD saddr, #byte  0A saddr data
    Bits |= getTargetOpValue(MI, 1, 2, Fixups, STI,
                             (MCFixupKind)RL78::fixup_RL78_DIR8U) &
            0xFF;
    unsigned int addr = getTargetOpValue(
        MI, 0, 1, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR8U_SAD);
    Bits |= (addr & 0xFF) << 8;
    break;
  }
  case RL78::LowCMPW_rp_imm: {
      // sknz 61 F8
      // cmpw ax, $imm16 44 datal datah
        RL78ReportError(MI.getOperand(0).getReg() == RL78::RP0,
                    "Instruction using illegal register.");
    unsigned int addressValue = getTargetOpValue(
        MI, 1, 3, Fixups, STI, (MCFixupKind)RL78::fixup_RL78_DIR16U);
    unsigned int laddr = (0x00FF & addressValue) << 8;
    unsigned int uaddr = (0xFF00 & addressValue) >> 8;
    Bits |= (uaddr | laddr);
      break;
  }
  default:
    break;
  }
  //  Although we set the endianness to big, RL78 is little endian, writing it
  //  this way
  // makes it more easily to follow the documentation Chapter "5.6 Instruction
  // Format".
  switch (Size) {
  case 1:
    support::endian::write<uint8_t>(OS, Bits, support::big);
    break;
  case 2:
    support::endian::write<uint16_t>(OS, Bits, support::big);
    break;
  case 3:
    support::endian::write<uint16_t>(OS, Bits >> 8, support::big);
    support::endian::write<uint8_t>(OS, Bits, support::big);
    break;
  case 4:
    support::endian::write<uint32_t>(OS, Bits, support::big);
    break;
  case 5:
    support::endian::write<uint32_t>(OS, Bits >> 8, support::big);
    support::endian::write<uint8_t>(OS, Bits, support::big);
    break;
  case 6:
    support::endian::write<uint16_t>(OS, Bits >> 32, support::big);
    support::endian::write<uint32_t>(OS, Bits, support::big);
    break;
  case 7:
    support::endian::write<uint16_t>(OS, Bits >> 40, support::big);
    support::endian::write<uint8_t>(OS, Bits >> 32, support::big);
    support::endian::write<uint32_t>(OS, Bits, support::big);
    break;
  case 8:
    support::endian::write<uint32_t>(OS, Bits >> 32, support::big);
    support::endian::write<uint32_t>(OS, Bits, support::big);
    break;
  default:
    llvm_unreachable("Invalid instruction size!");
  }

  ++MCNumEmitted; // Keep track of the # of mi's emitted.
}

unsigned
RL78MCCodeEmitter::getMachineOpValue(const MCInst &MI, const MCOperand &MO,
                                     SmallVectorImpl<MCFixup> &Fixups,
                                     const MCSubtargetInfo &STI) const {
  if (MO.isReg())
    return Ctx.getRegisterInfo()->getEncodingValue(MO.getReg());

  if (MO.isImm())
    return MO.getImm();

  llvm_unreachable("Unhandled expression!");
  return 0;
}

unsigned RL78MCCodeEmitter::getTargetOpValue(const MCInst &MI, unsigned OpNo,
                                             uint32_t offset,
                                             SmallVectorImpl<MCFixup> &Fixups,
                                             const MCSubtargetInfo &STI,
                                             enum MCFixupKind fixup1) const {
  const MCOperand &MO = MI.getOperand(OpNo);
  if (MO.isImm()) {
    int64_t immediateValue = MO.getImm();
    switch (static_cast<RL78::Fixups>(fixup1)) {
    case RL78::fixup_RL78_DIR8S_PCREL:
      RL78ReportError(immediateValue >= -128 && immediateValue <= 127,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR16S_PCREL:
      RL78ReportError(immediateValue >= -32768 && immediateValue <= 32767,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR3U:
      RL78ReportError(immediateValue >= 0x0 && immediateValue <= 0x7,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR8U:
      RL78ReportError(immediateValue >= -128 && immediateValue <= 255,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR8U_SAD:
      RL78ReportError(immediateValue >= 0xFFE20 && immediateValue <= 0XFFF1F,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR8UW_SAD:
      RL78ReportError(immediateValue >= 0xFFE20 && immediateValue <= 0xFFFFF &&
                          immediateValue % 2 == 0,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR16U:
      RL78ReportError(immediateValue >= -32768 && immediateValue <= 65536,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR16U_RAM:
    case RL78::fixup_RL78_DIR16UW_RAM:
      RL78ReportError(immediateValue >= -65536 && immediateValue <= 0xFFFFF,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR20U:
      RL78ReportError(immediateValue >= 0x00000 && immediateValue <= 0xFFFFF,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR20U_16:
    case RL78::fixup_RL78_DIR20UW_16:
      RL78ReportError(immediateValue >= -32768 && immediateValue <= 65536,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR32U:
      RL78ReportError(immediateValue >= INT32_MIN && immediateValue <= UINT32_MAX,
                      "Instruction using illegal operand");
      break;
    case RL78::fixup_RL78_DIR_CALLT:
      RL78ReportError(immediateValue >= 0x80 && immediateValue <= 0xBF &&
                          immediateValue % 2 == 0,
                      "Instruction using illegal operand");
      break;
    default:
      break;
    }
  }

  if (MO.isReg() || MO.isImm())
    return getMachineOpValue(MI, MO, Fixups, STI);

  unsigned valueSize;
  // Deduce the expected expression's result value size
  switch (static_cast<RL78::Fixups>(fixup1))
  {
  default: 
      // The missing fixups are doing pushes/pops on the relocation "stack",
      // so they should not appear as last, value producing fixups.
      llvm_unreachable("Unhandled fixup!");
      break;
  case RL78::fixup_RL78_DIR3U:
      valueSize = 3;
      break;
  case RL78::fixup_RL78_DIR8S_PCREL:
  case RL78::fixup_RL78_DIR8U:
  case RL78::fixup_RL78_DIR8U_SAD:
  case RL78::fixup_RL78_DIR8UW_SAD:
  case RL78::fixup_RL78_ABS8U:
  case RL78::fixup_RL78_DIR_CALLT:
      valueSize = 8;
      break;
  case RL78::fixup_RL78_DIR16S_PCREL:
  case RL78::fixup_RL78_DIR16U:
  case RL78::fixup_RL78_DIR16U_RAM:
  case RL78::fixup_RL78_DIR16UW_RAM:
  case RL78::fixup_RL78_DIR20U_16:
  case RL78::fixup_RL78_DIR20UW_16:
  case RL78::fixup_RL78_ABS16U:
  case RL78::fixup_RL78_ABS16UW:
      valueSize = 16;
      break;
  case RL78::fixup_RL78_DIR20U:
      valueSize = 24;
      break;
  case RL78::fixup_RL78_ABS32U:
  case RL78::fixup_RL78_DIR32U:
      valueSize = 32;
      break;
  }


  if (MO.isExpr() && fixup1 != RL78::fixup_RL78_DIR_CALLT) {
    RL78MCExpr::createFixupsForExpression(MO.getExpr(), offset, valueSize,
                                          Fixups, true, fixup1, Ctx, MO.getExpr()->getLoc());
    return 0;
  } 

  Fixups.push_back(MCFixup::create(offset, MO.getExpr(), fixup1));

  return 0;
}

MCCodeEmitter *llvm::createRL78MCCodeEmitter(const MCInstrInfo &MCII,
                                             MCContext &Ctx) {
  return new RL78MCCodeEmitter(MCII, Ctx);
}

#include "RL78GenMCCodeEmitter.inc"