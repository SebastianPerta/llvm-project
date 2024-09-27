//===- RL78Disassembler.cpp - Disassembler for RL78 -----------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is part of the RL78 Disassembler.
//
//===----------------------------------------------------------------------===//

#include "RL78Subtarget.h"
#include "TargetInfo/RL78TargetInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCDecoderOps.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/MC/TargetRegistry.h"

using namespace llvm;

#define DEBUG_TYPE "RL78-disassembler"

typedef MCDisassembler::DecodeStatus DecodeStatus;

namespace {

/// A disassembler class for RL78.
class RL78Disassembler : public MCDisassembler {
public:
  RL78Disassembler(const MCSubtargetInfo &STI, MCContext &Ctx)
      : MCDisassembler(STI, Ctx) {}
  virtual ~RL78Disassembler() {}

  DecodeStatus getInstruction(MCInst &Instr, uint64_t &Size,
                              ArrayRef<uint8_t> Bytes, uint64_t Address,
                              raw_ostream &CStream) const override;
};

class RL78Symbolizer : public MCSymbolizer {
private:
  void *DisInfo;

public:
  RL78Symbolizer(MCContext &Ctx, std::unique_ptr<MCRelocationInfo> &&RelInfo,
                 void *disInfo)
      : MCSymbolizer(Ctx, std::move(RelInfo)), DisInfo(disInfo) {}

  /*bool tryAddingSymbolicOperand(MCInst &Inst, raw_ostream &cStream,
                                int64_t Value, uint64_t Address, bool IsBranch,
                                uint64_t Offset, uint64_t InstSize) override;*/
 // This function tries to add a symbolic operand in place of the immediate
// Value in the MCInst. The immediate Value has had any PC adjustment made by
// the caller. If the instruction is a branch instruction then IsBranch is true,
// else false. If the getOpInfo() function was set as part of the
// setupForSymbolicDisassembly() call then that function is called to get any
// symbolic information at the Address for this instruction. If that returns
// non-zero then the symbolic information it returns is used to create an MCExpr
// and that is added as an operand to the MCInst. If getOpInfo() returns zero
// and IsBranch is true then a symbol look up for Value is done and if a symbol
// is found an MCExpr is created with that, else an MCExpr with Value is
// created. This function returns true if it adds an operand to the MCInst and
// false otherwise.
  bool tryAddingSymbolicOperand(MCInst &Inst, raw_ostream &cStream,
                                        int64_t Value, uint64_t Address,
                                        bool IsBranch, uint64_t Offset,
                                        uint64_t OpSize, uint64_t InstSize) override;

  void tryAddingPcLoadReferenceComment(raw_ostream &cStream, int64_t Value,
                                       uint64_t Address) override;
};

} // end anonymous namespace

static MCSymbolizer *
createRL78Symbolizer(const Triple & /*TT*/, LLVMOpInfoCallback /*GetOpInfo*/,
                     LLVMSymbolLookupCallback /*SymbolLookUp*/, void *DisInfo,
                     MCContext *Ctx,
                     std::unique_ptr<MCRelocationInfo> &&RelInfo) {
  return new RL78Symbolizer(*Ctx, std::move(RelInfo), DisInfo);
}

static MCDisassembler *createRL78Disassembler(const Target &T,
                                              const MCSubtargetInfo &STI,
                                              MCContext &Ctx) {
  return new RL78Disassembler(STI, Ctx);
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeRL78Disassembler() {
  // Register the disassembler.
  TargetRegistry::RegisterMCDisassembler(getTheRL78Target(),
                                         createRL78Disassembler);
  TargetRegistry::RegisterMCSymbolizer(getTheRL78Target(),
                                       createRL78Symbolizer);
}

#include "RL78GenDisassemblerTables.inc"

namespace llvm {

extern const MCInstrDesc RL78Insts[];

} // end namespace llvm

struct SBP {
  static const unsigned int adr = 0x101;
  static const unsigned int adrh = 0x102;
  static const unsigned int adrl = 0x103;
  static const unsigned int adrs = 0x104;
  static const unsigned int data = 0x105;
  static const unsigned int datah = 0x106;
  static const unsigned int datal = 0x107;
  static const unsigned int saddr = 0x108;
  static const unsigned int sfr = 0x109;
};

struct OPT {
  static const unsigned int ES_I_addr16 = 0x101;
  static const unsigned int ES_memDE = 0x102;
  static const unsigned int ES_memDE_byte = 0x103;
  static const unsigned int ES_memHL = 0x104;
  static const unsigned int ES_memHL0 = 0x105;
  static const unsigned int ES_memHL_B = 0x106;
  static const unsigned int ES_memHL_C = 0x107;
  static const unsigned int ES_memHL_byte = 0x108;
  static const unsigned int ES_word_memB = 0x109;
  static const unsigned int ES_word_memBC = 0x10A;
  static const unsigned int ES_word_memC = 0x10B;
  static const unsigned int II_addr20 = 0x10C;
  static const unsigned int I_addr16 = 0x10D;
  static const unsigned int RB0 = 0x10E;
  static const unsigned int RB1 = 0x10F;
  static const unsigned int RB2 = 0x110;
  static const unsigned int RB3 = 0x111;
  static const unsigned int SI_addr20 = 0x112;
  static const unsigned int S_addr20 = 0x113;
  static const unsigned int byte = 0x114;
  static const unsigned int imm0 = 0x115;
  static const unsigned int imm1 = 0x116;
  static const unsigned int imm10 = 0x117;
  static const unsigned int imm11 = 0x118;
  static const unsigned int imm12 = 0x119;
  static const unsigned int imm13 = 0x11A;
  static const unsigned int imm14 = 0x11B;
  static const unsigned int imm15 = 0x11C;
  static const unsigned int imm2 = 0x11D;
  static const unsigned int imm3 = 0x11E;
  static const unsigned int imm4 = 0x11F;
  static const unsigned int imm5 = 0x120;
  static const unsigned int imm6 = 0x121;
  static const unsigned int imm7 = 0x122;
  static const unsigned int imm8 = 0x123;
  static const unsigned int imm9 = 0x124;
  static const unsigned int memDE = 0x125;
  static const unsigned int memDE_byte = 0x126;
  static const unsigned int memHL = 0x127;
  static const unsigned int memHL0 = 0x128;
  static const unsigned int memHL_B = 0x129;
  static const unsigned int memHL_C = 0x12A;
  static const unsigned int memHL_byte = 0x12B;
  static const unsigned int memSP_byte = 0x12C;
  static const unsigned int mem_addr5 = 0x12D;
  static const unsigned int saddr = 0x12E;
  static const unsigned int saddrp = 0x12F;
  static const unsigned int sfr = 0x130;
  static const unsigned int sfrp = 0x131;
  static const unsigned int word = 0x132;
  static const unsigned int word_memB = 0x133;
  static const unsigned int word_memBC = 0x134;
  static const unsigned int word_memC = 0x135;
  static const unsigned int RL78CC_C = 0x200 + RL78CC::RL78CC_C;
  static const unsigned int RL78CC_NC = 0x200 + RL78CC::RL78CC_NC;
  static const unsigned int RL78CC_Z = 0x200 + RL78CC::RL78CC_Z;
  static const unsigned int RL78CC_NZ = 0x200 + RL78CC::RL78CC_NZ;
  static const unsigned int RL78CC_H = 0x200 + RL78CC::RL78CC_H;
  static const unsigned int RL78CC_NH = 0x200 + RL78CC::RL78CC_NH;
};

static std::map<unsigned char, unsigned int> saddrLookup = {
    {0xF8, RL78::R0},  {0xF9, RL78::R1},  {0xFA, RL78::R2},  {0xFB, RL78::R3},
    {0xFC, RL78::R4},  {0xFD, RL78::R5},  {0xFE, RL78::R6},  {0xFF, RL78::R7}};

static std::map<unsigned char, unsigned int> saddrpLookup = {
    {0xF8, RL78::RP0},  {0xFA, RL78::RP2},  {0xFC, RL78::RP4},
    {0xFE, RL78::RP6}};

struct InstructionInfo {
  int OpCode;
  std::vector<unsigned int> BitParts;
  std::vector<unsigned int> Operands;
};

// static std::multimap<char, InstructionInfo> instructions =
static std::multimap<unsigned int, InstructionInfo> instructionsS3 = {
    // DIVHU
    {0xCEU, {RL78::DIVHU, {0xFBU, 0x3U}, {}}},
    // DIVWU
    {0xCEU, {RL78::DIVWU, {0xFBU, 0x0BU}, {}}},
    // MACH
    {0xCEU, {RL78::MACH, {0xFBU, 0x6U}, {}}},
    // MACHU
    {0xCEU, {RL78::MACHU, {0xFBU, 0x5U}, {}}},
    // MULH
    {0xCEU, {RL78::MULH, {0xFBU, 0x2U}, {}}},
    // MULHU
    {0xCEU, {RL78::MULHU, {0xFBU, 0x1U}, {}}}};
// static std::multimap<char, InstructionInfo> instructions =
static std::multimap<unsigned int, InstructionInfo> instructions = {
    // clang-format off
    // ADD A,!addr16
    {0x0FU, {RL78::ADD_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // ADD saddr,#byte
    {0x0AU, {RL78::ADD_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // ADD A,#byte
    {0x0CU, {RL78::ADD_r_imm, {SBP::data}, {RL78::R1, RL78::R1, OPT::byte}}},
    // ADD A,[HL]
    {0x0DU, {RL78::ADD_r_memri, {}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // ADD A,[HL+byte]
    {0x0EU, {RL78::ADD_r_memri, {SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // ADD A,[HL+B]
    {0x61U, {RL78::ADD_r_memrr, {0x80U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // ADD A,[HL+C]
    {0x61U, {RL78::ADD_r_memrr, {0x82U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // ADD A,A
    {0x61U, {RL78::ADD_r_r, {0x1U}, {RL78::R1, RL78::R1, RL78::R1}}},
    // ADD A,B
    {0x61U, {RL78::ADD_r_r, {0x0BU}, {RL78::R1, RL78::R1, RL78::R3}}},
    // ADD A,C
    {0x61U, {RL78::ADD_r_r, {0x0AU}, {RL78::R1, RL78::R1, RL78::R2}}},
    // ADD A,D
    {0x61U, {RL78::ADD_r_r, {0x0DU}, {RL78::R1, RL78::R1, RL78::R5}}},
    // ADD A,E
    {0x61U, {RL78::ADD_r_r, {0x0CU}, {RL78::R1, RL78::R1, RL78::R4}}},
    // ADD A,H
    {0x61U, {RL78::ADD_r_r, {0x0FU}, {RL78::R1, RL78::R1, RL78::R7}}},
    // ADD A,L
    {0x61U, {RL78::ADD_r_r, {0x0EU}, {RL78::R1, RL78::R1, RL78::R6}}},
    // ADD A,X
    {0x61U, {RL78::ADD_r_r, {0x8U}, {RL78::R1, RL78::R1, RL78::R0}}},
    // ADD B,A
    {0x61U, {RL78::ADD_r_r, {0x3U}, {RL78::R3, RL78::R3, RL78::R1}}},
    // ADD C,A
    {0x61U, {RL78::ADD_r_r, {0x2U}, {RL78::R2, RL78::R2, RL78::R1}}},
    // ADD D,A
    {0x61U, {RL78::ADD_r_r, {0x5U}, {RL78::R5, RL78::R5, RL78::R1}}},
    // ADD E,A
    {0x61U, {RL78::ADD_r_r, {0x4U}, {RL78::R4, RL78::R4, RL78::R1}}},
    // ADD H,A
    {0x61U, {RL78::ADD_r_r, {0x7U}, {RL78::R7, RL78::R7, RL78::R1}}},
    // ADD L,A
    {0x61U, {RL78::ADD_r_r, {0x6U}, {RL78::R6, RL78::R6, RL78::R1}}},
    // ADD X,A
    {0x61U, {RL78::ADD_r_r, {0x0U}, {RL78::R0, RL78::R0, RL78::R1}}},
    // ADD A,saddr
    {0x0BU, {RL78::ADD_r_saddr, {SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // ADD A,ES:!addr16
    {0x11U, {RL78::ADD_r_esaddr16, {0x0FU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // ADD A,ES:[HL]
    {0x11U, {RL78::ADD_r_esmemHL, {0x0DU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // ADD A,ES:[HL+B]
    {0x11U, {RL78::ADD_r_esmemRpr, {0x61U, 0x80U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // ADD A,ES:[HL+byte]
    {0x11U, {RL78::ADD_r_esmemHLi, {0x0EU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // ADD A,ES:[HL+C]
    {0x11U, {RL78::ADD_r_esmemRpr, {0x61U, 0x82U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // ADDC A,!addr16
    {0x1FU, {RL78::ADDC_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // ADDC saddr,#byte
    {0x1AU, {RL78::ADDC_saddrabs_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // ADDC A,#byte
    {0x1CU, {RL78::ADDC_A_imm, {SBP::data}, {RL78::R1, RL78::R1, OPT::byte}}},
    // ADDC A,[HL]
    {0x1DU, {RL78::ADDC_r_memri, {}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // ADDC A,[HL+byte]
    {0x1EU, {RL78::ADDC_r_memri, {SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // ADDC A,[HL+B]
    {0x61U, {RL78::ADDC_r_memrr, {0x90U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // ADDC A,[HL+C]
    {0x61U, {RL78::ADDC_r_memrr, {0x92U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // ADDC A,A
    {0x61U, {RL78::ADDC_r_r, {0x11U}, {RL78::R1, RL78::R1, RL78::R1}}},
    // ADDC A,B
    {0x61U, {RL78::ADDC_r_r, {0x1BU}, {RL78::R1, RL78::R1, RL78::R3}}},
    // ADDC A,C
    {0x61U, {RL78::ADDC_r_r, {0x1AU}, {RL78::R1, RL78::R1, RL78::R2}}},
    // ADDC A,D
    {0x61U, {RL78::ADDC_r_r, {0x1DU}, {RL78::R1, RL78::R1, RL78::R5}}},
    // ADDC A,E
    {0x61U, {RL78::ADDC_r_r, {0x1CU}, {RL78::R1, RL78::R1, RL78::R4}}},
    // ADDC A,H
    {0x61U, {RL78::ADDC_r_r, {0x1FU}, {RL78::R1, RL78::R1, RL78::R7}}},
    // ADDC A,L
    {0x61U, {RL78::ADDC_r_r, {0x1EU}, {RL78::R1, RL78::R1, RL78::R6}}},
    // ADDC A,X
    {0x61U, {RL78::ADDC_r_r, {0x18U}, {RL78::R1, RL78::R1, RL78::R0}}},
    // ADDC B,A
    {0x61U, {RL78::ADDC_r_r, {0x13U}, {RL78::R3, RL78::R3, RL78::R1}}},
    // ADDC C,A
    {0x61U, {RL78::ADDC_r_r, {0x12U}, {RL78::R2, RL78::R2, RL78::R1}}},
    // ADDC D,A
    {0x61U, {RL78::ADDC_r_r, {0x15U}, {RL78::R5, RL78::R5, RL78::R1}}},
    // ADDC E,A
    {0x61U, {RL78::ADDC_r_r, {0x14U}, {RL78::R4, RL78::R4, RL78::R1}}},
    // ADDC H,A
    {0x61U, {RL78::ADDC_r_r, {0x17U}, {RL78::R7, RL78::R7, RL78::R1}}},
    // ADDC L,A
    {0x61U, {RL78::ADDC_r_r, {0x16U}, {RL78::R6, RL78::R6, RL78::R1}}},
    // ADDC X,A
    {0x61U, {RL78::ADDC_r_r, {0x10U}, {RL78::R0, RL78::R0, RL78::R1}}},
    // ADDC A,saddr
    {0x1BU, {RL78::ADDC_r_saddrabs, {SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // ADDC A,ES:!addr16
    {0x11U, {RL78::ADDC_r_esaddr16, {0x1FU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // ADDC A,ES:[HL]
    {0x11U, {RL78::ADDC_r_esmemHL, {0x1DU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // ADDC A,ES:[HL+B]
    {0x11U, {RL78::ADDC_r_esmemRpr, {0x61U, 0x90U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // ADDC A,ES:[HL+byte]
    {0x11U, {RL78::ADDC_r_esmemHLi, {0x1EU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // ADDC A,ES:[HL+C]
    {0x11U, {RL78::ADDC_r_esmemRpr, {0x61U, 0x92U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // ADDW AX,#word
    {0x4U, {RL78::ADDW_rp_imm, {SBP::datal, SBP::datah}, {RL78::RP0, RL78::RP0, OPT::word}}},
    // ADDW AX,!addr16
    {0x2U, {RL78::ADDW_rp_abs16, {SBP::adrl, SBP::adrh}, {RL78::RP0, RL78::RP0, OPT::I_addr16}}},
    // ADDW AX,[HL+byte]
    {0x61U, {RL78::ADDW_rp_memri, {0x9U, SBP::adr}, {RL78::RP0, RL78::RP0, OPT::memHL_byte}}},
    // ADDW AX,AX
    {0x1U, {RL78::ADDW_rp_rp, {}, {RL78::RP0, RL78::RP0, RL78::RP0}}},
    // ADDW AX,BC
    {0x3U, {RL78::ADDW_rp_rp, {}, {RL78::RP0, RL78::RP0, RL78::RP2}}},
    // ADDW AX,DE
    {0x5U, {RL78::ADDW_rp_rp, {}, {RL78::RP0, RL78::RP0, RL78::RP4}}},
    // ADDW AX,saddrp
    {0x6U, {RL78::ADDW_rp_saddr, {SBP::saddr}, {RL78::RP0, RL78::RP0, OPT::saddrp}}},
    // ADDW AX,HL
    {0x7U, {RL78::ADDW_rp_rp, {}, {RL78::RP0, RL78::RP0, RL78::RP6}}},
    // ADDW SP,#byte
    {0x10U, {RL78::ADDW_sp_imm, {SBP::data}, {RL78::SPreg, RL78::SPreg, OPT::byte}}},
    // ADDW AX,ES:!addr16
    {0x11U, {RL78::ADDW_rp_esaddr16, {0x2U, SBP::adrl, SBP::adrh}, {RL78::RP0,RL78::RP0,OPT::ES_I_addr16}}},
    // ADDW AX,ES:[HL+byte]
    {0x11U, {RL78::ADDW_rp_esmemHLi, {0x61U, 0x9U, SBP::adr}, {RL78::RP0,RL78::RP0,OPT::ES_memHL_byte}}},
    // AND A,!addr16
    {0x5FU, {RL78::AND_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // AND saddr,#byte
    {0x5AU, {RL78::AND_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // AND A,#byte
    {0x5CU, {RL78::AND_r_imm, {SBP::data}, {RL78::R1, RL78::R1, OPT::byte}}},
    // AND A,[HL]
    {0x5DU, {RL78::AND_r_memri, {}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // AND A,[HL+byte]
    {0x5EU, {RL78::AND_r_memri, {SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // AND A,[HL+B]
    {0x61U, {RL78::AND_r_memrr, {0xD0U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // AND A,[HL+C]
    {0x61U, {RL78::AND_r_memrr, {0xD2U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // AND A,A
    {0x61U, {RL78::AND_r_r, {0x51U}, {RL78::R1, RL78::R1, RL78::R1}}},
    // AND A,B
    {0x61U, {RL78::AND_r_r, {0x5BU}, {RL78::R1, RL78::R1, RL78::R3}}},
    // AND A,C
    {0x61U, {RL78::AND_r_r, {0x5AU}, {RL78::R1, RL78::R1, RL78::R2}}},
    // AND A,D
    {0x61U, {RL78::AND_r_r, {0x5DU}, {RL78::R1, RL78::R1, RL78::R5}}},
    // AND A,E
    {0x61U, {RL78::AND_r_r, {0x5CU}, {RL78::R1, RL78::R1, RL78::R4}}},
    // AND A,H
    {0x61U, {RL78::AND_r_r, {0x5FU}, {RL78::R1, RL78::R1, RL78::R7}}},
    // AND A,L
    {0x61U, {RL78::AND_r_r, {0x5EU}, {RL78::R1, RL78::R1, RL78::R6}}},
    // AND A,X
    {0x61U, {RL78::AND_r_r, {0x58U}, {RL78::R1, RL78::R1, RL78::R0}}},
    // AND B,A
    {0x61U, {RL78::AND_r_r, {0x53U}, {RL78::R3, RL78::R3, RL78::R1}}},
    // AND C,A
    {0x61U, {RL78::AND_r_r, {0x52U}, {RL78::R2, RL78::R2, RL78::R1}}},
    // AND D,A
    {0x61U, {RL78::AND_r_r, {0x55U}, {RL78::R5, RL78::R5, RL78::R1}}},
    // AND E,A
    {0x61U, {RL78::AND_r_r, {0x54U}, {RL78::R4, RL78::R4, RL78::R1}}},
    // AND H,A
    {0x61U, {RL78::AND_r_r, {0x57U}, {RL78::R7, RL78::R7, RL78::R1}}},
    // AND L,A
    {0x61U, {RL78::AND_r_r, {0x56U}, {RL78::R6, RL78::R6, RL78::R1}}},
    // AND X,A
    {0x61U, {RL78::AND_r_r, {0x50U}, {RL78::R0, RL78::R0, RL78::R1}}},
    // AND A,saddr
    {0x5BU, {RL78::AND_r_saddr, {SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // AND A,ES:!addr16
    {0x11U, {RL78::AND_r_esaddr16, {0x5FU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // AND A,ES:[HL]
    {0x11U, {RL78::AND_r_esmemHL, {0x5DU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // AND A,ES:[HL+B]
    {0x11U, {RL78::AND_r_esmemRpr, {0x61U, 0xD0U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // AND A,ES:[HL+byte]
    {0x11U, {RL78::AND_r_esmemHLi, {0x5EU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // AND A,ES:[HL+C]
    {0x11U, {RL78::AND_r_esmemRpr, {0x61U, 0xD2U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // AND1 CY,[HL].0
    {0x71U, {RL78::AND1_cy_memr, {0x85U}, {OPT::memHL, OPT::imm0}}},
    // AND1 CY,[HL].1
    {0x71U, {RL78::AND1_cy_memr, {0x95U}, {OPT::memHL, OPT::imm1}}},
    // AND1 CY,[HL].2
    {0x71U, {RL78::AND1_cy_memr, {0xA5U}, {OPT::memHL, OPT::imm2}}},
    // AND1 CY,[HL].3
    {0x71U, {RL78::AND1_cy_memr, {0xB5U}, {OPT::memHL, OPT::imm3}}},
    // AND1 CY,[HL].4
    {0x71U, {RL78::AND1_cy_memr, {0xC5U}, {OPT::memHL, OPT::imm4}}},
    // AND1 CY,[HL].5
    {0x71U, {RL78::AND1_cy_memr, {0xD5U}, {OPT::memHL, OPT::imm5}}},
    // AND1 CY,[HL].6
    {0x71U, {RL78::AND1_cy_memr, {0xE5U}, {OPT::memHL, OPT::imm6}}},
    // AND1 CY,[HL].7
    {0x71U, {RL78::AND1_cy_memr, {0xF5U}, {OPT::memHL, OPT::imm7}}},
    // AND1 CY,A.0
    {0x71U, {RL78::AND1_cy_r, {0x8DU}, {RL78::R1, OPT::imm0}}},
    // AND1 CY,A.1
    {0x71U, {RL78::AND1_cy_r, {0x9DU}, {RL78::R1, OPT::imm1}}},
    // AND1 CY,A.2
    {0x71U, {RL78::AND1_cy_r, {0xADU}, {RL78::R1, OPT::imm2}}},
    // AND1 CY,A.3
    {0x71U, {RL78::AND1_cy_r, {0xBDU}, {RL78::R1, OPT::imm3}}},
    // AND1 CY,A.4
    {0x71U, {RL78::AND1_cy_r, {0xCDU}, {RL78::R1, OPT::imm4}}},
    // AND1 CY,A.5
    {0x71U, {RL78::AND1_cy_r, {0xDDU}, {RL78::R1, OPT::imm5}}},
    // AND1 CY,A.6
    {0x71U, {RL78::AND1_cy_r, {0xEDU}, {RL78::R1, OPT::imm6}}},
    // AND1 CY,A.7
    {0x71U, {RL78::AND1_cy_r, {0xFDU}, {RL78::R1, OPT::imm7}}},
    // AND1 CY,saddr.0
    {0x71U, {RL78::AND1_cy_saddrx, {0x5U, SBP::saddr}, {OPT::saddr, OPT::imm0}}},
    // AND1 CY,saddr.1
    {0x71U, {RL78::AND1_cy_saddrx, {0x15U, SBP::saddr}, {OPT::saddr, OPT::imm1}}},
    // AND1 CY,saddr.2
    {0x71U, {RL78::AND1_cy_saddrx, {0x25U, SBP::saddr}, {OPT::saddr, OPT::imm2}}},
    // AND1 CY,saddr.3
    {0x71U, {RL78::AND1_cy_saddrx, {0x35U, SBP::saddr}, {OPT::saddr, OPT::imm3}}},
    // AND1 CY,saddr.4
    {0x71U, {RL78::AND1_cy_saddrx, {0x45U, SBP::saddr}, {OPT::saddr, OPT::imm4}}},
    // AND1 CY,saddr.5
    {0x71U, {RL78::AND1_cy_saddrx, {0x55U, SBP::saddr}, {OPT::saddr, OPT::imm5}}},
    // AND1 CY,saddr.6
    {0x71U, {RL78::AND1_cy_saddrx, {0x65U, SBP::saddr}, {OPT::saddr, OPT::imm6}}},
    // AND1 CY,saddr.7
    {0x71U, {RL78::AND1_cy_saddrx, {0x75U, SBP::saddr}, {OPT::saddr, OPT::imm7}}},
    // AND1 CY,ES:[HL].0
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0x85U}, {RL78::CY, OPT::ES_memHL,OPT::imm0}}},
    // AND1 CY,ES:[HL].1
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0x95U}, {RL78::CY, OPT::ES_memHL,OPT::imm1}}},
    // AND1 CY,ES:[HL].2
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0xA5U}, {RL78::CY, OPT::ES_memHL,OPT::imm2}}},
    // AND1 CY,ES:[HL].3
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0xB5U}, {RL78::CY, OPT::ES_memHL,OPT::imm3}}},
    // AND1 CY,ES:[HL].4
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0xC5U}, {RL78::CY, OPT::ES_memHL,OPT::imm4}}},
    // AND1 CY,ES:[HL].5
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0xD5U}, {RL78::CY, OPT::ES_memHL,OPT::imm5}}},
    // AND1 CY,ES:[HL].6
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0xE5U}, {RL78::CY, OPT::ES_memHL,OPT::imm6}}},
    // AND1 CY,ES:[HL].7
    {0x11U, {RL78::AND1_esmemr, {0x71U, 0xF5U}, {RL78::CY, OPT::ES_memHL,OPT::imm7}}},
    // AND1 CY,PSW.0
    {0x71U, {RL78::AND1_cy_PSW, {0x0DU, 0xFAU}, {RL78::PSW, OPT::imm0}}},
    // AND1 CY,PSW.1
    {0x71U, {RL78::AND1_cy_PSW, {0x1DU, 0xFAU}, {RL78::PSW, OPT::imm1}}},
    // AND1 CY,PSW.2
    {0x71U, {RL78::AND1_cy_PSW, {0x2DU, 0xFAU}, {RL78::PSW, OPT::imm2}}},
    // AND1 CY,PSW.3
    {0x71U, {RL78::AND1_cy_PSW, {0x3DU, 0xFAU}, {RL78::PSW, OPT::imm3}}},
    // AND1 CY,PSW.4
    {0x71U, {RL78::AND1_cy_PSW, {0x4DU, 0xFAU}, {RL78::PSW, OPT::imm4}}},
    // AND1 CY,PSW.5
    {0x71U, {RL78::AND1_cy_PSW, {0x5DU, 0xFAU}, {RL78::PSW, OPT::imm5}}},
    // AND1 CY,PSW.6
    {0x71U, {RL78::AND1_cy_PSW, {0x6DU, 0xFAU}, {RL78::PSW, OPT::imm6}}},
    // AND1 CY,PSW.7
    {0x71U, {RL78::AND1_cy_PSW, {0x7DU, 0xFAU}, {RL78::PSW, OPT::imm7}}},
    // AND1 CY,sfr.0
    {0x71U, {RL78::AND1_cy_sfr, {0x0DU, SBP::sfr}, {OPT::sfr,OPT::imm0}}},
    // AND1 CY,sfr.1
    {0x71U, {RL78::AND1_cy_sfr, {0x1DU, SBP::sfr}, {OPT::sfr,OPT::imm1}}},
    // AND1 CY,sfr.2
    {0x71U, {RL78::AND1_cy_sfr, {0x2DU, SBP::sfr}, {OPT::sfr,OPT::imm2}}},
    // AND1 CY,sfr.3
    {0x71U, {RL78::AND1_cy_sfr, {0x3DU, SBP::sfr}, {OPT::sfr,OPT::imm3}}},
    // AND1 CY,sfr.4
    {0x71U, {RL78::AND1_cy_sfr, {0x4DU, SBP::sfr}, {OPT::sfr,OPT::imm4}}},
    // AND1 CY,sfr.5
    {0x71U, {RL78::AND1_cy_sfr, {0x5DU, SBP::sfr}, {OPT::sfr,OPT::imm5}}},
    // AND1 CY,sfr.6
    {0x71U, {RL78::AND1_cy_sfr, {0x6DU, SBP::sfr}, {OPT::sfr,OPT::imm6}}},
    // AND1 CY,sfr.7
    {0x71U, {RL78::AND1_cy_sfr, {0x7DU, SBP::sfr}, {OPT::sfr,OPT::imm7}}},
    // BC $addr20
    {0xDCU, {RL78::B_cc, {SBP::adr}, {OPT::S_addr20, OPT::RL78CC_C}}},
    // BF [HL].0,$addr20
    {0x31U, {RL78::BTBF_memr, {0x85U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm0}}},
    // BF [HL].1,$addr20
    {0x31U, {RL78::BTBF_memr, {0x95U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm1}}},
    // BF [HL].2,$addr20
    {0x31U, {RL78::BTBF_memr, {0xA5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm2}}},
    // BF [HL].3,$addr20
    {0x31U, {RL78::BTBF_memr, {0xB5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm3}}},
    // BF [HL].4,$addr20
    {0x31U, {RL78::BTBF_memr, {0xC5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm4}}},
    // BF [HL].5,$addr20
    {0x31U, {RL78::BTBF_memr, {0xD5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm5}}},
    // BF [HL].6,$addr20
    {0x31U, {RL78::BTBF_memr, {0xE5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm6}}},
    // BF [HL].7,$addr20
    {0x31U, {RL78::BTBF_memr, {0xF5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::memHL, OPT::imm7}}},
    // BF A.0,$addr20
    {0x31U, {RL78::BTBF_A, {0x5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm0}}},
    // BF A.1,$addr20
    {0x31U, {RL78::BTBF_A, {0x15U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm1}}},
    // BF A.2,$addr20
    {0x31U, {RL78::BTBF_A, {0x25U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm2}}},
    // BF A.3,$addr20
    {0x31U, {RL78::BTBF_A, {0x35U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm3}}},
    // BF A.4,$addr20
    {0x31U, {RL78::BTBF_A, {0x45U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm4}}},
    // BF A.5,$addr20
    {0x31U, {RL78::BTBF_A, {0x55U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm5}}},
    // BF A.6,$addr20
    {0x31U, {RL78::BTBF_A, {0x65U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm6}}},
    // BF A.7,$addr20
    {0x31U, {RL78::BTBF_A, {0x75U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::R1, OPT::imm7}}},
    // BF saddr.0,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x4U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm0}}},
    // BF saddr.1,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x14U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm1}}},
    // BF saddr.2,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x24U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm2}}},
    // BF saddr.3,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x34U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm3}}},
    // BF saddr.4,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x44U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm4}}},
    // BF saddr.5,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x54U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm5}}},
    // BF saddr.6,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x64U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm6}}},
    // BF saddr.7,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x74U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::saddr, OPT::imm7}}},
    // BF ES:[HL].0,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0x85U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm0}}},
    // BF ES:[HL].1,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0x95U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm1}}},
    // BF ES:[HL].2,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xA5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm2}}},
    // BF ES:[HL].3,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xB5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm3}}},
    // BF ES:[HL].4,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xC5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm4}}},
    // BF ES:[HL].5,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xD5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm5}}},
    // BF ES:[HL].6,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xE5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm6}}},
    // BF ES:[HL].7,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xF5U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::ES_memHL, OPT::imm7}}},
    // BF PSW.0,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0x84U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm0}}},
    // BF PSW.1,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0x94U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm1}}},
    // BF PSW.2,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xA4U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm2}}},
    // BF PSW.3,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xB4U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm3}}},
    // BF PSW.4,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xC4U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm4}}},
    // BF PSW.5,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xD4U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm5}}},
    // BF PSW.6,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xE4U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm6}}},
    // BF PSW.7,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xF4U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, RL78::PSW, OPT::imm7}}},
    // BF sfr.0,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0x84U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm0}}},
    // BF sfr.1,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0x94U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm1}}},
    // BF sfr.2,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xA4U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm2}}},
    // BF sfr.3,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xB4U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm3}}},
    // BF sfr.4,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xC4U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm4}}},
    // BF sfr.5,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xD4U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm5}}},
    // BF sfr.6,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xE4U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm6}}},
    // BF sfr.7,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xF4U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ, OPT::sfr, OPT::imm7}}},
    // BH $addr20
    {0x61U, {RL78::B_cc, {0xC3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_H}}},
    // BNC $addr20
    {0xDEU, {RL78::B_cc, {SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NC}}},
    // BNH $addr20
    {0x61U, {RL78::B_cc, {0xD3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NH}}},
    // BNZ $addr20
    {0xDFU, {RL78::B_cc, {SBP::adr}, {OPT::S_addr20, OPT::RL78CC_NZ}}},
    // BR !addr16
    {0xEDU, {RL78::BR_addr16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // BR AX*/ 
    {0x61U, {RL78::BR_AX, {0xCBU}, {RL78::RP0}}},
    // BR $!addr20
    {0xEEU, {RL78::BR_rel16, {SBP::adrl, SBP::adrh}, {OPT::SI_addr20}}},
    // BR $addr20*/ 
    {0xEFU, {RL78::BR_rel8, {SBP::adr}, {OPT::S_addr20}}},
    // BR !!addr20
    {0xECU, {RL78::BR_addr20, {SBP::adrl, SBP::adrh, SBP::adrs}, {OPT::II_addr20}}},
    // BRK nan*/ 
    {0x61U, {RL78::BRK, {0xCCU}, {}}},
    // BT [HL].0,$addr20
    {0x31U, {RL78::BTBF_memr, {0x83U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm0}}},
    // BT [HL].1,$addr20
    {0x31U, {RL78::BTBF_memr, {0x93U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm1}}},
    // BT [HL].2,$addr20
    {0x31U, {RL78::BTBF_memr, {0xA3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm2}}},
    // BT [HL].3,$addr20
    {0x31U, {RL78::BTBF_memr, {0xB3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm3}}},
    // BT [HL].4,$addr20
    {0x31U, {RL78::BTBF_memr, {0xC3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm4}}},
    // BT [HL].5,$addr20
    {0x31U, {RL78::BTBF_memr, {0xD3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm5}}},
    // BT [HL].6,$addr20
    {0x31U, {RL78::BTBF_memr, {0xE3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm6}}},
    // BT [HL].7,$addr20
    {0x31U, {RL78::BTBF_memr, {0xF3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm7}}},
    // BT A.0,$addr20
    {0x31U, {RL78::BTBF_A, {0x3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm0}}},
    // BT A.1,$addr20
    {0x31U, {RL78::BTBF_A, {0x13U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm1}}},
    // BT A.2,$addr20
    {0x31U, {RL78::BTBF_A, {0x23U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm2}}},
    // BT A.3,$addr20
    {0x31U, {RL78::BTBF_A, {0x33U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm3}}},
    // BT A.4,$addr20
    {0x31U, {RL78::BTBF_A, {0x43U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm4}}},
    // BT A.5,$addr20
    {0x31U, {RL78::BTBF_A, {0x53U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm5}}},
    // BT A.6,$addr20
    {0x31U, {RL78::BTBF_A, {0x63U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm6}}},
    // BT A.7,$addr20
    {0x31U, {RL78::BTBF_A, {0x73U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm7}}},
    // BT saddr.0,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x2U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm0}}},
    // BT saddr.1,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x12U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm1}}},
    // BT saddr.2,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x22U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm2}}},
    // BT saddr.3,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x32U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm3}}},
    // BT saddr.4,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x42U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm4}}},
    // BT saddr.5,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x52U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm5}}},
    // BT saddr.6,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x62U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm6}}},
    // BT saddr.7,$addr20
    {0x31U, {RL78::BTBF_saddr, {0x72U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm7}}},
    // BT ES:[HL].0,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0x83U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm0}}},
    // BT ES:[HL].1,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0x93U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm1}}},
    // BT ES:[HL].2,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xA3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm2}}},
    // BT ES:[HL].3,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xB3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm3}}},
    // BT ES:[HL].4,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xC3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm4}}},
    // BT ES:[HL].5,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xD3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm5}}},
    // BT ES:[HL].6,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xE3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm6}}},
    // BT ES:[HL].7,$addr20
    {0x11U, {RL78::BTBF_esmemr, {0x31U, 0xF3U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::ES_memHL, OPT::imm7}}},
    // BT PSW.0,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0x82U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm0}}},
    // BT PSW.1,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0x92U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm1}}},
    // BT PSW.2,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xA2U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm2}}},
    // BT PSW.3,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xB2U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm3}}},
    // BT PSW.4,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xC2U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm4}}},
    // BT PSW.5,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xD2U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm5}}},
    // BT PSW.6,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xE2U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm6}}},
    // BT PSW.7,$addr20
    {0x31U, {RL78::BTBF_PSWi_addr, {0xF2U, 0xFAU, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, RL78::PSW, OPT::imm7}}},
    // BT sfr.0,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0x82U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm0}}},
    // BT sfr.1,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0x92U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm1}}},
    // BT sfr.2,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xA2U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm2}}},
    // BT sfr.3,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xB2U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm3}}},
    // BT sfr.4,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xC2U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm4}}},
    // BT sfr.5,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xD2U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm5}}},
    // BT sfr.6,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xE2U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm6}}},
    // BT sfr.7,$addr20
    {0x31U, {RL78::BTBF_sfri_addr, {0xF2U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::sfr, OPT::imm7}}},
    // BTCLR [HL].0,$addr20
    {0x31U, {RL78::BTCLR_memr, {0x81U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm0}}},
    // BTCLR [HL].1,$addr20
    {0x31U, {RL78::BTCLR_memr, {0x91U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm1}}},
    // BTCLR [HL].2,$addr20
    {0x31U, {RL78::BTCLR_memr, {0xA1U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm2}}},
    // BTCLR [HL].3,$addr20
    {0x31U, {RL78::BTCLR_memr, {0xB1U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm3}}},
    // BTCLR [HL].4,$addr20
    {0x31U, {RL78::BTCLR_memr, {0xC1U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm4}}},
    // BTCLR [HL].5,$addr20
    {0x31U, {RL78::BTCLR_memr, {0xD1U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm5}}},
    // BTCLR [HL].6,$addr20
    {0x31U, {RL78::BTCLR_memr, {0xE1U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm6}}},
    // BTCLR [HL].7,$addr20
    {0x31U, {RL78::BTCLR_memr, {0xF1U, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::memHL, OPT::imm7}}},
    // BTCLR A.0,$addr20
    {0x31U, {RL78::BTCLR_A, {0x1U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm0}}},
    // BTCLR A.1,$addr20
    {0x31U, {RL78::BTCLR_A, {0x11U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm1}}},
    // BTCLR A.2,$addr20
    {0x31U, {RL78::BTCLR_A, {0x21U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm2}}},
    // BTCLR A.3,$addr20
    {0x31U, {RL78::BTCLR_A, {0x31U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm3}}},
    // BTCLR A.4,$addr20
    {0x31U, {RL78::BTCLR_A, {0x41U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm4}}},
    // BTCLR A.5,$addr20
    {0x31U, {RL78::BTCLR_A, {0x51U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm5}}},
    // BTCLR A.6,$addr20
    {0x31U, {RL78::BTCLR_A, {0x61U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm6}}},
    // BTCLR A.7,$addr20
    {0x31U, {RL78::BTCLR_A, {0x71U, SBP::adr}, {RL78::R1, OPT::S_addr20, OPT::RL78CC_Z, RL78::R1, OPT::imm7}}},
    // BTCLR saddr.0,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x0U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm0}}},
    // BTCLR saddr.1,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x10U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm1}}},
    // BTCLR saddr.2,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x20U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm2}}},
    // BTCLR saddr.3,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x30U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm3}}},
    // BTCLR saddr.4,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x40U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm4}}},
    // BTCLR saddr.5,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x50U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm5}}},
    // BTCLR saddr.6,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x60U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm6}}},
    // BTCLR saddr.7,$addr20
    {0x31U, {RL78::BTCLR_saddr, {0x70U, SBP::saddr, SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z, OPT::saddr, OPT::imm7}}},
    // BTCLR ES:[HL].0,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0x81U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm0}}},
    // BTCLR ES:[HL].1,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0x91U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm1}}},
    // BTCLR ES:[HL].2,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0xA1U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm2}}},
    // BTCLR ES:[HL].3,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0xB1U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm3}}},
    // BTCLR ES:[HL].4,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0xC1U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm4}}},
    // BTCLR ES:[HL].5,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0xD1U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm5}}},
    // BTCLR ES:[HL].6,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0xE1U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm6}}},
    // BTCLR ES:[HL].7,$addr20
    {0x11U, {RL78::BTCLR_esmemr, {0x31U, 0xF1U, SBP::adr}, {OPT::S_addr20, OPT::ES_memHL, OPT::imm7}}},
    // BTCLR PSW.0,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0x80U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm0}}},
    // BTCLR PSW.1,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0x90U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm1}}},
    // BTCLR PSW.2,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0xA0U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm2}}},
    // BTCLR PSW.3,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0xB0U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm3}}},
    // BTCLR PSW.4,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0xC0U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm4}}},
    // BTCLR PSW.5,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0xD0U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm5}}},
    // BTCLR PSW.6,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0xE0U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm6}}},
    // BTCLR PSW.7,$addr20
    {0x31U, {RL78::BTCLR_PSWi_addr, {0xF0U, 0xFAU, SBP::adr}, {OPT::S_addr20, RL78::PSW, OPT::imm7}}},
    // BTCLR sfr.0,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0x80U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm0}}},
    // BTCLR sfr.1,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0x90U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm1}}},
    // BTCLR sfr.2,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0xA0U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm2}}},
    // BTCLR sfr.3,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0xB0U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm3}}},
    // BTCLR sfr.4,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0xC0U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm4}}},
    // BTCLR sfr.5,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0xD0U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm5}}},
    // BTCLR sfr.6,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0xE0U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm6}}},
    // BTCLR sfr.7,$addr20
    {0x31U, {RL78::BTCLR_sfri_addr, {0xF0U, SBP::sfr, SBP::adr}, {OPT::S_addr20, OPT::sfr, OPT::imm7}}},
    // BZ $addr20
    {0xDDU, {RL78::B_cc, {SBP::adr}, {OPT::S_addr20, OPT::RL78CC_Z}}},
    // CALL !addr16
    {0xFDU, {RL78::CALL_addr16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // CALL $!addr20
    {0xFEU, {RL78::CALL_addr16rel, {SBP::adrl, SBP::adrh}, {OPT::SI_addr20}}},
    // CALL !!addr20
    {0xFCU, {RL78::CALL_addr20, {SBP::adrl, SBP::adrh, SBP::adrs}, {OPT::II_addr20}}},
    // CALL AX*/ 
    {0x61U, {RL78::CALL_rp, {0xCAU}, {RL78::RP0}}},
    // CALL BC*/ 
    {0x61U, {RL78::CALL_rp, {0xDAU}, {RL78::RP2}}},
    // CALL DE*/ 
    {0x61U, {RL78::CALL_rp, {0xEAU}, {RL78::RP4}}},
    // CALL HL*/ 
    {0x61U, {RL78::CALL_rp, {0xFAU}, {RL78::RP6}}},
    // CALLT [0080h]
    {0x61U, {RL78::CALLT_addr5, {SBP::adr}, {OPT::mem_addr5}}},
    // CLR1 !addr16.0
    {0x71U, {RL78::CLR1_abs16, {0x8U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm0}}},
    // CLR1 !addr16.1
    {0x71U, {RL78::CLR1_abs16, {0x18U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm1}}},
    // CLR1 !addr16.2
    {0x71U, {RL78::CLR1_abs16, {0x28U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm2}}},
    // CLR1 !addr16.3
    {0x71U, {RL78::CLR1_abs16, {0x38U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm3}}},
    // CLR1 !addr16.4
    {0x71U, {RL78::CLR1_abs16, {0x48U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm4}}},
    // CLR1 !addr16.5
    {0x71U, {RL78::CLR1_abs16, {0x58U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm5}}},
    // CLR1 !addr16.6
    {0x71U, {RL78::CLR1_abs16, {0x68U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm6}}},
    // CLR1 !addr16.7
    {0x71U, {RL78::CLR1_abs16, {0x78U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm7}}},
    // CLR1 [HL].0
    {0x71U, {RL78::CLR1_memr, {0x83U}, {OPT::memHL, OPT::imm0}}},
    // CLR1 [HL].1
    {0x71U, {RL78::CLR1_memr, {0x93U}, {OPT::memHL, OPT::imm1}}},
    // CLR1 [HL].2
    {0x71U, {RL78::CLR1_memr, {0xA3U}, {OPT::memHL, OPT::imm2}}},
    // CLR1 [HL].3
    {0x71U, {RL78::CLR1_memr, {0xB3U}, {OPT::memHL, OPT::imm3}}},
    // CLR1 [HL].4
    {0x71U, {RL78::CLR1_memr, {0xC3U}, {OPT::memHL, OPT::imm4}}},
    // CLR1 [HL].5
    {0x71U, {RL78::CLR1_memr, {0xD3U}, {OPT::memHL, OPT::imm5}}},
    // CLR1 [HL].6
    {0x71U, {RL78::CLR1_memr, {0xE3U}, {OPT::memHL, OPT::imm6}}},
    // CLR1 [HL].7
    {0x71U, {RL78::CLR1_memr, {0xF3U}, {OPT::memHL, OPT::imm7}}},
    // CLR1 A.0
    {0x71U, {RL78::CLR1_A, {0x8BU}, {RL78::R1, RL78::R1, OPT::imm0}}},
    // CLR1 A.1
    {0x71U, {RL78::CLR1_A, {0x9BU}, {RL78::R1, RL78::R1, OPT::imm1}}},
    // CLR1 A.2
    {0x71U, {RL78::CLR1_A, {0xABU}, {RL78::R1, RL78::R1, OPT::imm2}}},
    // CLR1 A.3
    {0x71U, {RL78::CLR1_A, {0xBBU}, {RL78::R1, RL78::R1, OPT::imm3}}},
    // CLR1 A.4
    {0x71U, {RL78::CLR1_A, {0xCBU}, {RL78::R1, RL78::R1, OPT::imm4}}},
    // CLR1 A.5
    {0x71U, {RL78::CLR1_A, {0xDBU}, {RL78::R1, RL78::R1, OPT::imm5}}},
    // CLR1 A.6
    {0x71U, {RL78::CLR1_A, {0xEBU}, {RL78::R1, RL78::R1, OPT::imm6}}},
    // CLR1 A.7
    {0x71U, {RL78::CLR1_A, {0xFBU}, {RL78::R1, RL78::R1, OPT::imm7}}},
    // CLR1 saddr.0
    {0x71U, {RL78::CLR1_saddr, {0x3U, SBP::saddr}, {OPT::saddr, OPT::imm0}}},
    // CLR1 saddr.1
    {0x71U, {RL78::CLR1_saddr, {0x13U, SBP::saddr}, {OPT::saddr, OPT::imm1}}},
    // CLR1 saddr.2
    {0x71U, {RL78::CLR1_saddr, {0x23U, SBP::saddr}, {OPT::saddr, OPT::imm2}}},
    // CLR1 saddr.3
    {0x71U, {RL78::CLR1_saddr, {0x33U, SBP::saddr}, {OPT::saddr, OPT::imm3}}},
    // CLR1 saddr.4
    {0x71U, {RL78::CLR1_saddr, {0x43U, SBP::saddr}, {OPT::saddr, OPT::imm4}}},
    // CLR1 saddr.5
    {0x71U, {RL78::CLR1_saddr, {0x53U, SBP::saddr}, {OPT::saddr, OPT::imm5}}},
    // CLR1 saddr.6
    {0x71U, {RL78::CLR1_saddr, {0x63U, SBP::saddr}, {OPT::saddr, OPT::imm6}}},
    // CLR1 saddr.7
    {0x71U, {RL78::CLR1_saddr, {0x73U, SBP::saddr}, {OPT::saddr, OPT::imm7}}},
    // CLR1 ES:!addr16.0
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x8U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm0}}},
    // CLR1 ES:!addr16.1
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x18U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm1}}},
    // CLR1 ES:!addr16.2
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x28U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm2}}},
    // CLR1 ES:!addr16.3
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x38U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm3}}},
    // CLR1 ES:!addr16.4
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x48U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm4}}},
    // CLR1 ES:!addr16.5
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x58U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm5}}},
    // CLR1 ES:!addr16.6
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x68U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm6}}},
    // CLR1 ES:!addr16.7
    {0x11U, {RL78::CLR1_esaddr16, {0x71U, 0x78U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm7}}},
    // CLR1 ES:[HL].0
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0x83U}, {OPT::ES_memHL,OPT::imm0}}},
    // CLR1 ES:[HL].1
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0x93U}, {OPT::ES_memHL,OPT::imm1}}},
    // CLR1 ES:[HL].2
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0xA3U}, {OPT::ES_memHL,OPT::imm2}}},
    // CLR1 ES:[HL].3
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0xB3U}, {OPT::ES_memHL,OPT::imm3}}},
    // CLR1 ES:[HL].4
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0xC3U}, {OPT::ES_memHL,OPT::imm4}}},
    // CLR1 ES:[HL].5
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0xD3U}, {OPT::ES_memHL,OPT::imm5}}},
    // CLR1 ES:[HL].6
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0xE3U}, {OPT::ES_memHL,OPT::imm6}}},
    // CLR1 ES:[HL].7
    {0x11U, {RL78::CLR1_esmemr, {0x71U, 0xF3U}, {OPT::ES_memHL,OPT::imm7}}},
    // CLR1 CY
    {0x71U, {RL78::CLR1_cy, {0x88U}, {RL78::CY}}},
    // CLR1 PSW.0
    {0x71U, {RL78::CLR1_PSW, {0x0BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm0}}},
    // CLR1 PSW.1
    {0x71U, {RL78::CLR1_PSW, {0x1BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm1}}},
    // CLR1 PSW.2
    {0x71U, {RL78::CLR1_PSW, {0x2BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm2}}},
    // CLR1 PSW.3
    {0x71U, {RL78::CLR1_PSW, {0x3BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm3}}},
    // CLR1 PSW.4
    {0x71U, {RL78::CLR1_PSW, {0x4BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm4}}},
    // CLR1 PSW.5
    {0x71U, {RL78::CLR1_PSW, {0x5BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm5}}},
    // CLR1 PSW.6
    {0x71U, {RL78::CLR1_PSW, {0x6BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm6}}},
    // CLR1 PSW.7
    //{0x71U, {RL78::CLR1_PSW, {0x7BU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm7}}}, - we print DI instead
    // CLR1 sfr.0
    {0x71U, {RL78::CLR1_sfr, {0x0BU, SBP::sfr}, {OPT::sfr,OPT::imm0}}},
    // CLR1 sfr.1
    {0x71U, {RL78::CLR1_sfr, {0x1BU, SBP::sfr}, {OPT::sfr,OPT::imm1}}},
    // CLR1 sfr.2
    {0x71U, {RL78::CLR1_sfr, {0x2BU, SBP::sfr}, {OPT::sfr,OPT::imm2}}},
    // CLR1 sfr.3
    {0x71U, {RL78::CLR1_sfr, {0x3BU, SBP::sfr}, {OPT::sfr,OPT::imm3}}},
    // CLR1 sfr.4
    {0x71U, {RL78::CLR1_sfr, {0x4BU, SBP::sfr}, {OPT::sfr,OPT::imm4}}},
    // CLR1 sfr.5
    {0x71U, {RL78::CLR1_sfr, {0x5BU, SBP::sfr}, {OPT::sfr,OPT::imm5}}},
    // CLR1 sfr.6
    {0x71U, {RL78::CLR1_sfr, {0x6BU, SBP::sfr}, {OPT::sfr,OPT::imm6}}},
    // CLR1 sfr.7
    {0x71U, {RL78::CLR1_sfr, {0x7BU, SBP::sfr}, {OPT::sfr,OPT::imm7}}},
    // CLRB !addr16
    {0xF5U, {RL78::CLRB_abs16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // CLRB X*/ 
    {0xF0U, {RL78::CLRB_r, {}, {RL78::R0}}},
    // CLRB A*/ 
    {0xF1U, {RL78::CLRB_r, {}, {RL78::R1}}},
    // CLRB C*/ 
    {0xF2U, {RL78::CLRB_r, {}, {RL78::R2}}},
    // CLRB B*/ 
    {0xF3U, {RL78::CLRB_r, {}, {RL78::R3}}},
    // CLRB saddr*/ 
    {0xF4U, {RL78::CLRB_saddr, {SBP::saddr}, {OPT::saddr}}},
    // CLRB ES:!addr16
    {0x11U, {RL78::CLRB_esaddr16, {0xF5U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16}}},
    // CLRW AX*/ 
    {0xF6U, {RL78::CLRW_rp, {}, {RL78::RP0}}},
    // CLRW BC*/ 
    {0xF7U, {RL78::CLRW_rp, {}, {RL78::RP2}}},
    // CMP !addr16,#byte
    {0x40U, {RL78::CMP_abs16_imm, {SBP::adrl, SBP::adrh, SBP::data}, {OPT::I_addr16, OPT::byte}}},
    // CMP A,!addr16
    {0x4FU, {RL78::CMP_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, OPT::I_addr16}}},
    // CMP saddr,#byte
    {0x4AU, {RL78::CMP_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // CMP A,#byte
    {0x4CU, {RL78::CMP_r_imm, {SBP::data}, {RL78::R1, OPT::byte}}},
    // CMP A,[HL]*/ 
    {0x4DU, {RL78::CMP_r_memri, {}, {RL78::R1, OPT::memHL0}}},
    // CMP A,[HL+byte]
    {0x4EU, {RL78::CMP_r_memri, {SBP::adr}, {RL78::R1, OPT::memHL_byte}}},
    // CMP A,[HL+B]
    {0x61U, {RL78::CMP_r_memrr, {0xC0U}, {RL78::R1, OPT::memHL_B}}},
    // CMP A,[HL+C]
    {0x61U, {RL78::CMP_r_memrr, {0xC2U}, {RL78::R1, OPT::memHL_C}}},
    // CMP A,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x41U}, {RL78::R1, RL78::R1}}},
    // CMP A,B*/ 
    {0x61U, {RL78::CMP_r_r, {0x4BU}, {RL78::R1, RL78::R3}}},
    // CMP A,C*/ 
    {0x61U, {RL78::CMP_r_r, {0x4AU}, {RL78::R1, RL78::R2}}},
    // CMP A,D*/ 
    {0x61U, {RL78::CMP_r_r, {0x4DU}, {RL78::R1, RL78::R5}}},
    // CMP A,E*/ 
    {0x61U, {RL78::CMP_r_r, {0x4CU}, {RL78::R1, RL78::R4}}},
    // CMP A,H*/ 
    {0x61U, {RL78::CMP_r_r, {0x4FU}, {RL78::R1, RL78::R7}}},
    // CMP A,L*/ 
    {0x61U, {RL78::CMP_r_r, {0x4EU}, {RL78::R1, RL78::R6}}},
    // CMP A,X*/ 
    {0x61U, {RL78::CMP_r_r, {0x48U}, {RL78::R1, RL78::R0}}},
    // CMP B,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x43U}, {RL78::R3, RL78::R1}}},
    // CMP C,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x42U}, {RL78::R2, RL78::R1}}},
    // CMP D,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x45U}, {RL78::R5, RL78::R1}}},
    // CMP E,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x44U}, {RL78::R4, RL78::R1}}},
    // CMP H,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x47U}, {RL78::R7, RL78::R1}}},
    // CMP L,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x46U}, {RL78::R6, RL78::R1}}},
    // CMP X,A*/ 
    {0x61U, {RL78::CMP_r_r, {0x40U}, {RL78::R0, RL78::R1}}},
    // CMP A,saddr
    {0x4BU, {RL78::CMP_r_saddr, {SBP::saddr}, {RL78::R1, OPT::saddr}}},
    // CMP A,ES:!addr16
    {0x11U, {RL78::CMP_r_esaddr16, {0x4FU, SBP::adrl, SBP::adrh}, {RL78::R1,OPT::ES_I_addr16}}},
    // CMP A,ES:[HL]
    {0x11U, {RL78::CMP_r_esmemHL, {0x4DU}, {RL78::R1,OPT::ES_memHL0}}},
    // CMP A,ES:[HL+B]
    {0x11U, {RL78::CMP_r_esmemRpr, {0x61U, 0xC0U}, {RL78::R1,OPT::ES_memHL_B}}},
    // CMP A,ES:[HL+byte]
    {0x11U, {RL78::CMP_r_esmemHLi, {0x4EU, SBP::adr}, {RL78::R1,OPT::ES_memHL_byte}}},
    // CMP A,ES:[HL+C]
    {0x11U, {RL78::CMP_r_esmemRpr, {0x61U, 0xC2U}, {RL78::R1,OPT::ES_memHL_C}}},
    // CMP ES:!addr16,#byte
    {0x11U, {RL78::CMP_esaddr16_imm, {0x40U, SBP::adrl, SBP::adrh, SBP::data}, {OPT::ES_I_addr16,OPT::byte}}},
    // CMP0 !addr16
    {0xD5U, {RL78::CMP0_abs16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // CMP0 X*/ 
    {0xD0U, {RL78::CMP0_r, {}, {RL78::R0}}},
    // CMP0 A*/ 
    {0xD1U, {RL78::CMP0_r, {}, {RL78::R1}}},
    // CMP0 C*/ 
    {0xD2U, {RL78::CMP0_r, {}, {RL78::R2}}},
    // CMP0 B*/ 
    {0xD3U, {RL78::CMP0_r, {}, {RL78::R3}}},
    // CMP0 saddr*/ 
    {0xD4U, {RL78::CMP0_saddr, {SBP::saddr}, {OPT::saddr}}},
    // CMP0 ES:!addr16
    {0x11U, {RL78::CMP0_esaddr16, {0xD5U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16}}},
    // CMPS X,[HL+byte]
    {0x61U, {RL78::CMPS_r_memri, {0xDEU, SBP::adr}, {RL78::R0, OPT::memHL_byte}}},
    // CMPS X,ES:[HL+byte]
    {0x11U, {RL78::CMPS_rp_memri, {0x61U, 0xDEU, SBP::adr}, {RL78::R0,OPT::ES_memHL_byte}}},
    // CMPW AX,!addr16
    {0x42U, {RL78::CMPW_rp_abs16, {SBP::adrl, SBP::adrh}, {RL78::RP0, OPT::I_addr16}}},
    // CMPW AX,#word
    {0x44U, {RL78::CMPW_rp_imm, {SBP::datal, SBP::datah}, {RL78::RP0, OPT::word}}},
    // CMPW AX,[HL+byte]
    {0x61U, {RL78::CMPW_rp_memri, {0x49U, SBP::adr}, {RL78::RP0, OPT::memHL_byte}}},
    // CMPW AX,BC
    {0x43U, {RL78::CMPW_rp_rp, {}, {RL78::RP0, RL78::RP2}}},
    // CMPW AX,DE
    {0x45U, {RL78::CMPW_rp_rp, {}, {RL78::RP0, RL78::RP4}}},
    // CMPW AX,saddrp
    {0x46U, {RL78::CMPW_rp_saddr, {SBP::saddr}, {RL78::RP0, OPT::saddrp}}},
    // CMPW AX,HL*/ 
    {0x47U, {RL78::CMPW_rp_rp, {}, {RL78::RP0, RL78::RP6}}},
    // CMPW AX,ES:!addr16
    {0x11U, {RL78::CMPW_rp_esaddr16, {0x42U, SBP::adrl, SBP::adrh}, {RL78::RP0,OPT::ES_I_addr16}}},
    // CMPW AX,ES:[HL+byte]
    {0x11U, {RL78::CMPW_rp_esmemHLi, {0x61U, 0x49U, SBP::adr}, {RL78::RP0,OPT::ES_memHL_byte}}},
    // DEC !addr16
    {0xB0U, {RL78::DEC_abs16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // DEC [HL+byte]
    {0x61U, {RL78::DEC_memri, {0x69U, SBP::adr}, {OPT::memHL_byte}}},
    // DEC X
    {0x90U, {RL78::DEC_r, {}, {RL78::R0}}},
    // DEC A
    {0x91U, {RL78::DEC_r, {}, {RL78::R1}}},
    // DEC C
    {0x92U, {RL78::DEC_r, {}, {RL78::R2}}},
    // DEC B
    {0x93U, {RL78::DEC_r, {}, {RL78::R3}}},
    // DEC E
    {0x94U, {RL78::DEC_r, {}, {RL78::R4}}},
    // DEC D
    {0x95U, {RL78::DEC_r, {}, {RL78::R5}}},
    // DEC L
    {0x96U, {RL78::DEC_r, {}, {RL78::R6}}},
    // DEC H
    {0x97U, {RL78::DEC_r, {}, {RL78::R7}}},
    // DEC saddr
    {0xB4U, {RL78::DEC_saddr, {SBP::saddr}, {OPT::saddr}}},
    // DEC ES:!addr16
    {0x11U, {RL78::DEC_esaddr16, {0xB0U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16}}},
    // DEC ES:[HL+byte]
    {0x11U, {RL78::DEC_esmemHLi, {0x61U, 0x69U, SBP::adr}, {OPT::ES_memHL_byte}}},
    // DECW !addr16
    {0xB2U, {RL78::DECW_abs16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // DECW [HL+byte]
    {0x61U, {RL78::DECW_memri, {0x89U, SBP::adr}, {OPT::memHL_byte}}},
    // DECW AX*/ 
    {0xB1U, {RL78::DECW_rp, {}, {RL78::RP0}}},
    // DECW BC*/ 
    {0xB3U, {RL78::DECW_rp, {}, {RL78::RP2}}},
    // DECW DE*/ 
    {0xB5U, {RL78::DECW_rp, {}, {RL78::RP4}}},
    // DECW saddrp*/ 
    {0xB6U, {RL78::DECW_saddr, {SBP::saddr}, {OPT::saddrp}}},
    // DECW HL*/ 
    {0xB7U, {RL78::DECW_rp, {}, {RL78::RP6}}},
    // DECW ES:!addr16
    {0x11U, {RL78::DECW_esaddr16, {0xB2U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16}}},
    // DECW ES:[HL+byte]
    {0x11U, {RL78::DECW_esmemHLi, {0x61U, 0x89U, SBP::adr}, {OPT::ES_memHL_byte}}},
    // DI nan
    {0x71U, {RL78::DI, {0x7BU, 0xFAU}, {}}},
    // EI nan
    {0x71U, {RL78::EI, {0x7AU, 0xFAU}, {}}},
    // HALT nan*/ 
    {0x61U, {RL78::HALT, {0xEDU}, {}}},
    // INC !addr16
    {0xA0U, {RL78::INC_abs16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // INC [HL+byte]
    {0x61U, {RL78::INC_memri, {0x59U, SBP::adr}, {OPT::memHL_byte}}},
    // INC X*/ 
    {0x80U, {RL78::INC_r, {}, {RL78::R0}}},
    // INC A*/ 
    {0x81U, {RL78::INC_r, {}, {RL78::R1}}},
    // INC C*/ 
    {0x82U, {RL78::INC_r, {}, {RL78::R2}}},
    // INC B*/ 
    {0x83U, {RL78::INC_r, {}, {RL78::R3}}},
    // INC E*/ 
    {0x84U, {RL78::INC_r, {}, {RL78::R4}}},
    // INC D*/ 
    {0x85U, {RL78::INC_r, {}, {RL78::R5}}},
    // INC L*/ 
    {0x86U, {RL78::INC_r, {}, {RL78::R6}}},
    // INC H*/ 
    {0x87U, {RL78::INC_r, {}, {RL78::R7}}},
    // INC saddr
    {0xA4U, {RL78::INC_saddr, {SBP::saddr}, {OPT::saddr}}},
    // INC ES:!addr16
    {0x11U, {RL78::INC_esaddr16, {0xA0U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16}}},
    // INC ES:[HL+byte]
    {0x11U, {RL78::INC_esmemHLi, {0x61U, 0x59U, SBP::adr}, {OPT::ES_memHL_byte}}},
    // INCW !addr16
    {0xA2U, {RL78::INCW_abs16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // INCW [HL+byte]
    {0x61U, {RL78::INCW_memri, {0x79U, SBP::adr}, {OPT::memHL_byte}}},
    // INCW AX*/ 
    {0xA1U, {RL78::INCW_rp, {}, {RL78::RP0}}},
    // INCW BC*/ 
    {0xA3U, {RL78::INCW_rp, {}, {RL78::RP2}}},
    // INCW DE*/ 
    {0xA5U, {RL78::INCW_rp, {}, {RL78::RP4}}},
    // INCW saddrp*/ 
    {0xA6U, {RL78::INCW_saddr, {SBP::saddr}, {OPT::saddrp}}},
    // INCW HL*/ 
    {0xA7U, {RL78::INCW_rp, {}, {RL78::RP6}}},
    // INCW ES:!addr16
    {0x11U, {RL78::INCW_esaddr16, {0xA2U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16}}},
    // INCW ES:[HL+byte]
    {0x11U, {RL78::INCW_esmemHLi, {0x61U, 0x79U, SBP::adr}, {OPT::ES_memHL_byte}}},
    // MOV A,!addr16
    {0x8FU, {RL78::LOAD8_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, OPT::I_addr16}}},
    // MOV X,!addr16
    {0xD9U, {RL78::LOAD8_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R0, OPT::I_addr16}}},
    // MOV B,!addr16
    {0xE9U, {RL78::LOAD8_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R3, OPT::I_addr16}}},
    // MOV C,!addr16
    {0xF9U, {RL78::LOAD8_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R2, OPT::I_addr16}}},
    // MOV A,[HL+B]
    {0x61U, {RL78::LOAD8_r_memrr, {0xC9U}, {RL78::R1, OPT::memHL_B}}},
    // MOV A,[HL+C]
    {0x61U, {RL78::LOAD8_r_memrr, {0xE9U}, {RL78::R1, OPT::memHL_C}}},
    // MOV A,word[BC]
    {0x49U, {RL78::LOAD8_r_ri, {SBP::adrl, SBP::adrh}, {RL78::R1, OPT::word_memBC}}},
    // MOV A,[DE]*/ 
    {0x89U, {RL78::LOAD8_r_memDE, {}, {RL78::R1, OPT::memDE}}},
    // MOV A,[DE+byte]
    {0x8AU, {RL78::LOAD8_r_memDEi, {SBP::adr}, {RL78::R1, OPT::memDE_byte}}},
    // MOV A,[HL]*/ 
    {0x8BU, {RL78::LOAD8_r_memHL, {}, {RL78::R1, OPT::memHL0}}},
    // MOV A,[HL+byte]
    {0x8CU, {RL78::LOAD8_r_memHLi, {SBP::adr}, {RL78::R1, OPT::memHL_byte}}},
    // MOV A,[SP+byte]
    {0x88U, {RL78::LOAD8_r_stack_slot, {SBP::adr}, {RL78::R1, OPT::memSP_byte}}},
    // MOV A,CS*/ 
    {0x8EU, {RL78::MOV_A_cs, {0xFCU}, {RL78::R1, RL78::CS}}},
    // MOV A,ES*/ 
    {0x8EU, {RL78::MOV_A_es, {0xFDU}, {RL78::R1, RL78::ES}}},
    // MOV A,X*/ 
    {0x60U, {RL78::MOV_A_r, {}, {RL78::R1, RL78::R0}}},
    // MOV A,C*/ 
    {0x62U, {RL78::MOV_A_r, {}, {RL78::R1, RL78::R2}}},
    // MOV A,B*/ 
    {0x63U, {RL78::MOV_A_r, {}, {RL78::R1, RL78::R3}}},
    // MOV A,E
    {0x64U, {RL78::MOV_A_r, {}, {RL78::R1, RL78::R4}}},
    // MOV A,D
    {0x65U, {RL78::MOV_A_r, {}, {RL78::R1, RL78::R5}}},
    // MOV A,L
    {0x66U, {RL78::MOV_A_r, {}, {RL78::R1, RL78::R6}}},
    // MOV A,H
    {0x67U, {RL78::MOV_A_r, {}, {RL78::R1, RL78::R7}}},
    // MOV CS,A
    {0x9EU, {RL78::MOV_cs_A, {0xFCU}, {RL78::CS, RL78::R1}}},
    // MOV ES,A
    {0x9EU, {RL78::MOV_es_A, {0xFDU}, {RL78::ES, RL78::R1}}},
    // MOV ES,#byte
    {0x41U, {RL78::MOV_es_imm, {SBP::data}, {RL78::ES, OPT::byte}}},
    // MOV X,A*/ 
    {0x70U, {RL78::MOV_r_A, {}, {RL78::R0, RL78::R1}}},
    // MOV C,A*/ 
    {0x72U, {RL78::MOV_r_A, {}, {RL78::R2, RL78::R1}}},
    // MOV B,A
    {0x73U, {RL78::MOV_r_A, {}, {RL78::R3, RL78::R1}}},
    // MOV E,A
    {0x74U, {RL78::MOV_r_A, {}, {RL78::R4, RL78::R1}}},
    // MOV D,A
    {0x75U, {RL78::MOV_r_A, {}, {RL78::R5, RL78::R1}}},
    // MOV L,A
    {0x76U, {RL78::MOV_r_A, {}, {RL78::R6, RL78::R1}}},
    // MOV H,A
    {0x77U, {RL78::MOV_r_A, {}, {RL78::R7, RL78::R1}}},
    // MOV X,#byte
    {0x50U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R0, OPT::byte}}},
    // MOV A,#byte
    {0x51U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R1, OPT::byte}}},
    // MOV C,#byte
    {0x52U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R2, OPT::byte}}},
    // MOV B,#byte
    {0x53U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R3, OPT::byte}}},
    // MOV E,#byte
    {0x54U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R4, OPT::byte}}},
    // MOV D,#byte
    {0x55U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R5, OPT::byte}}},
    // MOV L,#byte
    {0x56U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R6, OPT::byte}}},
    // MOV H,#byte
    {0x57U, {RL78::MOV_r_imm, {SBP::data}, {RL78::R7, OPT::byte}}},
    // MOV saddr,#byte
    {0xCDU, {RL78::STORE8_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // MOV A,saddr
    {0x8DU, {RL78::LOAD8_rlo_saddr, {SBP::saddr}, {RL78::R1, OPT::saddr}}},
    // MOV X,saddr
    {0xD8U, {RL78::LOAD8_rlo_saddr, {SBP::saddr}, {RL78::R0, OPT::saddr}}},
    // MOV B,saddr
    {0xE8U, {RL78::LOAD8_rlo_saddr, {SBP::saddr}, {RL78::R3, OPT::saddr}}},
    // MOV C,saddr
    {0xF8U, {RL78::LOAD8_rlo_saddr, {SBP::saddr}, {RL78::R2, OPT::saddr}}},
    // MOV saddr,A
    {0x9DU, {RL78::STORE8_saddr_A, {SBP::saddr}, {OPT::saddr, RL78::R1}}},
    // MOV !addr16,#byte
    {0xCFU, {RL78::STORE8_abs16_imm, {SBP::adrl, SBP::adrh, SBP::data}, {OPT::I_addr16, OPT::byte}}},
    // MOV !addr16,A
    {0x9FU, {RL78::STORE8_abs16_r, {SBP::adrl, SBP::adrh}, {OPT::I_addr16, RL78::R1}}},
    // MOV [HL+B],A
    {0x61U, {RL78::STORE8_memrr_r, {0xD9U}, {OPT::memHL_B, RL78::R1}}},
    // MOV [HL+C],A
    {0x61U, {RL78::STORE8_memrr_r, {0xF9U}, {OPT::memHL_C, RL78::R1}}},
    // MOV word[BC],#byte
    {0x39U, {RL78::STORE8_ri_imm, {SBP::adrl, SBP::adrh, SBP::data}, {OPT::word_memBC, OPT::byte}}},
    // MOV [DE+byte],#byte
    {0xCAU, {RL78::STORE8_memDEi_imm, {SBP::adr, SBP::data}, {OPT::memDE_byte, OPT::byte}}},
    // MOV [HL+byte],#byte
    {0xCCU, {RL78::STORE8_memHLi_imm, {SBP::adr, SBP::data}, {OPT::memHL_byte, OPT::byte}}},
    // MOV word[BC],A
    {0x48U, {RL78::STORE8_ri_r, {SBP::adrl, SBP::adrh}, {OPT::word_memBC, RL78::R1}}},
    // MOV [DE],A*/ 
    {0x99U, {RL78::STORE8_memDE_r, {}, {OPT::memDE, RL78::R1}}},
    // MOV [DE+byte],A
    {0x9AU, {RL78::STORE8_memDEi_r, {SBP::adr}, {OPT::memDE_byte, RL78::R1}}},
    // MOV [HL],A*/ 
    {0x9BU, {RL78::STORE8_memHL_r, {}, {OPT::memHL0, RL78::R1}}},
    // MOV [HL+byte],A
    {0x9CU, {RL78::STORE8_memHLi_r, {SBP::adr}, {OPT::memHL_byte, RL78::R1}}},
    // MOV [SP+byte],#byte
    {0xC8U, {RL78::STORE8_stack_slot_imm, {SBP::adr, SBP::data}, {OPT::memSP_byte, OPT::byte}}},
    // MOV [SP+byte],A
    {0x98U, {RL78::STORE8_stack_slot_r, {SBP::adr}, {OPT::memSP_byte, RL78::R1}}},
    // MOV A,word[B]
    {0x9U, {RL78::LOAD8_r_ri, {SBP::adrl, SBP::adrh}, {RL78::R1,OPT::word_memB}}},
    // MOV A,ES:!addr16
    {0x11U, {RL78::MOV_r_esaddr16, {0x8FU, SBP::adrl, SBP::adrh}, {RL78::R1,OPT::ES_I_addr16}}},
    // MOV A,ES:[DE]
    {0x11U, {RL78::LOAD8_a_esmemDE, {0x89U}, {RL78::R1,OPT::ES_memDE}}},
    // MOV A,ES:[DE+byte]
    {0x11U, {RL78::LOAD8_a_esmemDEi, {0x8AU, SBP::adr}, {RL78::R1,OPT::ES_memDE_byte}}},
    // MOV A,ES:[HL]
    {0x11U, {RL78::LOAD8_rp_esmemHL, {0x8BU}, {RL78::R1,OPT::ES_memHL0}}},
    // MOV A,ES:[HL+B]
    {0x11U, {RL78::LOAD8_a_esmemRpr, {0x61U, 0xC9U}, {RL78::R1,OPT::ES_memHL_B}}},
    // MOV A,ES:[HL+byte]
    {0x11U, {RL78::LOAD8_a_esmemHLi, {0x8CU, SBP::adr}, {RL78::R1,OPT::ES_memHL_byte}}},
    // MOV A,ES:[HL+C]
    {0x11U, {RL78::LOAD8_a_esmemRpr, {0x61U, 0xE9U}, {RL78::R1,OPT::ES_memHL_C}}},
    // MOV A,ES:word[B]
    {0x11U, {RL78::LOAD8_a_esrborci, {0x9U, SBP::adrl, SBP::adrh}, {RL78::R1,OPT::ES_word_memB}}},
    // MOV A,ES:word[BC]
    {0x11U, {RL78::LOAD8_r_esrpi, {0x49U, SBP::adrl, SBP::adrh}, {RL78::R1,OPT::ES_word_memBC}}},
    // MOV A,ES:word[C]
    {0x11U, {RL78::LOAD8_a_esrborci, {0x29U, SBP::adrl, SBP::adrh}, {RL78::R1,OPT::ES_word_memC}}},
    // MOV B,ES:!addr16
    {0x11U, {RL78::MOV_r_esaddr16, {0xE9U, SBP::adrl, SBP::adrh}, {RL78::R3,OPT::ES_I_addr16}}},
    // MOV C,ES:!addr16
    {0x11U, {RL78::MOV_r_esaddr16, {0xF9U, SBP::adrl, SBP::adrh}, {RL78::R2,OPT::ES_I_addr16}}},
    // MOV ES:!addr16,#byte
    {0x11U, {RL78::MOV_esaddr16_imm, {0xCFU, SBP::adrl, SBP::adrh, SBP::data}, {OPT::ES_I_addr16,OPT::byte}}},
    // MOV ES:!addr16,A
    {0x11U, {RL78::MOV_esaddr16_a, {0x9FU, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,RL78::R1}}},
    // MOV ES:[DE],A
    {0x11U, {RL78::STORE8_esmemDE_r, {0x99U}, {OPT::ES_memDE,RL78::R1}}},
    // MOV ES:[DE+byte],#byte
    {0x11U, {RL78::STORE8_esmemDEi_imm, {0xCAU, SBP::adr, SBP::data}, {OPT::ES_memDE_byte,OPT::byte}}},
    // MOV ES:[DE+byte],A
    {0x11U, {RL78::STORE8_esmemDEi_a, {0x9AU, SBP::adr}, {OPT::ES_memDE_byte,RL78::R1}}},
    // MOV ES:[HL],A
    {0x11U, {RL78::STORE8_esmemHL_a, {0x9BU}, {OPT::ES_memHL0,RL78::R1}}},
    // MOV ES:[HL+B],A
    {0x11U, {RL78::STORE8_esmemRpr_a, {0x61U, 0xD9U}, {OPT::ES_memHL_B,RL78::R1}}},
    // MOV ES:[HL+byte],#byte
    {0x11U, {RL78::STORE8_esmemHLi_imm, {0xCCU, SBP::adr, SBP::data}, {OPT::ES_memHL_byte,OPT::byte}}},
    // MOV ES:[HL+byte],A
    {0x11U, {RL78::STORE8_esmemHLi_a, {0x9CU, SBP::adr}, {OPT::ES_memHL_byte,RL78::R1}}},
    // MOV ES:[HL+C],A
    {0x11U, {RL78::STORE8_esmemRpr_a, {0x61U, 0xF9U}, {OPT::ES_memHL_C,RL78::R1}}},
    // MOV ES:word[B],#byte
    {0x11U, {RL78::STORE8_esmemBCi_imm, {0x19U, SBP::adrl, SBP::adrh, SBP::data}, {OPT::ES_word_memB,OPT::byte}}},
    // MOV ES:word[B],A
    {0x11U, {RL78::STORE8_esrborci_r, {0x18U, SBP::adrl, SBP::adrh}, {OPT::ES_word_memB,RL78::R1}}},
    // MOV ES:word[BC],#byte
    {0x11U, {RL78::STORE8_esmemBCi_imm, {0x39U, SBP::adrl, SBP::adrh, SBP::data}, {OPT::ES_word_memBC,OPT::byte}}},
    // MOV ES:word[BC],A
    {0x11U, {RL78::STORE8_esrpi_r, {0x48U, SBP::adrl, SBP::adrh}, {OPT::ES_word_memBC,RL78::R1}}},
    // MOV ES:word[C],#byte
    {0x11U, {RL78::STORE8_esmemBorCi_imm, {0x38U, SBP::adrl, SBP::adrh, SBP::data}, {OPT::ES_word_memC,OPT::byte}}},
    // MOV ES:word[C],A
    {0x11U, {RL78::STORE8_esrborci_r, {0x28U, SBP::adrl, SBP::adrh}, {OPT::ES_word_memC,RL78::R1}}},
    // MOV X,ES:!addr16
    {0x11U, {RL78::MOV_r_esaddr16, {0xD9U, SBP::adrl, SBP::adrh}, {RL78::R0,OPT::ES_I_addr16}}},
    // MOV word[B],A
    {0x18U, {RL78::STORE8_ri_r, {SBP::adrl, SBP::adrh}, {OPT::word_memB,RL78::R1}}},
    // MOV word[B],#byte
    {0x19U, {RL78::STORE8_ri_imm, {SBP::adrl, SBP::adrh, SBP::data}, {OPT::word_memB,OPT::byte}}},
    // MOV word[C],A
    {0x28U, {RL78::STORE8_ri_r, {SBP::adrl, SBP::adrh}, {OPT::word_memC,RL78::R1}}},
    // MOV A,word[C]
    {0x29U, {RL78::LOAD8_r_ri, {SBP::adrl, SBP::adrh}, {RL78::R1,OPT::word_memC}}},
    // MOV word[C],#byte
    {0x38U, {RL78::STORE8_ri_imm, {SBP::adrl, SBP::adrh, SBP::data}, {OPT::word_memC,OPT::byte}}},
    // MOV ES,saddr
    {0x61U, {RL78::MOV_es_saddr, {0xB8U, SBP::saddr}, {RL78::ES,OPT::saddr}}},
    // MOV A,PSW
    {0x8EU, {RL78::MOV_A_PSW, {0xFAU}, {RL78::R1}}},
    // MOV A,sfr
    {0x8EU, {RL78::LOAD8_r_sfr, {SBP::sfr}, {RL78::R1,OPT::sfr}}},
    // MOV PSW,A
    {0x9EU, {RL78::MOV_PSW_A, {0xFAU}, {RL78::R1}}},
    // MOV sfr,A
    {0x9EU, {RL78::STORE8_sfr_r, {SBP::sfr}, {OPT::sfr,RL78::R1}}},
    // MOV CS,#byte
    {0xCEU, {RL78::MOV_cs_imm, {0xFCU, SBP::data}, {RL78::CS, OPT::byte}}},
    // MOV PSW,#byte
    {0xCEU, {RL78::MOV_psw_imm, {0xFAU, SBP::data}, {RL78::PSW, OPT::byte}}},
    // MOV sfr,#byte
    {0xCEU, {RL78::STORE8_sfr_imm, {SBP::sfr, SBP::data}, {OPT::sfr, OPT::byte}}},
    // MOV1 CY,[HL].0
    {0x71U, {RL78::MOV1_cy_memr, {0x84U}, {OPT::memHL, OPT::imm0}}},
    // MOV1 CY,[HL].1
    {0x71U, {RL78::MOV1_cy_memr, {0x94U}, {OPT::memHL, OPT::imm1}}},
    // MOV1 CY,[HL].2
    {0x71U, {RL78::MOV1_cy_memr, {0xA4U}, {OPT::memHL, OPT::imm2}}},
    // MOV1 CY,[HL].3
    {0x71U, {RL78::MOV1_cy_memr, {0xB4U}, {OPT::memHL, OPT::imm3}}},
    // MOV1 CY,[HL].4
    {0x71U, {RL78::MOV1_cy_memr, {0xC4U}, {OPT::memHL, OPT::imm4}}},
    // MOV1 CY,[HL].5
    {0x71U, {RL78::MOV1_cy_memr, {0xD4U}, {OPT::memHL, OPT::imm5}}},
    // MOV1 CY,[HL].6
    {0x71U, {RL78::MOV1_cy_memr, {0xE4U}, {OPT::memHL, OPT::imm6}}},
    // MOV1 CY,[HL].7
    {0x71U, {RL78::MOV1_cy_memr, {0xF4U}, {OPT::memHL, OPT::imm7}}},
    // MOV1 CY,PSW.0*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x0CU, 0xFAU}, {RL78::PSW, OPT::imm0}}},
    // MOV1 CY,PSW.1*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x1CU, 0xFAU}, {RL78::PSW,OPT::imm1}}},
    // MOV1 CY,PSW.2*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x2CU, 0xFAU}, {RL78::PSW,OPT::imm2}}},
    // MOV1 CY,PSW.3*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x3CU, 0xFAU}, {RL78::PSW,OPT::imm3}}},
    // MOV1 CY,PSW.4*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x4CU, 0xFAU}, {RL78::PSW,OPT::imm4}}},
    // MOV1 CY,PSW.5*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x5CU, 0xFAU}, {RL78::PSW,OPT::imm5}}},
    // MOV1 CY,PSW.6*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x6CU, 0xFAU}, {RL78::PSW,OPT::imm6}}},
    // MOV1 CY,PSW.7*/ 
    {0x71U, {RL78::MOV1_cy_psw, {0x7CU, 0xFAU}, {RL78::PSW,OPT::imm7}}},
    // MOV1 CY,A.0*/ 
    {0x71U, {RL78::MOV1_cy_r, {0x8CU}, {RL78::R1, OPT::imm0}}},
    // MOV1 CY,A.1*/ 
    {0x71U, {RL78::MOV1_cy_r, {0x9CU}, {RL78::R1, OPT::imm1}}},
    // MOV1 CY,A.2
    {0x71U, {RL78::MOV1_cy_r, {0xACU}, {RL78::R1, OPT::imm2}}},
    // MOV1 CY,A.3
    {0x71U, {RL78::MOV1_cy_r, {0xBCU}, {RL78::R1, OPT::imm3}}},
    // MOV1 CY,A.4
    {0x71U, {RL78::MOV1_cy_r, {0xCCU}, {RL78::R1, OPT::imm4}}},
    // MOV1 CY,A.5
    {0x71U, {RL78::MOV1_cy_r, {0xDCU}, {RL78::R1, OPT::imm5}}},
    // MOV1 CY,A.6
    {0x71U, {RL78::MOV1_cy_r, {0xECU}, {RL78::R1, OPT::imm6}}},
    // MOV1 CY,A.7
    {0x71U, {RL78::MOV1_cy_r, {0xFCU}, {RL78::R1, OPT::imm7}}},
    // MOV1 CY,saddr.0
    {0x71U, {RL78::MOV1_cy_saddr, {0x4U, SBP::saddr}, {OPT::saddr, OPT::imm0}}},
    // MOV1 CY,saddr.1
    {0x71U, {RL78::MOV1_cy_saddr, {0x14U, SBP::saddr}, {OPT::saddr, OPT::imm1}}},
    // MOV1 CY,saddr.2
    {0x71U, {RL78::MOV1_cy_saddr, {0x24U, SBP::saddr}, {OPT::saddr, OPT::imm2}}},
    // MOV1 CY,saddr.3
    {0x71U, {RL78::MOV1_cy_saddr, {0x34U, SBP::saddr}, {OPT::saddr, OPT::imm3}}},
    // MOV1 CY,saddr.4
    {0x71U, {RL78::MOV1_cy_saddr, {0x44U, SBP::saddr}, {OPT::saddr, OPT::imm4}}},
    // MOV1 CY,saddr.5
    {0x71U, {RL78::MOV1_cy_saddr, {0x54U, SBP::saddr}, {OPT::saddr, OPT::imm5}}},
    // MOV1 CY,saddr.6
    {0x71U, {RL78::MOV1_cy_saddr, {0x64U, SBP::saddr}, {OPT::saddr, OPT::imm6}}},
    // MOV1 CY,saddr.7
    {0x71U, {RL78::MOV1_cy_saddr, {0x74U, SBP::saddr}, {OPT::saddr, OPT::imm7}}},
    // MOV1 [HL].0,CY
    {0x71U, {RL78::MOV1_memr_cy, {0x81U}, {OPT::memHL, OPT::imm0}}},
    // MOV1 [HL].1,CY
    {0x71U, {RL78::MOV1_memr_cy, {0x91U}, {OPT::memHL, OPT::imm1}}},
    // MOV1 [HL].2,CY
    {0x71U, {RL78::MOV1_memr_cy, {0xA1U}, {OPT::memHL, OPT::imm2}}},
    // MOV1 [HL].3,CY
    {0x71U, {RL78::MOV1_memr_cy, {0xB1U}, {OPT::memHL, OPT::imm3}}},
    // MOV1 [HL].4,CY
    {0x71U, {RL78::MOV1_memr_cy, {0xC1U}, {OPT::memHL, OPT::imm4}}},
    // MOV1 [HL].5,CY
    {0x71U, {RL78::MOV1_memr_cy, {0xD1U}, {OPT::memHL, OPT::imm5}}},
    // MOV1 [HL].6,CY
    {0x71U, {RL78::MOV1_memr_cy, {0xE1U}, {OPT::memHL, OPT::imm6}}},
    // MOV1 [HL].7,CY
    {0x71U, {RL78::MOV1_memr_cy, {0xF1U}, {OPT::memHL, OPT::imm7}}},
    // MOV1 PSW.0,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x9U, 0xFAU},  {RL78::PSW, OPT::imm0}}},
    // MOV1 PSW.1,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x19U, 0xFAU}, {RL78::PSW, OPT::imm1}}},
    // MOV1 PSW.2,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x29U, 0xFAU}, {RL78::PSW, OPT::imm2}}},
    // MOV1 PSW.3,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x39U, 0xFAU}, {RL78::PSW, OPT::imm3}}},
    // MOV1 PSW.4,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x49U, 0xFAU}, {RL78::PSW, OPT::imm4}}},
    // MOV1 PSW.5,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x59U, 0xFAU}, {RL78::PSW, OPT::imm5}}},
    // MOV1 PSW.6,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x69U, 0xFAU}, {RL78::PSW, OPT::imm6}}},
    // MOV1 PSW.7,CY
    {0x71U, {RL78::MOV1_psw_cy, {0x79U, 0xFAU}, {RL78::PSW, OPT::imm7}}},
    // MOV1 A.0,CY
    {0x71U, {RL78::MOV1_r_cy, {0x89U}, {RL78::R1, RL78::R1, OPT::imm0}}},
    // MOV1 A.1,CY
    {0x71U, {RL78::MOV1_r_cy, {0x99U}, {RL78::R1, RL78::R1, OPT::imm1}}},
    // MOV1 A.2,CY
    {0x71U, {RL78::MOV1_r_cy, {0xA9U}, {RL78::R1, RL78::R1, OPT::imm2}}},
    // MOV1 A.3,CY
    {0x71U, {RL78::MOV1_r_cy, {0xB9U}, {RL78::R1, RL78::R1, OPT::imm3}}},
    // MOV1 A.4,CY
    {0x71U, {RL78::MOV1_r_cy, {0xC9U}, {RL78::R1, RL78::R1, OPT::imm4}}},
    // MOV1 A.5,CY
    {0x71U, {RL78::MOV1_r_cy, {0xD9U}, {RL78::R1, RL78::R1, OPT::imm5}}},
    // MOV1 A.6,CY
    {0x71U, {RL78::MOV1_r_cy, {0xE9U}, {RL78::R1, RL78::R1, OPT::imm6}}},
    // MOV1 A.7,CY
    {0x71U, {RL78::MOV1_r_cy, {0xF9U}, {RL78::R1, RL78::R1, OPT::imm7}}},
    // MOV1 saddr.0,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x1U, SBP::saddr}, {OPT::saddr, OPT::imm0}}},
    // MOV1 saddr.1,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x11U, SBP::saddr}, {OPT::saddr, OPT::imm1}}},
    // MOV1 saddr.2,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x21U, SBP::saddr}, {OPT::saddr,  OPT::imm2}}},
    // MOV1 saddr.3,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x31U, SBP::saddr}, {OPT::saddr,  OPT::imm3}}},
    // MOV1 saddr.4,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x41U, SBP::saddr}, {OPT::saddr,  OPT::imm4}}},
    // MOV1 saddr.5,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x51U, SBP::saddr}, {OPT::saddr,  OPT::imm5}}},
    // MOV1 saddr.6,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x61U, SBP::saddr}, {OPT::saddr,  OPT::imm6}}},
    // MOV1 saddr.7,CY
    {0x71U, {RL78::MOV1_saddr_cy, {0x71U, SBP::saddr}, {OPT::saddr,  OPT::imm7}}},
    // MOV1 CY,ES:[HL].0
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0x84U}, {RL78::CY, OPT::ES_memHL,OPT::imm0}}},
    // MOV1 CY,ES:[HL].1
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0x94U}, {RL78::CY, OPT::ES_memHL,OPT::imm1}}},
    // MOV1 CY,ES:[HL].2
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0xA4U}, {RL78::CY, OPT::ES_memHL,OPT::imm2}}},
    // MOV1 CY,ES:[HL].3
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0xB4U}, {RL78::CY, OPT::ES_memHL,OPT::imm3}}},
    // MOV1 CY,ES:[HL].4
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0xC4U}, {RL78::CY, OPT::ES_memHL,OPT::imm4}}},
    // MOV1 CY,ES:[HL].5
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0xD4U}, {RL78::CY, OPT::ES_memHL,OPT::imm5}}},
    // MOV1 CY,ES:[HL].6
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0xE4U}, {RL78::CY, OPT::ES_memHL,OPT::imm6}}},
    // MOV1 CY,ES:[HL].7
    {0x11U, {RL78::MOV1_cy_esmemr, {0x71U, 0xF4U}, {RL78::CY, OPT::ES_memHL,OPT::imm7}}},
    // MOV1 ES:[HL].0,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0x81U}, {OPT::ES_memHL,OPT::imm0, RL78::CY}}},
    // MOV1 ES:[HL].1,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0x91U}, {OPT::ES_memHL,OPT::imm1, RL78::CY}}},
    // MOV1 ES:[HL].2,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0xA1U}, {OPT::ES_memHL,OPT::imm2, RL78::CY}}},
    // MOV1 ES:[HL].3,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0xB1U}, {OPT::ES_memHL,OPT::imm3, RL78::CY}}},
    // MOV1 ES:[HL].4,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0xC1U}, {OPT::ES_memHL,OPT::imm4, RL78::CY}}},
    // MOV1 ES:[HL].5,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0xD1U}, {OPT::ES_memHL,OPT::imm5, RL78::CY}}},
    // MOV1 ES:[HL].6,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0xE1U}, {OPT::ES_memHL,OPT::imm6, RL78::CY}}},
    // MOV1 ES:[HL].7,CY
    {0x11U, {RL78::MOV1_esmemr_cy, {0x71U, 0xF1U}, {OPT::ES_memHL,OPT::imm7, RL78::CY}}},
    // MOV1 CY,sfr.0
    {0x71U, {RL78::MOV1_cy_sfr, {0x0CU, SBP::sfr}, {OPT::sfr,OPT::imm0}}},
    // MOV1 CY,sfr.1
    {0x71U, {RL78::MOV1_cy_sfr, {0x1CU, SBP::sfr}, {OPT::sfr,OPT::imm1}}},
    // MOV1 CY,sfr.2
    {0x71U, {RL78::MOV1_cy_sfr, {0x2CU, SBP::sfr}, {OPT::sfr,OPT::imm2}}},
    // MOV1 CY,sfr.3
    {0x71U, {RL78::MOV1_cy_sfr, {0x3CU, SBP::sfr}, {OPT::sfr,OPT::imm3}}},
    // MOV1 CY,sfr.4
    {0x71U, {RL78::MOV1_cy_sfr, {0x4CU, SBP::sfr}, {OPT::sfr,OPT::imm4}}},
    // MOV1 CY,sfr.5
    {0x71U, {RL78::MOV1_cy_sfr, {0x5CU, SBP::sfr}, {OPT::sfr,OPT::imm5}}},
    // MOV1 CY,sfr.6
    {0x71U, {RL78::MOV1_cy_sfr, {0x6CU, SBP::sfr}, {OPT::sfr,OPT::imm6}}},
    // MOV1 CY,sfr.7
    {0x71U, {RL78::MOV1_cy_sfr, {0x7CU, SBP::sfr}, {OPT::sfr,OPT::imm7}}},
    // MOV1 sfr.0,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x9U, SBP::sfr}, {OPT::sfr,OPT::imm0}}},
    // MOV1 sfr.1,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x19U, SBP::sfr}, {OPT::sfr,OPT::imm1}}},
    // MOV1 sfr.2,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x29U, SBP::sfr}, {OPT::sfr,OPT::imm2}}},
    // MOV1 sfr.3,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x39U, SBP::sfr}, {OPT::sfr,OPT::imm3}}},
    // MOV1 sfr.4,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x49U, SBP::sfr}, {OPT::sfr,OPT::imm4}}},
    // MOV1 sfr.5,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x59U, SBP::sfr}, {OPT::sfr,OPT::imm5}}},
    // MOV1 sfr.6,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x69U, SBP::sfr}, {OPT::sfr,OPT::imm6}}},
    // MOV1 sfr.7,CY
    {0x71U, {RL78::MOV1_sfr_cy, {0x79U, SBP::sfr}, {OPT::sfr,OPT::imm7}}},
    // MOVS [HL+byte],X
    {0x61U, {RL78::MOVS_memri_r, {0xCEU, SBP::adr}, {OPT::memHL_byte, RL78::R0}}},
    // MOVS ES:[HL+byte],X
    {0x11U, {RL78::MOVS_Esmemri_r, {0x61U, 0xCEU, SBP::adr}, {OPT::ES_memHL_byte,RL78::R0}}},
    // MOVW AX,!addr16
    {0xAFU, {RL78::LOAD16_rp_abs16, {SBP::adrl, SBP::adrh}, {RL78::RP0, OPT::I_addr16}}},
    // MOVW BC,!addr16
    {0xDBU, {RL78::LOAD16_rp_abs16, {SBP::adrl, SBP::adrh}, {RL78::RP2, OPT::I_addr16}}},
    // MOVW DE,!addr16
    {0xEBU, {RL78::LOAD16_rp_abs16, {SBP::adrl, SBP::adrh}, {RL78::RP4, OPT::I_addr16}}},
    // MOVW HL,!addr16
    {0xFBU, {RL78::LOAD16_rp_abs16, {SBP::adrl, SBP::adrh}, {RL78::RP6, OPT::I_addr16}}},
    // MOVW AX,ES:word[BC]
    {0x11U, {RL78::LOAD16_rp_esrpi, {0x79U, SBP::adrl, SBP::adrh}, {RL78::RP0, OPT::ES_word_memBC}}},
    // MOVW AX,word[BC]
    {0x79U, {RL78::LOAD16_rp_rpi, {SBP::adrl, SBP::adrh}, {RL78::RP0, OPT::word_memBC}}},
    // MOVW AX,[DE]
    {0xA9U, {RL78::LOAD16_rp_rpi, {}, {RL78::RP0, OPT::memDE}}},
    // MOVW AX,[DE+byte]
    {0xAAU, {RL78::LOAD16_rp_rpi, {SBP::adr}, {RL78::RP0, OPT::memDE_byte}}},
    // MOVW AX,[HL]
    {0xABU, {RL78::LOAD16_rp_rpi, {}, {RL78::RP0, OPT::memHL0}}},
    // MOVW AX,[HL+byte]
    {0xACU, {RL78::LOAD16_rp_rpi, {SBP::adr}, {RL78::RP0, OPT::memHL_byte}}},
    // MOVW AX,[SP+byte]
    {0xA8U, {RL78::LOAD16_rp_stack_slot, {SBP::adr}, {RL78::RP0, OPT::memSP_byte}}},
    // MOVW AX,BC*/ 
    {0x13U, {RL78::MOVW_AX_rp, {}, {RL78::RP0, RL78::RP2}}},
    // MOVW AX,DE*/ 
    {0x15U, {RL78::MOVW_AX_rp, {}, {RL78::RP0, RL78::RP4}}},
    // MOVW AX,HL*/ 
    {0x17U, {RL78::MOVW_AX_rp, {}, {RL78::RP0, RL78::RP6}}},
    // MOVW AX,saddrp
    {0xADU, {RL78::LOAD16_rp_saddrp, {SBP::saddr}, {RL78::RP0, OPT::saddrp}}},
    // MOVW BC,AX*/ 
    {0x12U, {RL78::MOVW_rp_AX, {}, {RL78::RP2, RL78::RP0}}},
    // MOVW DE,AX*/ 
    {0x14U, {RL78::MOVW_rp_AX, {}, {RL78::RP4, RL78::RP0}}},
    // MOVW HL,AX*/ 
    {0x16U, {RL78::MOVW_rp_AX, {}, {RL78::RP6, RL78::RP0}}},
    // MOVW AX,#word
    {0x30U, {RL78::MOVW_rp_imm, {SBP::datal, SBP::datah}, {RL78::RP0, OPT::word}}},
    // MOVW BC,#word
    {0x32U, {RL78::MOVW_rp_imm, {SBP::datal, SBP::datah}, {RL78::RP2, OPT::word}}},
    // MOVW DE,#word
    {0x34U, {RL78::MOVW_rp_imm, {SBP::datal, SBP::datah}, {RL78::RP4, OPT::word}}},
    // MOVW HL,#word
    {0x36U, {RL78::MOVW_rp_imm, {SBP::datal, SBP::datah}, {RL78::RP6, OPT::word}}},
    // MOVW saddrp,#word
    {0xC9U, {RL78::MOVW_saddrp_imm, {SBP::saddr, SBP::datal, SBP::datah}, {OPT::saddrp, OPT::word}}},
    // MOVW BC,saddrp
    {0xDAU, {RL78::LOAD16_rp_saddrp, {SBP::saddr}, {RL78::RP2, OPT::saddrp}}},
    // MOVW DE,saddrp
    {0xEAU, {RL78::LOAD16_rp_saddrp, {SBP::saddr}, {RL78::RP4, OPT::saddrp}}},
    // MOVW HL,saddrp
    {0xFAU, {RL78::LOAD16_rp_saddrp, {SBP::saddr}, {RL78::RP6, OPT::saddrp}}},
    // MOVW AX,SP
    {0xAEU, {RL78::MOVW_rp_sp, {0xF8U}, {RL78::RP0, RL78::SPreg}}},
    // MOVW BC,SP
    {0xDBU, {RL78::MOVW_rp_sp, {0xF8U, 0xF9U}, {RL78::RP2, RL78::SPreg}}},
    // MOVW DE,SP
    {0xEBU, {RL78::MOVW_rp_sp, {0xF8U, 0xF9U}, {RL78::RP4, RL78::SPreg}}},
    // MOVW HL,SP
    {0xFBU, {RL78::MOVW_rp_sp, {0xF8U, 0xF9U}, {RL78::RP6, RL78::SPreg}}},
    // MOVW saddrp,AX
    {0xBDU, {RL78::STORE16_saddrp_rp, {SBP::saddr}, {OPT::saddrp, RL78::RP0}}},
    // MOVW SP,#word
    {0xCBU, {RL78::MOVW_sp_imm, {0xF8U, SBP::datal, SBP::datah}, {RL78::SPreg, OPT::word}}},
    // MOVW SP,AX
    {0xBEU, {RL78::MOVW_sp_rp, {0xF8U}, {RL78::SPreg, RL78::RP0}}},
    // MOVW !addr16,AX
    {0xBFU, {RL78::STORE16_abs16_rp, {SBP::adrl, SBP::adrh}, {OPT::I_addr16, RL78::RP0}}},
    // MOVW ES:word[BC],AX
    {0x11U, {RL78::STORE16_esrpi_rp, {0x78U, SBP::adrl, SBP::adrh}, {OPT::ES_word_memBC, RL78::RP0}}},
    // MOVW word[BC],AX
    {0x78U, {RL78::STORE16_rpi_rp, {SBP::adrl, SBP::adrh}, {OPT::word_memBC, RL78::RP0}}},
    // MOVW [DE],AX
    {0xB9U, {RL78::STORE16_rpi_rp, {}, {OPT::memDE, RL78::RP0}}},
    // MOVW [DE+byte],AX
    {0xBAU, {RL78::STORE16_rpi_rp, {SBP::adr}, {OPT::memDE_byte, RL78::RP0}}},
    // MOVW [HL],AX
    {0xBBU, {RL78::STORE16_rpi_rp, {}, {OPT::memHL0, RL78::RP0}}},
    // MOVW [HL+byte],AX
    {0xBCU, {RL78::STORE16_rpi_rp, {SBP::adr}, {OPT::memHL_byte, RL78::RP0}}},
    // MOVW [SP+byte],AX
    {0xB8U, {RL78::STORE16_stack_slot_rp, {SBP::adr}, {OPT::memSP_byte, RL78::RP0}}},
    // MOVW AX,ES:!addr16
    {0x11U, {RL78::LOAD16_rp_esaddr16, {0xAFU, SBP::adrl, SBP::adrh}, {RL78::RP0,OPT::ES_I_addr16}}},
    // MOVW AX,ES:[DE]
    {0x11U, {RL78::LOAD16_rp_esmemDE, {0xA9U}, {RL78::RP0,OPT::ES_memDE}}},
    // MOVW AX,ES:[DE+byte]
    {0x11U, {RL78::LOAD16_rp_esmemDEi, {0xAAU, SBP::adr}, {RL78::RP0,OPT::ES_memDE_byte}}},
    // MOVW AX,ES:[HL]
    {0x11U, {RL78::LOAD16_rp_esmemHL, {0xABU}, {RL78::RP0,OPT::ES_memHL0}}},
    // MOVW AX,ES:[HL+byte]
    {0x11U, {RL78::LOAD16_rp_esmemHLi, {0xACU, SBP::adr}, {RL78::RP0,OPT::ES_memHL_byte}}},
    // MOVW AX,ES:word[B]
    {0x11U, {RL78::LOAD16_rp_esrbci, {0x59U, SBP::adrl, SBP::adrh}, {RL78::RP0,OPT::ES_word_memB}}},
    // MOVW AX,ES:word[C]
    {0x11U, {RL78::LOAD16_rp_esrbci, {0x69U, SBP::adrl, SBP::adrh}, {RL78::RP0,OPT::ES_word_memC}}},
    // MOVW BC,ES:!addr16
    {0x11U, {RL78::LOAD16_rp_esaddr16, {0xDBU, SBP::adrl, SBP::adrh}, {RL78::RP2,OPT::ES_I_addr16}}},
    // MOVW DE,ES:!addr16
    {0x11U, {RL78::LOAD16_rp_esaddr16, {0xEBU, SBP::adrl, SBP::adrh}, {RL78::RP4,OPT::ES_I_addr16}}},
    // MOVW ES:!addr16,AX
    {0x11U, {RL78::STORE16_esaddr16_rp, {0xBFU, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,RL78::RP0}}},
    // MOVW ES:[DE],AX
    {0x11U, {RL78::STORE16_esmemDE_rp, {0xB9U}, {OPT::ES_memDE,RL78::RP0}}},
    // MOVW ES:[DE+byte],AX
    {0x11U, {RL78::STORE16_esmemDEi_rp, {0xBAU, SBP::adr}, {OPT::ES_memDE_byte,RL78::RP0}}},
    // MOVW ES:[HL],AX
    {0x11U, {RL78::STORE16_esmemHL_rp, {0xBBU}, {OPT::ES_memHL0,RL78::RP0}}},
    // MOVW ES:[HL+byte],AX
    {0x11U, {RL78::STORE16_esmemHLi_rp, {0xBCU, SBP::adr}, {OPT::ES_memHL_byte,RL78::RP0}}},
    // MOVW ES:word[B],AX
    {0x11U, {RL78::STORE16_esrbci_rp, {0x58U, SBP::adrl, SBP::adrh}, {OPT::ES_word_memB,RL78::RP0}}},
    // MOVW ES:word[C],AX
    {0x11U, {RL78::STORE16_esrbci_rp, {0x68U, SBP::adrl, SBP::adrh}, {OPT::ES_word_memC,RL78::RP0}}},
    // MOVW HL,ES:!addr16
    {0x11U, {RL78::LOAD16_rp_esaddr16, {0xFBU, SBP::adrl, SBP::adrh}, {RL78::RP6,OPT::ES_I_addr16}}},
    // MOVW word[B],AX
    {0x58U, {RL78::STORE16_rbci_rp, {SBP::adrl, SBP::adrh}, {OPT::word_memB,RL78::RP0}}},
    // MOVW AX,word[B]
    {0x59U, {RL78::LOAD16_rp_rbci, {SBP::adrl, SBP::adrh}, {RL78::RP0,OPT::word_memB}}},
    // MOVW word[C],AX
    {0x68U, {RL78::STORE16_rbci_rp, {SBP::adrl, SBP::adrh}, {OPT::word_memC,RL78::RP0}}},
    // MOVW AX,word[C]
    {0x69U, {RL78::LOAD16_rp_rbci, {SBP::adrl, SBP::adrh}, {RL78::RP0,OPT::word_memC}}},
    // MOVW AX,sfrp
    {0xAEU, {RL78::LOAD16_rp_sfrp, {SBP::sfr}, {RL78::RP0,OPT::sfrp}}},
    // MOVW sfrp,AX
    {0xBEU, {RL78::STORE16_sfrp_rp, {SBP::sfr}, {OPT::sfrp,RL78::RP0}}},
    // MOVW sfrp,#word
    {0xCBU, {RL78::STORE16_sfrp_imm, {SBP::sfr, SBP::datal, SBP::datah}, {OPT::sfrp,OPT::word}}},
    // MULU X*/ 
    {0xD6U, {RL78::MULU_r, {}, {RL78::R0}}},
    // NOP nan*/ 
    {0x0U, {RL78::NOP, {}, {}}},
    // NOT1 CY*/ 
    {0x71U, {RL78::NOT1_cy, {0xC0U}, {}}},
    // ONEB !addr16
    {0xE5U, {RL78::ONEB_abs16, {SBP::adrl, SBP::adrh}, {OPT::I_addr16}}},
    // ONEB X*/ 
    {0xE0U, {RL78::ONEB_r, {}, {RL78::R0}}},
    // ONEB A*/ 
    {0xE1U, {RL78::ONEB_r, {}, {RL78::R1}}},
    // ONEB C*/ 
    {0xE2U, {RL78::ONEB_r, {}, {RL78::R2}}},
    // ONEB B*/ 
    {0xE3U, {RL78::ONEB_r, {}, {RL78::R3}}},
    // ONEB saddr*/ 
    {0xE4U, {RL78::ONEB_saddr, {SBP::saddr}, {OPT::saddr}}},
    // ONEB ES:!addr16
    {0x11U, {RL78::ONEB_esaddr16, {0xE5U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16}}},
    // ONEW AX*/ 
    {0xE6U, {RL78::ONEW_rp, {}, {RL78::RP0}}},
    // ONEW BC*/ 
    {0xE7U, {RL78::ONEW_rp, {}, {RL78::RP2}}},
    // OR A,!addr16
    {0x6FU, {RL78::OR_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // OR saddr,#byte
    {0x6AU, {RL78::OR_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // OR A,#byte
    {0x6CU, {RL78::OR_r_imm, {SBP::data}, {RL78::R1, RL78::R1, OPT::byte}}},
    // OR A,[HL]
    {0x6DU, {RL78::OR_r_memri, {}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // OR A,[HL+byte]
    {0x6EU, {RL78::OR_r_memri, {SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // OR A,[HL+B]
    {0x61U, {RL78::OR_r_memrr, {0xE0U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // OR A,[HL+C]
    {0x61U, {RL78::OR_r_memrr, {0xE2U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // OR A,A*/ 
    {0x61U, {RL78::OR_r_r, {0x61U}, {RL78::R1, RL78::R1, RL78::R1}}},
    // OR A,B*/ 
    {0x61U, {RL78::OR_r_r, {0x6BU}, {RL78::R1, RL78::R1, RL78::R3}}},
    // OR A,C*/ 
    {0x61U, {RL78::OR_r_r, {0x6AU}, {RL78::R1, RL78::R1, RL78::R2}}},
    // OR A,D*/ 
    {0x61U, {RL78::OR_r_r, {0x6DU}, {RL78::R1, RL78::R1, RL78::R5}}},
    // OR A,E*/ 
    {0x61U, {RL78::OR_r_r, {0x6CU}, {RL78::R1, RL78::R1, RL78::R4}}},
    // OR A,H
    {0x61U, {RL78::OR_r_r, {0x6FU}, {RL78::R1, RL78::R1, RL78::R7}}},
    // OR A,L
    {0x61U, {RL78::OR_r_r, {0x6EU}, {RL78::R1, RL78::R1, RL78::R6}}},
    // OR A,X
    {0x61U, {RL78::OR_r_r, {0x68U}, {RL78::R1, RL78::R1, RL78::R0}}},
    // OR B,A
    {0x61U, {RL78::OR_r_r, {0x63U}, {RL78::R3, RL78::R3, RL78::R1}}},
    // OR C,A
    {0x61U, {RL78::OR_r_r, {0x62U}, {RL78::R2, RL78::R2, RL78::R1}}},
    // OR D,A
    {0x61U, {RL78::OR_r_r, {0x65U}, {RL78::R5, RL78::R5, RL78::R1}}},
    // OR E,A
    {0x61U, {RL78::OR_r_r, {0x64U}, {RL78::R4, RL78::R4, RL78::R1}}},
    // OR H,A
    {0x61U, {RL78::OR_r_r, {0x67U}, {RL78::R7, RL78::R7, RL78::R1}}},
    // OR L,A
    {0x61U, {RL78::OR_r_r, {0x66U}, {RL78::R6, RL78::R6, RL78::R1}}},
    // OR X,A
    {0x61U, {RL78::OR_r_r, {0x60U}, {RL78::R0, RL78::R0, RL78::R1}}},
    // OR A,saddr
    {0x6BU, {RL78::OR_r_saddr, {SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // OR A,ES:!addr16
    {0x11U, {RL78::OR_r_esaddr16, {0x6FU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // OR A,ES:[HL]
    {0x11U, {RL78::OR_r_esmemHL, {0x6DU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // OR A,ES:[HL+B]
    {0x11U, {RL78::OR_r_esmemRpr, {0x61U, 0xE0U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // OR A,ES:[HL+byte]
    {0x11U, {RL78::OR_r_esmemHLi, {0x6EU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // OR A,ES:[HL+C]
    {0x11U, {RL78::OR_r_esmemRpr, {0x61U, 0xE2U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // OR1 CY,[HL].0
    {0x71U, {RL78::OR1_cy_memr, {0x86U}, {OPT::memHL, OPT::imm0}}},
    // OR1 CY,[HL].1
    {0x71U, {RL78::OR1_cy_memr, {0x96U}, {OPT::memHL, OPT::imm1}}},
    // OR1 CY,[HL].2
    {0x71U, {RL78::OR1_cy_memr, {0xA6U}, {OPT::memHL, OPT::imm2}}},
    // OR1 CY,[HL].3
    {0x71U, {RL78::OR1_cy_memr, {0xB6U}, {OPT::memHL, OPT::imm3}}},
    // OR1 CY,[HL].4
    {0x71U, {RL78::OR1_cy_memr, {0xC6U}, {OPT::memHL, OPT::imm4}}},
    // OR1 CY,[HL].5
    {0x71U, {RL78::OR1_cy_memr, {0xD6U}, {OPT::memHL, OPT::imm5}}},
    // OR1 CY,[HL].6
    {0x71U, {RL78::OR1_cy_memr, {0xE6U}, {OPT::memHL, OPT::imm6}}},
    // OR1 CY,[HL].7
    {0x71U, {RL78::OR1_cy_memr, {0xF6U}, {OPT::memHL, OPT::imm7}}},
    // OR1 CY,A.0*/ 
    {0x71U, {RL78::OR1_cy_r, {0x8EU}, {RL78::R1, OPT::imm0}}},
    // OR1 CY,A.1
    {0x71U, {RL78::OR1_cy_r, {0x9EU}, {RL78::R1, OPT::imm1}}},
    // OR1 CY,A.2
    {0x71U, {RL78::OR1_cy_r, {0xAEU}, {RL78::R1, OPT::imm2}}},
    // OR1 CY,A.3
    {0x71U, {RL78::OR1_cy_r, {0xBEU}, {RL78::R1, OPT::imm3}}},
    // OR1 CY,A.4
    {0x71U, {RL78::OR1_cy_r, {0xCEU}, {RL78::R1, OPT::imm4}}},
    // OR1 CY,A.5
    {0x71U, {RL78::OR1_cy_r, {0xDEU}, {RL78::R1, OPT::imm5}}},
    // OR1 CY,A.6
    {0x71U, {RL78::OR1_cy_r, {0xEEU}, {RL78::R1, OPT::imm6}}},
    // OR1 CY,A.7
    {0x71U, {RL78::OR1_cy_r, {0xFEU}, {RL78::R1, OPT::imm7}}},
    // OR1 CY,saddr.0
    {0x71U, {RL78::OR1_cy_saddrx, {0x6U, SBP::saddr}, {OPT::saddr, OPT::imm0}}},
    // OR1 CY,saddr.1
    {0x71U, {RL78::OR1_cy_saddrx, {0x16U, SBP::saddr}, {OPT::saddr, OPT::imm1}}},
    // OR1 CY,saddr.2
    {0x71U, {RL78::OR1_cy_saddrx, {0x26U, SBP::saddr}, {OPT::saddr, OPT::imm2}}},
    // OR1 CY,saddr.3
    {0x71U, {RL78::OR1_cy_saddrx, {0x36U, SBP::saddr}, {OPT::saddr, OPT::imm3}}},
    // OR1 CY,saddr.4
    {0x71U, {RL78::OR1_cy_saddrx, {0x46U, SBP::saddr}, {OPT::saddr, OPT::imm4}}},
    // OR1 CY,saddr.5
    {0x71U, {RL78::OR1_cy_saddrx, {0x56U, SBP::saddr}, {OPT::saddr, OPT::imm5}}},
    // OR1 CY,saddr.6
    {0x71U, {RL78::OR1_cy_saddrx, {0x66U, SBP::saddr}, {OPT::saddr, OPT::imm6}}},
    // OR1 CY,saddr.7
    {0x71U, {RL78::OR1_cy_saddrx, {0x76U, SBP::saddr}, {OPT::saddr, OPT::imm7}}},
    // OR1 CY,ES:[HL].0
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0x86U}, {RL78::CY, OPT::ES_memHL,OPT::imm0}}},
    // OR1 CY,ES:[HL].1
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0x96U}, {RL78::CY, OPT::ES_memHL,OPT::imm1}}},
    // OR1 CY,ES:[HL].2
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0xA6U}, {RL78::CY, OPT::ES_memHL,OPT::imm2}}},
    // OR1 CY,ES:[HL].3
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0xB6U}, {RL78::CY, OPT::ES_memHL,OPT::imm3}}},
    // OR1 CY,ES:[HL].4
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0xC6U}, {RL78::CY, OPT::ES_memHL,OPT::imm4}}},
    // OR1 CY,ES:[HL].5
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0xD6U}, {RL78::CY, OPT::ES_memHL,OPT::imm5}}},
    // OR1 CY,ES:[HL].6
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0xE6U}, {RL78::CY, OPT::ES_memHL,OPT::imm6}}},
    // OR1 CY,ES:[HL].7
    {0x11U, {RL78::OR1_esmemr, {0x71U, 0xF6U}, {RL78::CY, OPT::ES_memHL,OPT::imm7}}},
    // OR1 CY,PSW.0
    {0x71U, {RL78::OR1_cy_PSW, {0x0EU, 0xFAU}, {RL78::PSW, OPT::imm0}}},
    // OR1 CY,PSW.1
    {0x71U, {RL78::OR1_cy_PSW, {0x1EU, 0xFAU}, {RL78::PSW, OPT::imm1}}},
    // OR1 CY,PSW.2
    {0x71U, {RL78::OR1_cy_PSW, {0x2EU, 0xFAU}, {RL78::PSW, OPT::imm2}}},
    // OR1 CY,PSW.3
    {0x71U, {RL78::OR1_cy_PSW, {0x3EU, 0xFAU}, {RL78::PSW, OPT::imm3}}},
    // OR1 CY,PSW.4
    {0x71U, {RL78::OR1_cy_PSW, {0x4EU, 0xFAU}, {RL78::PSW, OPT::imm4}}},
    // OR1 CY,PSW.5
    {0x71U, {RL78::OR1_cy_PSW, {0x5EU, 0xFAU}, {RL78::PSW, OPT::imm5}}},
    // OR1 CY,PSW.6
    {0x71U, {RL78::OR1_cy_PSW, {0x6EU, 0xFAU}, {RL78::PSW, OPT::imm6}}},
    // OR1 CY,PSW.7
    {0x71U, {RL78::OR1_cy_PSW, {0x7EU, 0xFAU}, {RL78::PSW, OPT::imm7}}},
    // OR1 CY,sfr.0
    {0x71U, {RL78::OR1_cy_sfr, {0x0EU, SBP::sfr}, {OPT::sfr,OPT::imm0}}},
    // OR1 CY,sfr.1
    {0x71U, {RL78::OR1_cy_sfr, {0x1EU, SBP::sfr}, {OPT::sfr,OPT::imm1}}},
    // OR1 CY,sfr.2
    {0x71U, {RL78::OR1_cy_sfr, {0x2EU, SBP::sfr}, {OPT::sfr,OPT::imm2}}},
    // OR1 CY,sfr.3
    {0x71U, {RL78::OR1_cy_sfr, {0x3EU, SBP::sfr}, {OPT::sfr,OPT::imm3}}},
    // OR1 CY,sfr.4
    {0x71U, {RL78::OR1_cy_sfr, {0x4EU, SBP::sfr}, {OPT::sfr,OPT::imm4}}},
    // OR1 CY,sfr.5
    {0x71U, {RL78::OR1_cy_sfr, {0x5EU, SBP::sfr}, {OPT::sfr,OPT::imm5}}},
    // OR1 CY,sfr.6
    {0x71U, {RL78::OR1_cy_sfr, {0x6EU, SBP::sfr}, {OPT::sfr,OPT::imm6}}},
    // OR1 CY,sfr.7
    {0x71U, {RL78::OR1_cy_sfr, {0x7EU, SBP::sfr}, {OPT::sfr,OPT::imm7}}},
    // POP PSW
    {0x61U, {RL78::POP_cc, {0xCDU}, {}}},
    // POP AX
    {0xC0U, {RL78::POP_rp, {}, {RL78::RP0}}},
    // POP BC
    {0xC2U, {RL78::POP_rp, {}, {RL78::RP2}}},
    // POP DE
    {0xC4U, {RL78::POP_rp, {}, {RL78::RP4}}},
    // POP HL
    {0xC6U, {RL78::POP_rp, {}, {RL78::RP6}}},
    // PREFIX nan
    {0x11U, {RL78::PREFIX, {}, {}}},
    // PUSH PSW
    {0x61U, {RL78::PUSH_cc, {0xDDU}, {}}},
    // PUSH AX
    {0xC1U, {RL78::PUSH_rp, {}, {RL78::RP0}}},
    // PUSH BC
    {0xC3U, {RL78::PUSH_rp, {}, {RL78::RP2}}},
    // PUSH DE
    {0xC5U, {RL78::PUSH_rp, {}, {RL78::RP4}}},
    // PUSH HL
    {0xC7U, {RL78::PUSH_rp, {}, {RL78::RP6}}},
    // RET nan
    {0xD7U, {RL78::RET, {}, {}}},
    // RETB nan
    {0x61U, {RL78::RETB, {0xECU}, {}}},
    // RETI nan
    {0x61U, {RL78::RETI, {0xFCU}, {}}},
    // ROL A,1
    {0x61U, {RL78::ROL_r_1, {0xEBU}, {RL78::R1, OPT::imm1}}},
    // ROLC A,1
    {0x61U, {RL78::ROLC_r_1, {0xDCU}, {RL78::R1, OPT::imm1}}},
    // ROLWC AX,1
    {0x61U, {RL78::ROLWC_rp_1, {0xEEU}, {RL78::RP0, OPT::imm1}}},
    // ROLWC BC,1
    {0x61U, {RL78::ROLWC_rp_1, {0xFEU}, {RL78::RP2, OPT::imm1}}},
    // ROR A,1
    {0x61U, {RL78::ROR_r_1, {0xDBU}, {RL78::R1, OPT::imm1}}},
    // RORC A,1
    {0x61U, {RL78::RORC_r_1, {0xFBU}, {RL78::R1, OPT::imm1}}},
    // SAR A,1
    {0x31U, {RL78::SAR_r_i, {0x1BU}, {RL78::R1, RL78::R1, OPT::imm1}}},
    // SAR A,2
    {0x31U, {RL78::SAR_r_i, {0x2BU}, {RL78::R1, RL78::R1, OPT::imm2}}},
    // SAR A,3
    {0x31U, {RL78::SAR_r_i, {0x3BU}, {RL78::R1, RL78::R1, OPT::imm3}}},
    // SAR A,4
    {0x31U, {RL78::SAR_r_i, {0x4BU}, {RL78::R1, RL78::R1, OPT::imm4}}},
    // SAR A,5
    {0x31U, {RL78::SAR_r_i, {0x5BU}, {RL78::R1, RL78::R1, OPT::imm5}}},
    // SAR A,6
    {0x31U, {RL78::SAR_r_i, {0x6BU}, {RL78::R1, RL78::R1, OPT::imm6}}},
    // SAR A,7
    {0x31U, {RL78::SAR_r_i, {0x7BU}, {RL78::R1, RL78::R1, OPT::imm7}}},
    // SARW AX,1
    {0x31U, {RL78::SARW_rp_i, {0x1FU}, {RL78::RP0, RL78::RP0, OPT::imm1}}},
    // SARW AX,10
    {0x31U, {RL78::SARW_rp_i, {0xAFU}, {RL78::RP0, RL78::RP0, OPT::imm10}}},
    // SARW AX,11
    {0x31U, {RL78::SARW_rp_i, {0xBFU}, {RL78::RP0, RL78::RP0, OPT::imm11}}},
    // SARW AX,12
    {0x31U, {RL78::SARW_rp_i, {0xCFU}, {RL78::RP0, RL78::RP0, OPT::imm12}}},
    // SARW AX,13
    {0x31U, {RL78::SARW_rp_i, {0xDFU}, {RL78::RP0, RL78::RP0, OPT::imm13}}},
    // SARW AX,14
    {0x31U, {RL78::SARW_rp_i, {0xEFU}, {RL78::RP0, RL78::RP0, OPT::imm14}}},
    // SARW AX,15
    {0x31U, {RL78::SARW_rp_i, {0xFFU}, {RL78::RP0, RL78::RP0, OPT::imm15}}},
    // SARW AX,2
    {0x31U, {RL78::SARW_rp_i, {0x2FU}, {RL78::RP0, RL78::RP0, OPT::imm2}}},
    // SARW AX,3
    {0x31U, {RL78::SARW_rp_i, {0x3FU}, {RL78::RP0, RL78::RP0, OPT::imm3}}},
    // SARW AX,4
    {0x31U, {RL78::SARW_rp_i, {0x4FU}, {RL78::RP0, RL78::RP0, OPT::imm4}}},
    // SARW AX,5
    {0x31U, {RL78::SARW_rp_i, {0x5FU}, {RL78::RP0, RL78::RP0, OPT::imm5}}},
    // SARW AX,6
    {0x31U, {RL78::SARW_rp_i, {0x6FU}, {RL78::RP0, RL78::RP0, OPT::imm6}}},
    // SARW AX,7
    {0x31U, {RL78::SARW_rp_i, {0x7FU}, {RL78::RP0, RL78::RP0, OPT::imm7}}},
    // SARW AX,8
    {0x31U, {RL78::SARW_rp_i, {0x8FU}, {RL78::RP0, RL78::RP0, OPT::imm8}}},
    // SARW AX,9
    {0x31U, {RL78::SARW_rp_i, {0x9FU}, {RL78::RP0, RL78::RP0, OPT::imm9}}},
    // SELNote RB0
    {0x61U, {RL78::SEL, {0xCFU}, {OPT::RB0}}},
    // SELNote RB1
    {0x61U, {RL78::SEL, {0xDFU}, {OPT::RB1}}},
    // SELNote RB2
    {0x61U, {RL78::SEL, {0xEFU}, {OPT::RB2}}},
    // SELNote RB3
    {0x61U, {RL78::SEL, {0xFFU}, {OPT::RB3}}},
    // SET1 !addr16.0
    {0x71U, {RL78::SET1_abs16, {0x0U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm0}}},
    // SET1 !addr16.1
    {0x71U, {RL78::SET1_abs16, {0x10U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm1}}},
    // SET1 !addr16.2
    {0x71U, {RL78::SET1_abs16, {0x20U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm2}}},
    // SET1 !addr16.3
    {0x71U, {RL78::SET1_abs16, {0x30U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm3}}},
    // SET1 !addr16.4
    {0x71U, {RL78::SET1_abs16, {0x40U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm4}}},
    // SET1 !addr16.5
    {0x71U, {RL78::SET1_abs16, {0x50U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm5}}},
    // SET1 !addr16.6
    {0x71U, {RL78::SET1_abs16, {0x60U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm6}}},
    // SET1 !addr16.7
    {0x71U, {RL78::SET1_abs16, {0x70U, SBP::adrl, SBP::adrh}, {OPT::I_addr16, OPT::imm7}}},
    // SET1 [HL].0
    {0x71U, {RL78::SET1_memr, {0x82U}, {OPT::memHL, OPT::imm0}}},
    // SET1 [HL].1
    {0x71U, {RL78::SET1_memr, {0x92U}, {OPT::memHL, OPT::imm1}}},
    // SET1 [HL].2
    {0x71U, {RL78::SET1_memr, {0xA2U}, {OPT::memHL, OPT::imm2}}},
    // SET1 [HL].3
    {0x71U, {RL78::SET1_memr, {0xB2U}, {OPT::memHL, OPT::imm3}}},
    // SET1 [HL].4
    {0x71U, {RL78::SET1_memr, {0xC2U}, {OPT::memHL, OPT::imm4}}},
    // SET1 [HL].5
    {0x71U, {RL78::SET1_memr, {0xD2U}, {OPT::memHL, OPT::imm5}}},
    // SET1 [HL].6
    {0x71U, {RL78::SET1_memr, {0xE2U}, {OPT::memHL, OPT::imm6}}},
    // SET1 [HL].7
    {0x71U, {RL78::SET1_memr, {0xF2U}, {OPT::memHL, OPT::imm7}}},
    // SET1 A.0
    {0x71U, {RL78::SET1_A, {0x8AU}, {RL78::R1, RL78::R1, OPT::imm0}}},
    // SET1 A.1
    {0x71U, {RL78::SET1_A, {0x9AU}, {RL78::R1, RL78::R1, OPT::imm1}}},
    // SET1 A.2
    {0x71U, {RL78::SET1_A, {0xAAU}, {RL78::R1, RL78::R1, OPT::imm2}}},
    // SET1 A.3
    {0x71U, {RL78::SET1_A, {0xBAU}, {RL78::R1, RL78::R1, OPT::imm3}}},
    // SET1 A.4
    {0x71U, {RL78::SET1_A, {0xCAU}, {RL78::R1, RL78::R1, OPT::imm4}}},
    // SET1 A.5
    {0x71U, {RL78::SET1_A, {0xDAU}, {RL78::R1, RL78::R1, OPT::imm5}}},
    // SET1 A.6
    {0x71U, {RL78::SET1_A, {0xEAU}, {RL78::R1, RL78::R1, OPT::imm6}}},
    // SET1 A.7
    {0x71U, {RL78::SET1_A, {0xFAU}, {RL78::R1, RL78::R1, OPT::imm7}}},
    // SET1 saddr.0
    {0x71U, {RL78::SET1_saddr, {0x2U, SBP::saddr}, {OPT::saddr, OPT::imm0}}},
    // SET1 saddr.1
    {0x71U, {RL78::SET1_saddr, {0x12U, SBP::saddr}, {OPT::saddr, OPT::imm1}}},
    // SET1 saddr.2
    {0x71U, {RL78::SET1_saddr, {0x22U, SBP::saddr}, {OPT::saddr, OPT::imm2}}},
    // SET1 saddr.3
    {0x71U, {RL78::SET1_saddr, {0x32U, SBP::saddr}, {OPT::saddr, OPT::imm3}}},
    // SET1 saddr.4
    {0x71U, {RL78::SET1_saddr, {0x42U, SBP::saddr}, {OPT::saddr, OPT::imm4}}},
    // SET1 saddr.5
    {0x71U, {RL78::SET1_saddr, {0x52U, SBP::saddr}, {OPT::saddr, OPT::imm5}}},
    // SET1 saddr.6
    {0x71U, {RL78::SET1_saddr, {0x62U, SBP::saddr}, {OPT::saddr, OPT::imm6}}},
    // SET1 saddr.7
    {0x71U, {RL78::SET1_saddr, {0x72U, SBP::saddr}, {OPT::saddr, OPT::imm7}}},
    // SET1 ES:!addr16.0
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x0U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm0}}},
    // SET1 ES:!addr16.1
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x10U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm1}}},
    // SET1 ES:!addr16.2
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x20U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm2}}},
    // SET1 ES:!addr16.3
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x30U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm3}}},
    // SET1 ES:!addr16.4
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x40U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm4}}},
    // SET1 ES:!addr16.5
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x50U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm5}}},
    // SET1 ES:!addr16.6
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x60U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm6}}},
    // SET1 ES:!addr16.7
    {0x11U, {RL78::SET1_esaddr16, {0x71U, 0x70U, SBP::adrl, SBP::adrh}, {OPT::ES_I_addr16,OPT::imm7}}},
    // SET1 ES:[HL].0
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0x82U}, {OPT::ES_memHL,OPT::imm0}}},
    // SET1 ES:[HL].1
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0x92U}, {OPT::ES_memHL,OPT::imm1}}},
    // SET1 ES:[HL].2
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0xA2U}, {OPT::ES_memHL,OPT::imm2}}},
    // SET1 ES:[HL].3
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0xB2U}, {OPT::ES_memHL,OPT::imm3}}},
    // SET1 ES:[HL].4
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0xC2U}, {OPT::ES_memHL,OPT::imm4}}},
    // SET1 ES:[HL].5
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0xD2U}, {OPT::ES_memHL,OPT::imm5}}},
    // SET1 ES:[HL].6
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0xE2U}, {OPT::ES_memHL,OPT::imm6}}},
    // SET1 ES:[HL].7
    {0x11U, {RL78::SET1_esmemr, {0x71U, 0xF2U}, {OPT::ES_memHL,OPT::imm7}}},
    // SET1 CY
    {0x71U, {RL78::SET1_cy, {0x80U}, {RL78::CY}}},
    // SET1 PSW.0
    {0x71U, {RL78::SET1_PSW, {0x0AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm0}}},
    // SET1 PSW.1
    {0x71U, {RL78::SET1_PSW, {0x1AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm1}}},
    // SET1 PSW.2
    {0x71U, {RL78::SET1_PSW, {0x2AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm2}}},
    // SET1 PSW.3
    {0x71U, {RL78::SET1_PSW, {0x3AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm3}}},
    // SET1 PSW.4
    {0x71U, {RL78::SET1_PSW, {0x4AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm4}}},
    // SET1 PSW.5
    {0x71U, {RL78::SET1_PSW, {0x5AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm5}}},
    // SET1 PSW.6
    {0x71U, {RL78::SET1_PSW, {0x6AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm6}}},
    // SET1 PSW.7
    //{0x71U, {RL78::SET1_PSW, {0x7AU, 0xFAU}, {RL78::PSW, RL78::PSW, OPT::imm7}}}, - we print EI instead
    // SET1 sfr.0
    {0x71U, {RL78::SET1_sfr, {0x0AU, SBP::sfr}, {OPT::sfr,OPT::imm0}}},
    // SET1 sfr.1
    {0x71U, {RL78::SET1_sfr, {0x1AU, SBP::sfr}, {OPT::sfr,OPT::imm1}}},
    // SET1 sfr.2
    {0x71U, {RL78::SET1_sfr, {0x2AU, SBP::sfr}, {OPT::sfr,OPT::imm2}}},
    // SET1 sfr.3
    {0x71U, {RL78::SET1_sfr, {0x3AU, SBP::sfr}, {OPT::sfr,OPT::imm3}}},
    // SET1 sfr.4
    {0x71U, {RL78::SET1_sfr, {0x4AU, SBP::sfr}, {OPT::sfr,OPT::imm4}}},
    // SET1 sfr.5
    {0x71U, {RL78::SET1_sfr, {0x5AU, SBP::sfr}, {OPT::sfr,OPT::imm5}}},
    // SET1 sfr.6
    {0x71U, {RL78::SET1_sfr, {0x6AU, SBP::sfr}, {OPT::sfr,OPT::imm6}}},
    // SET1 sfr.7
    {0x71U, {RL78::SET1_sfr, {0x7AU, SBP::sfr}, {OPT::sfr,OPT::imm7}}},
    // SHL A,1
    {0x31U, {RL78::SHL_r_imm, {0x19U}, {RL78::R1, RL78::R1, OPT::imm1}}},
    // SHL A,2
    {0x31U, {RL78::SHL_r_imm, {0x29U}, {RL78::R1, RL78::R1, OPT::imm2}}},
    // SHL A,3
    {0x31U, {RL78::SHL_r_imm, {0x39U}, {RL78::R1, RL78::R1, OPT::imm3}}},
    // SHL A,4
    {0x31U, {RL78::SHL_r_imm, {0x49U}, {RL78::R1, RL78::R1, OPT::imm4}}},
    // SHL A,5
    {0x31U, {RL78::SHL_r_imm, {0x59U}, {RL78::R1, RL78::R1, OPT::imm5}}},
    // SHL A,6
    {0x31U, {RL78::SHL_r_imm, {0x69U}, {RL78::R1, RL78::R1, OPT::imm6}}},
    // SHL A,7
    {0x31U, {RL78::SHL_r_imm, {0x79U}, {RL78::R1, RL78::R1, OPT::imm7}}},
    // SHL B,1
    {0x31U, {RL78::SHL_r_imm, {0x18U}, {RL78::R3, RL78::R3, OPT::imm1}}},
    // SHL B,2
    {0x31U, {RL78::SHL_r_imm, {0x28U}, {RL78::R3, RL78::R3, OPT::imm2}}},
    // SHL B,3
    {0x31U, {RL78::SHL_r_imm, {0x38U}, {RL78::R3, RL78::R3, OPT::imm3}}},
    // SHL B,4
    {0x31U, {RL78::SHL_r_imm, {0x48U}, {RL78::R3, RL78::R3, OPT::imm4}}},
    // SHL B,5
    {0x31U, {RL78::SHL_r_imm, {0x58U}, {RL78::R3, RL78::R3, OPT::imm5}}},
    // SHL B,6
    {0x31U, {RL78::SHL_r_imm, {0x68U}, {RL78::R3, RL78::R3, OPT::imm6}}},
    // SHL B,7
    {0x31U, {RL78::SHL_r_imm, {0x78U}, {RL78::R3, RL78::R3, OPT::imm7}}},
    // SHL C,1
    {0x31U, {RL78::SHL_r_imm, {0x17U}, {RL78::R2, RL78::R2, OPT::imm1}}},
    // SHL C,2
    {0x31U, {RL78::SHL_r_imm, {0x27U}, {RL78::R2, RL78::R2, OPT::imm2}}},
    // SHL C,3
    {0x31U, {RL78::SHL_r_imm, {0x37U}, {RL78::R2, RL78::R2, OPT::imm3}}},
    // SHL C,4
    {0x31U, {RL78::SHL_r_imm, {0x47U}, {RL78::R2, RL78::R2, OPT::imm4}}},
    // SHL C,5
    {0x31U, {RL78::SHL_r_imm, {0x57U}, {RL78::R2, RL78::R2, OPT::imm5}}},
    // SHL C,6
    {0x31U, {RL78::SHL_r_imm, {0x67U}, {RL78::R2, RL78::R2, OPT::imm6}}},
    // SHL C,7
    {0x31U, {RL78::SHL_r_imm, {0x77U}, {RL78::R2, RL78::R2, OPT::imm7}}},
    // SHLW AX,1
    {0x31U, {RL78::SHLW_rp_imm, {0x1DU}, {RL78::RP0, RL78::RP0, OPT::imm1}}},
    // SHLW AX,10
    {0x31U, {RL78::SHLW_rp_imm, {0xADU}, {RL78::RP0, RL78::RP0, OPT::imm10}}},
    // SHLW AX,11
    {0x31U, {RL78::SHLW_rp_imm, {0xBDU}, {RL78::RP0, RL78::RP0, OPT::imm11}}},
    // SHLW AX,12
    {0x31U, {RL78::SHLW_rp_imm, {0xCDU}, {RL78::RP0, RL78::RP0, OPT::imm12}}},
    // SHLW AX,13
    {0x31U, {RL78::SHLW_rp_imm, {0xDDU}, {RL78::RP0, RL78::RP0, OPT::imm13}}},
    // SHLW AX,14
    {0x31U, {RL78::SHLW_rp_imm, {0xEDU}, {RL78::RP0, RL78::RP0, OPT::imm14}}},
    // SHLW AX,15
    {0x31U, {RL78::SHLW_rp_imm, {0xFDU}, {RL78::RP0, RL78::RP0, OPT::imm15}}},
    // SHLW AX,2
    {0x31U, {RL78::SHLW_rp_imm, {0x2DU}, {RL78::RP0, RL78::RP0, OPT::imm2}}},
    // SHLW AX,3
    {0x31U, {RL78::SHLW_rp_imm, {0x3DU}, {RL78::RP0, RL78::RP0, OPT::imm3}}},
    // SHLW AX,4
    {0x31U, {RL78::SHLW_rp_imm, {0x4DU}, {RL78::RP0, RL78::RP0, OPT::imm4}}},
    // SHLW AX,5
    {0x31U, {RL78::SHLW_rp_imm, {0x5DU}, {RL78::RP0, RL78::RP0, OPT::imm5}}},
    // SHLW AX,6
    {0x31U, {RL78::SHLW_rp_imm, {0x6DU}, {RL78::RP0, RL78::RP0, OPT::imm6}}},
    // SHLW AX,7
    {0x31U, {RL78::SHLW_rp_imm, {0x7DU}, {RL78::RP0, RL78::RP0, OPT::imm7}}},
    // SHLW AX,8
    {0x31U, {RL78::SHLW_rp_imm, {0x8DU}, {RL78::RP0, RL78::RP0, OPT::imm8}}},
    // SHLW AX,9
    {0x31U, {RL78::SHLW_rp_imm, {0x9DU}, {RL78::RP0, RL78::RP0, OPT::imm9}}},
    // SHLW BC,1
    {0x31U, {RL78::SHLW_rp_imm, {0x1CU}, {RL78::RP2, RL78::RP2, OPT::imm1}}},
    // SHLW BC,10
    {0x31U, {RL78::SHLW_rp_imm, {0xACU}, {RL78::RP2, RL78::RP2, OPT::imm10}}},
    // SHLW BC,11
    {0x31U, {RL78::SHLW_rp_imm, {0xBCU}, {RL78::RP2, RL78::RP2, OPT::imm11}}},
    // SHLW BC,12
    {0x31U, {RL78::SHLW_rp_imm, {0xCCU}, {RL78::RP2, RL78::RP2, OPT::imm12}}},
    // SHLW BC,13
    {0x31U, {RL78::SHLW_rp_imm, {0xDCU}, {RL78::RP2, RL78::RP2, OPT::imm13}}},
    // SHLW BC,14
    {0x31U, {RL78::SHLW_rp_imm, {0xECU}, {RL78::RP2, RL78::RP2, OPT::imm14}}},
    // SHLW BC,15
    {0x31U, {RL78::SHLW_rp_imm, {0xFCU}, {RL78::RP2, RL78::RP2, OPT::imm15}}},
    // SHLW BC,2
    {0x31U, {RL78::SHLW_rp_imm, {0x2CU}, {RL78::RP2, RL78::RP2, OPT::imm2}}},
    // SHLW BC,3
    {0x31U, {RL78::SHLW_rp_imm, {0x3CU}, {RL78::RP2, RL78::RP2, OPT::imm3}}},
    // SHLW BC,4
    {0x31U, {RL78::SHLW_rp_imm, {0x4CU}, {RL78::RP2, RL78::RP2, OPT::imm4}}},
    // SHLW BC,5
    {0x31U, {RL78::SHLW_rp_imm, {0x5CU}, {RL78::RP2, RL78::RP2, OPT::imm5}}},
    // SHLW BC,6
    {0x31U, {RL78::SHLW_rp_imm, {0x6CU}, {RL78::RP2, RL78::RP2, OPT::imm6}}},
    // SHLW BC,7
    {0x31U, {RL78::SHLW_rp_imm, {0x7CU}, {RL78::RP2, RL78::RP2, OPT::imm7}}},
    // SHLW BC,8
    {0x31U, {RL78::SHLW_rp_imm, {0x8CU}, {RL78::RP2, RL78::RP2, OPT::imm8}}},
    // SHLW BC,9
    {0x31U, {RL78::SHLW_rp_imm, {0x9CU}, {RL78::RP2, RL78::RP2, OPT::imm9}}},
    // SHR A,1
    {0x31U, {RL78::SHR_r_i, {0x1AU}, {RL78::R1, RL78::R1, OPT::imm1}}},
    // SHR A,2
    {0x31U, {RL78::SHR_r_i, {0x2AU}, {RL78::R1, RL78::R1, OPT::imm2}}},
    // SHR A,3
    {0x31U, {RL78::SHR_r_i, {0x3AU}, {RL78::R1, RL78::R1, OPT::imm3}}},
    // SHR A,4
    {0x31U, {RL78::SHR_r_i, {0x4AU}, {RL78::R1, RL78::R1, OPT::imm4}}},
    // SHR A,5
    {0x31U, {RL78::SHR_r_i, {0x5AU}, {RL78::R1, RL78::R1, OPT::imm5}}},
    // SHR A,6
    {0x31U, {RL78::SHR_r_i, {0x6AU}, {RL78::R1, RL78::R1, OPT::imm6}}},
    // SHR A,7
    {0x31U, {RL78::SHR_r_i, {0x7AU}, {RL78::R1, RL78::R1, OPT::imm7}}},
    // SHRW AX,1
    {0x31U, {RL78::SHRW_rp_i, {0x1EU}, {RL78::RP0, RL78::RP0, OPT::imm1}}},
    // SHRW AX,10
    {0x31U, {RL78::SHRW_rp_i, {0xAEU}, {RL78::RP0, RL78::RP0, OPT::imm10}}},
    // SHRW AX,11
    {0x31U, {RL78::SHRW_rp_i, {0xBEU}, {RL78::RP0, RL78::RP0, OPT::imm11}}},
    // SHRW AX,12
    {0x31U, {RL78::SHRW_rp_i, {0xCEU}, {RL78::RP0, RL78::RP0, OPT::imm12}}},
    // SHRW AX,13
    {0x31U, {RL78::SHRW_rp_i, {0xDEU}, {RL78::RP0, RL78::RP0, OPT::imm13}}},
    // SHRW AX,14
    {0x31U, {RL78::SHRW_rp_i, {0xEEU}, {RL78::RP0, RL78::RP0, OPT::imm14}}},
    // SHRW AX,15
    {0x31U, {RL78::SHRW_rp_i, {0xFEU}, {RL78::RP0, RL78::RP0, OPT::imm15}}},
    // SHRW AX,2
    {0x31U, {RL78::SHRW_rp_i, {0x2EU}, {RL78::RP0, RL78::RP0, OPT::imm2}}},
    // SHRW AX,3
    {0x31U, {RL78::SHRW_rp_i, {0x3EU}, {RL78::RP0, RL78::RP0, OPT::imm3}}},
    // SHRW AX,4
    {0x31U, {RL78::SHRW_rp_i, {0x4EU}, {RL78::RP0, RL78::RP0, OPT::imm4}}},
    // SHRW AX,5
    {0x31U, {RL78::SHRW_rp_i, {0x5EU}, {RL78::RP0, RL78::RP0, OPT::imm5}}},
    // SHRW AX,6
    {0x31U, {RL78::SHRW_rp_i, {0x6EU}, {RL78::RP0, RL78::RP0, OPT::imm6}}},
    // SHRW AX,7
    {0x31U, {RL78::SHRW_rp_i, {0x7EU}, {RL78::RP0, RL78::RP0, OPT::imm7}}},
    // SHRW AX,8
    {0x31U, {RL78::SHRW_rp_i, {0x8EU}, {RL78::RP0, RL78::RP0, OPT::imm8}}},
    // SHRW AX,9
    {0x31U, {RL78::SHRW_rp_i, {0x9EU}, {RL78::RP0, RL78::RP0, OPT::imm9}}},
    // SKC nan
    {0x61U, {RL78::SK_cc_nodst, {0xC8U}, {OPT::RL78CC_C}}},
    // SKH nan
    {0x61U, {RL78::SK_cc_nodst, {0xE3U}, {OPT::RL78CC_H}}},
    // SKNC nan
    {0x61U, {RL78::SK_cc_nodst, {0xD8U}, {OPT::RL78CC_NC}}},
    // SKNH nan
    {0x61U, {RL78::SK_cc_nodst, {0xF3U}, {OPT::RL78CC_NH}}},
    // SKNZ nan
    {0x61U, {RL78::SK_cc_nodst, {0xF8U}, {OPT::RL78CC_NZ}}},
    // SKZ nan
    {0x61U, {RL78::SK_cc_nodst, {0xE8U}, {OPT::RL78CC_Z}}},
    // STOP nan
    {0x61U, {RL78::STOP, {0xFDU}, {}}},
    // SUB A,!addr16
    {0x2FU, {RL78::SUB_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // SUB saddr,#byte
    {0x2AU, {RL78::SUB_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // SUB A,#byte
    {0x2CU, {RL78::SUB_r_imm, {SBP::data}, {RL78::R1, RL78::R1, OPT::byte}}},
    // SUB A,[HL]
    {0x2DU, {RL78::SUB_r_memri, {}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // SUB A,[HL+byte]
    {0x2EU, {RL78::SUB_r_memri, {SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // SUB A,[HL+B]
    {0x61U, {RL78::SUB_r_memrr, {0xA0U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // SUB A,[HL+C]
    {0x61U, {RL78::SUB_r_memrr, {0xA2U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // SUB A,A
    {0x61U, {RL78::SUB_r_r, {0x21U}, {RL78::R1, RL78::R1, RL78::R1}}},
    // SUB A,B
    {0x61U, {RL78::SUB_r_r, {0x2BU}, {RL78::R1, RL78::R1, RL78::R3}}},
    // SUB A,C
    {0x61U, {RL78::SUB_r_r, {0x2AU}, {RL78::R1, RL78::R1, RL78::R2}}},
    // SUB A,D
    {0x61U, {RL78::SUB_r_r, {0x2DU}, {RL78::R1, RL78::R1, RL78::R5}}},
    // SUB A,E
    {0x61U, {RL78::SUB_r_r, {0x2CU}, {RL78::R1, RL78::R1, RL78::R4}}},
    // SUB A,H
    {0x61U, {RL78::SUB_r_r, {0x2FU}, {RL78::R1, RL78::R1, RL78::R7}}},
    // SUB A,L
    {0x61U, {RL78::SUB_r_r, {0x2EU}, {RL78::R1, RL78::R1, RL78::R6}}},
    // SUB A,X
    {0x61U, {RL78::SUB_r_r, {0x28U}, {RL78::R1, RL78::R1, RL78::R0}}},
    // SUB B,A
    {0x61U, {RL78::SUB_r_r, {0x23U}, {RL78::R3, RL78::R3, RL78::R1}}},
    // SUB C,A
    {0x61U, {RL78::SUB_r_r, {0x22U}, {RL78::R2, RL78::R2, RL78::R1}}},
    // SUB D,A
    {0x61U, {RL78::SUB_r_r, {0x25U}, {RL78::R5, RL78::R5, RL78::R1}}},
    // SUB E,A
    {0x61U, {RL78::SUB_r_r, {0x24U}, {RL78::R4, RL78::R4, RL78::R1}}},
    // SUB H,A
    {0x61U, {RL78::SUB_r_r, {0x27U}, {RL78::R7, RL78::R7, RL78::R1}}},
    // SUB L,A
    {0x61U, {RL78::SUB_r_r, {0x26U}, {RL78::R6, RL78::R6, RL78::R1}}},
    // SUB X,A
    {0x61U, {RL78::SUB_r_r, {0x20U}, {RL78::R0, RL78::R0, RL78::R1}}},
    // SUB A,saddr
    {0x2BU, {RL78::SUB_r_saddr, {SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // SUB A,ES:!addr16
    {0x11U, {RL78::SUB_r_esaddr16, {0x2FU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // SUB A,ES:[HL]
    {0x11U, {RL78::SUB_r_esmemHL, {0x2DU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // SUB A,ES:[HL+B]
    {0x11U, {RL78::SUB_r_esmemRpr, {0x61U, 0xA0U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // SUB A,ES:[HL+byte]
    {0x11U, {RL78::SUB_r_esmemHLi, {0x2EU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // SUB A,ES:[HL+C]
    {0x11U, {RL78::SUB_r_esmemRpr, {0x61U, 0xA2U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // SUBC A,!addr16
    {0x3FU, {RL78::SUBC_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // SUBC saddr,#byte
    {0x3AU, {RL78::SUBC_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // SUBC A,#byte
    {0x3CU, {RL78::SUBC_A_imm, {SBP::data}, {RL78::R1, RL78::R1, OPT::byte}}},
    // SUBC A,[HL]
    {0x3DU, {RL78::SUBC_r_memri, {}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // SUBC A,[HL+byte]
    {0x3EU, {RL78::SUBC_r_memri, {SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // SUBC A,[HL+B]
    {0x61U, {RL78::SUBC_r_memrr, {0xB0U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // SUBC A,[HL+C]
    {0x61U, {RL78::SUBC_r_memrr, {0xB2U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // SUBC A,A
    {0x61U, {RL78::SUBC_r_r, {0x31U}, {RL78::R1, RL78::R1, RL78::R1}}},
    // SUBC A,B
    {0x61U, {RL78::SUBC_r_r, {0x3BU}, {RL78::R1, RL78::R1, RL78::R3}}},
    // SUBC A,C
    {0x61U, {RL78::SUBC_r_r, {0x3AU}, {RL78::R1, RL78::R1, RL78::R2}}},
    // SUBC A,D
    {0x61U, {RL78::SUBC_r_r, {0x3DU}, {RL78::R1, RL78::R1, RL78::R5}}},
    // SUBC A,E
    {0x61U, {RL78::SUBC_r_r, {0x3CU}, {RL78::R1, RL78::R1, RL78::R4}}},
    // SUBC A,H
    {0x61U, {RL78::SUBC_r_r, {0x3FU}, {RL78::R1, RL78::R1, RL78::R7}}},
    // SUBC A,L
    {0x61U, {RL78::SUBC_r_r, {0x3EU}, {RL78::R1, RL78::R1, RL78::R6}}},
    // SUBC A,X
    {0x61U, {RL78::SUBC_r_r, {0x38U}, {RL78::R1, RL78::R1, RL78::R0}}},
    // SUBC B,A
    {0x61U, {RL78::SUBC_r_r, {0x33U}, {RL78::R3, RL78::R3, RL78::R1}}},
    // SUBC C,A
    {0x61U, {RL78::SUBC_r_r, {0x32U}, {RL78::R2, RL78::R2, RL78::R1}}},
    // SUBC D,A
    {0x61U, {RL78::SUBC_r_r, {0x35U}, {RL78::R5, RL78::R5, RL78::R1}}},
    // SUBC E,A
    {0x61U, {RL78::SUBC_r_r, {0x34U}, {RL78::R4, RL78::R4, RL78::R1}}},
    // SUBC H,A
    {0x61U, {RL78::SUBC_r_r, {0x37U}, {RL78::R7, RL78::R7, RL78::R1}}},
    // SUBC L,A
    {0x61U, {RL78::SUBC_r_r, {0x36U}, {RL78::R6, RL78::R6, RL78::R1}}},
    // SUBC X,A
    {0x61U, {RL78::SUBC_r_r, {0x30U}, {RL78::R0, RL78::R0, RL78::R1}}},
    // SUBC A,saddr
    {0x3BU, {RL78::SUBC_r_saddr, {SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // SUBC A,ES:!addr16
    {0x11U, {RL78::SUBC_r_esaddr16, {0x3FU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // SUBC A,ES:[HL]
    {0x11U, {RL78::SUBC_r_esmemHL, {0x3DU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // SUBC A,ES:[HL+B]
    {0x11U, {RL78::SUBC_r_esmemRpr, {0x61U, 0xB0U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // SUBC A,ES:[HL+byte]
    {0x11U, {RL78::SUBC_r_esmemHLi, {0x3EU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // SUBC A,ES:[HL+C]
    {0x11U, {RL78::SUBC_r_esmemRpr, {0x61U, 0xB2U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // SUBW AX,#word
    {0x24U, {RL78::SUBW_rp_imm, {SBP::datal, SBP::datah}, {RL78::RP0, RL78::RP0, OPT::word}}},
    // SUBW AX,!addr16
    {0x22U, {RL78::SUBW_rp_abs16, {SBP::adrl, SBP::adrh}, {RL78::RP0, RL78::RP0, OPT::I_addr16}}},
    // SUBW AX,[HL+byte]
    {0x61U, {RL78::SUBW_rp_memri, {0x29U, SBP::adr}, {RL78::RP0, RL78::RP0, OPT::memHL_byte}}},
    // SUBW AX,BC
    {0x23U, {RL78::SUBW_rp_rp, {}, {RL78::RP0, RL78::RP0, RL78::RP2}}},
    // SUBW AX,DE
    {0x25U, {RL78::SUBW_rp_rp, {}, {RL78::RP0, RL78::RP0, RL78::RP4}}},
    // SUBW AX,saddrp
    {0x26U, {RL78::SUBW_rp_saddr, {SBP::saddr}, {RL78::RP0, RL78::RP0, OPT::saddrp}}},
    // SUBW AX,HL
    {0x27U, {RL78::SUBW_rp_rp, {}, {RL78::RP0, RL78::RP0, RL78::RP6}}},
    // SUBW SP,#byte
    {0x20U, {RL78::SUBW_sp_imm, {SBP::data}, {RL78::SPreg, RL78::SPreg, OPT::byte}}},
    // SUBW AX,ES:!addr16
    {0x11U, {RL78::SUBW_rp_esaddr16, {0x22U, SBP::adrl, SBP::adrh}, {RL78::RP0,RL78::RP0,OPT::ES_I_addr16}}},
    // SUBW AX,ES:[HL+byte]
    {0x11U, {RL78::SUBW_rp_esmemHLi, {0x61U, 0x29U, SBP::adr}, {RL78::RP0,RL78::RP0,OPT::ES_memHL_byte}}},
    // XCH A,!addr16
    {0x61U, {RL78::XCH_A_abs16, {0xAAU, SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // XCH A,[DE]
    {0x61U, {RL78::XCH_A_memri, {0xAEU}, {RL78::R1, RL78::R1, OPT::memDE}}},
    // XCH A,[DE+byte]
    {0x61U, {RL78::XCH_A_memri, {0xAFU, SBP::adr}, {RL78::R1, RL78::R1, OPT::memDE_byte}}},
    // XCH A,[HL]
    {0x61U, {RL78::XCH_A_memri, {0xACU}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // XCH A,[HL+byte]
    {0x61U, {RL78::XCH_A_memri, {0xADU, SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // XCH A,[HL+B]
    {0x61U, {RL78::XCH_A_memrr, {0xB9U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // XCH A,[HL+C]
    {0x61U, {RL78::XCH_A_memrr, {0xA9U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // XCH A,X
    {0x8U, {RL78::XCH_A_r, {}, {RL78::R1, RL78::R0, RL78::R1, RL78::R0}}},
    // XCH A,B
    {0x61U, {RL78::XCH_A_r, {0x8BU}, {RL78::R1, RL78::R3, RL78::R1, RL78::R3}}},
    // XCH A,C
    {0x61U, {RL78::XCH_A_r, {0x8AU}, {RL78::R1, RL78::R2, RL78::R1, RL78::R2}}},
    // XCH A,D
    {0x61U, {RL78::XCH_A_r, {0x8DU}, {RL78::R1, RL78::R5, RL78::R1, RL78::R5}}},
    // XCH A,E
    {0x61U, {RL78::XCH_A_r, {0x8CU}, {RL78::R1, RL78::R4, RL78::R1, RL78::R4}}},
    // XCH A,H
    {0x61U, {RL78::XCH_A_r, {0x8FU}, {RL78::R1, RL78::R7, RL78::R1, RL78::R7}}},
    // XCH A,L
    {0x61U, {RL78::XCH_A_r, {0x8EU}, {RL78::R1, RL78::R6, RL78::R1, RL78::R6}}},
    // XCH A,saddr
    {0x61U, {RL78::XCH_A_saddrabs, {0xA8U, SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // XCH A,ES:!addr16
    {0x11U, {RL78::XCH_A_esaddr16, {0x61U, 0xAAU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // XCH A,ES:[DE]
    {0x11U, {RL78::XCH_A_esmemDE, {0x61U, 0xAEU}, {RL78::R1,RL78::R1,OPT::ES_memDE}}},
    // XCH A,ES:[DE+byte]
    {0x11U, {RL78::XCH_A_esmemRpi, {0x61U, 0xAFU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memDE_byte}}},
    // XCH A,ES:[HL]
    {0x11U, {RL78::XCH_A_esmemHL, {0x61U, 0xACU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // XCH A,ES:[HL+B]
    {0x11U, {RL78::XCH_A_esmemRpr, {0x61U, 0xB9U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // XCH A,ES:[HL+byte]
    {0x11U, {RL78::XCH_A_esmemRpi, {0x61U, 0xADU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // XCH A,ES:[HL+C]
    {0x11U, {RL78::XCH_A_esmemRpr, {0x61U, 0xA9U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // XCH A,sfr
    {0x61U, {RL78::XCH_A_sfr, {0xABU, SBP::sfr}, {RL78::R1,OPT::sfr,RL78::R1,OPT::sfr}}},
    // XCHW AX,BC
    {0x33U, {RL78::XCHW_AX_rp, {}, {RL78::RP0, RL78::RP2, RL78::RP0, RL78::RP2}}},
    // XCHW AX,DE
    {0x35U, {RL78::XCHW_AX_rp, {}, {RL78::RP0, RL78::RP4, RL78::RP0, RL78::RP4}}},
    // XCHW AX,HL
    {0x37U, {RL78::XCHW_AX_rp, {}, {RL78::RP0, RL78::RP6, RL78::RP0, RL78::RP6}}},
    // XOR A,!addr16
    {0x7FU, {RL78::XOR_r_abs16, {SBP::adrl, SBP::adrh}, {RL78::R1, RL78::R1, OPT::I_addr16}}},
    // XOR saddr,#byte
    {0x7AU, {RL78::XOR_saddr_imm, {SBP::saddr, SBP::data}, {OPT::saddr, OPT::byte}}},
    // XOR A,#byte
    {0x7CU, {RL78::XOR_r_imm, {SBP::data}, {RL78::R1, RL78::R1, OPT::byte}}},
    // XOR A,[HL]
    {0x7DU, {RL78::XOR_r_memri, {}, {RL78::R1, RL78::R1, OPT::memHL0}}},
    // XOR A,[HL+byte]
    {0x7EU, {RL78::XOR_r_memri, {SBP::adr}, {RL78::R1, RL78::R1, OPT::memHL_byte}}},
    // XOR A,[HL+B]
    {0x61U, {RL78::XOR_r_memrr, {0xF0U}, {RL78::R1, RL78::R1, OPT::memHL_B}}},
    // XOR A,[HL+C]
    {0x61U, {RL78::XOR_r_memrr, {0xF2U}, {RL78::R1, RL78::R1, OPT::memHL_C}}},
    // XOR A,A
    {0x61U, {RL78::XOR_r_r, {0x71U}, {RL78::R1, RL78::R1, RL78::R1}}},
    // XOR A,B
    {0x61U, {RL78::XOR_r_r, {0x7BU}, {RL78::R1, RL78::R1, RL78::R3}}},
    // XOR A,C
    {0x61U, {RL78::XOR_r_r, {0x7AU}, {RL78::R1, RL78::R1, RL78::R2}}},
    // XOR A,D
    {0x61U, {RL78::XOR_r_r, {0x7DU}, {RL78::R1, RL78::R1, RL78::R5}}},
    // XOR A,E
    {0x61U, {RL78::XOR_r_r, {0x7CU}, {RL78::R1, RL78::R1, RL78::R4}}},
    // XOR A,H
    {0x61U, {RL78::XOR_r_r, {0x7FU}, {RL78::R1, RL78::R1, RL78::R7}}},
    // XOR A,L
    {0x61U, {RL78::XOR_r_r, {0x7EU}, {RL78::R1, RL78::R1, RL78::R6}}},
    // XOR A,X
    {0x61U, {RL78::XOR_r_r, {0x78U}, {RL78::R1, RL78::R1, RL78::R0}}},
    // XOR B,A
    {0x61U, {RL78::XOR_r_r, {0x73U}, {RL78::R3, RL78::R3, RL78::R1}}},
    // XOR C,A
    {0x61U, {RL78::XOR_r_r, {0x72U}, {RL78::R2, RL78::R2, RL78::R1}}},
    // XOR D,A
    {0x61U, {RL78::XOR_r_r, {0x75U}, {RL78::R5, RL78::R5, RL78::R1}}},
    // XOR E,A
    {0x61U, {RL78::XOR_r_r, {0x74U}, {RL78::R4, RL78::R4, RL78::R1}}},
    // XOR H,A
    {0x61U, {RL78::XOR_r_r, {0x77U}, {RL78::R7, RL78::R7, RL78::R1}}},
    // XOR L,A
    {0x61U, {RL78::XOR_r_r, {0x76U}, {RL78::R6, RL78::R6, RL78::R1}}},
    // XOR X,A
    {0x61U, {RL78::XOR_r_r, {0x70U}, {RL78::R0, RL78::R0, RL78::R1}}},
    // XOR A,saddr
    {0x7BU, {RL78::XOR_r_saddr, {SBP::saddr}, {RL78::R1, RL78::R1, OPT::saddr}}},
    // XOR A,ES:!addr16
    {0x11U, {RL78::XOR_r_esaddr16, {0x7FU, SBP::adrl, SBP::adrh}, {RL78::R1,RL78::R1,OPT::ES_I_addr16}}},
    // XOR A,ES:[HL]
    {0x11U, {RL78::XOR_r_esmemHL, {0x7DU}, {RL78::R1,RL78::R1,OPT::ES_memHL0}}},
    // XOR A,ES:[HL+B]
    {0x11U, {RL78::XOR_r_esmemRpr, {0x61U, 0xF0U}, {RL78::R1,RL78::R1,OPT::ES_memHL_B}}},
    // XOR A,ES:[HL+byte]
    {0x11U, {RL78::XOR_r_esmemHLi, {0x7EU, SBP::adr}, {RL78::R1,RL78::R1,OPT::ES_memHL_byte}}},
    // XOR A,ES:[HL+C]
    {0x11U, {RL78::XOR_r_esmemRpr, {0x61U, 0xF2U}, {RL78::R1,RL78::R1,OPT::ES_memHL_C}}},
    // XOR1 CY,[HL].0
    {0x71U, {RL78::XOR1_cy_memr, {0x87U}, {OPT::memHL, OPT::imm0}}},
    // XOR1 CY,[HL].1
    {0x71U, {RL78::XOR1_cy_memr, {0x97U}, {OPT::memHL, OPT::imm1}}},
    // XOR1 CY,[HL].2
    {0x71U, {RL78::XOR1_cy_memr, {0xA7U}, {OPT::memHL, OPT::imm2}}},
    // XOR1 CY,[HL].3
    {0x71U, {RL78::XOR1_cy_memr, {0xB7U}, {OPT::memHL, OPT::imm3}}},
    // XOR1 CY,[HL].4
    {0x71U, {RL78::XOR1_cy_memr, {0xC7U}, {OPT::memHL, OPT::imm4}}},
    // XOR1 CY,[HL].5
    {0x71U, {RL78::XOR1_cy_memr, {0xD7U}, {OPT::memHL, OPT::imm5}}},
    // XOR1 CY,[HL].6
    {0x71U, {RL78::XOR1_cy_memr, {0xE7U}, {OPT::memHL, OPT::imm6}}},
    // XOR1 CY,[HL].7
    {0x71U, {RL78::XOR1_cy_memr, {0xF7U}, {OPT::memHL, OPT::imm7}}},
    // XOR1 CY,A.0*/ 
    {0x71U, {RL78::XOR1_cy_r, {0x8FU}, {RL78::R1, OPT::imm0}}},
    // XOR1 CY,A.1*/ 
    {0x71U, {RL78::XOR1_cy_r, {0x9FU}, {RL78::R1, OPT::imm1}}},
    // XOR1 CY,A.2*/ 
    {0x71U, {RL78::XOR1_cy_r, {0xAFU}, {RL78::R1, OPT::imm2}}},
    // XOR1 CY,A.3*/ 
    {0x71U, {RL78::XOR1_cy_r, {0xBFU}, {RL78::R1, OPT::imm3}}},
    // XOR1 CY,A.4*/ 
    {0x71U, {RL78::XOR1_cy_r, {0xCFU}, {RL78::R1, OPT::imm4}}},
    // XOR1 CY,A.5*/ 
    {0x71U, {RL78::XOR1_cy_r, {0xDFU}, {RL78::R1, OPT::imm5}}},
    // XOR1 CY,A.6*/ 
    {0x71U, {RL78::XOR1_cy_r, {0xEFU}, {RL78::R1, OPT::imm6}}},
    // XOR1 CY,A.7*/ 
    {0x71U, {RL78::XOR1_cy_r, {0xFFU}, {RL78::R1, OPT::imm7}}},
    // XOR1 CY,saddr.0
    {0x71U, {RL78::XOR1_cy_saddrx, {0x7U, SBP::saddr}, {OPT::saddr, OPT::imm0}}},
    // XOR1 CY,saddr.1
    {0x71U, {RL78::XOR1_cy_saddrx, {0x17U, SBP::saddr}, {OPT::saddr, OPT::imm1}}},
    // XOR1 CY,saddr.2
    {0x71U, {RL78::XOR1_cy_saddrx, {0x27U, SBP::saddr}, {OPT::saddr, OPT::imm2}}},
    // XOR1 CY,saddr.3
    {0x71U, {RL78::XOR1_cy_saddrx, {0x37U, SBP::saddr}, {OPT::saddr, OPT::imm3}}},
    // XOR1 CY,saddr.4
    {0x71U, {RL78::XOR1_cy_saddrx, {0x47U, SBP::saddr}, {OPT::saddr, OPT::imm4}}},
    // XOR1 CY,saddr.5
    {0x71U, {RL78::XOR1_cy_saddrx, {0x57U, SBP::saddr}, {OPT::saddr, OPT::imm5}}},
    // XOR1 CY,saddr.6
    {0x71U, {RL78::XOR1_cy_saddrx, {0x67U, SBP::saddr}, {OPT::saddr, OPT::imm6}}},
    // XOR1 CY,saddr.7
    {0x71U, {RL78::XOR1_cy_saddrx, {0x77U, SBP::saddr}, {OPT::saddr, OPT::imm7}}},
    // XOR1 CY,ES:[HL].0
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0x87U}, {RL78::CY, OPT::ES_memHL,OPT::imm0}}},
    // XOR1 CY,ES:[HL].1
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0x97U}, {RL78::CY, OPT::ES_memHL,OPT::imm1}}},
    // XOR1 CY,ES:[HL].2
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0xA7U}, {RL78::CY, OPT::ES_memHL,OPT::imm2}}},
    // XOR1 CY,ES:[HL].3
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0xB7U}, {RL78::CY, OPT::ES_memHL,OPT::imm3}}},
    // XOR1 CY,ES:[HL].4
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0xC7U}, {RL78::CY, OPT::ES_memHL,OPT::imm4}}},
    // XOR1 CY,ES:[HL].5
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0xD7U}, {RL78::CY, OPT::ES_memHL,OPT::imm5}}},
    // XOR1 CY,ES:[HL].6
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0xE7U}, {RL78::CY, OPT::ES_memHL,OPT::imm6}}},
    // XOR1 CY,ES:[HL].7
    {0x11U, {RL78::XOR1_esmemr, {0x71U, 0xF7U}, {RL78::CY, OPT::ES_memHL,OPT::imm7}}},
    // XOR1 CY,PSW.0
    {0x71U, {RL78::XOR1_cy_PSW, {0x0FU, 0xFAU}, {RL78::PSW, OPT::imm0}}},
    // XOR1 CY,PSW.1
    {0x71U, {RL78::XOR1_cy_PSW, {0x1FU, 0xFAU}, {RL78::PSW, OPT::imm1}}},
    // XOR1 CY,PSW.2
    {0x71U, {RL78::XOR1_cy_PSW, {0x2FU, 0xFAU}, {RL78::PSW, OPT::imm2}}},
    // XOR1 CY,PSW.3
    {0x71U, {RL78::XOR1_cy_PSW, {0x3FU, 0xFAU}, {RL78::PSW, OPT::imm3}}},
    // XOR1 CY,PSW.4
    {0x71U, {RL78::XOR1_cy_PSW, {0x4FU, 0xFAU}, {RL78::PSW, OPT::imm4}}},
    // XOR1 CY,PSW.5
    {0x71U, {RL78::XOR1_cy_PSW, {0x5FU, 0xFAU}, {RL78::PSW, OPT::imm5}}},
    // XOR1 CY,PSW.6
    {0x71U, {RL78::XOR1_cy_PSW, {0x6FU, 0xFAU}, {RL78::PSW, OPT::imm6}}},
    // XOR1 CY,PSW.7
    {0x71U, {RL78::XOR1_cy_PSW, {0x7FU, 0xFAU}, {RL78::PSW, OPT::imm7}}},
    // XOR1 CY,sfr.0
    {0x71U, {RL78::XOR1_cy_sfr, {0x0FU, SBP::sfr}, {OPT::sfr,OPT::imm0}}},
    // XOR1 CY,sfr.1
    {0x71U, {RL78::XOR1_cy_sfr, {0x1FU, SBP::sfr}, {OPT::sfr,OPT::imm1}}},
    // XOR1 CY,sfr.2
    {0x71U, {RL78::XOR1_cy_sfr, {0x2FU, SBP::sfr}, {OPT::sfr,OPT::imm2}}},
    // XOR1 CY,sfr.3
    {0x71U, {RL78::XOR1_cy_sfr, {0x3FU, SBP::sfr}, {OPT::sfr,OPT::imm3}}},
    // XOR1 CY,sfr.4
    {0x71U, {RL78::XOR1_cy_sfr, {0x4FU, SBP::sfr}, {OPT::sfr,OPT::imm4}}},
    // XOR1 CY,sfr.5
    {0x71U, {RL78::XOR1_cy_sfr, {0x5FU, SBP::sfr}, {OPT::sfr,OPT::imm5}}},
    // XOR1 CY,sfr.6
    {0x71U, {RL78::XOR1_cy_sfr, {0x6FU, SBP::sfr}, {OPT::sfr,OPT::imm6}}},
    // XOR1 CY,sfr.7
    {0x71U, {RL78::XOR1_cy_sfr, {0x7FU, SBP::sfr}, {OPT::sfr,OPT::imm7}}},
    // clang-format on
};

static std::map<int64_t, int64_t> calltOpcodeToAddr{

    {0x84, 0x0080}, {0x94, 0x0082}, {0xa4, 0x0084}, {0xb4, 0x0086},
    {0xc4, 0x0088}, {0xd4, 0x008a}, {0xe4, 0x008c}, {0xf4, 0x008e},
    {0x85, 0x0090}, {0x95, 0x0092}, {0xa5, 0x0094}, {0xb5, 0x0096},
    {0xc5, 0x0098}, {0xd5, 0x009a}, {0xe5, 0x009c}, {0xf5, 0x009e},
    {0x86, 0x00a0}, {0x96, 0x00a2}, {0xa6, 0x00a4}, {0xb6, 0x00a6},
    {0xc6, 0x00a8}, {0xd6, 0x00aa}, {0xe6, 0x00ac}, {0xf6, 0x00ae},
    {0x87, 0x00b0}, {0x97, 0x00b2}, {0xa7, 0x00b4}, {0xb7, 0x00b6},
    {0xc7, 0x00b8}, {0xd7, 0x00ba}, {0xe7, 0x00bc}, {0xf7, 0x00be},

};

static size_t findPartIndex(InstructionInfo info, unsigned int sbp) {
  size_t byteIndex = 0;
  for (size_t i = 0, e = info.BitParts.size(); i != e; ++i) {
    if (info.BitParts[i] == sbp) {
      byteIndex = i + 1;
      break;
    }
  }

  assert(byteIndex && "Requested sbp was not present in the instruction info");
  return byteIndex;
}

static unsigned char extract8bitValue(ArrayRef<uint8_t> Bytes,
                                      InstructionInfo info, unsigned int sbp) {
  size_t byteIndex = findPartIndex(info, sbp);
  return Bytes[byteIndex];
}

static unsigned int extract16bitValue(ArrayRef<uint8_t> Bytes,
                                      InstructionInfo info, unsigned int sbp_h,
                                      unsigned int sbp_l) {
  size_t hi_Index = findPartIndex(info, sbp_h);
  size_t lo_Index = findPartIndex(info, sbp_l);
  return Bytes[hi_Index] << 8 | Bytes[lo_Index];
}

static unsigned int extract20bitValue(ArrayRef<uint8_t> Bytes,
                                      InstructionInfo info, unsigned int sbp_h,
                                      unsigned int sbp_md, unsigned int sbp_l) {
  size_t hi_Index = findPartIndex(info, sbp_h);
  size_t md_Index = findPartIndex(info, sbp_md);
  size_t lo_Index = findPartIndex(info, sbp_l);
  return Bytes[hi_Index] << 16 | Bytes[md_Index] << 8 | Bytes[lo_Index];
}

static void decodeSADDR(MCInst &Instr, ArrayRef<uint8_t> Bytes,
                        InstructionInfo info,
                        std::map<unsigned char, unsigned int> lookup) {
  Instr.addOperand(
      MCOperand::createImm(extract8bitValue(Bytes, info, SBP::saddr)));
}

static void handleOperand(uint64_t Address, MCInst &Instr,
                          ArrayRef<uint8_t> Bytes, InstructionInfo info,
                          unsigned int operand, const RL78Disassembler *Dis) {
  switch (operand) {
  case OPT::ES_I_addr16:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl)));
    break;
  case OPT::ES_memDE:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP4));
    Instr.addOperand(MCOperand::createImm(0));
    break;
  case OPT::ES_memDE_byte:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP4));
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::adr)));
    break;
  case OPT::ES_memHL:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    break;
  case OPT::ES_memHL0:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(MCOperand::createImm(0));
    break;
  case OPT::ES_memHL_B:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(MCOperand::createReg(RL78::R3));
    break;
  case OPT::ES_memHL_C:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(MCOperand::createReg(RL78::R2));
    break;
  case OPT::ES_memHL_byte:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::adr)));
    break;
  case OPT::ES_word_memB:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::R3));
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl)));
    break;
  case OPT::ES_word_memBC:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::RP2));
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl)));
    break;
  case OPT::ES_word_memC:
    Instr.addOperand(MCOperand::createReg(RL78::ES));
    Instr.addOperand(MCOperand::createReg(RL78::R2));
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl)));
    break;
  case OPT::II_addr20: {
    unsigned int addr20 =
        extract20bitValue(Bytes, info, SBP::adrs, SBP::adrh, SBP::adrl);
    if (!Dis->tryAddingSymbolicOperand(Instr, addr20, 0, true,
                                       /* Offset */ 0, 0, /* InstSize */3)) {
      Instr.addOperand(MCOperand::createImm(addr20));
    }
  } break;
  case OPT::I_addr16: {
    unsigned int addr16 = extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl);

    switch (Instr.getOpcode()) {
    case RL78::BR_addr16:
    case RL78::CALL_addr16:
      break;
    default:
      addr16 += 0xf0000;
    }

    if (!Dis->tryAddingSymbolicOperand(Instr, addr16, Address, false,
                                       /* Offset */ 0, 0, /* InstSize */3))
      Instr.addOperand(MCOperand::createImm(addr16));

  } break;
  case OPT::RB0:
    Instr.addOperand(MCOperand::createImm(0));
    break;
  case OPT::RB1:
    Instr.addOperand(MCOperand::createImm(1));
    break;
  case OPT::RB2:
    Instr.addOperand(MCOperand::createImm(2));
    break;
  case OPT::RB3:
    Instr.addOperand(MCOperand::createImm(3));
    break;
  case OPT::SI_addr20: {
    signed int jdsp16 = extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl);
    if (!Dis->tryAddingSymbolicOperand(
            Instr, jdsp16 + Address + info.BitParts.size() + 1, Address, true,
            /* Offset */ 0, 0, /* InstSize */3))
      Instr.addOperand(MCOperand::createImm(jdsp16));

  } break;
  case OPT::S_addr20: {
    signed char jdsp8 = extract8bitValue(Bytes, info, SBP::adr);
    if (!Dis->tryAddingSymbolicOperand(
            Instr, jdsp8 + Address + info.BitParts.size() + 1, Address, true,
            /* Offset */ 0, 0, /* InstSize */ 3))
      Instr.addOperand(MCOperand::createImm(jdsp8));
  } break;
  case OPT::byte:
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::data)));
    break;
  case OPT::imm0:
    Instr.addOperand(MCOperand::createImm(0));
    break;
  case OPT::imm1:
    Instr.addOperand(MCOperand::createImm(1));
    break;
  case OPT::imm10:
    Instr.addOperand(MCOperand::createImm(10));
    break;
  case OPT::imm11:
    Instr.addOperand(MCOperand::createImm(11));
    break;
  case OPT::imm12:
    Instr.addOperand(MCOperand::createImm(12));
    break;
  case OPT::imm13:
    Instr.addOperand(MCOperand::createImm(13));
    break;
  case OPT::imm14:
    Instr.addOperand(MCOperand::createImm(14));
    break;
  case OPT::imm15:
    Instr.addOperand(MCOperand::createImm(15));
    break;
  case OPT::imm2:
    Instr.addOperand(MCOperand::createImm(2));
    break;
  case OPT::imm3:
    Instr.addOperand(MCOperand::createImm(3));
    break;
  case OPT::imm4:
    Instr.addOperand(MCOperand::createImm(4));
    break;
  case OPT::imm5:
    Instr.addOperand(MCOperand::createImm(5));
    break;
  case OPT::imm6:
    Instr.addOperand(MCOperand::createImm(6));
    break;
  case OPT::imm7:
    Instr.addOperand(MCOperand::createImm(7));
    break;
  case OPT::imm8:
    Instr.addOperand(MCOperand::createImm(8));
    break;
  case OPT::imm9:
    Instr.addOperand(MCOperand::createImm(9));
    break;
  case OPT::memDE:
    Instr.addOperand(MCOperand::createReg(RL78::RP4));
    Instr.addOperand(MCOperand::createImm(0));
    break;
  case OPT::memDE_byte:
    Instr.addOperand(MCOperand::createReg(RL78::RP4));
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::adr)));
    break;
  case OPT::memHL:
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    break;
  case OPT::memHL0:
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(MCOperand::createImm(0));
    break;
  case OPT::memHL_B:
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(MCOperand::createReg(RL78::R3));
    break;
  case OPT::memHL_C:
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(MCOperand::createReg(RL78::R2));
    break;
  case OPT::memHL_byte:
    Instr.addOperand(MCOperand::createReg(RL78::RP6));
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::adr)));
    break;
  case OPT::memSP_byte:
    Instr.addOperand(MCOperand::createReg(RL78::SPreg));
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::adr)));
    break;
  case OPT::mem_addr5:
    Instr.addOperand(MCOperand::createImm(
        calltOpcodeToAddr[extract8bitValue(Bytes, info, SBP::adr)]));
    break;
  case OPT::saddr:
    decodeSADDR(Instr, Bytes, info, saddrLookup);
    break;
  case OPT::saddrp:
    decodeSADDR(Instr, Bytes, info, saddrpLookup);
    break;
  case OPT::sfr:
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::sfr)));
    break;
  case OPT::sfrp:
    Instr.addOperand(
        MCOperand::createImm(extract8bitValue(Bytes, info, SBP::sfr)));
    break;
  case OPT::word:
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::datah, SBP::datal)));
    break;
  case OPT::word_memB:
    Instr.addOperand(MCOperand::createReg(RL78::R3));
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl)));
    break;
  case OPT::word_memBC:
    Instr.addOperand(MCOperand::createReg(RL78::RP2));
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl)));
    break;
  case OPT::word_memC:
    Instr.addOperand(MCOperand::createReg(RL78::R2));
    Instr.addOperand(MCOperand::createImm(
        extract16bitValue(Bytes, info, SBP::adrh, SBP::adrl)));
    break;
  case RL78::CS:
  case RL78::CY:
  case RL78::ES:
  case RL78::PSW:
  case RL78::R0:
  case RL78::R1:
  case RL78::R2:
  case RL78::R3:
  case RL78::R4:
  case RL78::R5:
  case RL78::R6:
  case RL78::R7:
  case RL78::RP0:
  case RL78::RP2:
  case RL78::RP4:
  case RL78::RP6:
  case RL78::SPreg:
    Instr.addOperand(MCOperand::createReg(operand));
    break;
  case OPT::RL78CC_C:
  case OPT::RL78CC_NC:
  case OPT::RL78CC_Z:
  case OPT::RL78CC_NZ:
  case OPT::RL78CC_H:
  case OPT::RL78CC_NH:
    Instr.addOperand(MCOperand::createImm(operand & 0xFF));
    break;
  default:
    llvm_unreachable("Operand not implemented");
  }
}

static DecodeStatus handleMatch(uint64_t Address, InstructionInfo Match,
                                MCInst &Instr, uint64_t &Size,
                                ArrayRef<uint8_t> Bytes,
                                const RL78Disassembler *Dis) {
  Size = Match.BitParts.size() + 1;
  Instr.setOpcode(Match.OpCode);
  for (unsigned int op : Match.Operands)
    handleOperand(Address, Instr, Bytes, Match, op, Dis);
  return MCDisassembler::Success;
}
static bool instructionsMergedS3core = false;
DecodeStatus RL78Disassembler::getInstruction(MCInst &Instr, uint64_t &Size,
                                              ArrayRef<uint8_t> Bytes,
                                              uint64_t Address,
                                              raw_ostream &CStream) const {

  if (STI.getCPU() == "RL78_S3" && !instructionsMergedS3core) {
    instructions.insert(instructionsS3.begin(), instructionsS3.end());
    instructionsMergedS3core = true;
  }

  if (Bytes.size() < 1) {
    Size = 0;
    return MCDisassembler::Fail;
  }
  auto matchCount = instructions.count(Bytes[0]);
  if (matchCount == 1) {
    return handleMatch(Address, instructions.find(Bytes[0])->second, Instr,
                       Size, Bytes, this);
  } else if (matchCount > 1 && Bytes.size() >= 2) {
    // find an exact match by trying to match additional bytes
    std::pair<std::multimap<unsigned int, InstructionInfo>::iterator,
              std::multimap<unsigned int, InstructionInfo>::iterator>
        matchIterator = instructions.equal_range(Bytes[0]);

    std::vector<InstructionInfo> matches;
    for (auto match = matchIterator.first, e = matchIterator.second; match != e;
         ++match)
      matches.push_back(match->second);

    unsigned char byteIndex = 0;
    do {

      std::vector<InstructionInfo> exactMatches;
      std::vector<InstructionInfo> coverMatches;
      for (InstructionInfo match : matches) {
        if (match.BitParts.size() > byteIndex &&
            Bytes[byteIndex + 1] == match.BitParts[byteIndex]) {
          exactMatches.push_back(match);
        }
        if (match.BitParts.size() > byteIndex &&
            match.BitParts[byteIndex] >= SBP::adr) {
          coverMatches.push_back(match);
        }
      }
      byteIndex++;

      if (exactMatches.size() == 1)
        matches = exactMatches;
      else if (exactMatches.size() > 1 && coverMatches.size() > 0) {
        matches = exactMatches;
        matches.insert(matches.end(), coverMatches.begin(), coverMatches.end());
      } else
        matches = exactMatches.size() ? exactMatches : coverMatches;

    } while (matches.size() != 1 && byteIndex != 4 &&
             byteIndex + 1U < Bytes.size());
    if (matches.size() == 1)
      return handleMatch(Address, matches[0], Instr, Size, Bytes, this);
  }
  // handle special case of the PREFIX instr
  if (Bytes[0] == 0x11) {
    for (std::multimap<unsigned int, InstructionInfo>::iterator
             it = instructions.begin(),
             e = instructions.end();
         it != e; ++it)
      if (it->second.OpCode == RL78::PREFIX)
        return handleMatch(Address, it->second, Instr, Size, Bytes, this);
  }

  Size = 0;
  return MCDisassembler::Fail;
}

// Try to find symbol name for specified label
bool RL78Symbolizer::tryAddingSymbolicOperand(
    MCInst &Inst, raw_ostream& /*cStream*/,
                                        int64_t Value, uint64_t /*Address*/,
                                        bool IsBranch, uint64_t /*Offset*/,
                                        uint64_t /*OpSize*/, uint64_t /*InstSize*/) {
  auto *AllSymbols =
      static_cast<std::map<object::SectionRef, SectionSymbolsTy> *>(DisInfo);
  if (!AllSymbols)
    return false;

  StringRef matchedSymbol = "";
  uint64_t startSymbolAddress = 0;

  if (IsBranch) {
    for (std::pair<const object::SectionRef, SectionSymbolsTy> &SecSyms :
         *AllSymbols)
      if (SecSyms.first.isText() &&
          SecSyms.first.getAddress() <= static_cast<uint64_t>(Value) &&
          SecSyms.first.getSize() + SecSyms.first.getAddress() >=
              static_cast<uint64_t>(Value))
        for (SymbolInfoTy &symbol : SecSyms.second)
          if (symbol.Addr <= static_cast<uint64_t>(Value)) {
            matchedSymbol = symbol.Name;
            startSymbolAddress = symbol.Addr;
          } else
            break;

  } else
    for (std::pair<const object::SectionRef, SectionSymbolsTy> &SecSyms :
         *AllSymbols)
      if (SecSyms.first.getAddress() <= static_cast<uint64_t>(Value) &&
          SecSyms.first.getSize() + SecSyms.first.getAddress() >=
              static_cast<uint64_t>(Value))
        for (SymbolInfoTy &symbol : SecSyms.second)
          // Assume that the symbols are ordered by address and take the
          // last symbol from a group of symbols having the same address
          if (symbol.Addr == static_cast<uint64_t>(Value))
            matchedSymbol = symbol.Name;

  if (matchedSymbol != "") {
    auto *Sym = Ctx.getOrCreateSymbol(matchedSymbol);
    const auto *SymExpr = MCSymbolRefExpr::create(Sym, Ctx);
    if (startSymbolAddress != 0 && startSymbolAddress != Value)
      Inst.addOperand(MCOperand::createExpr(MCBinaryExpr::createAdd(
          SymExpr, MCConstantExpr::create(Value - startSymbolAddress, Ctx),
          Ctx)));
    else
      Inst.addOperand(MCOperand::createExpr(SymExpr));
    return true;
  }
  return false;
}

void RL78Symbolizer::tryAddingPcLoadReferenceComment(raw_ostream &cStream,
                                                     int64_t Value,
                                                     uint64_t Address) {
  llvm_unreachable("unimplemented");
}