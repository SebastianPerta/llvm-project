//===-- RL78InstPrinter.cpp - Convert RL78 MCInst to assembly syntax -----==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an RL78 MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include "RL78InstPrinter.h"
#include "RL78TargetMachine.h"

using namespace llvm;

#define DEBUG_TYPE "asm-printer"

#define GET_INSTRUCTION_NAME
#define PRINT_ALIAS_INSTR
#include "RL78GenAsmWriter.inc"

void RL78InstPrinter::printRegName(raw_ostream &OS, MCRegister Reg) const {
  OS << StringRef(getRegisterName(Reg)).lower();
}

void RL78InstPrinter::printInst(const MCInst *MI, uint64_t Address,
                                StringRef Annot, const MCSubtargetInfo &STI,
                                raw_ostream &O) {
  if (!printAliasInstr(MI, Address, STI, O))
    printInstruction(MI, Address, STI, O);
  printAnnotation(O, Annot);
}

void RL78InstPrinter::printOperand(const MCInst *MI, int opNum,
                                   const MCSubtargetInfo &STI, raw_ostream &O) {
  const MCOperand &MO = MI->getOperand(opNum);
  // MI->dump();
  // MO.dump();

  if (MO.isReg()) {
    printRegName(O, MO.getReg());
    return;
  }

  if (MO.isImm()) {
    O << "#" << (int)MO.getImm();
    return;
  }

  if (MO.isExpr()) {
    O << "#";
    MO.getExpr()->print(O, &MAI);
    return;
  }
}

void RL78InstPrinter::printMemOperand(const MCInst *MI, int opNum,
                                      const MCSubtargetInfo &STI,
                                      raw_ostream &O, const char *Modifier) {
  const MCOperand &MO = MI->getOperand(opNum);
  const MCOperand &MO1 = MI->getOperand(opNum + 1);
  // word[BC], word[B], word[C].
  if (MO.isReg() && (MO.getReg() == RL78::RP2 || MO.getReg() == RL78::R2 ||
                     MO.getReg() == RL78::R3)) {
    if (MO1.isImm()) {
      O << (int)MO1.getImm();
    } else if (MO1.isExpr()) {
      MO1.getExpr()->print(O, &MAI);
    } else
      llvm_unreachable("Operand type is not Immediate or Expression!");
    O << "[";
    printOperand(MI, opNum, STI, O);
    O << "]";
    return;
  }
  O << "[";
  printOperand(MI, opNum, STI, O);

  if (MO1.isImm()) {
    switch (MI->getOpcode()) {
    // [HL] only, [HL+byte] not available in this case.
    case RL78::SET1_memr:
    case RL78::CLR1_memr:
    case RL78::MOV1_cy_memr:
    case RL78::MOV1_memr_cy:
    case RL78::AND1_cy_memr:
    case RL78::OR1_cy_memr:
    case RL78::XOR1_cy_memr:
    case RL78::BTBF_memr:
      break;
    // [HL+byte] only, [HL] not available in this case.
    case RL78::INC_memri:
    case RL78::INCW_memri:
    case RL78::DEC_memri:
    case RL78::DECW_memri:
    case RL78::MOVS_memri_r:
      O << "+";
      O << (int)MO1.getImm();
      break;
    default:
      // Both variants [DE/HL], [DE/HL+byte] available chose the shortest one.
      if (MO1.getImm() != 0) {
        O << "+";
        O << (int)MO1.getImm();
      }
      break;
    }
  } else if (MO1.isExpr()) {
    O << "+";
    MO1.getExpr()->print(O, &MAI);
  } else
    llvm_unreachable("Operand type is not Immediate or Expression!");
  O << "]";
}

void RL78InstPrinter::printSELRBxOperand(const MCInst *MI, int opNum,
                                         const MCSubtargetInfo &STI,
                                         raw_ostream &O) {
  static const char *RB[] = {"rb0", "rb1", "rb2", "rb3"};
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << RB[MO.getImm()];
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printBitOperand(const MCInst *MI, int opNum,
                                      const MCSubtargetInfo &STI,
                                      raw_ostream &O) {
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm()) {
    RL78ReportError((int)MO.getImm() >= 0 && (int)MO.getImm() < 8,
                    "Instruction using operand outside of range.");
    O << "." << (int)MO.getImm();
  } else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printShiftOperand(const MCInst *MI, int opNum,
                                        const MCSubtargetInfo &STI,
                                        raw_ostream &O) {
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << (int)MO.getImm();
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printABS8Operand(const MCInst *MI, int opNum,
                                       const MCSubtargetInfo &STI,
                                       raw_ostream &O) {
  // TODO: assert for symbolref only, for the rest below as well.
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << "0xffe" << format_hex_no_prefix(MO.getImm(), 2);
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printSfrOperand(const MCInst *MI, int opNum,
                                      const MCSubtargetInfo &STI,
                                      raw_ostream &O) {
  // TODO: assert for symbolref only, for the rest below as well.
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << "0xfff" << format_hex_no_prefix(0xFF & MO.getImm(), 2);
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printABS16Operand(const MCInst *MI, int opNum,
                                        const MCSubtargetInfo &STI,
                                        raw_ostream &O) {
  O << "!";
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm()) {

    switch (MI->getOpcode()) {
    default:
      O << "0xf" << format_hex_no_prefix(0xFFFF & MO.getImm(), 4);
      break;
    case RL78::CALL_addr16:
    case RL78::BR_addr16:
      O << format_hex(MO.getImm(), 0);
      break;
    }
  } else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);

  assert((MO.isImm() || MO.isExpr()) &&
         "Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printABS5Operand(const MCInst *MI, int opNum,
                                       const MCSubtargetInfo &STI,
                                       raw_ostream &O) {
  O << "[";
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << format_hex(MO.getImm(), 6);
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");

  O << "]";
}

void RL78InstPrinter::printABS20Operand(const MCInst *MI, int opNum,
                                        const MCSubtargetInfo &STI,
                                        raw_ostream &O) {
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << format_hex(MO.getImm(), 0);
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printStackSlotOperand(const MCInst *MI, int opNum,
                                            const MCSubtargetInfo &STI,
                                            raw_ostream &O) {
  O << "[";
  printOperand(MI, opNum, STI, O);

  const MCOperand &MO = MI->getOperand(opNum + 1);
  O << "+";
  if (MO.isImm())
    O << (int)MO.getImm();
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");

  O << "]";
}

void RL78InstPrinter::printRel8Operand(const MCInst *MI, int opNum,
                                       const MCSubtargetInfo &STI,
                                       raw_ostream &O) {
  O << "$";
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << format_hex(MO.getImm(), 2);
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}
void RL78InstPrinter::printRel16Operand(const MCInst *MI, int opNum,
                                        const MCSubtargetInfo &STI,
                                        raw_ostream &O) {
  O << "$!";
  const MCOperand &MO = MI->getOperand(opNum);
  if (MO.isImm())
    O << format_hex(MO.getImm(), 0);
  else if (MO.isExpr())
    MO.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}

void RL78InstPrinter::printHLMemOperand(const MCInst *MI, int opNum,
                                        const MCSubtargetInfo &STI,
                                        raw_ostream &O) {
  const MCOperand &MO = MI->getOperand(opNum);
  assert(MO.isReg() && MO.getReg() == RL78::RP6 && "Expected HL register");
  if (MO.isReg() && (MO.getReg() == RL78::RP6)) {
    O << "[";
    printOperand(MI, opNum, STI, O);
    O << "]";
    return;
  }
  return;
}
void RL78InstPrinter::printRegSumMemOperand(const MCInst *MI, int opNum,
                                            const MCSubtargetInfo &STI,
                                            raw_ostream &O) {
  O << "[";
  printOperand(MI, opNum, STI, O);

  O << "+";

  assert(MI->getOperand(opNum + 1).isReg() && "Expected B or C register");
  printOperand(MI, opNum + 1, STI, O);

  O << "]";
}
void RL78InstPrinter::printEsRegMemOperand(const MCInst *MI, int opNum,
                                           const MCSubtargetInfo &STI,
                                           raw_ostream &O) {
  assert((MI->getOperand(opNum).isReg() &&
          MI->getOperand(opNum).getReg() == RL78::ES) &&
         "Expected ES register");
  const MCOperand &MO1 = MI->getOperand(opNum + 1);
  const MCOperand &MO2 = MI->getOperand(opNum + 2);
  printOperand(MI, opNum, STI, O);
  O << ":";
  // word[BC], word[B], word[C].
  if (MO1.isReg() && (MO1.getReg() == RL78::RP2 || MO1.getReg() == RL78::R2 ||
                      MO1.getReg() == RL78::R3)) {

    if (MO2.isImm()) {
      O << (int)MO2.getImm();
    } else if (MO2.isExpr()) {
      MO2.getExpr()->print(O, &MAI);
    } else
      llvm_unreachable("Operand type is not Immediate or Expression!");

    O << "[";
    printOperand(MI, opNum + 1, STI, O);
    O << "]";
    return;
  }
  O << "[";
  printOperand(MI, opNum + 1, STI, O);

  if (MO2.isImm()) {
    // Both variants [DE/HL], [DE/HL+byte] available chose the shortest one.
    if (MO2.getImm() != 0) {
      O << "+";
      O << (int)MO2.getImm();
    }
  } else if (MO2.isExpr()) {
    O << "+";
    MO2.getExpr()->print(O, &MAI);
  } else
    llvm_unreachable("Operand type is not Immediate or Expression!");
  O << "]";
  return;
}

void RL78InstPrinter::printEsRegHLOnlyMemOperand(const MCInst *MI, int opNum,
                                                 const MCSubtargetInfo &STI,
                                                 raw_ostream &O) {
  assert((MI->getOperand(opNum).isReg() &&
          MI->getOperand(opNum).getReg() == RL78::ES) &&
         "Expected ES register");
  const MCOperand &MO1 = MI->getOperand(opNum + 1);
  printOperand(MI, opNum, STI, O);
  O << ":";

  if (MO1.isReg() && (MO1.getReg() == RL78::RP6)) {
    O << "[";
    printOperand(MI, opNum + 1, STI, O);
    O << "]";
    return;
  }

  return;
}

void RL78InstPrinter::printEsAddr16Operand(const MCInst *MI, int opNum,
                                           const MCSubtargetInfo &STI,
                                           raw_ostream &O) {
  assert((MI->getOperand(opNum).isReg() &&
          MI->getOperand(opNum).getReg() == RL78::ES) &&
         "Expected ES register");
  printOperand(MI, opNum, STI, O);
  O << ":";
  O << "!";
  const MCOperand &MO1 = MI->getOperand(opNum + 1);
  if (MO1.isImm())
    O << format_hex(0xFFFF & MO1.getImm(), 0);
  else if (MO1.isExpr())
    MO1.getExpr()->print(O, &MAI);
  else
    llvm_unreachable("Operand type is not Immediate or Expression!");
}
void RL78InstPrinter::printEsRegRegSumMemOperand(const MCInst *MI, int opNum,
                                                 const MCSubtargetInfo &STI,
                                                 raw_ostream &O) {
  assert((MI->getOperand(opNum).isReg() &&
          MI->getOperand(opNum).getReg() == RL78::ES) &&
         "Expected ES register");

  printOperand(MI, opNum, STI, O);
  O << ":";

  O << "[";
  printOperand(MI, opNum + 1, STI, O);

  O << "+";

  assert(MI->getOperand(opNum + 2).isReg() && "Expected B or C register");
  printOperand(MI, opNum + 2, STI, O);

  O << "]";
}

void RL78InstPrinter::printCCOperand(const MCInst *MI, int opNum,
                                     const MCSubtargetInfo &STI,
                                     raw_ostream &O) {
  // CC operand is always immediate/const.
  int CC = static_cast<int>(MI->getOperand(opNum).getImm());
  switch (MI->getOpcode()) {
  default:
    break;
  case RL78::BTBF:
  case RL78::BTBF_mem:
  case RL78::BTBF_A:
  case RL78::BTBF_memr:
  case RL78::BTCLR_A:
  case RL78::BTBF_sfri_addr:
  case RL78::BTBF_PSWi_addr:
  case RL78::BTBF_esmemr:
  case RL78::BTBF_saddr:
    switch (CC) {
    default:
      llvm_unreachable("Invalid condition code!");
    case RL78CC::RL78CC_Z:
      O << "t";
      return;
    case RL78CC::RL78CC_NZ:
      O << "f";
      return;
    }
  }
  O << RL78CondCodeToString((RL78CC::CondCodes)CC);
}
