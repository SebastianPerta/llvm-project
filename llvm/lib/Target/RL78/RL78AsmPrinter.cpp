//===-- RL78AsmPrinter.cpp - RL78 LLVM assembly writer ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains a printer that converts from our internal representation
// of machine-dependent LLVM code to GAS-format RL78 assembly language.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/RL78InstPrinter.h"
#include "MCTargetDesc/RL78MCExpr.h"
#include "MCTargetDesc/RL78TargetStreamer.h"
#include "RL78TargetMachine.h"
#include "TargetInfo/RL78TargetInfo.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/MachineModuleInfoImpls.h"
#include "llvm/MC/MCInstBuilder.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/TargetRegistry.h"
using namespace llvm;

#define DEBUG_TYPE "asm-printer"

namespace {
class RL78AsmPrinter : public AsmPrinter {
  RL78TargetStreamer &getTargetStreamer() {
    return static_cast<RL78TargetStreamer &>(*OutStreamer->getTargetStreamer());
  }

public:
  explicit RL78AsmPrinter(TargetMachine &TM,
                          std::unique_ptr<MCStreamer> Streamer)
      : AsmPrinter(TM, std::move(Streamer)) {}

  StringRef getPassName() const override { return "RL78 Assembly Printer"; }

  void printOperand(const MachineInstr *MI, int opNum, raw_ostream &OS);
  void printMemOperand(const MachineInstr *MI, int opNum, raw_ostream &OS,
                       const char *Modifier = nullptr);

  void emitStartOfAsmFile(Module &) override;
  void emitFunctionBodyStart() override;
  void emitFunctionBodyEnd() override;
  void emitInstruction(const MachineInstr *MI) override;
  const MCExpr *lowerConstant(const Constant *CV) override;

  static const char *getRegisterName(unsigned RegNo) {
    return RL78InstPrinter::getRegisterName(RegNo);
  }

  bool PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                       const char *ExtraCode, raw_ostream &O);
  bool PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNo,
                             const char *ExtraCode, raw_ostream &O);

private:
  void emitInterruptVectorSymbol(uint64_t Specs);
};
} // end of anonymous namespace

static MCOperand createRL78MCOperand(RL78MCExpr::VariantKind Kind,
                                     MCSymbol *Sym, MCContext &OutContext) {
  const MCSymbolRefExpr *MCSym = MCSymbolRefExpr::create(Sym, OutContext);
  const RL78MCExpr *expr = RL78MCExpr::create(Kind, MCSym, OutContext);
  return MCOperand::createExpr(expr);
}
static MCOperand createPCXCallOP(MCSymbol *Label, MCContext &OutContext) {
  return createRL78MCOperand(RL78MCExpr::VK_RL78_None, Label, OutContext);
}

static MCOperand createPCXRelExprOp(RL78MCExpr::VariantKind Kind,
                                    MCSymbol *GOTLabel, MCSymbol *StartLabel,
                                    MCSymbol *CurLabel, MCContext &OutContext) {
  const MCSymbolRefExpr *GOT = MCSymbolRefExpr::create(GOTLabel, OutContext);
  const MCSymbolRefExpr *Start =
      MCSymbolRefExpr::create(StartLabel, OutContext);
  const MCSymbolRefExpr *Cur = MCSymbolRefExpr::create(CurLabel, OutContext);

  const MCBinaryExpr *Sub = MCBinaryExpr::createSub(Cur, Start, OutContext);
  const MCBinaryExpr *Add = MCBinaryExpr::createAdd(GOT, Sub, OutContext);
  const RL78MCExpr *expr = RL78MCExpr::create(Kind, Add, OutContext);
  return MCOperand::createExpr(expr);
}

void RL78AsmPrinter::emitInstruction(const MachineInstr *MI) {
  switch (MI->getOpcode()) {
  default:
    break;
  case RL78::ADJCALLSTACKDOWN:
  case RL78::ADJCALLSTACKUP:
    return;
  }
  
  // MI->dump();
  if (MI->getOpcode() == TargetOpcode::BUNDLE) {
    MachineBasicBlock::const_instr_iterator I = MI->getIterator();
    MachineBasicBlock::const_instr_iterator E = MI->getParent()->instr_end();
    while (++I != E && I->isInsideBundle()) {
      assert(!I->isBundle() && "No nested bundle!");
      MCInst TmpInst;
      LowerRL78MachineInstrToMCInst(&*I, TmpInst, *this);
      EmitToStreamer(*OutStreamer, TmpInst);
    }
  } else {
    MCInst TmpInst;
    LowerRL78MachineInstrToMCInst(MI, TmpInst, *this);
    EmitToStreamer(*OutStreamer, TmpInst);
  }
}

void RL78AsmPrinter::emitStartOfAsmFile(Module &M) {
  MCSectionELF *TextSection = OutStreamer->getContext().getELFSection(
      ".text", ELF::SHT_PROGBITS, ELF::SHF_EXECINSTR | ELF::SHF_ALLOC);
  TextSection->setAlignment(Align(1));
  // If none of the defined functions has callt attribute
  // there's noting to do here.
  if (none_of(M, [](const Function &F) {
        return !F.isDeclaration() && F.hasFnAttribute("callt");
      }))
    return;
  OutStreamer->pushSection();
  MCSectionELF *Callt = OutStreamer->getContext().getELFSection(
      ".callt0", ELF::SHT_PROGBITS, ELF::SHF_ALLOC);
  OutStreamer->switchSection(Callt);
  emitAlignment(Align(2));
  //
  for (auto F = M.begin(), E = M.end(); F != E; ++F) {
    if (F->isDeclaration() || !F->hasFnAttribute("callt"))
      continue;
    MCSymbol *CurrentFnSym = getSymbol(&*F);
    auto calltSym =
        OutContext.getOrCreateSymbol(Twine("@") + CurrentFnSym->getName());
    OutStreamer->emitSymbolAttribute(calltSym, MCSA_Global);
    OutStreamer->emitLabel(calltSym);
    const MCSymbolRefExpr *FnStartRef = MCSymbolRefExpr::create(
        CurrentFnSym, /*LOW16?,*/ OutStreamer->getContext());
    OutStreamer->emitValue(FnStartRef, 2);
  }

  OutStreamer->endSection(Callt);
  OutStreamer->popSection();
}

void RL78AsmPrinter::emitInterruptVectorSymbol(uint64_t Specs) {
  if (Specs & 0xFE) {
    auto vect = OutContext.getOrCreateSymbol(
        Twine("___vector_") + Twine::utohexstr(Specs & 0xFE) + Twine("_"));
    RL78ReportError(vect->isUndefined() && !vect->isVariable(),
                    "Redefinition of the 0x" +
                        Twine::utohexstr(Specs & 0xFE).str() +
                        " entry in the interrupt table!");
    getTargetStreamer().getStreamer().emitLabel(vect);
    getTargetStreamer().getStreamer().emitSymbolAttribute(vect, MCSA_Global);
  }
}

void RL78AsmPrinter::emitFunctionBodyStart() {
  if (!MF->getFunction().hasFnAttribute("interrupt") &&
      !MF->getFunction().hasFnAttribute("brk_interrupt"))
    return;

  if (MF->getFunction().hasFnAttribute("brk_interrupt")) {
    // Vector address for the BRK interrupt.
    emitInterruptVectorSymbol(0x7e);
    return;
  }

  uint64_t Specs;
  StringRef SpecsstringInterrupt =
      MF->getFunction().getFnAttribute("interrupt").getValueAsString();
  std::string VectStr = "Vect_";
  size_t LastVect = SpecsstringInterrupt.find(VectStr, 0);
  while (LastVect != std::string::npos) {
    size_t CurrentVect = SpecsstringInterrupt.find(VectStr, LastVect + 1);
    if (CurrentVect != std::string::npos) {
      SpecsstringInterrupt
          .substr(LastVect + VectStr.length(),
                  CurrentVect - LastVect - VectStr.length())
          .getAsInteger(0, Specs);
    } else {
      SpecsstringInterrupt
          .substr(LastVect + VectStr.length(),
                  SpecsstringInterrupt.size() - (LastVect + VectStr.length()))
          .getAsInteger(0, Specs);
    }
    // Apply vector start offset.
    emitInterruptVectorSymbol(Specs);
    LastVect = CurrentVect;
  }
}

void RL78AsmPrinter::emitFunctionBodyEnd() {
  if (MF->getFunction().hasFnAttribute("inline_asm")) {
    // Since we marked with naked the inline_asm function, we need to add a
    // return to it's end.
    getTargetStreamer().getStreamer().emitInstruction(MCInstBuilder(RL78::RET),
                                                      getSubtargetInfo());
  }
}

void RL78AsmPrinter::printOperand(const MachineInstr *MI, int opNum,
                                  raw_ostream &O) {
  const DataLayout &DL = getDataLayout();
  const MachineOperand &MO = MI->getOperand(opNum);
  RL78MCExpr::VariantKind TF = (RL78MCExpr::VariantKind)MO.getTargetFlags();

  bool CloseParen = RL78MCExpr::printVariantKind(O, TF);

  switch (MO.getType()) {
  case MachineOperand::MO_Register:
    O << StringRef(getRegisterName(MO.getReg())).lower();
    break;

  case MachineOperand::MO_Immediate:
    O << (int)MO.getImm();
    break;
  case MachineOperand::MO_MachineBasicBlock:
    MO.getMBB()->getSymbol()->print(O, MAI);
    return;
  case MachineOperand::MO_GlobalAddress:
    getSymbol(MO.getGlobal())->print(O, MAI);
    break;
  case MachineOperand::MO_BlockAddress:
    O << GetBlockAddressSymbol(MO.getBlockAddress())->getName();
    break;
  case MachineOperand::MO_ExternalSymbol:
    O << MO.getSymbolName();
    break;
  case MachineOperand::MO_ConstantPoolIndex:
    O << DL.getPrivateGlobalPrefix() << "CPI" << getFunctionNumber() << "_"
      << MO.getIndex();
    break;
  case MachineOperand::MO_Metadata:
    MO.getMetadata()->printAsOperand(O, MMI->getModule());
    break;
  default:
    llvm_unreachable("<unknown operand type>");
  }
  if (CloseParen)
    O << ")";
}

void RL78AsmPrinter::printMemOperand(const MachineInstr *MI, int opNum,
                                     raw_ostream &O, const char *Modifier) {
  printOperand(MI, opNum, O);
}

/// PrintAsmOperand - Print out an operand for an inline asm expression.
///
bool RL78AsmPrinter::PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                                     const char *ExtraCode, raw_ostream &O) {
  if (ExtraCode && ExtraCode[0]) {
    if (ExtraCode[1] != 0)
      return true; // Unknown modifier.
                   // TODO:
    switch (ExtraCode[0]) {
    default:
      // See if this is a generic print operand.
      return AsmPrinter::PrintAsmOperand(MI, OpNo, ExtraCode, O);
    case 'f':
    case 'r':
      break;
    }
  }

  printOperand(MI, OpNo, O);

  return false;
}

bool RL78AsmPrinter::PrintAsmMemoryOperand(const MachineInstr *MI,
                                           unsigned OpNo, const char *ExtraCode,
                                           raw_ostream &O) {
  if (ExtraCode && ExtraCode[0])
    return true; // Unknown modifier.
  // TODO:
  O << '[';
  printMemOperand(MI, OpNo, O);
  O << ']';

  return false;
}

const MCExpr *RL78AsmPrinter::lowerConstant(const Constant *CV) {
  const ConstantExpr *CE = dyn_cast<ConstantExpr>(CV);
  if (!CE || CE->getOpcode() != Instruction::AddrSpaceCast) {
    return AsmPrinter::lowerConstant(CV);
  }

  const Constant *Op = CE->getOperand(0);
  unsigned DstAS = CE->getType()->getPointerAddressSpace();
  unsigned SrcAS = Op->getType()->getPointerAddressSpace();
  if (TM.isNoopAddrSpaceCast(SrcAS, DstAS))
    return AsmPrinter::lowerConstant(Op);

  // Handle the absolute address case.
  int64_t Constant;
  const MCExpr *ConstExpr = AsmPrinter::lowerConstant(Op);
  if (ConstExpr->evaluateAsAbsolute(Constant)) {
    Constant = Constant & 0xFF'FFFF;
    switch (DstAS) {
    case RL78AS::Default:
    case RL78AS::Near:
      return MCConstantExpr::create(Constant & 0xFFFF, OutContext);
    case RL78AS::FarCode:
      assert(SrcAS == RL78AS::Near || SrcAS == RL78AS::Default);
      return MCConstantExpr::create(Constant, OutContext);
    case RL78AS::FarData:
      assert(SrcAS == RL78AS::Near || SrcAS == RL78AS::Default);
      assert(Constant <= 0xFFFF);
      return MCConstantExpr::create((Constant & 0xFFFF) | 0x0F'0000,
                                    OutContext);
    default:
      llvm_unreachable("Unexpected RL78 address space");
      break;
    }
  }

  // Handle the relocatable address case.
  const MCExpr *RelExpr =
      RL78MCExpr::create(RL78MCExpr::VK_RL78_LOWW, ConstExpr, OutContext);
  switch (DstAS) {
  case RL78AS::Default:
  case RL78AS::Near:
    return RelExpr;
  case RL78AS::FarCode: {
    assert(SrcAS == RL78AS::Near || SrcAS == RL78AS::Default);
    // TODO: this is not how CC-RL does it, nor is it correct, but no idea how to replicate it for
    // now. Should we error out?
    return ConstExpr;
  }
  case RL78AS::FarData: {
    assert(SrcAS == RL78AS::Near || SrcAS == RL78AS::Default);
    // TODO: this is not how CC-RL does it, nor is it correct, but no idea how to replicate it for
    // now. Should we error out?   
    return ConstExpr;
  }
  default:
    llvm_unreachable("Unexpected RL78 address space");
    break;
  }

  std::string S;
  raw_string_ostream OS(S);
  OS << "Unsupported expression in static initializer: ";
  CE->printAsOperand(OS, /*PrintType=*/false,
                     !MF ? nullptr : MF->getFunction().getParent());
  report_fatal_error(Twine(OS.str()));
}

// Force static initialization.
extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeRL78AsmPrinter() {
  RegisterAsmPrinter<RL78AsmPrinter> X(getTheRL78Target());
}
