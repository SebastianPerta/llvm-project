//===-- RL78MCInstLower.cpp - Convert RL78 MachineInstr to MCInst -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains code to lower RL78 MachineInstrs to their corresponding
// MCInst records.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/RL78MCExpr.h"
#include "RL78.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/MC/MCContext.h"

using namespace llvm;

static MCOperand LowerSymbolOperand(const MachineInstr *MI,
                                    const MachineOperand &MO, AsmPrinter &AP) {

  RL78MCExpr::VariantKind Kind = (RL78MCExpr::VariantKind)MO.getTargetFlags();
  const MCSymbol *Symbol = nullptr;
  // MO.dump();
  switch (MO.getType()) {
  default:
    llvm_unreachable("Unknown type in LowerSymbolOperand");
  case MachineOperand::MO_MachineBasicBlock:
    Symbol = MO.getMBB()->getSymbol();
    // Symbol->dump();
    break;

  case MachineOperand::MO_GlobalAddress:
    Symbol = AP.getSymbol(MO.getGlobal());
    if (MI->getOpcode() == RL78::CALLT_addr5) {
      Symbol = AP.OutContext.getOrCreateSymbol(Twine("@") + Symbol->getName());
      Symbol->setExternal(true);
    }
    break;

  case MachineOperand::MO_BlockAddress:
    Symbol = AP.GetBlockAddressSymbol(MO.getBlockAddress());
    break;

  case MachineOperand::MO_ExternalSymbol:
    Symbol = AP.GetExternalSymbolSymbol(MO.getSymbolName());
    break;

  case MachineOperand::MO_ConstantPoolIndex:
    Symbol = AP.GetCPISymbol(MO.getIndex());
    break;

  case MachineOperand::MO_JumpTableIndex:
    Symbol = AP.GetJTISymbol(MO.getIndex());
    break;
  }

  const MCExpr *Expr = MCSymbolRefExpr::create(Symbol, AP.OutContext);

  if ((MO.getType() != MachineOperand::MO_MachineBasicBlock) &&
      (MO.getType() != MachineOperand::MO_JumpTableIndex) && MO.getOffset()) {
    Expr = MCBinaryExpr::createAdd(
        Expr, MCConstantExpr::create(MO.getOffset(), AP.OutContext),
        AP.OutContext);
  }
  if (Kind != RL78MCExpr::VK_RL78_None)
    Expr = RL78MCExpr::create(Kind, Expr, AP.OutContext);
  // Expr->dump();
  return MCOperand::createExpr(Expr);
}

static MCOperand LowerOperand(const MachineInstr *MI, const MachineOperand &MO,
                              AsmPrinter &AP) {
  switch (MO.getType()) {
  default:
    llvm_unreachable("unknown operand type");
    break;
  case MachineOperand::MO_Register:
    if (MO.isImplicit())
      break;
    return MCOperand::createReg(MO.getReg());

  case MachineOperand::MO_Immediate:
    return MCOperand::createImm(MO.getImm());

  case MachineOperand::MO_MachineBasicBlock:
  case MachineOperand::MO_GlobalAddress:
  case MachineOperand::MO_BlockAddress:
  case MachineOperand::MO_ExternalSymbol:
  case MachineOperand::MO_ConstantPoolIndex:
  case MachineOperand::MO_JumpTableIndex:
    return LowerSymbolOperand(MI, MO, AP);

  case MachineOperand::MO_RegisterMask:
    break;
  }
  return MCOperand();
}

void llvm::LowerRL78MachineInstrToMCInst(const MachineInstr *MI, MCInst &OutMI,
                                         AsmPrinter &AP) {

  OutMI.setOpcode(MI->getOpcode());
  // MI->dump();
  for (unsigned i = 0, e = MI->getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = MI->getOperand(i);
    // MO.dump();
    MCOperand MCOp = LowerOperand(MI, MO, AP);

    if (MCOp.isValid())
      OutMI.addOperand(MCOp);
  }
  // OutMI.dump();
}
