//===-- RL78SelectBTCLR.cpp - Define TargetMachine for RL78 ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//
//===----------------------------------------------------------------------===//

#include "RL78TargetMachine.h"

using namespace llvm;

namespace {
class RL78SelectBTCLRPass : public MachineFunctionPass {
public:
  RL78SelectBTCLRPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "RL78 select BTCLR instruction";
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  static char ID;
};

char RL78SelectBTCLRPass::ID = 0;
} // end anonymous namespace

FunctionPass *llvm::createRL78SelectBTCLRPass() {
  return new RL78SelectBTCLRPass();
}

//TODO: rewrite this:
// -check for volatile
// -firstMI is the first instruction in TBB (MI.getOperand(0)
// -BUildMI needs more params for BTCLR
// -saddr, sfr
bool RL78SelectBTCLRPass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;
  const TargetInstrInfo *TII = MF.getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty())
      continue;
    //
    MachineBasicBlock::iterator I = MBB.getLastNonDebugInstr();
    if (I == MBB.end())
      continue;
    //
    MachineInstr &MI = *I;
    MachineFunction::iterator MBBI = MBB.getIterator();
    // if BT.
    if (((MI.getOpcode() == RL78::BTBF_A) ||
         (MI.getOpcode() == RL78::BTBF_memr)) &&
        (MI.getOperand(1).getImm() == RL78CC::RL78CC_Z)) {
      MachineInstr &firstMI = *MBB.getFirstNonDebugInstr();
      //
      if ((firstMI.getOpcode() == ISD::AND) &&
          (firstMI.getOperand(0).getReg() == MI.getOperand(0).getReg()) &&
          firstMI.getOperand(2).isImm() &&
          (firstMI.getOperand(2).getImm() == MI.getOperand(3).getImm())) {
        // Replace the BT + AND with a BTCLR.
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BTCLR_A))
            .add(MI.getOperand(0));
        MI.eraseFromParent();
        firstMI.eraseFromParent();
        Changed = true;
      } else if ((firstMI.getOpcode() == RL78::CLR1_memr) &&
                 (firstMI.getOperand(0).getReg() ==
                  MI.getOperand(0).getReg()) &&
                 (firstMI.getOperand(1).getImm() ==
                  MI.getOperand(3).getImm())) {
        // Replace the BT + CLR1 with a BTCLR.
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BTCLR_memr))
            .add(MI.getOperand(0));
        MI.eraseFromParent();
        firstMI.eraseFromParent();
        Changed = true;
      }
    }
  }
  //
  return Changed;
}