//===-- RL78CMPWithZeroElimination.cpp - Define TargetMachine for RL78 ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//
//===----------------------------------------------------------------------===//

#include "RL78.h"
#include "RL78Subtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "RL78CMPWithZeroElimPass"
using namespace llvm;

namespace {
class RL78CMPWithZeroElimPass : public MachineFunctionPass {
public:
  RL78CMPWithZeroElimPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "RL78 CMP with 0 elimination";
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  static char ID;
};

char RL78CMPWithZeroElimPass::ID = 0;
} // end anonymous namespace

FunctionPass *llvm::createRL78CMPWithZeroElimPass() {
  return new RL78CMPWithZeroElimPass();
}

static bool definesCCReg(MachineInstr &MI, bool requiresZflag) {
  bool hasdefCCReg = false;
  bool hasdefZflag = false;
  for (unsigned i = MI.getNumExplicitOperands(), e = MI.getNumOperands();
       i != e; ++i) {
    if (MI.getOperand(i).isReg() && (MI.getOperand(i).getReg() == RL78::CCreg))
      hasdefCCReg = MI.getOperand(i).isDef();
    else if (MI.getOperand(i).isReg() &&
             (MI.getOperand(i).getReg() == RL78::Zflag))
      hasdefZflag = MI.getOperand(i).isDef();
  }
  return (requiresZflag) ? hasdefCCReg && hasdefZflag : hasdefCCReg;
}

static void updateCCRegFlag(MachineInstr &MI) {
  for (unsigned i = MI.getNumExplicitOperands(), e = MI.getNumOperands();
       i != e; ++i) {
    if (MI.getOperand(i).isReg() &&
        (MI.getOperand(i).getReg() == RL78::CCreg)) {
      MI.getOperand(i).setIsDead(false);
      break;
    }
  }
}

// TODO: split this function into 2 functions
// FIXME: MOV A, X + MOV [HL+byte(!=0)], A + CMP0 A (isKill) -> MOVS [HL+byte],
// X
bool RL78CMPWithZeroElimPass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;
  //
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty())
      continue;
    //
    if (MBB.getLastNonDebugInstr() == MBB.end())
      continue;
    // MBB.dump();
    for (MachineBasicBlock::reverse_iterator prevI = MBB.rbegin(),
                                             e = MBB.rend();
         prevI != e; ++prevI) {
      // prevI->dump();
      // If conditional branch
      if (prevI->getOpcode() == RL78::BRCC) {
        // We can only remove the compare instruction in case of "!= 0" and "==
        // 0" operations.
        assert(prevI->getOperand(1).isImm() &&
               "Invalid BRCC instruction operand(2)!");
        RL78CC::CondCodes targetCC =
            static_cast<RL78CC::CondCodes>(prevI->getOperand(1).getImm());
        if ((targetCC != RL78CC::RL78CC_NZ) && (targetCC != RL78CC::RL78CC_Z))
          break;
        ++prevI;
        while (prevI != MBB.rend()) {
          if (definesCCReg(*prevI, false))
            break;
          ++prevI;
        }
        // Sometimes blocks get merged and the CMP instruction gets placed in
        // another MBB, so we should give up trying to optimize this.
        if (prevI == MBB.rend())
          break;
        // If compare with 0 instruction.
        // We don't check for CMP0_abs16 because it's highly unlikely to happen:
        // We will not have a store and a load (maybe in case of volatile in
        // which case we don't realy want to touch it) normally the compiler
        // will do a store and a compare using the same registers (which
        // contains the store value) as operand 0. We also ignore any signed
        // comparisons which needed extra instruction (XOR1_cy_r etc.), see
        // RL78TargetLowering::LowerSignedCMP.
        if ((prevI->getOpcode() == RL78::CMP0_r) ||
            ((prevI->getOpcode() == RL78::CMPW_rp_imm) &&
             (prevI->getOperand(1).getImm() == 0))) {
          MachineInstr &CMPI = *prevI;
          ++prevI;
          while (prevI != MBB.rend()) {
            MachineInstr &PrevMI = *prevI;
            // Don't go past function calls.
            if (PrevMI.isCall())
              break;
            // PrevMI.dump();
            // XCH(W) have 2 dst registers but doesn't update CCReg
            // so we need to make sure the second dst reg is not writing
            // the register in question.
            if ((PrevMI.getNumOperands() > 1) && PrevMI.getOperand(1).isReg() &&
                PrevMI.getOperand(1).isDef() &&
                (PrevMI.getOperand(1).getReg() ==
                 CMPI.getOperand(0).getReg())) {
              break;
            }
            // If we have a reg def.
            if ((PrevMI.getNumOperands() > 0) && PrevMI.getOperand(0).isReg() &&
                PrevMI.getOperand(0).isDef()) {
              const TargetRegisterInfo *TRI =
                  MF.getSubtarget<RL78Subtarget>().getRegisterInfo();
              // if PrevMI defines a subreg of CMPI's dest reg
              // we can't do anything.
              if (TRI->isSubRegister(CMPI.getOperand(0).getReg(),
                                     PrevMI.getOperand(0).getReg()))
                break;
              // If PrevMI defines the register used by the CMPI.
              if (PrevMI.getOperand(0).getReg() ==
                  CMPI.getOperand(0).getReg()) {
                if (definesCCReg(PrevMI, true)) {
                  // the CC reg of this instruction is
                  // marked as dead we need to update this.
                  updateCCRegFlag(PrevMI);
                  // Erase CMP instruction.
                  CMPI.eraseFromParent();
                  Changed = true;
                }
                break;
              }
            }
            ++prevI;
          }
        }
        break;
      }
    }
    
    SmallVector<MachineInstr*, 4> InstToKill;
    for (MachineBasicBlock::reverse_iterator prevI = MBB.rbegin(),
                                             e = MBB.rend();
         prevI != e; ++prevI) {
      if (prevI->getOpcode() == RL78::BRCC) {
        MachineInstr &BRCC = *prevI;
        RL78CC::CondCodes targetCC =
            static_cast<RL78CC::CondCodes>(BRCC.getOperand(1).getImm());
        if ((targetCC != RL78CC::RL78CC_NZ) && (targetCC != RL78CC::RL78CC_Z))
          break;
        do {
          prevI++;
        } while (prevI != MBB.rend() && prevI->isDebugInstr());

        if (prevI == MBB.rend())
          break;

        // Optimize compare with 0xFF to INC
        if (prevI != MBB.rend() && prevI->getOpcode() == RL78::CMP_r_imm &&
            prevI->getOperand(1).getImm() == -1 &&
            prevI->getOperand(0).isKill()) {
            const TargetInstrInfo *TII = MBB.getParent()->getSubtarget<RL78Subtarget>().getInstrInfo();
            BuildMI(MBB, prevI.getReverse(), prevI->getDebugLoc(),
                  TII->get(RL78::INC_r))
              .add(prevI->getOperand(0))
              .add(prevI->getOperand(1));
            BuildMI(MBB, BRCC, BRCC.getDebugLoc(),
                  TII->get(RL78::BRCC))
              .add(BRCC.getOperand(0))
              .addImm(targetCC);
            InstToKill.push_back(&*prevI);
            InstToKill.push_back(&BRCC);
        }
      }
    }

    for (MachineInstr *Inst : InstToKill) {
      LLVM_DEBUG(dbgs() << "erasing instruction: ");
      LLVM_DEBUG(Inst->dump());
      Inst->eraseFromParent();
      Changed = true;
    }

    // Eliminate instructions after the first unconditional branch.
    // See: tests\LLVM_RL78\LLVM_RL78\gcc_c_torture\Input\pr86714.c
    // We delete/merge/simplify conditional and unconditional branches in various places.
    // But we don't update the BB successors (sometimes we can't), which results in the
    // BranchFolding making wrong assumptions about the destination of said branches,
    // since it looks at predecessors/successors.
    // Attempt to fix this here.
    LLVM_DEBUG(dbgs() << "Parsing " << MBB.getFullName()
                      << " for dead code after BR \n");
    InstToKill.clear();
    bool killRemaining = false;
    // Treat BR BB1
    //       BR BB2
    for (MachineBasicBlock::iterator currI = MBB.begin(), e = MBB.end();
         currI != e; ++currI) {
      if (currI->isUnconditionalBranch() && !killRemaining)
        killRemaining = true;
      else if (killRemaining)
        InstToKill.push_back(&*currI);
    }

    for (MachineInstr *Inst : InstToKill) {
      if (Inst->isBranch()) {
        LLVM_DEBUG(dbgs() << "erasing successor: "
                          << Inst->getOperand(0).getMBB() << "\n");
        MBB.removeSuccessor(Inst->getOperand(0).getMBB());
      }
      LLVM_DEBUG(dbgs() << "erasing instruction: ");
      LLVM_DEBUG(Inst->dump());
      Inst->eraseFromParent();
      Changed = true;
    }
  }
  return Changed;
}
