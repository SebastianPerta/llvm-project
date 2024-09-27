//===-- RL78BranchExpand.cpp - Define TargetMachine for RL78 --------------===//
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

// TODO: look at BranchRelaxation.

namespace {
class RL78BranchExpandPass : public MachineFunctionPass {
public:
  RL78BranchExpandPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "RL78 branch expand"; }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  static char ID;
  //
  std::map<int, unsigned> bbSizeMap;
  //
  bool processBranch(MachineInstr &MI, MachineBasicBlock &MBB,
                     const TargetInstrInfo *TII);
};

char RL78BranchExpandPass::ID = 0;
} // end anonymous namespace

FunctionPass *llvm::createRL78BranchExpandPass() {
  return new RL78BranchExpandPass();
}

static unsigned calcBasicBlockSize(MachineBasicBlock &MBB, const TargetInstrInfo *TII) {
  return std::accumulate(
      MBB.begin(), MBB.end(), 0, [TII](unsigned Sum, const MachineInstr &MI) {
        return Sum + TII->getInstSizeInBytes(MI);
      });
}

// Check if MBB has only 1 instruction.
static bool isSingleInstructionBB(MachineBasicBlock &MBB) {
  unsigned blockSize = 0;
  for (MachineBasicBlock::iterator Next = MBB.begin(), E = MBB.end(); Next != E;
       Next++) {
    MachineInstr &MI = *Next;
    switch (MI.getOpcode()) {
    case RL78::ADJCALLSTACKDOWN:
    case RL78::ADJCALLSTACKUP:
      // Not real instructions.
      break;
    case RL78::BSWAP32_rp:
      // 2 x XCH + 1 x XCHW.
      blockSize += 3;
      break;
    case RL78::UDIVREM16_r_r:
    case RL78::UDIVREM32_r_r:
      // DIV + NOP.
      blockSize += 2;
      break;
    default:
      blockSize += 1;
      break;
    }
    if (blockSize > 1)
      return false;
  }
  //
  return (blockSize == 1);
}

bool RL78BranchExpandPass::processBranch(MachineInstr &MI,
                                         MachineBasicBlock &MBB,
                                         const TargetInstrInfo *TII) {
  // Return if not the BRCC/BR/BTBF/BTCLR.
  if ((MI.getOpcode() != RL78::BRCC) && (MI.getOpcode() != RL78::BR) &&
      (MI.getOpcode() != RL78::BTBF) && (MI.getOpcode() != RL78::BTBF_mem) &&
      (MI.getOpcode() != RL78::BTBF_sfr))
    return false;
  // MI.dump();
  MachineFunction::iterator MBBI = MBB.getIterator(), MBBE;
  MachineBasicBlock &targetMBB = *MI.getOperand(0).getMBB();
  // if this is the last instruction in MBB and the next (fall-through) block
  // has only 1 instruction.
  if ((MI.getOpcode() == RL78::BRCC) && (MI == MBB.getLastNonDebugInstr()) &&
      isSingleInstructionBB(*++MBBI) && ((++MBBI) == targetMBB.getIterator())) {
    // Insert a conditional skip instruction.
    BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::SK_cc))
        .add(MI.getOperand(0))
        .add(MI.getOperand(1));
  } else {
    // First check if the jump is in range [-128 + size(instruction), +127]
    // bytes size(instruction) = { BC, BNC, BZ, BNZ = 2 bytes, BH, BNH = 3
    // bytes, BT, BF, BTCLR = 3/4}.
    unsigned jumpSize = 0;
    unsigned range = 0;
    // Find jump direction:
    // targetMBB->isLayoutSuccessor(MBB) might be useful
    // however we will be looking at BranchRelaxation.
    bool forwardJump = false;
    for (MBBI = ++MBB.getIterator(), MBBE = MBB.getParent()->end();
         MBBI != MBBE; ++MBBI)
      if (targetMBB.getIterator() == MBBI) {
        forwardJump = true;
        break;
      }
    if (forwardJump) {
      for (MBBI = ++MBB.getIterator(), MBBE = targetMBB.getIterator();
           MBBI != MBBE; ++MBBI)
        jumpSize += bbSizeMap.at(MBBI->getNumber());
      range = 127;
    }
    // Backward jump.
    else {
      for (MBBI = MBB.getIterator();
           MBBE = targetMBB.getIterator(), MBBI != MBBE; --MBBI)
        jumpSize += bbSizeMap.at(MBBI->getNumber());
      jumpSize += bbSizeMap.at(targetMBB.getNumber());
      // range = -128 + size(instruction)
      // size(instruction) = { BC, BNC, BZ, BNZ = 2 bytes, BH, BNH = 3 bytes, BR
      // = 2, BT, BF, BTCLR = 3/4}.
      range = 128 - 4;
    }
    //
    if (jumpSize < range) {
      // Insert a rel8 branch.
      switch (MI.getOpcode()) {
      default:
        llvm_unreachable("Invalid branch instruction!");
      case RL78::BTBF:
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BTBF_A))
            .add(MI.getOperand(0))
            .add(MI.getOperand(1))
            .add(MI.getOperand(2))
            .add(MI.getOperand(3));
        break;
      case RL78::BTBF_mem:
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BTBF_memr))
            .add(MI.getOperand(0))
            .add(MI.getOperand(1))
            .add(MI.getOperand(2))
            .add(MI.getOperand(3));
        break;
      case RL78::BTBF_sfr:
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BTBF_sfri_addr))
            .add(MI.getOperand(0))
            .add(MI.getOperand(1))
            .add(MI.getOperand(2))
            .add(MI.getOperand(3));
        break;
      case RL78::BRCC:
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::B_cc))
            .add(MI.getOperand(0))
            .add(MI.getOperand(1));
        break;
      case RL78::BR:
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BR_rel8))
            .add(MI.getOperand(0));
        break;
      }
    } else {
      // Use SKIP with opposite branch condition + unconditional rel16 branch.
      SmallVector<MachineOperand, 4> Cond;
      // If conditional branch (BR has only 1 operand).
      if (MI.getNumOperands() > 1) {
        Cond.push_back(MachineOperand::CreateImm(MI.getOperand(1).getImm()));
        TII->reverseBranchCondition(Cond);
      }
      //
      switch (MI.getOpcode()) {
      default:
        llvm_unreachable("Invalid branch instruction!");
      case RL78::BTBF_mem:
      case RL78::BTBF_sfr:
      case RL78::BTBF: {
        if (MI.getOpcode() == RL78::BTBF_sfr)
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::MOV1_cy_sfr))
              .add(MI.getOperand(2))
              .add(MI.getOperand(3));
        else if (MI.getOpcode() == RL78::BTBF_mem)
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::MOV1_cy_memr))
              .add(MI.getOperand(2))
              .add(MI.getOperand(3));
        else
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::MOV1_cy_r))
              .add(MI.getOperand(2))
              .add(MI.getOperand(3));

        RL78CC::CondCodes CC =
            static_cast<RL78CC::CondCodes>(MI.getOperand(1).getImm());
        RL78CC::CondCodes ReversedInCy = CC == RL78CC::CondCodes::RL78CC_Z
                                             ? RL78CC::CondCodes::RL78CC_NC
                                             : RL78CC::CondCodes::RL78CC_C;

        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::SK_cc))
            .add(MI.getOperand(0))
            .addImm(ReversedInCy);

        if (isInt<16>(jumpSize))
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BR_rel16))
              .add(MI.getOperand(0));
        else
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BR_addr20))
              .add(MI.getOperand(0));
        break;
      }
      case RL78::BRCC:
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::SK_cc))
            .add(MI.getOperand(0))
            .addImm(Cond[0].getImm());
        LLVM_FALLTHROUGH;
      case RL78::BR:
        if (isInt<16>(jumpSize))
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BR_rel16))
              .add(MI.getOperand(0));
        else
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::BR_addr20))
              .add(MI.getOperand(0));
        break;
      }
    }
  }
  // Remove the pseudo instruction.
  MI.eraseFromParent();
  return true;
}

bool RL78BranchExpandPass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;
  const TargetInstrInfo *TII = MF.getSubtarget<RL78Subtarget>().getInstrInfo();
  // Calc the size of each basic block.
  for (MachineBasicBlock &MBB : MF) {
    bbSizeMap.insert(
        std::pair<int, unsigned>(MBB.getNumber(), calcBasicBlockSize(MBB, TII)));
  }
  //
  // MF.dump();
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty())
      continue;
    //
    MachineBasicBlock::iterator I = MBB.getLastNonDebugInstr();
    if (I == MBB.end())
      continue;
    //
    Changed |= processBranch(*I, MBB, TII);
    // The iterator may be invalidated.
    I = MBB.getLastNonDebugInstr();
    // Was this the only branch instruction?
    if (I == MBB.begin() || !(I->isBranch()))
      continue;
    Changed |= processBranch(*(--I), MBB, TII);
  }
  //
  // MF.dump();
  bbSizeMap.clear();
  return Changed;
}