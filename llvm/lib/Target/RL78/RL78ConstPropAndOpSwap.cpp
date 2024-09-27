//=== RL78ConstPropAndOpSwap.cpp - RL78 Constant Propagation and Opnd Swap ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains a pass that does cosntant propagation and opperand
// swapping for commutative instructions- in case we do not have an optimal
// case. By optimal case we mean the copy instr introduced by the custom
// inserter can be removed
//
//===----------------------------------------------------------------------===//

#include "RL78TargetMachine.h"

using namespace llvm;
#define DEBUG_TYPE "rl78-ctprop-opswap"

namespace {

class RL78ConstPropAndOpSwap : public MachineFunctionPass {

public:
  RL78ConstPropAndOpSwap() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "RL78 Constant Propagation and Op swap Pass";
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

  std::pair<std::optional<MachineOperand>, unsigned int> getCoresspondingCpyOrConst(
      const MachineOperand &opnd,
      std::vector<std::tuple<MachineOperand, MachineOperand, unsigned int>>
          &ACP);

  void removeCoresspondingCpyOrConstPair(
      const MachineOperand &opnd,
      std::vector<std::tuple<MachineOperand, MachineOperand, unsigned int>>
          &ACP);

  bool hasDef(MachineInstr &MI);

public:
  static char ID;

  MachineRegisterInfo *MRI;

  const TargetRegisterInfo *TRI;
};

} // end anonymous namespace

char RL78ConstPropAndOpSwap::ID = 0;

FunctionPass *llvm::createRL78ConstPropAndOpSwap() {
  return new RL78ConstPropAndOpSwap();
}

static bool IsMACReg(Register reg, const MachineRegisterInfo *MRI) {
  return !reg.isVirtual() && (reg == RL78::MACRH && reg == RL78::MACRL) ||
         reg.isVirtual() &&
             (MRI->getRegClass(reg) == &RL78::RL78RegMACRHRegClass ||
              MRI->getRegClass(reg) == &RL78::RL78RegMACRLRegClass);
}

bool RL78ConstPropAndOpSwap::runOnMachineFunction(MachineFunction &MF) {

  bool changed = false;
  MRI = &(MF.getRegInfo());
  TRI = MF.getSubtarget().getRegisterInfo();

  // this holds available copy (reg, reg) and/or constant(reg, const) pairs and
  // MI id(to differentiate)
  std::vector<std::tuple<MachineOperand, MachineOperand, unsigned int>>
      ACPM;

  for (auto &MBB : MF) {

    for (MachineBasicBlock::iterator Next = MBB.begin(), E = MBB.end();
         Next != E;) {

      MachineInstr &MI = *Next;
      ++Next;

      // Check copy and commutative instr
      if (MI.isCopy() && Next != MBB.end()) {

        MachineInstr &MI1 = *Next;

        if (MI1.getOpcode() == RL78::AND16_rp_rp ||
            MI1.getOpcode() == RL78::OR16_rp_rp ||
            MI1.getOpcode() == RL78::XOR16_rp_rp ||
            MI1.getOpcode() == RL78::ADD_r_r ||
            MI1.getOpcode() == RL78::AND_r_r ||
            MI1.getOpcode() == RL78::ADDW_rp_rp ||
            MI1.getOpcode() == RL78::ADDC_r_r ||
            MI1.getOpcode() == RL78::OR_r_r ||
            MI1.getOpcode() == RL78::XOR_r_r) {

          std::pair<std::optional<MachineOperand>, unsigned int> crspCpyAndInstr =
              getCoresspondingCpyOrConst(MI1.getOperand(2), ACPM);

          // if MI1 is commutative and we can create an opportunity for dead
          // copy instr
          if (crspCpyAndInstr.second == RL78::COPY &&
              crspCpyAndInstr.first.has_value() &&
              crspCpyAndInstr.first.value().getReg() == MI1.getOperand(1).getReg() &&
              MI1.getOperand(1).getReg() == MI.getOperand(0).getReg() &&
              MI1.getOperand(2).getReg() != MI.getOperand(1).getReg()) {

            Register tmpRegCpy = MI1.getOperand(2).getReg();

            MI1.getOperand(2).ChangeToRegister(MI.getOperand(1).getReg(), false,
                                               MI1.getOperand(2).isImplicit(),
                                               true);

            MI.getOperand(1).ChangeToRegister(
                tmpRegCpy, false, MI.getOperand(1).isImplicit(), true);

            changed = true;
            // remove pairs containing defs from MI and MI1 from ACPM
            removeCoresspondingCpyOrConstPair(MI.getOperand(0), ACPM);
            removeCoresspondingCpyOrConstPair(MI1.getOperand(0), ACPM);

            // We can skip MI1 next
            ++Next;
          }

          // handle mul* where we have two copy instructions above
        } else if (MI1.isCopy() && Next != MBB.end()) {

          ++Next;

          if (Next != MBB.end()) {

            MachineInstr &MI2 = *Next;

            if (MI2.getOpcode() == RL78::MUL8_r_r ||
                MI2.getOpcode() == RL78::MUL16_rp_rp && Next != MBB.end()) {

              std::pair<std::optional<MachineOperand>, unsigned int> crspCpyAndInstrMIop1 =
                  getCoresspondingCpyOrConst(MI.getOperand(1), ACPM);

              std::pair<std::optional<MachineOperand>, unsigned int> crspCpyAndInstrMI1op1 =
                  getCoresspondingCpyOrConst(MI1.getOperand(1), ACPM);

              if ((crspCpyAndInstrMIop1.second == RL78::COPY &&
                   crspCpyAndInstrMI1op1.second == RL78::COPY) &&

                  ((MI2.getOperand(2).getReg() == MI1.getOperand(0).getReg() &&
                    MI2.getOperand(1).getReg() == MI.getOperand(0).getReg() &&
                    crspCpyAndInstrMI1op1.first.has_value() &&
                    (crspCpyAndInstrMI1op1.first.value().getReg() !=
                         MI2.getOperand(2).getReg() ||
                     crspCpyAndInstrMIop1.first.value().getReg() !=
                         MI2.getOperand(1).getReg())) ||

                   (MI2.getOperand(2).getReg() == MI.getOperand(0).getReg() &&
                    MI2.getOperand(1).getReg() == MI1.getOperand(0).getReg() &&
                    crspCpyAndInstrMI1op1.first.has_value() &&
                    (crspCpyAndInstrMI1op1.first.value().getReg() !=
                         MI2.getOperand(1).getReg() ||
                     crspCpyAndInstrMIop1.first.value().getReg() !=
                         MI2.getOperand(2).getReg())))) {

                Register tmpCpyMI = MI1.getOperand(1).getReg();
                Register tmpCpyMI1 = MI.getOperand(1).getReg();

                MI.getOperand(1).ChangeToRegister(
                    tmpCpyMI, false, MI.getOperand(1).isImplicit(), true);

                MI1.getOperand(1).ChangeToRegister(
                    tmpCpyMI1, false, MI1.getOperand(1).isImplicit(), true);

                changed = true;

                // remove pairs containing defs from MI and MI1 from ACPM
                removeCoresspondingCpyOrConstPair(MI.getOperand(0), ACPM);
                removeCoresspondingCpyOrConstPair(MI1.getOperand(0), ACPM);
                removeCoresspondingCpyOrConstPair(MI2.getOperand(0), ACPM);
                // We can skip MI2 next
                ++Next;
              } else {

                --Next;
              }
            } else
              --Next;
          } else
            --Next;
        }
      }

      // constant propagation section
      bool removeFlag = false;

      if (MI.getNumOperands() == 2 && MI.getOperand(0).isReg() &&
          MI.getOperand(1).isReg()) {

        std::pair<std::optional<MachineOperand>, unsigned int> crspCpyAndInstr =
            getCoresspondingCpyOrConst(MI.getOperand(1), ACPM);

        if (crspCpyAndInstr.second == RL78::MOVW_rp_imm && MI.isCopy() &&
            TRI->getRegSizeInBits(MI.getOperand(0).getReg(), *MRI) == 16 &&
            !IsMACReg(MI.getOperand(0).getReg(), MRI) &&
            crspCpyAndInstr.first.has_value()) {
          const RL78InstrInfo &TII = *static_cast<const RL78InstrInfo *>(
              MF.getSubtarget().getInstrInfo());

          BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                  TII.get(RL78::MOVW_rp_imm), MI.getOperand(0).getReg())
              .add(crspCpyAndInstr.first.value());

          removeFlag = true;

        } else if (crspCpyAndInstr.second == RL78::MOV_r_imm && MI.isCopy() &&
                   TRI->getRegSizeInBits(MI.getOperand(0).getReg(), *MRI) ==
                       8 &&
                  crspCpyAndInstr.first.has_value()) {

          const RL78InstrInfo &TII = *static_cast<const RL78InstrInfo *>(
              MF.getSubtarget().getInstrInfo());

          BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                  TII.get(RL78::MOV_r_imm), MI.getOperand(0).getReg())
              .add(crspCpyAndInstr.first.value());

          removeFlag = true;
        }
      }

      // remove def operands from ACPM
      if (hasDef(MI)) {
        unsigned int noOp = MI.getNumOperands();
        for (unsigned int i = 0; i < noOp; i++)
          if (MI.getOperand(i).isReg() && MI.getOperand(i).isDef())
            removeCoresspondingCpyOrConstPair(MI.getOperand(i), ACPM);
      }

      // if we get a call ->remove operands from ACPM
      if (MI.isCall()) {
        unsigned int noOp = MI.getNumOperands();
        for (unsigned int i = 0; i < noOp; i++)
          if (MI.getOperand(i).isReg())
            removeCoresspondingCpyOrConstPair(MI.getOperand(i), ACPM);
      }

      // MOV_R_IMM
      // we add the register to ACPM
      if (MI.getOpcode() == RL78::MOVW_rp_imm ||
          MI.getOpcode() == RL78::MOV_r_imm)
        ACPM.push_back(std::make_tuple(MI.getOperand(0), MI.getOperand(1),
                                       MI.getOpcode()));

      // Copy - add all-- needed for swapping
      if (MI.isCopy())
        ACPM.push_back(std::make_tuple(MI.getOperand(0), MI.getOperand(1),
                                       MI.getOpcode()));

      // remove previous instruction if we created a new one
      if (removeFlag) {
        changed = true;
        MI.eraseFromParent();
      }
    }
  }

  return changed;
}

// searches the available copy/const table to find a correspondance
// if something is found it returns a pair of corresponding operand
// and from which MI it comes from
// otherwise it reutns a pair containing 0 as MI id

std::pair<std::optional<MachineOperand>, unsigned int>
RL78ConstPropAndOpSwap::getCoresspondingCpyOrConst(
    const MachineOperand &opnd,
    std::vector<std::tuple<MachineOperand , MachineOperand , unsigned int>>
        &ACP) {
  for (auto const &acp : ACP) {
    MachineOperand first = std::get<0>(acp);
    MachineOperand second = std::get<1>(acp);
    unsigned int opcode = std::get<2>(acp);

    if (first.getType() == opnd.getType() && first.getReg() == opnd.getReg())
      return std::make_pair(second, opcode);
  }
  return std::make_pair(std::nullopt, 0);
}

// removes a pair from the available copy/const table
// if a regiter or subregister is rewritten

void RL78ConstPropAndOpSwap::removeCoresspondingCpyOrConstPair(
    const MachineOperand &opnd,
    std::vector<std::tuple<MachineOperand, MachineOperand, unsigned int>>
        &ACP) {
  std::vector<std::tuple<MachineOperand, MachineOperand,
                         unsigned int>>::const_iterator iter = ACP.begin();
  std::vector<std::tuple<MachineOperand, MachineOperand, unsigned int>>   newACP;
  while (iter != ACP.end()) {
    MachineOperand first = std::get<0>(*iter);
    MachineOperand second = std::get<1>(*iter);

    if ((first.isReg() && opnd.isReg() &&
         first.getReg() == opnd.getReg()) ||

        (second.isReg() && opnd.isReg() &&
         second.getReg() == opnd.getReg()) ||

        (first.isReg() && opnd.isReg() &&
         first.getReg().isPhysical() && opnd.getReg().isPhysical() &&
         (TRI->isSubRegister(first.getReg(), opnd.getReg()) ||
          TRI->isSubRegister(opnd.getReg(), first.getReg()))) ||

        (second.isReg() && opnd.isReg() &&
         second.getReg().isPhysical() && opnd.getReg().isPhysical() &&
         (TRI->isSubRegister(second.getReg(), opnd.getReg()) ||
          TRI->isSubRegister(opnd.getReg(), second.getReg())))

    ) {
      // do nothing
    }
    else {
      newACP.push_back(*iter);
    }
      ++iter;
  }
  ACP.swap(newACP);
}

// checks if machine instruction has any def registers
bool RL78ConstPropAndOpSwap::hasDef(MachineInstr &MI) {
  // do we have defs on instructions where first is not def?
  return MI.getNumOperands() > 0 && MI.getOperand(0).isReg() &&
         MI.getOperand(0).isDef();
}
