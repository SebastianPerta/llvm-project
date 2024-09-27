//===-- RL78FrameLowering.cpp - RL78 Frame Information ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the RL78 implementation of TargetFrameLowering class.
//
//===----------------------------------------------------------------------===//

#include "RL78Subtarget.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineModuleInfo.h"

using namespace llvm;

static uint32_t getCSRegisterInfo(MachineFunction &MF) {
  uint32_t mask = ~0U;
  unsigned int sizeof_mask = CHAR_BIT * sizeof(mask);
  unsigned regNo;
  const TargetRegisterInfo *TRI =
      MF.getSubtarget<RL78Subtarget>().getRegisterInfo();
  // If a call is present we need to save/restore all registers.
  if (MF.getFrameInfo().hasCalls()) {
    mask = mask >> (sizeof_mask - (RL78::RP6 - RL78::RP0 + 1));
  } else {
    // Mark used regs.
    mask = 0;
    for (regNo = RL78::RP0; regNo <= RL78::RP6; ++regNo) {
      if (!MF.getRegInfo().reg_empty(regNo) ||
          !MF.getRegInfo().reg_empty(TRI->getSubReg(regNo, RL78::sub_lo)) ||
          !MF.getRegInfo().reg_empty(TRI->getSubReg(regNo, RL78::sub_hi)))

        mask |= 1 << (regNo - RL78::RP0);
    }
  }

  regNo = RL78::RP6 - RL78::RP0 + 1;
  if (!MF.getRegInfo().reg_empty(RL78::CS) || MF.getFrameInfo().hasCalls())
    mask |= 1 << regNo;

  regNo++;
  if (!MF.getRegInfo().reg_empty(RL78::ES) || MF.getFrameInfo().hasCalls())
    mask |= 1 << regNo;

  return mask;
}

RL78FrameLowering::RL78FrameLowering(const RL78Subtarget &ST)
    : TargetFrameLowering(TargetFrameLowering::StackGrowsUp, Align(2), 0) {}

void RL78FrameLowering::emitPrologue(MachineFunction &MF,
                                     MachineBasicBlock &MBB) const {
  const RL78Subtarget &Subtarget = MF.getSubtarget<RL78Subtarget>();
  MachineFrameInfo &MFI = MF.getFrameInfo();
  const RL78InstrInfo &TII =
      *static_cast<const RL78InstrInfo *>(MF.getSubtarget().getInstrInfo());
  const RL78RegisterInfo &RegInfo = *static_cast<const RL78RegisterInfo *>(
      MF.getSubtarget().getRegisterInfo());
  MachineBasicBlock::iterator MBBI = MBB.begin();
  SmallVector<unsigned, 4> CSR;
  // Debug location must be unknown since the first debug location is used
  // to determine the end of the prologue.
  DebugLoc dl;
  bool NeedsStackRealignment = RegInfo.shouldRealignStack(MF);

  // Get the number of bytes to allocate from the FrameInfo
  // TODO: if we are using FP, we are wasting stack here, since we will
  // reallocate stack for parameter passing before each call. So maybe we could
  // decrease this initial allocation by the max space allocated for function
  // calls?
  unsigned NumBytes = (int)MFI.getStackSize();

  // Align the stack size (2).
  if (NumBytes & 1) // TODO: is it even possible to have odd stack size? replace
                    // with assert?
    NumBytes++;

  unsigned NumBytesForCSRegs = 0;
  if (MF.getFunction().hasFnAttribute("brk_interrupt") ||
      MF.getFunction().hasFnAttribute("interrupt")) {
    uint64_t Specs;

    if (MF.getFunction().hasFnAttribute("interrupt")) {
      StringRef SpecsstringInterrupt =
          MF.getFunction().getFnAttribute("interrupt").getValueAsString();
      size_t HasVect = SpecsstringInterrupt.find("Vect_");
      if (HasVect != std::string::npos)
        SpecsstringInterrupt.substr(0, HasVect).getAsInteger(0, Specs);
      else
        SpecsstringInterrupt.getAsInteger(0, Specs);
    } else {
      MF.getFunction()
          .getFnAttribute("brk_interrupt")
          .getValueAsString()
          .getAsInteger(0, Specs);
    }
    // Bit 10 representes nested interrupts.

    if (Specs & 0x8)
      BuildMI(MBB, MBBI, dl, TII.get(RL78::EI));
    // Bits 0, 1 and 2 represent the regiter bank:
    // 0 is a register bank was specified
    // 1,2 the bank number: 0/1/2/3.
    unsigned Bank = Specs & 0x7;

    if (Subtarget.isRL78S1CoreType() && Bank) {
      report_fatal_error("Bank selection is not supported for S1 core type");
    }

    uint32_t mask = getCSRegisterInfo(MF);
    // If we use the bank= specification.
    if (Bank) {
      // When no register is used or no function is called in an interrupt
      // handler, the instruction for switching register banks is not output
      // even if register bank switching is specified
      if (mask || MFI.hasCalls())
        BuildMI(MBB, MBBI, dl, TII.get(RL78::SEL)).addImm(Bank >> 1);
    } else {
      for (unsigned reg = 0; reg < 4; ++reg) {
        if ((1 << reg) & mask) {
          BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp))
              .addReg(RL78::RP0 + (reg % 4));
          NumBytesForCSRegs += 2;
          unsigned CFIIndex =
              MF.addFrameInst(MCCFIInstruction::cfiDefCfaOffset(
                  nullptr, NumBytesForCSRegs + 4));
          BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
              .addCFIIndex(CFIIndex);
        }
      }
    }
    if (mask & (1 << 5) && mask & (1 << 4)) {
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_A_cs), RL78::R1)
          .addReg(RL78::CS);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_r_A), RL78::R0).addReg(RL78::R1);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_A_es), RL78::R1)
          .addReg(RL78::ES);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp)).addReg(RL78::RP0);
      NumBytesForCSRegs += 2;
      unsigned CFIIndex = MF.addFrameInst(MCCFIInstruction::cfiDefCfaOffset(
          nullptr, NumBytesForCSRegs + 4));
      BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
          .addCFIIndex(CFIIndex);
    } else {
      if (mask & (1 << 4)) {
        BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_A_cs), RL78::R1)
            .addReg(RL78::CS);
        BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp)).addReg(RL78::RP0);
        NumBytesForCSRegs += 2;
        unsigned CFIIndex =
            MF.addFrameInst(MCCFIInstruction::cfiDefCfaOffset(
                nullptr, NumBytesForCSRegs + 4));
        BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
            .addCFIIndex(CFIIndex);
      }
      if (mask & (1 << 5)) {
        BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_A_es), RL78::R1)
            .addReg(RL78::ES);
        BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp)).addReg(RL78::RP0);
        NumBytesForCSRegs += 2;
        unsigned CFIIndex =
            MF.addFrameInst(MCCFIInstruction::cfiDefCfaOffset(
                nullptr, NumBytesForCSRegs + 4));
        BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
            .addCFIIndex(CFIIndex);
      }
    }
  }

  // Update stack size with corrected value.
  if (NeedsStackRealignment) {
    // Reserve a slot for the old sp.
    NumBytes += 2;
    // Save AX, to be restored after we are done aligning.
    BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp)).addReg(RL78::RP0);
  }

  MFI.setStackSize(NumBytes + NumBytesForCSRegs);

  // Emit SUBW SP, #N.
  if (NumBytes > 0) {
    if (NumBytes == 2)
      BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp)).addReg(RL78::RP0);
    else if (NumBytes < 0x100)
      BuildMI(MBB, MBBI, dl, TII.get(RL78::SUBW_sp_imm), RL78::SPreg)
          .addReg(RL78::SPreg)
          .addImm(NumBytes);
    else if (NumBytes < 0x1FC) {
      // TODO: we can do for 3 x SUBW as well if RP0 is used
      BuildMI(MBB, MBBI, dl, TII.get(RL78::SUBW_sp_imm), RL78::SPreg)
          .addReg(RL78::SPreg)
          .addImm(0xFE);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::SUBW_sp_imm), RL78::SPreg)
          .addReg(RL78::SPreg)
          .addImm(NumBytes - 0xFE);
    } else if (NumBytes < 0x10000) {
      // TODO: check if RP0 is actually used i.e. the function has parameters.
      // BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp))
      //    .addReg(RL78::RP0, RegState::Kill);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
          .addReg(RL78::RP6, RegState::Define)
          .addReg(RL78::RP0, RegState::Kill)
          .addReg(RL78::RP6, RegState::Kill);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_sp), RL78::RP0)
          .addReg(RL78::SPreg);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::SUBW_rp_imm), RL78::RP0)
          .addReg(RL78::RP0)
          .addImm(NumBytes);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_sp_rp), RL78::SPreg)
          .addReg(RL78::RP0);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
          .addReg(RL78::RP6, RegState::Define)
          .addReg(RL78::RP0, RegState::Kill)
          .addReg(RL78::RP6, RegState::Kill);
    }
    // Most RL78 devices just have a few KB of RAM,
    // the biggest RAM which I've seen on RL78 is 48 KB (R5F104xL) so well under
    // 64 KB (0x10000).
    else
      llvm_unreachable("Invalid stack allocation!");

    unsigned CFIIndex = MF.addFrameInst(MCCFIInstruction::cfiDefCfaOffset(
        nullptr, (NumBytes + NumBytesForCSRegs) + 4));
    BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
        .addCFIIndex(CFIIndex);
  }

  if (NeedsStackRealignment) {
    // Save SP to HL.
    BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_sp), RL78::RP6)
        .addReg(RL78::SPreg);

    BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_sp), RL78::RP0)
        .addReg(RL78::SPreg);

    // Align to the requested boundary.
    const unsigned alignment = (~(MFI.getMaxAlign().value() - 1)) & 0xffff;
    if (MFI.getMaxAlign().value() & 0xFF00)
      BuildMI(MBB, MBBI, dl, TII.get(RL78::AND_r_imm), RL78::R1)
          .addReg(RL78::R1)
          .addImm(alignment >> 8);

    BuildMI(MBB, MBBI, dl, TII.get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
    BuildMI(MBB, MBBI, dl, TII.get(RL78::AND_r_imm), RL78::R1)
        .addReg(RL78::R1)
        .addImm(alignment & 0xff);
    BuildMI(MBB, MBBI, dl, TII.get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);

    // Change SP to the new aligned address.
    BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_sp_rp), RL78::SPreg)
        .addReg(RL78::RP0, RegState::Kill);

    // Save the old sp just above the new stack start.
    BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_AX_rp), RL78::RP0)
        .addReg(RL78::RP6);
    if (isUInt<8>(NumBytes)) {
      BuildMI(MBB, MBBI, dl, TII.get(RL78::STORE16_stack_slot_rp))
          .addReg(RL78::SPreg)
          .addImm(NumBytes - 2)
          .addReg(RL78::RP0, RegState::Kill);

      // Restore old ax value.
      BuildMI(MBB, MBBI, dl, TII.get(RL78::LOAD16_rp_rpi), RL78::RP0)
          .addReg(RL78::RP6, RegState::Kill)
          .addImm(NumBytes);

    } else if (isUInt<16>(NumBytes + 2)) {
      // Store using word[BC], save the old sp.
      BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp))
          .addReg(RL78::RP2, RegState::Kill);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_sp), RL78::RP2)
          .addReg(RL78::SPreg);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::STORE16_rpi_rp))
          .addReg(RL78::RP2, RegState::Kill)
          .addImm(NumBytes)
          .addReg(RL78::RP0, RegState::Kill);

      // Restore old ax value.
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_AX_rp), RL78::RP0)
          .addReg(RL78::RP6, RegState::Kill);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_AX), RL78::RP2)
          .addReg(RL78::RP0, RegState::Kill);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::LOAD16_rp_rpi), RL78::RP0)
          .addReg(RL78::RP2, RegState::Kill)
          .addImm(NumBytes);

      BuildMI(MBB, MBBI, dl, TII.get(RL78::POP_rp), RL78::RP2);
    } else
      llvm_unreachable("Invalid stack offset!");
  }

  if (hasFP(MF)) {
    // Update FP with the new base value...
    BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_sp), RL78::RP6)
        .addReg(RL78::SPreg);
    // Dwarf regnum of HL is 6.
    unsigned CFIIndex =
        MF.addFrameInst(MCCFIInstruction::createDefCfaRegister(nullptr, 6));
    BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
        .addCFIIndex(CFIIndex);

    // Mark the FramePtr as live-in in every block except the entry.
    for (MachineFunction::iterator I = std::next(MF.begin()), E = MF.end();
         I != E; ++I)
      I->addLiveIn(RL78::RP6);
  }
}

MachineBasicBlock::iterator RL78FrameLowering::eliminateCallFramePseudoInstr(
    MachineFunction &MF, MachineBasicBlock &MBB,
    MachineBasicBlock::iterator I) const {

  const RL78InstrInfo &TII =
      *static_cast<const RL78InstrInfo *>(MF.getSubtarget().getInstrInfo());

  int64_t Amount = I->getOperand(0).getImm();
  if (!hasFP(MF) || Amount == 0)
    return MBB.erase(I);

  const DebugLoc &DL = I->getDebugLoc();
  if (I->getOpcode() == TII.getCallFrameSetupOpcode()) {
    // allocate stack for parameter passing
    BuildMI(MBB, I, DL, TII.get(RL78::SUBW_sp_imm), RL78::SPreg)
        .addReg(RL78::SPreg)
        .addImm(Amount);
  } else {
    // deallocate stack used for parameter passing
    BuildMI(MBB, I, DL, TII.get(RL78::ADDW_sp_imm), RL78::SPreg)
        .addReg(RL78::SPreg)
        .addImm(Amount);
  }

  return MBB.erase(I);
}

void RL78FrameLowering::emitEpilogue(MachineFunction &MF,
                                     MachineBasicBlock &MBB) const {
  MachineBasicBlock::iterator MBBI = MBB.getLastNonDebugInstr();
  const RL78InstrInfo &TII =
      *static_cast<const RL78InstrInfo *>(MF.getSubtarget().getInstrInfo());
  DebugLoc dl = MBBI->getDebugLoc();
  // if (!FuncInfo->isLeafProc()) {
  //  return;
  //}
  MachineFrameInfo &MFI = MF.getFrameInfo();

  int NumBytes = (int)MFI.getStackSize();
  // if (NumBytes == 0)
  // return;

  if (hasFP(MF)) {
    // Restore SP from FP
    BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
        .addReg(RL78::RP6, RegState::Define)
        .addReg(RL78::RP0, RegState::Kill)
        .addReg(RL78::RP6, RegState::Kill);
    // Dwarf regnum of AX is 0.
    unsigned CFIIndex =
        MF.addFrameInst(MCCFIInstruction::createDefCfaRegister(nullptr, 0));
    BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
        .addCFIIndex(CFIIndex);

    BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_sp_rp), RL78::SPreg)
        .addReg(RL78::RP0);
    // Dwarf regnum of SP is 32.
    CFIIndex =
        MF.addFrameInst(MCCFIInstruction::createDefCfaRegister(nullptr, 32));
    BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
        .addCFIIndex(CFIIndex);

    BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
        .addReg(RL78::RP6, RegState::Define)
        .addReg(RL78::RP0, RegState::Kill)
        .addReg(RL78::RP6, RegState::Kill);
  }

  unsigned NumBytesForCSRegs = 0;
  uint64_t Specs;
  uint32_t mask;
  unsigned Bank;

  if (MF.getFunction().hasFnAttribute("brk_interrupt") ||
      MF.getFunction().hasFnAttribute("interrupt")) {

    if (MF.getFunction().hasFnAttribute("interrupt")) {
      StringRef SpecsstringInterrupt =
          MF.getFunction().getFnAttribute("interrupt").getValueAsString();
      size_t HasVect = SpecsstringInterrupt.find("Vect_");
      if (HasVect != std::string::npos)
        SpecsstringInterrupt.substr(0, HasVect).getAsInteger(0, Specs);
      else
        SpecsstringInterrupt.getAsInteger(0, Specs);
    } else {
      MF.getFunction()
          .getFnAttribute("brk_interrupt")
          .getValueAsString()
          .getAsInteger(0, Specs);
    }
    // Bits 0, 1 and 2 represent the regiter bank:
    // 0 is a register bank was specified
    // 1,2 the bank number: 0/1/2/3.
    Bank = Specs & 0x7;
    // In case we use the bank= sepcification, we don't need to set the register
    // bank back to 0 becuase the the hardware does this automatically (RBS0 and
    // RBS1 bits are part of PSW register): "The data saved to the stack returns
    // to the PC and the PSW, and the program returns from the interrupt
    // servicing routine. "
    mask = getCSRegisterInfo(MF);

    if (mask & (1 << 5) && mask & (1 << 4)) {
      NumBytesForCSRegs += 2;
    } else {
      if (mask & (1 << 5))
        NumBytesForCSRegs += 2;
      if (mask & (1 << 4))
        NumBytesForCSRegs += 2;
    }

    if (!Bank) {
      for (unsigned reg = 4; reg > 0; --reg)
        if ((1 << (reg - 1)) & mask)
          NumBytesForCSRegs += 2;
    }
  }

  unsigned NumBytesAdjusted = NumBytes - NumBytesForCSRegs;

  // Restore the old SP.
  const RL78RegisterInfo &RegInfo = *static_cast<const RL78RegisterInfo *>(
      MF.getSubtarget().getRegisterInfo());
  if (RegInfo.shouldRealignStack(MF)) {
    BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
        .addReg(RL78::RP6, RegState::Define)
        .addReg(RL78::RP0, RegState::Kill)
        .addReg(RL78::RP6, RegState::Kill);

    if (isUInt<8>(NumBytesAdjusted - 2))
      BuildMI(MBB, MBBI, dl, TII.get(RL78::LOAD16_rp_stack_slot), RL78::RP0)
          .addReg(RL78::SPreg)
          .addImm(NumBytesAdjusted - 2);
    else if (isUInt<16>(NumBytesAdjusted)) {
      // Load using word[BC], restore the old sp.
      BuildMI(MBB, MBBI, dl, TII.get(RL78::PUSH_rp))
          .addReg(RL78::RP2, RegState::Kill);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_sp), RL78::RP2)
          .addReg(RL78::SPreg);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::LOAD16_rp_rpi), RL78::RP0)
          .addReg(RL78::RP2, RegState::Kill)
          .addImm(NumBytesAdjusted);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::POP_rp), RL78::RP2);
    } else
      llvm_unreachable("Invalid stack offset!");

    BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_sp_rp), RL78::SPreg)
        .addReg(RL78::RP0);
    BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
        .addReg(RL78::RP6, RegState::Define)
        .addReg(RL78::RP0, RegState::Kill)
        .addReg(RL78::RP6, RegState::Kill);
    // Free up the slot used to save AX in the prologue.
    NumBytesAdjusted += 2;
  }

  if (NumBytesAdjusted != 0) {
    // TODO: we can use  POP  in some cases (depending on ret value)
    // Emit ADDW SP, #N.
    if (NumBytesAdjusted < 0x100)
      BuildMI(MBB, MBBI, dl, TII.get(RL78::ADDW_sp_imm), RL78::SPreg)
          .addReg(RL78::SPreg)
          .addImm(NumBytesAdjusted);
    else if (NumBytesAdjusted < 0x1FC) {
      // TODO: we can do for 3 x ADDW as well if RP0 is used
      BuildMI(MBB, MBBI, dl, TII.get(RL78::ADDW_sp_imm), RL78::SPreg)
          .addReg(RL78::SPreg)
          .addImm(0xFE);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::ADDW_sp_imm), RL78::SPreg)
          .addReg(RL78::SPreg)
          .addImm(NumBytesAdjusted - 0xFE);
    } else if (NumBytesAdjusted < 0x10000) {
      // TODO: check if RP0 is usesd
      BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
          .addReg(RL78::RP6, RegState::Define)
          .addReg(RL78::RP0, RegState::Kill)
          .addReg(RL78::RP6, RegState::Kill);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_rp_sp), RL78::RP0)
          .addReg(RL78::SPreg);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::ADDW_rp_imm), RL78::RP0)
          .addReg(RL78::RP0)
          .addImm(NumBytesAdjusted);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOVW_sp_rp), RL78::SPreg)
          .addReg(RL78::RP0);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::XCHW_AX_rp), RL78::RP0)
          .addReg(RL78::RP6, RegState::Define)
          .addReg(RL78::RP0, RegState::Kill)
          .addReg(RL78::RP6, RegState::Kill);
    } else
      llvm_unreachable("Invalid stack allocation!");

    unsigned CFIIndex =
        MF.addFrameInst(MCCFIInstruction::cfiDefCfaOffset(nullptr, 4));
    BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
        .addCFIIndex(CFIIndex);
  }
  if (MF.getFunction().hasFnAttribute("brk_interrupt") ||
      MF.getFunction().hasFnAttribute("interrupt")) {
    if (mask & (1 << 5) && mask & (1 << 4)) {
      BuildMI(MBB, MBBI, dl, TII.get(RL78::POP_rp), RL78::RP0);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_es_A), RL78::ES)
          .addReg(RL78::R1);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_A_r), RL78::R1).addReg(RL78::R0);
      BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_cs_A), RL78::CS)
          .addReg(RL78::R1);
      NumBytes -= 2;
      unsigned CFIIndex = MF.addFrameInst(
          MCCFIInstruction::cfiDefCfaOffset(nullptr, NumBytes + 4));
      BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
          .addCFIIndex(CFIIndex);
    } else {
      if (mask & (1 << 5)) {
        BuildMI(MBB, MBBI, dl, TII.get(RL78::POP_rp), RL78::RP0);
        BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_es_A), RL78::ES)
            .addReg(RL78::R1);
        NumBytes -= 2;
        unsigned CFIIndex = MF.addFrameInst(
            MCCFIInstruction::cfiDefCfaOffset(nullptr, NumBytes + 4));
        BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
            .addCFIIndex(CFIIndex);
      }
      if (mask & (1 << 4)) {
        BuildMI(MBB, MBBI, dl, TII.get(RL78::POP_rp), RL78::RP0);
        BuildMI(MBB, MBBI, dl, TII.get(RL78::MOV_cs_A), RL78::CS)
            .addReg(RL78::R1);
        NumBytes -= 2;
        unsigned CFIIndex = MF.addFrameInst(
            MCCFIInstruction::cfiDefCfaOffset(nullptr, NumBytes + 4));
        BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
            .addCFIIndex(CFIIndex);
      }
    }

    if (!Bank) {
      for (unsigned reg = 4; reg > 0; --reg) {
        if ((1 << (reg - 1)) & mask) {
          BuildMI(MBB, MBBI, dl, TII.get(RL78::POP_rp),
                  RL78::RP0 + ((reg - 1) % 4));
          NumBytes -= 2;
          unsigned CFIIndex = MF.addFrameInst(
              MCCFIInstruction::cfiDefCfaOffset(nullptr, NumBytes + 4));
          BuildMI(MBB, MBBI, dl, TII.get(TargetOpcode::CFI_INSTRUCTION))
              .addCFIIndex(CFIIndex);
        }
      }
    }
  }
}

bool RL78FrameLowering::hasReservedCallFrame(const MachineFunction &MF) const {
  // Reserve call frame if there are no variable sized objects on the stack.
  return !MF.getFrameInfo().hasVarSizedObjects();
}

// hasFP - Return true if the specified function should have a dedicated frame
// pointer register.  This is true if the function has variable sized allocas or
// if frame pointer elimination is disabled.
bool RL78FrameLowering::hasFP(const MachineFunction &MF) const {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  return MFI.hasVarSizedObjects();
}

StackOffset RL78FrameLowering::getFrameIndexReference(const MachineFunction &MF, int FI,
                                              Register &FrameReg) const {
  const RL78Subtarget &Subtarget = MF.getSubtarget<RL78Subtarget>();
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  const RL78RegisterInfo *RegInfo = Subtarget.getRegisterInfo();

  int64_t FrameOffset = MFI.getObjectOffset(FI);
  auto stackSize = MFI.getStackSize();
  if ((FI < 0) && (FrameOffset >= 0))
    FrameReg = RL78::SPreg;
  else if (RegInfo->shouldRealignStack(MF) && (FI < 0))
    // References to passed parameters need to load the old SP first.
    FrameReg = RL78::RP4;
  else
    FrameReg = RegInfo->getFrameRegister(MF);

  if (FI < 0) {
    // The return address is a special case.
    if (FrameOffset == -2)
      FrameOffset = stackSize;
    else if (FrameOffset < 0)
      FrameOffset = stackSize - FrameOffset;
    if (FrameReg == RL78::RP4)
      FrameOffset += 2;
  }
  return StackOffset::getFixed(FrameOffset);
}

bool RL78FrameLowering::isLeafProc(MachineFunction &MF) const {
  MachineFrameInfo &MFI = MF.getFrameInfo();

  return !(MFI.hasCalls() // has calls
           || hasFP(MF)); // need FP
}

namespace {
// Struct used by orderFrameObjects to help sort the stack objects.
struct RL78FrameSortingObject {
  bool IsValid = false;       // true if we care about this Object.
  unsigned ObjectIndex = 0;   // Index of Object into MFI list.
  unsigned ObjectNumUses = 0; // Object static number of uses.
};

struct RL78FrameSortingComparator {
  inline bool operator()(const RL78FrameSortingObject &A,
                         const RL78FrameSortingObject &B) {
    // For consistency in our comparison, all invalid objects are placed
    // at the end. This also allows us to stop walking when we hit the
    // first invalid item after it's all sorted.
    if (!A.IsValid)
      return false;
    if (!B.IsValid)
      return true;

    return A.ObjectNumUses > B.ObjectNumUses;
  }
};
} // namespace

// Order frame objects:
// We want to place the more freequently used objects first (lower address)
// becuase we use [SP+offset] when offset < 256 and offset[BC] when offset >=
// 256. This will improve both code size and speed.
void RL78FrameLowering::orderFrameObjects(
    const MachineFunction &MF, SmallVectorImpl<int> &objectsToAllocate) const {
  const MachineFrameInfo &MFI = MF.getFrameInfo();

  // Don't waste time if there's nothing to do.
  if (objectsToAllocate.empty())
    return;

  // Create an array of all MFI objects. We won't need all of these
  // objects, but we're going to create a full array of them to make
  // it easier to index into when we're counting "uses" down below.
  // We want to be able to easily/cheaply access an object by simply
  // indexing into it, instead of having to search for it every time.
  std::vector<RL78FrameSortingObject> SortingObjects(MFI.getObjectIndexEnd());

  // Walk the objects we care about and mark them as such in our working
  // struct.
  int ObjectsSize = 0;
  for (auto &Obj : objectsToAllocate) {
    SortingObjects[Obj].IsValid = true;
    SortingObjects[Obj].ObjectIndex = Obj;
    ObjectsSize += MFI.getObjectSize(Obj);
  }

  if (ObjectsSize < 256)
    return;

  // Count the number of uses for each object.
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      if (MI.isDebugInstr())
        continue;
      for (const MachineOperand &MO : MI.operands()) {
        // Check to see if it's a local stack symbol.
        if (!MO.isFI())
          continue;
        int Index = MO.getIndex();
        // Check to see if it falls within our range, and is tagged
        // to require ordering.
        if (Index >= 0 && Index < MFI.getObjectIndexEnd())
          SortingObjects[Index].ObjectNumUses++;
      }
    }
  }
  // Sort the objects using X86FrameSortingAlgorithm (see its comment for
  // info).
  llvm::stable_sort(SortingObjects, RL78FrameSortingComparator());

  // Now modify the original list to represent the final order that
  // we want.
  int i = 0;
  for (auto &Obj : SortingObjects) {
    // All invalid items are sorted at the end, so it's safe to stop.
    if (!Obj.IsValid)
      break;
    objectsToAllocate[i++] = Obj.ObjectIndex;
  }
}
