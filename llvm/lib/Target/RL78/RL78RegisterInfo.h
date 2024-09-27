//===-- RL78RegisterInfo.h - RL78 Register Information Impl ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the RL78 implementation of the TargetRegisterInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78REGISTERINFO_H
#define LLVM_LIB_TARGET_RL78_RL78REGISTERINFO_H

#define GET_REGINFO_HEADER
#include "RL78GenRegisterInfo.inc"

namespace llvm {
struct RL78RegisterInfo : public RL78GenRegisterInfo {
  RL78RegisterInfo();

  /// Code Generation virtual methods...
  const MCPhysReg *getCalleeSavedRegs(const MachineFunction *MF) const override;
  const uint32_t *getCallPreservedMask(const MachineFunction &MF,
                                       CallingConv::ID CC) const override;

  BitVector getReservedRegs(const MachineFunction &MF) const override;

  const TargetRegisterClass *getPointerRegClass(const MachineFunction &MF,
                                                unsigned Kind) const override;

  bool eliminateFrameIndex(MachineBasicBlock::iterator II, int SPAdj,
                           unsigned FIOperandNum,
                           RegScavenger *RS = nullptr) const override;

  Register getFrameRegister(const MachineFunction &MF) const override;

  bool trackLivenessAfterRegAlloc(const MachineFunction &MF) const override {
    return true;
  }

  /// Allow the target to reverse allocation order of local live ranges. This
  /// will generally allocate shorter local live ranges first. For targets with
  /// many registers, this could reduce regalloc compile time by a large
  /// factor.
  bool reverseLocalAssignment() const override { return true; }
};

} // end namespace llvm

#endif
