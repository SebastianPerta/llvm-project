//===- RL78MachineFunctionInfo.h - RL78 Machine Function Info -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares  RL78 specific per-machine-function information.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_LIB_TARGET_RL78_RL78MACHINEFUNCTIONINFO_H
#define LLVM_LIB_TARGET_RL78_RL78MACHINEFUNCTIONINFO_H

#include "llvm/CodeGen/MachineFunction.h"

namespace llvm {

class RL78MachineFunctionInfo : public MachineFunctionInfo {
  virtual void anchor();

private:
  unsigned GlobalBaseReg;

  /// VarArgsFrameOffset - Frame offset to start of varargs area.
  int VarArgsFrameOffset;

  /// SRetReturnReg - Holds the virtual register(s) into which the sret
  /// argument is passed.
  unsigned SRetReturnReg[2];

  /// IsLeafProc - True if the function is a leaf procedure.
  bool IsLeafProc;

public:
  RL78MachineFunctionInfo()
      : GlobalBaseReg(0), VarArgsFrameOffset(0), SRetReturnReg{0},
        IsLeafProc(false) {}
  RL78MachineFunctionInfo(const Function &F, const TargetSubtargetInfo *STI)
      : GlobalBaseReg(0), VarArgsFrameOffset(0), SRetReturnReg{0},
        IsLeafProc(false) {}

  MachineFunctionInfo *
  clone(BumpPtrAllocator &Allocator, MachineFunction &DestMF,
        const DenseMap<MachineBasicBlock *, MachineBasicBlock *> &Src2DstMBB)
      const override {
      return DestMF.cloneInfo<RL78MachineFunctionInfo>(*this);
  }

  unsigned getGlobalBaseReg() const { return GlobalBaseReg; }
  void setGlobalBaseReg(unsigned Reg) { GlobalBaseReg = Reg; }

  int getVarArgsFrameOffset() const { return VarArgsFrameOffset; }
  void setVarArgsFrameOffset(int Offset) { VarArgsFrameOffset = Offset; }

  unsigned getSRetReturnReg(unsigned Idx = 0) const { return SRetReturnReg[Idx]; }
  void setSRetReturnReg(unsigned Reg, unsigned Idx = 0) { SRetReturnReg[Idx] = Reg; }

  void setLeafProc(bool rhs) { IsLeafProc = rhs; }
  bool isLeafProc() const { return IsLeafProc; }
};
} // end namespace llvm

#endif
