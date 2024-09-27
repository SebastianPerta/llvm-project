//===-- RL78InstrInfo.h - RL78 Instruction Information --------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the RL78 implementation of the TargetInstrInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78INSTRINFO_H
#define LLVM_LIB_TARGET_RL78_RL78INSTRINFO_H

#include "RL78RegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

#define GET_INSTRINFO_HEADER
#include "RL78GenInstrInfo.inc"

namespace llvm {

class RL78Subtarget;

/// SPII - This namespace holds all of the target specific flags that
/// instruction info tracks.
///
namespace SPII {
enum {
  Pseudo = (1 << 0),
  Load = (1 << 1),
  Store = (1 << 2),
  DelaySlot = (1 << 3)
};

/// Target Operand Flag enum. Assumes same order as RL78MCExpr::VariantKind
enum TOF { MO_NO_FLAG, MO_LOW8, MO_LOW16, MO_HI16 };

} // end namespace SPII

class RL78InstrInfo : public RL78GenInstrInfo {
  const RL78RegisterInfo RI;
  const RL78Subtarget &Subtarget;
  virtual void anchor();

public:
  explicit RL78InstrInfo(RL78Subtarget &ST);

  /// getRegisterInfo - TargetInstrInfo is a superset of MRegister info.  As
  /// such, whenever a client has an instance of instruction info, it should
  /// always be able to get register info as well (through this method).
  ///
  const RL78RegisterInfo &getRegisterInfo() const { return RI; }

  /// isLoadFromStackSlot - If the specified machine instruction is a direct
  /// load from a stack slot, return the virtual or physical register number of
  /// the destination along with the FrameIndex of the loaded stack slot.  If
  /// not, return 0.  This predicate must return 0 if the instruction has
  /// any side effects other than loading from the stack slot.
  unsigned isLoadFromStackSlot(const MachineInstr &MI,
                               int &FrameIndex) const override;

  /// isStoreToStackSlot - If the specified machine instruction is a direct
  /// store to a stack slot, return the virtual or physical register number of
  /// the source reg along with the FrameIndex of the loaded stack slot.  If
  /// not, return 0.  This predicate must return 0 if the instruction has
  /// any side effects other than storing to the stack slot.
  unsigned isStoreToStackSlot(const MachineInstr &MI,
                              int &FrameIndex) const override;

  bool analyzeBranch(MachineBasicBlock &MBB, MachineBasicBlock *&TBB,
                     MachineBasicBlock *&FBB,
                     SmallVectorImpl<MachineOperand> &Cond,
                     bool AllowModify = false) const override;

  unsigned removeBranch(MachineBasicBlock &MBB,
                        int *BytesRemoved = nullptr) const override;

  unsigned insertBranch(MachineBasicBlock &MBB, MachineBasicBlock *TBB,
                        MachineBasicBlock *FBB, ArrayRef<MachineOperand> Cond,
                        const DebugLoc &DL,
                        int *BytesAdded = nullptr) const override;

  bool
  reverseBranchCondition(SmallVectorImpl<MachineOperand> &Cond) const override;

  void copyPhysReg(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                   const DebugLoc &DL, MCRegister DestReg, MCRegister SrcReg,
                   bool KillSrc) const override;

  void storeRegToStackSlot(MachineBasicBlock &MBB,
                           MachineBasicBlock::iterator MBBI, Register SrcReg,
                           bool isKill, int FrameIndex,
                           const TargetRegisterClass *RC,
                           const TargetRegisterInfo *TRI, 
                           Register VReg) const override;

  void loadRegFromStackSlot(MachineBasicBlock &MBB,
                            MachineBasicBlock::iterator MBBI, Register DestReg,
                            int FrameIndex, const TargetRegisterClass *RC,
                            const TargetRegisterInfo *TRI, 
                            Register VReg) const override;
  
  bool expandPostRAPseudo(MachineInstr &MI) const override;

  /// Returns the size in bytes of the specified MachineInstr, or ~0U
  /// when this function is not implemented by a target.
  unsigned getInstSizeInBytes(const MachineInstr &MI) const override;

  /// Returns a \p outliner::OutlinedFunction struct containing target-specific
  /// information for a set of outlining candidates.
  std::optional<outliner::OutlinedFunction> getOutliningCandidateInfo(
      std::vector<outliner::Candidate> &RepeatedSequenceLocs) const override;

  /// Returns how or if \p MI should be outlined.
  outliner::InstrType getOutliningTypeImpl(MachineBasicBlock::iterator &MIT,
                                       unsigned Flags) const override;

  /// Insert a custom frame for outlined functions.
  void buildOutlinedFrame(MachineBasicBlock &MBB, MachineFunction &MF,
                          const outliner::OutlinedFunction &OF) const override;

  /// Insert a call to an outlined function into the program.
  /// Returns an iterator to the spot where we inserted the call. This must be
  /// implemented by the target.
  MachineBasicBlock::iterator
  insertOutlinedCall(Module &M, MachineBasicBlock &MBB,
                     MachineBasicBlock::iterator &It, MachineFunction &MF,
                     outliner::Candidate &C) const override;

  /// Return true if the function can safely be outlined from.
  /// A function \p MF is considered safe for outlining if an outlined function
  /// produced from instructions in F will produce a program which produces the
  /// same output for any set of given inputs.
  bool isFunctionSafeToOutlineFrom(MachineFunction &MF,
                                   bool OutlineFromLinkOnceODRs) const override;

  /// Return true if the function should be outlined from by default.
  bool shouldOutlineFromFunctionByDefault(MachineFunction &MF) const override;

  /// Return true if the instruction is as cheap as a move instruction.
  ///
  /// Targets for different archs need to override this, and different
  /// micro-architectures can also be finely tuned inside.
  /// For code size improvements, consider that every MachineInstruction is
  /// cheaper than a move.
  bool isAsCheapAsAMove(const MachineInstr &MI) const override {
    return MI.getParent()->getParent()->getFunction().hasOptSize();
  }

  bool isSubregFoldable() const override { return true; }

  ArrayRef<std::pair<unsigned, const char *>>
  getSerializableDirectMachineOperandTargetFlags() const override;

  MachineInstr *foldMemoryOperandImpl(MachineFunction &MF, MachineInstr &MI,
                                      ArrayRef<unsigned> Ops,
                                      MachineBasicBlock::iterator InsertPt,
                                      int FrameIndex,
                                      LiveIntervals *LIS = nullptr,
                                      VirtRegMap *VRM = nullptr) const override;

  bool isReallyTriviallyReMaterializable(const MachineInstr &MI) const override {
    return true;
  }

  bool hasLowDefLatency(const TargetSchedModel &SchedModel,
                        const MachineInstr &DefMI,
                        unsigned DefIdx) const override {
    // Only DIVHU and DIVWU have high def latency.
    if ((DefMI.getOpcode() == RL78::UDIVREM16_r_r) ||
        (DefMI.getOpcode() == RL78::UDIVREM32_r_r))
      return false;
    return true;
  }

  bool isUnconditionalTailCall(const MachineInstr &MI) const override {
    if ((MI.getOpcode() == RL78::BR_addr16) ||
        (MI.getOpcode() == RL78::BR_addr20))
      return true;
    return false;
  }

  ScheduleHazardRecognizer *
  CreateTargetPostRAHazardRecognizer(const InstrItineraryData *,
                                     const ScheduleDAG *DAG) const override;
};

} // end namespace llvm

#endif
