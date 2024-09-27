//===-- RL78TargetMachine.h - Define TargetMachine for RL78 ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares the RL78 specific subclass of TargetMachine.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78TARGETMACHINE_H
#define LLVM_LIB_TARGET_RL78_RL78TARGETMACHINE_H

#include "RL78Subtarget.h"

namespace llvm {

class RL78TargetMachine : public LLVMTargetMachine {
  std::unique_ptr<TargetLoweringObjectFile> TLOF;
  //RL78Subtarget Subtarget;
  bool is64Bit;
  mutable StringMap<std::unique_ptr<RL78Subtarget>> SubtargetMap;

public:
  RL78TargetMachine(const Target &T, const Triple &TT, StringRef CPU,
                    StringRef FS, const TargetOptions &Options,
                    std::optional<Reloc::Model> RM, std::optional<CodeModel::Model> CM,
                    CodeGenOpt::Level OL, bool JIT);
  ~RL78TargetMachine() override;

  // DO NOT IMPLEMENT: There is no such thing as a valid default subtarget,
  // subtargets are per-function entities based on the target-specific
  // attributes of each function.
  const RL78Subtarget *getSubtargetImpl() const = delete;
  const RL78Subtarget *getSubtargetImpl(const Function &) const override;

  // Pass Pipeline Configuration
  TargetPassConfig *createPassConfig(PassManagerBase &PM) override;
  TargetTransformInfo getTargetTransformInfo(const Function &F) const override;
  MachineFunctionInfo *
  createMachineFunctionInfo(BumpPtrAllocator &Allocator, const Function &F,
                            const TargetSubtargetInfo *STI) const override;
  TargetLoweringObjectFile *getObjFileLowering() const override {
    return TLOF.get();
  }

  bool isMachineVerifierClean() const override { return false; }

  // FIXME: currently we are using substitutePass(&PostRASchedulerID,
  // &PostMachineSchedulerID)
  // we might come back to this at some point maybe on -O3.
  // Temporary option to allow experimenting with MachineScheduler as a post-RA
  // scheduler. Targets can "properly" enable this with
  // substitutePass(&PostRASchedulerID, &PostMachineSchedulerID).
  // Targets can return true in targetSchedulesPostRAScheduling() and
  // insert a PostRA scheduling pass wherever it wants.
  bool targetSchedulesPostRAScheduling() const override { return false; }

  bool useIPRA() const override { return true; }

  bool isNoopAddrSpaceCast(unsigned SrcAS, unsigned DestAS) const override {
    // when -mfar-data the default AS is far, so the only outlier is the near AS
    if (DL.getPointerSizeInBits(0) == 32)
      return (SrcAS != RL78AS::Near) == (DestAS != RL78AS::Near);

    return SrcAS == DestAS ||
           (RL78AS::Near == SrcAS && RL78AS::Default == DestAS) ||
           (RL78AS::FarCode == SrcAS && RL78AS::FarData == DestAS) ||
           (RL78AS::FarData == SrcAS && RL78AS::FarCode == DestAS);
  }

};

static unsigned int tryGetRP6(MachineBasicBlock *BB) {
  const TargetRegisterInfo *TRI = BB->getParent()->getSubtarget().getRegisterInfo();
  return TRI->getReservedRegs(*BB->getParent()).test(RL78::RP6) ? RL78::RP4
                                                             : RL78::RP6;
}

static bool isFPUsed(MachineBasicBlock *BB) {
    return tryGetRP6(BB) != RL78::RP6;
}

} // end namespace llvm

#endif
