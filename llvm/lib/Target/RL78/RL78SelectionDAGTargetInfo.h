//===-- RL78SelectionDAGTargetInfo.h - Define SelectionDAGTargetInfo for the
// RL78 -------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares the RL78 specific subclass of SelectionDAGTargetInfo.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78SELECTIONDAGTARGETINFO_H
#define LLVM_LIB_TARGET_RL78_RL78SELECTIONDAGTARGETINFO_H

#include "llvm/CodeGen/SelectionDAGTargetInfo.h"

namespace llvm {

class RL78SelectionDAGTargetInfo : public SelectionDAGTargetInfo {
public:
  explicit RL78SelectionDAGTargetInfo() = default;
  RL78SelectionDAGTargetInfo(const RL78SelectionDAGTargetInfo &) = delete;
  RL78SelectionDAGTargetInfo &
  operator=(const RL78SelectionDAGTargetInfo &) = delete;
  virtual ~RL78SelectionDAGTargetInfo();

  SDValue EmitTargetCodeForMemcpy(SelectionDAG &DAG, const SDLoc &dl,
                                  SDValue Chain, SDValue Op1, SDValue Op2,
                                  SDValue Op3, Align Align, bool isVolatile,
                                  bool AlwaysInline,
                                  MachinePointerInfo DstPtrInfo,
                                  MachinePointerInfo SrcPtrInfo) const override;

  SDValue
  EmitTargetCodeForMemmove(SelectionDAG &DAG, const SDLoc &dl, SDValue Chain,
                           SDValue Op1, SDValue Op2, SDValue Op3,
                           Align Align, bool isVolatile,
                           MachinePointerInfo DstPtrInfo,
                           MachinePointerInfo SrcPtrInfo) const override;

  SDValue EmitTargetCodeForMemset(SelectionDAG &DAG, const SDLoc &dl,
                                  SDValue Chain, SDValue Op1, SDValue Op2,
                                  SDValue Op3, Align Align, bool isVolatile,
                                  bool AlwaysInline,
                                  MachinePointerInfo DstPtrInfo) const override;
private:
  SDValue EmitTargetCodeForMemcpymove(
      SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1,
      SDValue Op2, SDValue Op3, Align Align, bool isVolatile, bool AlwaysInline,
      MachinePointerInfo DstPtrInfo, MachinePointerInfo SrcPtrInfo,
      unsigned LibCall, const char *FarLibCallName) const;
};

} // end namespace llvm
#endif
