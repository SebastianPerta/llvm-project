//===-- RL78ISelLowering.h - RL78 DAG Lowering Interface ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines the interfaces that RL78 uses to lower LLVM code into a
// selection DAG.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78ISELLOWERING_H
#define LLVM_LIB_TARGET_RL78_RL78ISELLOWERING_H

#include "RL78.h"
#include "llvm/CodeGen/TargetLowering.h"

namespace llvm {
class RL78Subtarget;

namespace RL78ISD {
enum NodeType : unsigned {
  FIRST_NUMBER = ISD::BUILTIN_OP_END,
  SEL_RB,
  CMP,
  LOWCMP,
  CALL,
  CALLT,
  CALL_FP,
  TAIL_CALL,
  RET,
  RETI,
  RETB,
  BRCC,
  SELECTCC,
  BTBF,
  MOV1TOCY,
  MOV1FROMCY,
  LOAD1TOCY,
  STORE1FROMCY,
  AND1CY,
  OR1CY,
  XOR1CY,
  SET1,
  CLR1,
  NOT1CY,
  DIVWU,
  XCHW,
  LOW8,
  LOW16,
  HI16,
  ANDMEM,
  ORMEM,
  XORMEM,
  MACHU,
  MACH,
  INC
};
}

class RL78TargetLowering : public TargetLowering {
  const RL78Subtarget *Subtarget;

public:
  RL78TargetLowering(const TargetMachine &TM, const RL78Subtarget &STI);

  SDValue LowerOperation(SDValue Op, SelectionDAG &DAG) const override;
  SDValue PerformDAGCombine(SDNode *N, DAGCombinerInfo &DCI) const override;

  bool useSoftFloat() const override;

  bool ExpandInlineAsm(CallInst *) const override;

  unsigned getJumpTableEncoding() const override;

  bool getTgtMemIntrinsic(IntrinsicInfo &Info, const CallInst &I,
                          MachineFunction &MF,
                          unsigned Intrinsic) const override;

  /// computeKnownBitsForTargetNode - Determine which of the bits specified
  /// in Mask are known to be either zero or one and return them in the
  /// KnownZero/KnownOne bitsets.
  void computeKnownBitsForTargetNode(const SDValue Op, KnownBits &Known,
                                     const APInt &DemandedElts,
                                     const SelectionDAG &DAG,
                                     unsigned Depth = 0) const override;

  MachineBasicBlock *
  EmitInstrWithCustomInserter(MachineInstr &MI,
                              MachineBasicBlock *MBB) const override;

  const char *getTargetNodeName(unsigned Opcode) const override;

  ConstraintType getConstraintType(StringRef Constraint) const override;
  ConstraintWeight
  getSingleConstraintMatchWeight(AsmOperandInfo &info,
                                 const char *constraint) const override;

  std::pair<unsigned, const TargetRegisterClass *>
  getRegForInlineAsmConstraint(const TargetRegisterInfo *TRI,
                               StringRef Constraint, MVT VT) const override;

  MVT getScalarShiftAmountTy(const DataLayout &, EVT vt) const override {
    return MVT::i8;
  }

  /// Return the ValueType for comparison libcalls. Comparions libcalls include
  /// floating point comparion calls, and Ordered/Unordered check calls on
  /// floating point numbers.
  MVT::SimpleValueType getCmpLibcallReturnType() const override {
    return MVT::i16;
  }

  Register getRegisterByName(const char *RegName, LLT VT,
                             const MachineFunction &MF) const override;

  /// getSetCCResultType - Return the ISD::SETCC ValueType
  EVT getSetCCResultType(const DataLayout &DL, LLVMContext &Context,
                         EVT VT) const override;

  bool CanLowerReturn(CallingConv::ID CallConv, MachineFunction &MF,
                      bool isVarArg,
                      const SmallVectorImpl<ISD::OutputArg> &Outs,
                      LLVMContext &Context) const override;

  SDValue LowerFormalArguments(SDValue Chain, CallingConv::ID CallConv,
                               bool isVarArg,
                               const SmallVectorImpl<ISD::InputArg> &Ins,
                               const SDLoc &dl, SelectionDAG &DAG,
                               SmallVectorImpl<SDValue> &InVals) const override;

  SDValue LowerCall(TargetLowering::CallLoweringInfo &CLI,
                    SmallVectorImpl<SDValue> &InVals) const override;

  SDValue LowerReturn(SDValue Chain, CallingConv::ID CallConv, bool isVarArg,
                      const SmallVectorImpl<ISD::OutputArg> &Outs,
                      const SmallVectorImpl<SDValue> &OutVals, const SDLoc &dl,
                      SelectionDAG &DAG) const override;

  EVT getTypeForExtReturn(LLVMContext &Context, EVT VT,
                          ISD::NodeType ExtendKind) const override;

  SDValue LowerMULO(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerExternalSymbol(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerGlobalAddress(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerConstantPool(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerBlockAddress(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerJumpTable(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerLOAD(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerSTORE(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerSETCC(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerDYNAMIC_STACKALLOC(SDValue Op, SelectionDAG &DAG) const;

  SDValue withTargetFlags(SDValue Op, unsigned TF, SelectionDAG &DAG) const;
  SDValue makeAddress(SDValue Op, SelectionDAG &DAG) const;

  void ReplaceNodeResults(SDNode *N, SmallVectorImpl<SDValue> &Results,
                          SelectionDAG &DAG) const override;
  void LowerOperationWrapper(SDNode *N, SmallVectorImpl<SDValue> &Results,
                             SelectionDAG &DAG) const override;

  /// Speculating a call to intrinsic cttz is cheap.
  bool isCheapToSpeculateCttz(Type *Ty) const override { return true; }

  /// Speculating a call to intrinsic ctlz is cheap.
  bool isCheapToSpeculateCtlz(Type *Ty) const override { return true; }

  bool shouldConvertConstantLoadToIntImm(const APInt &Imm,
                                         Type *Ty) const override {
    return true;
  }

  // Hoisting introdcues extra copies, we prefer sinking for RL78.
  bool isProfitableToHoist(Instruction *I) const override { return false; }

  // We have BT/BF.
  bool isMaskAndCmp0FoldingBeneficial(const Instruction &AndI) const override {
    return true;
  }

  bool shouldSinkOperands(Instruction *I,
                          SmallVectorImpl<Use *> &Ops) const override {

    if (!I->getFunction()->hasOptSize())
      return false;

    for (unsigned i = 0; i < I->getNumOperands(); ++i) {
      bool operandValid = true;
      if (auto UI = dyn_cast<Instruction>(I->getOperandUse(i))) {

        if (UI->getOpcode() == Instruction::Call ||
            UI->getOpcode() == Instruction::Load ||
            UI->getOpcode() == Instruction::Store ||
            UI->getOpcode() == Instruction::Alloca)
          operandValid = false;

        if (UI->isTerminator() || isa<PHINode>(UI) || UI->isEHPad() ||
            UI->mayThrow())
          operandValid = false;

        for (unsigned j = 0; (j < UI->getNumOperands()) && operandValid; ++j) {
          if (auto UI2 = dyn_cast<Instruction>(UI->getOperandUse(j)))
            operandValid = false;
        }

        if (operandValid && !UI->hasNUsesOrMore(2))
          Ops.push_back(&I->getOperandUse(i));
      }
    }
    return !Ops.empty();
  }

  // It's always profitable to narrow on RL78.
  bool isNarrowingProfitable(EVT VT1, EVT VT2) const override {
    return true;
  }

  bool isMultiStoresCheaperThanBitsMerge(EVT LTy, EVT HTy) const override {
    return true;
  }

  bool isTruncateFree(EVT FromVT, EVT ToVT) const override { return true; }

  bool mayBeEmittedAsTailCall(const CallInst *CI) const override {
    return CI->isTailCall();
  }

  ShiftLegalizationStrategy
  preferredShiftLegalizationStrategy(SelectionDAG &DAG, SDNode *N,
                                     unsigned ExpansionFactor) const override {
    return ShiftLegalizationStrategy::LowerToLibcall;
  }

  bool isDesirableToCommuteWithShift(const SDNode *N,
                                             CombineLevel Level) const override;

  MVT getVectorIdxTy(const DataLayout &DL) const override { return MVT::i16; }

private:
  // CC-RL calling convention specific operand allocator functions
  void
  AnalyzeCCRLCallOperands(CCState &State,
                          const SmallVectorImpl<ISD::OutputArg> &Outs) const;
  void
  AnalyzeCCRLFormalOperands(CCState &State,
                            const SmallVectorImpl<ISD::InputArg> &Outs) const;
  template <typename T>
  void AnalyzeCCRLReturnOperands(CCState &State,
                                 const SmallVectorImpl<T> &Outs) const;

  // lower a library call for the specified, pseudo, op
  SDValue LowerLibCall(SDValue Op, SelectionDAG &DAG,
                       const char *libFunctionName, bool IsSigned,
                       unsigned OperandIndex = 0) const;
  SDValue LowerLibCall(SDValue Op, SelectionDAG &DAG,
                       const char *libFunctionName, bool IsSigned,
                       ArrayRef<SDValue> Ops) const;

  SDValue LowerMul(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerAndOrXor(SDValue Op, SelectionDAG &DAG,
                        unsigned int opcode) const;
  SDValue LowerCDIV(SDValue Op, SelectionDAG &DAG, unsigned int opcode) const;
  SDValue LowerShift(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerRotate(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerIntrinsicWithChain(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerIntrinsicWithoutChain(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerIntrinsicVoid(SDValue Op, SelectionDAG &DAG) const;

  SDValue PerformBRCCCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformBRCONDCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformMULCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformUDIVREMCombine(SDNode *N, DAGCombinerInfo &DCI,
                                ISD::NodeType otherNodeType) const;
  SDValue PerformADDCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformSUBCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformMULADDCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformXORAddCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformTruncateCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformANDCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformORCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformXORCombine(SDNode *N, DAGCombinerInfo &DCI) const;
  SDValue PerformSHLCombine(SDNode *N, DAGCombinerInfo &DCI) const;

  MachineBasicBlock *LowerEXTEND(bool sext, MachineInstr &MI,
                                 MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerADDE_SUBE_rp_rp(unsigned int opcode, MachineInstr &MI,
                                          MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerADDE_SUBE_rp_imm(unsigned int opcode,
                                           MachineInstr &MI,
                                           MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerADDE_SUBE_rp_memri(unsigned int opcode,
                                             MachineInstr &MI,
                                             MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerADDE_SUBE_rp_abs16(unsigned int opcode,
                                             MachineInstr &MI,
                                             MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerAndOrXor16_rp_imm(unsigned int opcode,
                                            MachineInstr &MI,
                                            MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerAndOrXor16_rp_rp(unsigned int opcode,
                                           MachineInstr &MI,
                                           MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerAndOrXor16_rp_memri(unsigned int opcode,
                                              unsigned int opcode2,
                                              MachineInstr &MI,
                                              MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerAndOrXor16_rp_abs16(unsigned int opcode,
                                              MachineInstr &MI,
                                              MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerSignedCMP0(bool cmpw, MachineInstr &MI,
                                     MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerSignedCMP(MachineInstr &MI,
                                    MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerSignedCMPW(MachineInstr &MI,
                                     MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerSignedCMPWMem(MachineInstr &MI,
                                        MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerRotate_r_imm(MachineInstr &MI, MachineBasicBlock *BB,
                                       bool rotl) const;
  MachineBasicBlock *LowerRotate16_rp_imm(MachineInstr &MI,
                                          MachineBasicBlock *BB,
                                          bool rotl) const;
  MachineBasicBlock *LowerSELECTCC(bool isI8, MachineInstr &MI,
                                   MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerMUL8(MachineInstr &MI, MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerMUL16(MachineInstr &MI, MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerShiftOrRotateForSpeed(MachineInstr &MI,
                                                MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerShift_Or_LowerRotate_rp_rp(MachineInstr &MI,
                                                     MachineBasicBlock *BB,
                                                     unsigned int opcode,
                                                     bool isI8) const;
  MachineBasicBlock *LowerMUL8Zext16(MachineInstr &MI,
                                     MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerUMUL_LOHI16(MachineInstr &MI,
                                      MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerMULDIV16(MachineInstr &MI, MachineBasicBlock *BB,
                                   unsigned srcIndex) const;
  MachineBasicBlock *LowerDIVWU(MachineInstr &MI, MachineBasicBlock *BB) const;
  MachineBasicBlock *Lower8BitOpAA(MachineInstr &MI,
                                   MachineBasicBlock *BB) const;
  MachineBasicBlock *Lower16BitOpAXAX(MachineInstr &MI,
                                      MachineBasicBlock *BB) const;
  MachineBasicBlock *Lower8bitADst(MachineInstr &MI,
                                   MachineBasicBlock *BB) const;
  MachineBasicBlock *Lower16bitAXDst(MachineInstr &MI,
                                     MachineBasicBlock *BB) const;
  MachineBasicBlock *Lower8bitASrc(MachineInstr &MI, MachineBasicBlock *BB,
                                   unsigned OpNum = 0,
                                   unsigned Reg = RL78::R1) const;
  MachineBasicBlock *Lower16bitAXSrc(MachineInstr &MI, MachineBasicBlock *BB,
                                     unsigned OpNum = 0,
                                     unsigned Reg = RL78::RP0) const;
  MachineBasicBlock *LowerESSrc(MachineInstr &MI, MachineBasicBlock *BB,
                                unsigned OpNum) const;
  MachineBasicBlock *LowerCallCSRP(MachineInstr &MI,
                                   MachineBasicBlock *BB) const;
  MachineBasicBlock *LowerBSWAP32(MachineInstr &MI,
                                  MachineBasicBlock *BB) const;

  bool decomposeMulByConstant(LLVMContext &Context, EVT VT,
                              SDValue C) const override;
};
} // end namespace llvm

#endif // RL78_ISELLOWERING_H
