//===-- RL78ISelLowering.cpp - RL78 DAG Lowering Implementation ---------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the interfaces that RL78 uses to lower LLVM code into a
// selection DAG.
//
//===----------------------------------------------------------------------===//

#include "RL78ISelLowering.h"
#include "MCTargetDesc/RL78MCExpr.h"
#include "RL78MachineFunctionInfo.h"
#include "RL78TargetMachine.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/CodeGen/CallingConvLower.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/IR/IntrinsicsRL78.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/KnownBits.h"
using namespace llvm;
#define DEBUG_TYPE "isellowering"

#include "RL78GenRegisterInfo.inc"

//===----------------------------------------------------------------------===//
// Calling Convention Implementation
//===----------------------------------------------------------------------===//

#include "RL78GenCallingConv.inc"

/// Return the type that should be used to zero or sign extend a
/// zeroext/signext integer return value.  FIXME: Some C calling conventions
/// require the return type to be promoted, but this is not true all the time,
/// e.g. i1/i8/i16 on x86/x86_64. It is also not necessary for non-C calling
/// conventions. The frontend should handle this and include all of the
/// necessary information.
EVT RL78TargetLowering::getTypeForExtReturn(LLVMContext &Context, EVT VT,
                                            ISD::NodeType ExtendKind) const {
  MVT ReturnMVT = MVT::i16;
  if ((VT == MVT::i1) || (VT == MVT::i8))
    ReturnMVT = MVT::i8;

  EVT MinVT = getRegisterType(Context, ReturnMVT);
  return VT.bitsLT(MinVT) ? MinVT : VT;
}

/// Check whether the return values
/// described by the Outs array can fit into the return registers.  If false
/// is returned, an sret-demotion is performed.
SDValue
RL78TargetLowering::LowerReturn(SDValue Chain, CallingConv::ID CallConv,
                                bool IsVarArg,
                                const SmallVectorImpl<ISD::OutputArg> &Outs,
                                const SmallVectorImpl<SDValue> &OutVals,
                                const SDLoc &DL, SelectionDAG &DAG) const {

  MachineFunction &MF = DAG.getMachineFunction();

  // CCValAssign - represent the assignment of the return value to locations.
  SmallVector<CCValAssign, 16> RVLocs;
  // CCState - Info about the registers and stack slot.
  CCState CCInfo(CallConv, IsVarArg, DAG.getMachineFunction(), RVLocs,
                 *DAG.getContext());
  if (MF.getSubtarget<RL78Subtarget>().HasCCRLCallingConvention())
    AnalyzeCCRLReturnOperands(CCInfo, Outs);
  else
    CCInfo.AnalyzeReturn(Outs, RetCC_RL78_LLVM);

  // Chain.dump();
  // Copy the result values into the output registers.
  SDValue Flag;
  SmallVector<SDValue, 4> RetOps(1, Chain);
  for (unsigned i = 0, realRVLocIdx = 0, e = RVLocs.size(); i != e;
       ++i, ++realRVLocIdx) {
    CCValAssign &VA = RVLocs[i];
    assert(VA.isRegLoc() && "Can only return in registers!");
    SDValue Arg = OutVals[realRVLocIdx];
    // Arg.dump(&DAG);

    switch (VA.getLocInfo()) {
    default:
      // Loc info must be one of Full, SExt, ZExt, or AExt.
      llvm_unreachable("Unknown loc info!");
    case CCValAssign::Full:
      break;
    case CCValAssign::Trunc:
      Arg = DAG.getNode(ISD::TRUNCATE, DL, VA.getLocVT(), Arg);
      break;
    }

    Chain = DAG.getCopyToReg(Chain, DL, VA.getLocReg(), Arg, Flag);

    // Guarantee that all emitted copies are stuck together with flags.
    Flag = Chain.getValue(1);
    RetOps.push_back(DAG.getRegister(VA.getLocReg(), VA.getLocVT()));
  }

  RetOps[0] = Chain; // Update chain.

  // If the function has a StructRet.
  if (MF.getFunction().hasStructRetAttr()) {
    RL78MachineFunctionInfo *SFI = MF.getInfo<RL78MachineFunctionInfo>();
    unsigned Reg = SFI->getSRetReturnReg();
    if (!Reg)
      llvm_unreachable("sret virtual register not created in the entry block");
    auto PtrVT = getPointerTy(DAG.getDataLayout());
    if (PtrVT.getSizeInBits() == 16) {
      SDValue Val = DAG.getCopyFromReg(Chain, DL, Reg, PtrVT);
      Chain = DAG.getCopyToReg(Chain, DL, RL78::RP0, Val, Flag);
      Flag = Chain.getValue(1);
      RetOps.push_back(DAG.getRegister(RL78::RP0, PtrVT));
    }
    else {
      assert(PtrVT.getSizeInBits() == 32);
      unsigned SReg = SFI->getSRetReturnReg(1);
      if (!SReg)
        llvm_unreachable("sret virtual segment register not created in the entry block");

      // TODO: other calling convention(s)?
      assert(MF.getSubtarget<RL78Subtarget>().HasCCRLCallingConvention() && "ccrl only so far");

      SDValue Val = DAG.getCopyFromReg(Chain, DL, Reg, MVT::i16);
      auto Chain1 = DAG.getCopyToReg(Chain, DL, RL78::RP4, Val, Flag);
      Flag = Chain1.getValue(1);
      RetOps.push_back(DAG.getRegister(RL78::RP4, MVT::i16));

      SDValue SVal = DAG.getCopyFromReg(Chain, DL, SReg, MVT::i8);
      auto Chain2 = DAG.getCopyToReg(Chain, DL, RL78::R1, SVal, Flag);
      Flag = Chain2.getValue(1);
      RetOps.push_back(DAG.getRegister(RL78::R1, MVT::i8));
    }
  }

  // Add the flag if we have it.
  if (Flag.getNode())
    RetOps.push_back(Flag);

  // MF.getFunction().dump();
  if (MF.getFunction().hasFnAttribute("brk_interrupt"))
    return DAG.getNode(RL78ISD::RETB, DL, MVT::Other, RetOps);
  else if (MF.getFunction().hasFnAttribute("interrupt"))
    return DAG.getNode(RL78ISD::RETI, DL, MVT::Other, RetOps);
  else
    return DAG.getNode(RL78ISD::RET, DL, MVT::Other, RetOps);
}

bool RL78TargetLowering::CanLowerReturn(
    CallingConv::ID CallConv, MachineFunction &MF, bool isVarArg,
    const SmallVectorImpl<ISD::OutputArg> &Outs, LLVMContext &Context) const {
  // TODO for CCRL callconv only.
  uint64_t size = 0;
  for (auto arg : Outs)
    size += arg.VT.getSizeInBits();

  return size <= 32;
}

/// Lower the incoming (formal) arguments,
/// described by the Ins array, into the specified DAG. The implementation
/// should fill in the InVals array with legal-type argument values, and
/// return the resulting token chain value.
SDValue RL78TargetLowering::LowerFormalArguments(
    SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, const SDLoc &DL,
    SelectionDAG &DAG, SmallVectorImpl<SDValue> &InVals) const {
  MachineFunction &MF = DAG.getMachineFunction();
  MachineFrameInfo &MFI = MF.getFrameInfo();

  // Assign locations to all of the incoming arguments.
  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, IsVarArg, DAG.getMachineFunction(), ArgLocs,
                 *DAG.getContext());
  if (MF.getSubtarget<RL78Subtarget>().HasCCRLCallingConvention())
    AnalyzeCCRLFormalOperands(CCInfo, Ins);
  else
    CCInfo.AnalyzeFormalArguments(Ins, CC_RL78_LLVM);

  unsigned InIdx = 0;
  for (unsigned i = 0, e = ArgLocs.size(); i != e; ++i, ++InIdx) {
    CCValAssign &VA = ArgLocs[i];

    if (VA.isRegLoc()) {
      SDValue Arg;
      if (VA.getLocVT() == MVT::i8) {
        if (VA.getValVT() == MVT::i16) {
          // Revert the truncation of the pointer.
          unsigned VReg =
              MF.getRegInfo().createVirtualRegister(&RL78::RL78RegRegClass);
          MF.getRegInfo().addLiveIn(VA.getLocReg(), VReg);
          Arg = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i8);
          Arg = DAG.getNode(ISD::ZERO_EXTEND, DL, VA.getValVT(), Arg);
        } else {
          unsigned VReg =
              MF.getRegInfo().createVirtualRegister(&RL78::RL78RegRegClass);
          MF.getRegInfo().addLiveIn(VA.getLocReg(), VReg);
          Arg = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i8);
        }
      } else if (VA.getLocVT() == MVT::i16) {
        unsigned VReg =
            MF.getRegInfo().createVirtualRegister(&RL78::RL78RPRegsRegClass);
        MF.getRegInfo().addLiveIn(VA.getLocReg(), VReg);
        Arg = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i16);
      } else if (VA.getLocVT() == MVT::i32) {
        unsigned VReg =
            MF.getRegInfo().createVirtualRegister(&RL78::RL78RPRegsRegClass);
        MF.getRegInfo().addLiveIn(VA.getLocReg(), VReg);
        SDValue HiPart = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i16);
        Arg = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i16);
      } else {
        llvm_unreachable("Not implemented!");
      }
      InVals.push_back(Arg);
      continue;
    }
    assert(VA.isMemLoc());

    int StackLocation = -4 - VA.getLocMemOffset();

    int FI = MFI.CreateFixedObject(2, StackLocation, true);
    SDValue FIN = DAG.getFrameIndex(FI, MVT::i16);
    InVals.push_back(
        DAG.getLoad(VA.getValVT(), DL, Chain, FIN, MachinePointerInfo()));
  }

  if (MF.getFunction().hasStructRetAttr()) {
    // Copy the SRet Argument to SRetReturnReg.
    RL78MachineFunctionInfo *SFI = MF.getInfo<RL78MachineFunctionInfo>();
    const auto mfar_data = DAG.getDataLayout().getPointerSizeInBits() == 32;
    unsigned Reg = SFI->getSRetReturnReg(), SReg = 0;
    if (!Reg) {
      Reg = MF.getRegInfo().createVirtualRegister(&RL78::RL78RPRegsRegClass);
      SFI->setSRetReturnReg(Reg);
      if (mfar_data) {
        SReg = MF.getRegInfo().createVirtualRegister(&RL78::RL78RegRegClass);
        SFI->setSRetReturnReg(SReg, 1);
      }
    }
    SDValue Copy = DAG.getCopyToReg(DAG.getEntryNode(), DL, Reg, InVals[0]);
    if (mfar_data) {
      Copy = DAG.getCopyToReg(
          Copy, DL, SReg, DAG.getNode(ISD::TRUNCATE, DL, MVT::i8, InVals[1]));
    }
    Chain = DAG.getNode(ISD::TokenFactor, DL, MVT::Other, Copy, Chain);
  }
  // If the function takes variable number of arguments, make a frame index for
  // the start of the first vararg value... for expansion of llvm.va_start.
  if (IsVarArg) {
    // static const MCPhysReg ArgRegs[] = { RL78::RP0, RL78::RP2, RL78::RP4 };
    // unsigned NumAllocated = CCInfo.getFirstUnallocated(ArgRegs);
    // const MCPhysReg *CurArgReg = ArgRegs + NumAllocated,
    //                *ArgRegEnd = ArgRegs + 3;
    // int StackOffset = CCInfo.getNextStackOffset() + 4;
    // unsigned StackSize = MF.getFrameInfo().getStackSize();
    RL78MachineFunctionInfo *RL78MFI = MF.getInfo<RL78MachineFunctionInfo>();
    int FI =
        MFI.CreateFixedObject(2, -4 - (int)CCInfo.getStackSize(), true);
    RL78MFI->setVarArgsFrameOffset(FI);
    // std::vector<SDValue> OutChains;
    //   //MF.getFrameInfo().getStackSize();
    // for (; CurArgReg != ArgRegEnd; ++CurArgReg) {
    //  unsigned VReg =
    //  MF.getRegInfo().createVirtualRegister(&RL78::RL78RPRegsRegClass);
    //     MF.getRegInfo().addLiveIn(*CurArgReg, VReg);
    //     SDValue Arg = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i16);
    //     StackOffset -= 2;
    //     int FI = MFI.CreateFixedObject(2, StackOffset, true);
    //     SDValue FIN = DAG.getFrameIndex(FI, MVT::i16);
    //     OutChains.push_back(
    //         DAG.getStore(DAG.getRoot(), DL, Arg, FIN, MachinePointerInfo()));
    //}

    ////MF.getFrameInfo().setStackSize(MF.getFrameInfo().getStackSize() +
    /// StackOffset);

    // if (!OutChains.empty()) {
    //     OutChains.push_back(Chain);
    //     Chain = DAG.getNode(ISD::TokenFactor, DL, MVT::Other, OutChains);
    //   }
  }
  // Chain.dump();
  return Chain;
}

static bool TraverseMergeValues(SDValue RootNode, SDValue &LoadAddr) {
  if (RootNode.getOpcode() == ISD::MERGE_VALUES && RootNode.getResNo() != 0)
    return false;

  unsigned int StepSize;

  if (RootNode.getValueType() == MVT::i8)
    StepSize = 1;
  else if (RootNode.getValueType() == MVT::i16)
    StepSize = 2;
  else
    return false;

  // loadAddr = BaseAddr + BaseAddrStartingOffset
  LoadAddr = RootNode;
  while (LoadAddr.getOpcode() == ISD::MERGE_VALUES)
    LoadAddr = LoadAddr.getOperand(0);
  if (LoadAddr.getOpcode() != ISD::LOAD) {
    return false;
  } else {
    LoadAddr = LoadAddr.getOperand(1);
  }

  SDValue BaseAddr = LoadAddr;
  unsigned int BaseAddrStartingOffset = 0;

  if (LoadAddr.getOpcode() == ISD::ADD) {
    BaseAddr = LoadAddr.getOperand(0);
    if (LoadAddr.getOperand(1).getOpcode() != ISD::Constant)
      return false;
    else
      BaseAddrStartingOffset = LoadAddr.getConstantOperandVal(1);
  }

  // We now have to check for memory continuity:
  // We are checking that the loads of the merged values are located
  // in memory continously, with the correct step size.
  for (size_t i = RootNode.getNumOperands() - 1; i > 0; i--) {
    SDValue CurrentLoad = RootNode.getOperand(i);
    while (CurrentLoad.getOpcode() == ISD::MERGE_VALUES)
      CurrentLoad = CurrentLoad.getOperand(i);
    if (CurrentLoad.getOpcode() != ISD::LOAD)
      return false;
    if (CurrentLoad.getOperand(1).getOpcode() != ISD::ADD)
      return false;
    if (CurrentLoad.getOperand(1).getOperand(1).getOpcode() != ISD::Constant)
      return false;
    unsigned int CurrentOffset =
        CurrentLoad.getOperand(1).getConstantOperandVal(1);
    SDValue CurrentBaseAddr = CurrentLoad.getOperand(1).getOperand(0);

    // Walk the possible ADD chains.
    // We can have ADD baseAddr, Constant or
    // ADD temp1, Constant where temp1 was an ADD baseAddr, Constant.
    while (CurrentBaseAddr != BaseAddr &&
           CurrentBaseAddr.getOpcode() == ISD::ADD) {
      if (CurrentBaseAddr.getOperand(1).getOpcode() != ISD::Constant)
        return false;
      CurrentOffset += CurrentBaseAddr.getConstantOperandVal(1);
      CurrentBaseAddr = CurrentBaseAddr.getOperand(0);
    }
    if (CurrentBaseAddr != BaseAddr ||
        CurrentOffset != (i * StepSize + BaseAddrStartingOffset))
      return false;
  }

  return true;
}

static bool correctSubRegForMerge(unsigned high, unsigned low) { 
  if (high == RL78::R0)
    return low == RL78::R1;
  else if (high == RL78::R3)
    return low == RL78::R2;
  else if (high == RL78::R5)
    return low == RL78::R4;
  return false;
}

static unsigned getMergeRegFromSubRegs(unsigned high) {
  switch (high) {
  case RL78::R0:
    return RL78::RP0;
  case RL78::R3:
    return RL78::RP2;
  case RL78::R5:
    return RL78::RP4;
  default:
    llvm_unreachable("Invalid reg used for call!");
  }
}

/// Lower calls into the specified
/// DAG. The outgoing arguments to the call are described by the Outs array,
/// and the values to be returned by the call are described by the Ins
/// array. The implementation should fill in the InVals array with legal-type
/// return values from the call, and return the resulting token chain value.
SDValue RL78TargetLowering::LowerCall(TargetLowering::CallLoweringInfo &CLI,
                                      SmallVectorImpl<SDValue> &InVals) const {
  SelectionDAG &DAG = CLI.DAG;
  SDLoc &dl = CLI.DL;
  SmallVectorImpl<ISD::OutputArg> &Outs = CLI.Outs;
  SmallVectorImpl<SDValue> &OutVals = CLI.OutVals;
  SmallVectorImpl<ISD::InputArg> &Ins = CLI.Ins;
  SDValue Chain = CLI.Chain;
  SDValue Callee = CLI.Callee;
  bool &isTailCall = CLI.IsTailCall;
  CallingConv::ID CallConv = CLI.CallConv;
  bool isVarArg = CLI.IsVarArg;
  MachineFunction &MF = DAG.getMachineFunction();

  // Analyze operands of the call, assigning locations to each operand.
  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), ArgLocs,
                 *DAG.getContext());
  if (MF.getSubtarget<RL78Subtarget>().HasCCRLCallingConvention())
    AnalyzeCCRLCallOperands(CCInfo, Outs);
  else
    CCInfo.AnalyzeCallOperands(Outs, CC_RL78_LLVM);

  bool hasFP = MF.getSubtarget<RL78Subtarget>().getFrameLowering()->hasFP(MF);

  // Get the size of the outgoing arguments stack space requirement.
  unsigned ArgsSize = CCInfo.getStackSize();

  if (ArgsSize & 1)
    ArgsSize++;

  // Consider the saved FP as the last argument.
  if (hasFP)
    ArgsSize += 2;

  // Keep stack frames 2-byte aligned.
  // ArgsSize = (ArgsSize + 7) & ~3;
  // ArgsSize &= ~3;

  MachineFrameInfo &MFI = DAG.getMachineFunction().getFrameInfo();

  SmallVector<std::pair<unsigned, SDValue>, 16> RegsToPass;
  SmallVector<SDValue, 8> MemOpChains;

  // Keep the stack addresses near, even if -mfar-data
  auto StackAS = DAG.getDataLayout().getAllocaAddrSpace();
  auto FIPtrTy = getPointerTy(DAG.getDataLayout(), StackAS);

  // Create local copies for byval args.
  SmallVector<SDValue, 8> ByValArgs;
  for (unsigned i = 0, e = Outs.size(); i != e; ++i) {
    ISD::ArgFlagsTy Flags = Outs[i].Flags;
    if (!Flags.isByVal())
      continue;

    SDValue Arg = OutVals[i];
    // Arg.dump(&DAG);
    unsigned Size = Flags.getByValSize();
    Align align = Flags.getNonZeroByValAlign();
    // Size == 0 can be reproduced with pr23135.c from gcc c-torture.
    if (Size > 0U) {
      int FI = MFI.CreateStackObject(Size, align, false);
      SDValue FIPtr = DAG.getFrameIndex(FI, FIPtrTy);
      SDValue SizeNode = DAG.getConstant(Size, dl, MVT::i16);
      Chain = DAG.getMemcpy(Chain, dl, FIPtr, Arg, SizeNode, align,
                            false,       // isVolatile,
                            (Size <= 2), // AlwaysInline if size <= 2,
                            false,       // isTailCall
                            MachinePointerInfo(StackAS), MachinePointerInfo(StackAS));
      ByValArgs.push_back(FIPtr);
    } else {
      SDValue nullVal;
      ByValArgs.push_back(nullVal);
    }
  }

  // Increments depending on the number of registers from the calling conv
  // we will increment with 1 for i8 register and with 2 for an i16 register.
  int noImplicitNotDeadRegs = 0;

  // We want to keep track if we are using ax or a and x separatelly
  // if noImplicitNotDeadRegs >=5 is safe to assume that both r0 and r1 are in
  // use We choose to save R0/R1 instead of always using RP0 (also using RP0
  // when an 8 bit value is present) because saving R0/R1 will cost 1 execution
  // cycle less 0 if none of the registers R0, R1 or RP0 are used 1 if R0 is
  // used and not R1 2 if R1 is used and not R0 3 if R0 and R1 are used 4 if RP0
  // is used.
  unsigned int usesR0andorR1 = 0;

  for (unsigned i = 0, e = ArgLocs.size(); i != e; ++i) {
    CCValAssign &VA = ArgLocs[i];
    if (VA.isRegLoc()) {
      unsigned Reg = VA.getLocReg();
      if (Reg == RL78::R0 || Reg == RL78::R1 || Reg == RL78::R2 ||
          Reg == RL78::R3 || Reg == RL78::R4 || Reg == RL78::R5) {
        noImplicitNotDeadRegs = noImplicitNotDeadRegs + 1;
        if (Reg == RL78::R0)
          usesR0andorR1 = usesR0andorR1 + 1; // 1 if R0 is used and not R1.
        if (Reg == RL78::R1)
          usesR0andorR1 = usesR0andorR1 + 2; // 2 if R1 is used and not R0.
        // usesR0andorR1 is 3 if R0 and R1 are used.
      } else if (Reg == RL78::RP0 || Reg == RL78::RP2 || Reg == RL78::RP4) {
        noImplicitNotDeadRegs = noImplicitNotDeadRegs + 2;
        if (Reg == RL78::RP0)
          usesR0andorR1 = 4; // 4 if RP0 is used.
      }
    }
  }

  // Checking if we will run out of registers in case of call_rp and no register
  // left for the call.
  bool willRunOutOfRegs = !dyn_cast<ExternalSymbolSDNode>(Callee) &&
                          !dyn_cast<GlobalAddressSDNode>(Callee) && hasFP &&
                          noImplicitNotDeadRegs >= 5;

  if (willRunOutOfRegs)
    ArgsSize += 4;

  Chain = DAG.getCALLSEQ_START(Chain, ArgsSize, 0, dl);

  bool isMemLoc = false;
  // Walk the register / memloc assignments, inserting copies / loads.
  int fpOffset = 0;
  for (unsigned i = 0, byvalArgIdx = 0, e = ArgLocs.size(); i < e; ++i) {
    CCValAssign &VA = ArgLocs[i];
    SDValue Arg = OutVals[i];
    ISD::ArgFlagsTy Flags = Outs[i].Flags;

    // Use local copy if it is a byval arg.
    if (Flags.isByVal()) {
      Arg = ByValArgs[byvalArgIdx++];
      if (!Arg) {
        continue;
      }
    }

    // Promote the value if needed.
    switch (VA.getLocInfo()) {
    default:
      // Loc info must be one of Full, SExt, ZExt, or AExt.
      llvm_unreachable("Unknown loc info!");
    case CCValAssign::Full:
      break;
    case CCValAssign::Trunc:
      Arg = DAG.getNode(ISD::TRUNCATE, dl, VA.getLocVT(), Arg);
      break;
    case CCValAssign::BCvt:
      Arg = DAG.getNode(ISD::BITCAST, dl, VA.getLocVT(), Arg);
      break;
    case CCValAssign::SExt:
      Arg = DAG.getNode(ISD::SIGN_EXTEND, dl, VA.getLocVT(), Arg);
      break;
    case CCValAssign::ZExt:
      Arg = DAG.getNode(ISD::ZERO_EXTEND, dl, VA.getLocVT(), Arg);
      break;
    case CCValAssign::AExt:
      Arg = DAG.getNode(ISD::ANY_EXTEND, dl, VA.getLocVT(), Arg);
      break;
    }

    // Arguments that can be passed on register must be kept at RegsToPass
    // vector.
    if (VA.isRegLoc()) {
      RegsToPass.push_back(std::make_pair(VA.getLocReg(), Arg));
    } else if (VA.isMemLoc()) {
      isMemLoc = true;
      unsigned int MaxStores = DAG.shouldOptForSize()
                                   ? MaxStoresPerMemcpyOptSize
                                   : MaxStoresPerMemcpy;
      SDValue LoadAddr;
      if (Arg.getNumOperands() > MaxStores &&
          TraverseMergeValues(Arg, LoadAddr)) {

        // we will use memcpy instead of individual stores for this argument
        unsigned PartNum = Arg->getNumValues();
        int Offset = VA.getLocMemOffset();
        unsigned Size = Arg.getValueSizeInBits() * PartNum / 8;
        int FI = MF.getFrameInfo().CreateFixedObject(Size, Offset, true);
        SDValue FIPtr = DAG.getFrameIndex(FI, FIPtrTy);
        SDValue SizeNode = DAG.getConstant(Size, dl, MVT::i16);
        SDValue MemCpyChain =
            DAG.getMemcpy(Chain, dl, FIPtr, LoadAddr, SizeNode, Align(2),
                          false, // isVolatile,
                          false, // AlwaysInline
                          false, // isTailCall
                          MachinePointerInfo(StackAS), MachinePointerInfo(StackAS));

        fpOffset = ArgLocs[i + PartNum - 1].getLocMemOffset() + 2;
        i += PartNum - 1;
        MemOpChains.push_back(MemCpyChain);
      } else {
        int Offset = VA.getLocMemOffset();
        fpOffset = Offset + 2;
        int FI = MF.getFrameInfo().CreateFixedObject(
            Arg.getValueSizeInBits() / 8, Offset, true);

        SDValue FIPtr = DAG.getFrameIndex(FI, FIPtrTy);
        MemOpChains.push_back(
            DAG.getStore(Chain, dl, Arg, FIPtr, MachinePointerInfo(StackAS)));
      }

      //// TODO if renesas extensions, promote near pointer to varg if it a
      /// va_arg
      // if (Flags.isPointer() && Flags.getPointerAddrSpace() == 0 &&
      //! Outs[i].IsFixed) {
      //  // Fill the stack slot with 0x000F for the promoted near pointer
      //  FI = MF.getFrameInfo().CreateFixedObject(2,  Offset + 2, true);
      //  SDValue FIPtr =
      //      DAG.getFrameIndex(FI, FIPtrTy);
      //  SDValue NearSegment =
      //      DAG.getConstant(0x000F, dl, MVT::i16);
      //  MemOpChains.push_back(
      //      DAG.getStore(Chain, dl, NearSegment, FIPtr,
      //      MachinePointerInfo()));
      //}
    }
  }

  if (!dyn_cast<GlobalAddressSDNode>(Callee) || isMemLoc)
    isTailCall = false;

  SDValue SavedFPFIPtr;
  SDValue SavedFP;
  // Save the FP, will be restored by CALL_FP.
  if (hasFP) {
    int FI;
    if (willRunOutOfRegs) {
      FI = MF.getFrameInfo().CreateFixedObject(2, fpOffset + 4, true);
    } else {
      FI = MF.getFrameInfo().CreateFixedObject(2, fpOffset, true);
    }
    SavedFPFIPtr = DAG.getFrameIndex(FI, FIPtrTy);
    SavedFP = SavedFPFIPtr;
    MemOpChains.push_back(DAG.getStore(Chain, dl,
                                       DAG.getRegister(RL78::RP6, MVT::i16),
                                       SavedFPFIPtr, MachinePointerInfo(StackAS)));
  }

  if (!MemOpChains.empty())
    Chain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other, MemOpChains);

  // Build a sequence of copy-to-reg nodes chained together with token chain and
  // flag operands which copy the outgoing args into registers.  The InFlag in
  // necessary since all emitted instructions must be stuck together.
  SDValue InFlag;

  // We need these variables in case willRunOutOfRegs is true.
  SDValue AxReg = DAG.getRegister(RL78::RP0, MVT::i16);
  SDValue AReg = DAG.getRegister(RL78::R1, MVT::i8);
  SDValue CSReg = DAG.getRegister(RL78::CS, MVT::i8);
  SDValue HlReg = DAG.getRegister(RL78::RP6, MVT::i16);
  SDValue SavedAxFIPtr;

  if (willRunOutOfRegs) {
    if (Callee.getValueType() == MVT::i32) {
      SDValue Low = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16, Callee,
                                DAG.getConstant(0, dl, MVT::i16));
      SDValue High = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16, Callee,
                                 DAG.getConstant(1, dl, MVT::i16));
      SDValue Segment = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i8, High,
                                    DAG.getConstant(0, dl, MVT::i8));
      Chain = DAG.getCopyToReg(Chain, dl, AReg, Segment, InFlag);
      Chain = DAG.getCopyToReg(Chain, dl, CSReg, AReg, InFlag);
      Chain = DAG.getCopyToReg(Chain, dl, AxReg, Low, InFlag);
    } else {
      Chain = DAG.getCopyToReg(Chain, dl, AxReg, Callee, InFlag);
    }

    // Put ax on stack.
    int FI = MF.getFrameInfo().CreateFixedObject(2, fpOffset, true);
    SavedFPFIPtr = DAG.getFrameIndex(FI, FIPtrTy);
    Chain = DAG.getStore(Chain, dl, AxReg, SavedFPFIPtr,
                         MachinePointerInfo(StackAS));
  }

  // We do this backwards because R1/RP0 it's more optimal.
  for (int i = RegsToPass.size() - 1; i >= 0; --i) {
    if ((i > 0) &&
      (RegsToPass[i].second.getOpcode() == ISD::Constant) &&
      (RegsToPass[i].second.getValueType() == MVT::i8) &&
      (RegsToPass[i - 1].second.getOpcode() == ISD::Constant) &&
      (RegsToPass[i - 1].second.getValueType() == MVT::i8) &&
      correctSubRegForMerge(RegsToPass[i].first, RegsToPass[i - 1].first)) {
      unsigned Reg = getMergeRegFromSubRegs(RegsToPass[i].first);
      uint64_t high =
          cast<ConstantSDNode>(RegsToPass[i].second)->getZExtValue();
      uint64_t low =
          cast<ConstantSDNode>(RegsToPass[i - 1].second)->getZExtValue();
      uint64_t highLow = (RegsToPass[i].first == RL78::R0) ? (low << 8) | high
                                                           : (high << 8) | low;
      SDValue mergedConst = DAG.getConstant(highLow, dl, MVT::i16);
      Chain = DAG.getCopyToReg(Chain, dl, Reg, mergedConst, InFlag);
      InFlag = Chain.getValue(1);
      --i;
    } else {
      unsigned Reg = RegsToPass[i].first;
      Chain = DAG.getCopyToReg(Chain, dl, Reg, RegsToPass[i].second, InFlag);
      InFlag = Chain.getValue(1);
    }
  }

  if (willRunOutOfRegs) {

    switch (usesR0andorR1) {
    case 3:
    case 4: {
      int FI = MF.getFrameInfo().CreateFixedObject(2, fpOffset + 2, true);
      SavedAxFIPtr = DAG.getFrameIndex(FI, FIPtrTy);
      Chain = DAG.getStore(Chain, dl, AxReg, SavedAxFIPtr,
                           MachinePointerInfo(StackAS));
      break;
    }
    case 1: {
      int FI = MF.getFrameInfo().CreateFixedObject(2, fpOffset + 2, true);
      SavedAxFIPtr = DAG.getFrameIndex(FI, FIPtrTy);
      Chain = DAG.getStore(Chain, dl, DAG.getRegister(RL78::R0, MVT::i8),
                           SavedAxFIPtr, MachinePointerInfo(StackAS));
    }
    case 2: {
      int FI = MF.getFrameInfo().CreateFixedObject(2, fpOffset + 2, true);
      SavedAxFIPtr = DAG.getFrameIndex(FI, FIPtrTy);
      Chain = DAG.getStore(Chain, dl, DAG.getRegister(RL78::R1, MVT::i8),
                           SavedAxFIPtr, MachinePointerInfo(StackAS));
      break;
    }
    default:
      llvm_unreachable("R0 or R1 are not used.");
      break;
    }
  }

  bool IsCallt = false;
  bool IsFarFunction = false;
  // If the callee is a GlobalAddress node (quite common, every direct call is)
  // turn it into a TargetGlobalAddress node so that legalize doesn't hack it.
  // Likewise ExternalSymbol -> TargetExternalSymbol.
  if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee)) {
    if (const Function *F = dyn_cast<Function>(G->getGlobal())) {
      IsFarFunction = F->getAddressSpace() == RL78AS::FarCode;
      IsCallt = F->hasFnAttribute("callt");
    }
    if (IsFarFunction)
      Callee = DAG.getTargetGlobalAddress(G->getGlobal(), SDLoc(G), MVT::i32,
                                          G->getOffset());
    else
      Callee =
          DAG.getTargetGlobalAddress(G->getGlobal(), SDLoc(G), MVT::i16,
                                     G->getOffset(), RL78MCExpr::VK_RL78_None);
  }
  // else if (ExternalSymbolSDNode *E = dyn_cast<ExternalSymbolSDNode>(Callee))
  //    Callee = DAG.getTargetExternalSymbol(E->getSymbol(), MVT::i16);

  // Callee.dump();
  // if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee)) {
  //  G->getGlobal()->getAlignment();
  //}

  if (willRunOutOfRegs) {

    Chain = DAG.getLoad(MVT::i16, dl, Chain.getValue(0), SavedFPFIPtr,
                        MachinePointerInfo());
    InFlag = Chain.getValue(1);
    Chain = DAG.getCopyToReg(Chain, dl, HlReg, Chain.getValue(0), InFlag);
    InFlag = Chain.getValue(1);

    switch (usesR0andorR1) {
    case 3:
    case 4: {
      Chain =
          DAG.getLoad(MVT::i16, dl, Chain, SavedAxFIPtr, MachinePointerInfo());
      InFlag = Chain.getValue(1);

      Chain = DAG.getCopyToReg(Chain, dl, AxReg, Chain.getValue(0), InFlag);
      InFlag = Chain.getValue(1);
      break;
    }
    case 1: {
      Chain =
          DAG.getLoad(MVT::i8, dl, Chain, SavedAxFIPtr, MachinePointerInfo());
      InFlag = Chain.getValue(1);

      Chain = DAG.getCopyToReg(Chain, dl, DAG.getRegister(RL78::R0, MVT::i8),
                               Chain.getValue(0), InFlag);
      InFlag = Chain.getValue(1);
      break;
    }
    case 2: {
      Chain =
          DAG.getLoad(MVT::i8, dl, Chain, SavedAxFIPtr, MachinePointerInfo());
      InFlag = Chain.getValue(1);

      Chain = DAG.getCopyToReg(Chain, dl, DAG.getRegister(RL78::R1, MVT::i8),
                               Chain.getValue(0), InFlag);
      InFlag = Chain.getValue(1);
      break;
    }
    default:
      llvm_unreachable("R0 or R1 are not used.");
      break;
    }

    Callee = HlReg.getValue(0);
  }

  // Returns a chain & a flag for retval copy to use.
  SDVTList NodeTys = DAG.getVTList(MVT::Other, MVT::Glue);
  SmallVector<SDValue, 8> Ops;
  Ops.push_back(Chain);
  Ops.push_back(Callee);
  if (hasFP)
    Ops.push_back(SavedFP);

  for (unsigned i = 0, e = RegsToPass.size(); i != e; ++i)
    Ops.push_back(DAG.getRegister(RegsToPass[i].first,
                                  RegsToPass[i].second.getValueType()));

  const uint32_t *Mask =
      MF.getSubtarget<RL78Subtarget>().getRegisterInfo()->getCallPreservedMask(
          MF, CallConv);
  Ops.push_back(DAG.getRegisterMask(Mask));

  if (InFlag.getNode())
    Ops.push_back(InFlag);

  if (IsCallt)
    Chain = DAG.getNode(RL78ISD::CALLT, dl, NodeTys, Ops);
  // After the call the FP is invalid and the reg alloc can insert a load from
  // stack, see: SingleSource\BenchMarks\BenchMarkGame\spectral-norm.c.
  else if (hasFP)
    Chain = DAG.getNode(RL78ISD::CALL_FP, dl, NodeTys, Ops);
  else if (isTailCall)
    Chain = DAG.getNode(RL78ISD::TAIL_CALL, dl, NodeTys, Ops);
  else
    Chain = DAG.getNode(RL78ISD::CALL, dl, NodeTys, Ops);
  InFlag = Chain.getValue(1);

  unsigned AS = DAG.getDataLayout().getAllocaAddrSpace();
  Chain = DAG.getCALLSEQ_END(Chain, DAG.getIntPtrConstant(ArgsSize, dl, true, AS),
                             DAG.getIntPtrConstant(0, dl, true, AS), InFlag, dl);
  InFlag = Chain.getValue(1);

  // Assign locations to each value returned by this call.
  SmallVector<CCValAssign, 16> RVLocs;
  CCState RVInfo(CallConv, isVarArg, DAG.getMachineFunction(), RVLocs,
                 *DAG.getContext());

  if (MF.getSubtarget<RL78Subtarget>().HasCCRLCallingConvention()) {
    AnalyzeCCRLReturnOperands(RVInfo, Ins);
  } else {
    RVInfo.AnalyzeCallResult(Ins, RetCC_RL78_LLVM);
  }

  if (!isTailCall) {
    // Copy all of the result registers out of their specified physreg.
    for (unsigned i = 0, e = RVLocs.size(); i != e; ++i) {
      Chain = DAG.getCopyFromReg(Chain, dl, RVLocs[i].getLocReg(),
                                 RVLocs[i].getLocVT(), InFlag)
                  .getValue(1);
      SDValue returnVal = Chain.getValue(0);
      switch (RVLocs[i].getLocInfo()) {
      default:
        llvm_unreachable("Unknown loc info!");
      case CCValAssign::Full:
        InFlag = Chain.getValue(2);
        InVals.push_back(returnVal);
        break;
      case CCValAssign::Trunc:
        SDVTList NodeTys = DAG.getVTList(RVLocs[i].getValVT(), MVT::Other);
        SDValue extended =
            DAG.getNode(ISD::ANY_EXTEND, dl, NodeTys, returnVal, InFlag);
        returnVal = extended.getValue(0);
        InFlag = extended.getValue(1);
        InVals.push_back(returnVal);
        break;
      }
    }
  }

  // DAG.dump();
  return Chain;
}

// Group arguments that were split by LLVM to legal types,
// since according to the CC-RL ABI, variables can't be
// split between registers and the stack when passing them.
template <typename T>
static void GroupArgumentParts(std::vector<std::vector<T>> &args,
                               const SmallVectorImpl<T> &Outs) {
  size_t partCount = Outs.size();
  if (partCount == 0)
    return;

  size_t argCount = 0;
  unsigned int currentOrigArgIndex = Outs[0].OrigArgIndex;
  args.push_back({Outs[0]});

  for (size_t i = 1; i < partCount; i++) {
    if (Outs[i].OrigArgIndex >= currentOrigArgIndex + 1) {
      args.push_back({});
      currentOrigArgIndex = Outs[i].OrigArgIndex;
      argCount++;
    }
    args[argCount].push_back(Outs[i]);
  }
}

static bool allocate3(unsigned R1, unsigned R2, unsigned R3, unsigned ValNo,
                      MVT ValVT, MVT LocVT, CCValAssign::LocInfo LocInfo,
                      CCState &State) {
  bool canAllocate = !State.isAllocated(R1) && !State.isAllocated(R2) &&
                     !State.isAllocated(R3);
  if (canAllocate) {
    State.AllocateReg(R1);
    State.AllocateReg(R2);
    State.AllocateReg(R3);
    State.addLoc(CCValAssign::getReg(ValNo, ValVT, R3, LocVT, LocInfo));
    State.addLoc(CCValAssign::getReg(ValNo + 1, ValVT, R2, LocVT, LocInfo));
    State.addLoc(CCValAssign::getReg(ValNo + 2, ValVT, R1, LocVT, LocInfo));
  }
  return canAllocate;
}

static bool allocateAddr20(unsigned R, unsigned RP, unsigned ValNo, MVT ValVT,
                           CCState &State) {
  bool canAllocate = !State.isAllocated(R) && !State.isAllocated(RP);

  if (canAllocate) {
    State.AllocateReg(R);
    State.AllocateReg(RP);
    State.addLoc(
        CCValAssign::getReg(ValNo + 1, ValVT, RP, ValVT, CCValAssign::Full));
    State.addLoc(
        CCValAssign::getReg(ValNo, ValVT, R, MVT::i8, CCValAssign::Trunc));
  }
  return canAllocate;
}

static const std::vector<MCPhysReg> I8RegList = {RL78::R1, RL78::R0, RL78::R2,
                                                 RL78::R3, RL78::R4, RL78::R5};

static const std::vector<MCPhysReg> I16RegList = {RL78::RP0, RL78::RP2,
                                                  RL78::RP4};

static void AllocateFarPointer(unsigned ValNo, MVT ValVT, CCState &State,
                               unsigned int partCount, bool isReturn = false,
                               bool isVarArg = false) {
  assert(ValVT == MVT::i16 && partCount == 2);

  // Allocate to A-DE, X-DE, C-DE, B-DE, X-BC.

  if (!isVarArg && allocateAddr20(RL78::R1, RL78::RP4, ValNo, ValVT, State))
    return;

  if (isReturn)
    llvm_unreachable("Unable to return far pointer, A-DE already allocated!");

  if (!isVarArg && allocateAddr20(RL78::R0, RL78::RP4, ValNo, ValVT, State))
    return;
  if (!isVarArg && allocateAddr20(RL78::R2, RL78::RP4, ValNo, ValVT, State))
    return;
  if (!isVarArg && allocateAddr20(RL78::R3, RL78::RP4, ValNo, ValVT, State))
    return;
  if (!isVarArg && allocateAddr20(RL78::R0, RL78::RP2, ValNo, ValVT, State))
    return;

  // If we didn't manage to allocate so far, put it on the stack.
  for (size_t i = 0; i < partCount; i++) {
    unsigned size = 2;
    unsigned align = 2;
    unsigned Offset = State.AllocateStack(size, Align(align));
    State.addLoc(CCValAssign::getMem(ValNo + i, ValVT, Offset, ValVT,
                                     CCValAssign::Full));
  }
}

static void AllocateMultiPartArgument(unsigned ValNo, MVT ValVT, MVT LocVT,
                                      CCValAssign::LocInfo LocInfo,
                                      ISD::ArgFlagsTy ArgFlags, CCState &State,
                                      unsigned int partCount,
                                      bool isVarArg = false) {

  // Handle far pointers.
  if (ArgFlags.isPointer() &&
      (ArgFlags.getPointerAddrSpace() == RL78AS::FarData ||
       ArgFlags.getPointerAddrSpace() == RL78AS::FarCode ||
       (ArgFlags.getPointerAddrSpace() == RL78AS::Default && partCount == 2))) {
    AllocateFarPointer(ValNo, ValVT, State, partCount, false, isVarArg);
    return;
  }

  //// TODO if renesas extensions, promote near pointer to varg if it a va_arg
  //// promote near pointer when using varg
  // if (ArgFlags.isPointer() && ArgFlags.getPointerAddrSpace() == 0 &&
  // isVarArg) {
  //  unsigned Offset = State.AllocateStack(2, 2);
  //  State.addLoc(CCValAssign::getMem(ValNo, ValVT, Offset, LocVT, LocInfo));
  //  Offset = State.AllocateStack(2, 2); // reserve space for 0x000F
  //  return;
  //}

  // R0-X, R1=A, R2=C, R3=B, R4=E, R5=D
  if (LocVT == MVT::i8 && !isVarArg) {
    unsigned Reg = RL78::NoRegister;
    if ((partCount == 1) && (Reg = State.AllocateReg(I8RegList))) {
      // Allocate to A, X, C, B, E, D.
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return;
    }
    if (partCount == 2) {
      // Allocate to AX, BC, DE.
      if (!State.isAllocated(RL78::RP0)) {
        State.AllocateReg(RL78::RP0);
        State.addLoc(
            CCValAssign::getReg(ValNo, ValVT, RL78::R0, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 1, ValVT, RL78::R1, LocVT, LocInfo));
        return;
      }
      if (!State.isAllocated(RL78::RP2)) {
        State.AllocateReg(RL78::RP2);
        State.addLoc(
            CCValAssign::getReg(ValNo, ValVT, RL78::R2, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 1, ValVT, RL78::R3, LocVT, LocInfo));
        return;
      }
      if (!State.isAllocated(RL78::RP4)) {
        State.AllocateReg(RL78::RP4);
        State.addLoc(
            CCValAssign::getReg(ValNo, ValVT, RL78::R4, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 1, ValVT, RL78::R5, LocVT, LocInfo));
        return;
      }
    }
    if (partCount == 3) {
      // Allocate to C-AX, X-BC, E-BC, X-DE, B-DE.
      if (allocate3(RL78::R2, RL78::R1, RL78::R0, ValNo, ValVT, LocVT, LocInfo,
                    State))
        return;
      if (allocate3(RL78::R0, RL78::R3, RL78::R2, ValNo, ValVT, LocVT, LocInfo,
                    State))
        return;
      if (allocate3(RL78::R4, RL78::R3, RL78::R2, ValNo, ValVT, LocVT, LocInfo,
                    State))
        return;
      if (allocate3(RL78::R0, RL78::R5, RL78::R4, ValNo, ValVT, LocVT, LocInfo,
                    State))
        return;
      if (allocate3(RL78::R3, RL78::R5, RL78::R4, ValNo, ValVT, LocVT, LocInfo,
                    State))
        return;
    }

    if (partCount == 4) {
      // Allocate BC-AX, DE-BC.
      if (!State.isAllocated(RL78::RP2) && !State.isAllocated(RL78::RP0)) {
        State.AllocateReg(RL78::RP2);
        State.AllocateReg(RL78::RP0);
        State.addLoc(
            CCValAssign::getReg(ValNo, ValVT, RL78::R0, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 1, ValVT, RL78::R1, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 2, ValVT, RL78::R2, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 3, ValVT, RL78::R3, LocVT, LocInfo));
        return;
      }
      if (!State.isAllocated(RL78::RP4) && !State.isAllocated(RL78::RP2)) {
        State.AllocateReg(RL78::RP4);
        State.AllocateReg(RL78::RP2);
        State.addLoc(
            CCValAssign::getReg(ValNo, ValVT, RL78::R2, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 1, ValVT, RL78::R3, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 2, ValVT, RL78::R4, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 3, ValVT, RL78::R5, LocVT, LocInfo));
        return;
      }
    }
  }

  if (LocVT == MVT::i16 && !isVarArg) {

    unsigned Reg = RL78::NoRegister;
    if ((partCount == 1) && (Reg = State.AllocateReg(I16RegList))) {
      // Allocate to AX, BC, DE.
      State.addLoc(CCValAssign::getReg(ValNo, ValVT, Reg, LocVT, LocInfo));
      return;
    }
    if (partCount == 2) {
      // Allocate BC-AX, DE-BC.
      if (!State.isAllocated(RL78::RP2) && !State.isAllocated(RL78::RP0)) {
        State.AllocateReg(RL78::RP2);
        State.AllocateReg(RL78::RP0);
        State.addLoc(
            CCValAssign::getReg(ValNo, ValVT, RL78::RP0, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 1, ValVT, RL78::RP2, LocVT, LocInfo));
        return;
      }
      if (!State.isAllocated(RL78::RP4) && !State.isAllocated(RL78::RP2)) {
        State.AllocateReg(RL78::RP4);
        State.AllocateReg(RL78::RP2);
        State.addLoc(
            CCValAssign::getReg(ValNo, ValVT, RL78::RP2, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(ValNo + 1, ValVT, RL78::RP4, LocVT, LocInfo));
        return;
      }
    }
  }

  // If we didn't manage to allocate so far, put it on the stack.
  for (size_t i = 0; i < partCount; i++) {
    unsigned size = LocVT == MVT::i8 ? 1 : 2;
    unsigned align = partCount == 1 ? 2 : size;
    unsigned Offset = State.AllocateStack(size, Align(align));
    State.addLoc(CCValAssign::getMem(ValNo + i, ValVT, Offset, LocVT, LocInfo));
  }
}

static void AllocateMultiPartReturn(MVT ValVT, MVT LocVT,
                                    CCValAssign::LocInfo LocInfo,
                                    ISD::ArgFlagsTy ArgFlags, CCState &State,
                                    unsigned int partCount) {

  // Handle far pointers.
  if (ArgFlags.isPointer() &&
      (ArgFlags.getPointerAddrSpace() == RL78AS::FarData ||
       ArgFlags.getPointerAddrSpace() == RL78AS::FarCode ||
       (ArgFlags.getPointerAddrSpace() == RL78AS::Default && partCount == 2))) {
    AllocateFarPointer(0, ValVT, State, partCount, true);
    return;
  }

  // Here the valno order doesn't matter that much, the addloc order is used
  // when building up the return chain.
  if (LocVT == MVT::i8) {
    unsigned Reg = RL78::NoRegister;
    if ((partCount == 1) && (Reg = State.AllocateReg(RL78::R1))) {
      // Allocate to A.
      State.addLoc(CCValAssign::getReg(0, ValVT, Reg, LocVT, LocInfo));
      return;
    }
    if (partCount == 2) {
      // Allocate to AX.
      if (!State.isAllocated(RL78::RP0)) {
        State.AllocateReg(RL78::RP0);
        State.addLoc(
            CCValAssign::getReg(1, ValVT, RL78::R1, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(0, ValVT, RL78::R0, LocVT, LocInfo));
        return;
      }
    }
    if (partCount == 3) {
      // Allocate to C-AX.
      if (allocate3(RL78::R2, RL78::R1, RL78::R0, 0, ValVT, LocVT, LocInfo,
                    State))
        return;
    }

    if (partCount == 4) {
      // Allocate BC-AX.
      if (!State.isAllocated(RL78::RP2) && !State.isAllocated(RL78::RP0)) {
        State.AllocateReg(RL78::RP2);
        State.AllocateReg(RL78::RP0);
        State.addLoc(
            CCValAssign::getReg(0, ValVT, RL78::R0, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(1, ValVT, RL78::R1, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(2, ValVT, RL78::R2, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(3, ValVT, RL78::R3, LocVT, LocInfo));
        return;
      }
    }
  }

  if (LocVT == MVT::i16) {

    unsigned Reg = RL78::NoRegister;
    if ((partCount == 1) && (Reg = State.AllocateReg(RL78::RP0))) {
      // Allocate to AX.
      State.addLoc(CCValAssign::getReg(0, ValVT, Reg, LocVT, LocInfo));
      return;
    }
    if (partCount == 2) {
      // Allocate BC-AX.
      if (!State.isAllocated(RL78::RP2) && !State.isAllocated(RL78::RP0)) {
        State.AllocateReg(RL78::RP2);
        State.AllocateReg(RL78::RP0);
        State.addLoc(
            CCValAssign::getReg(0, ValVT, RL78::RP0, LocVT, LocInfo));
        State.addLoc(
            CCValAssign::getReg(1, ValVT, RL78::RP2, LocVT, LocInfo));
        return;
      }
    }
  }

  llvm_unreachable("Unable to return type of this size!");
}

void RL78TargetLowering::AnalyzeCCRLCallOperands(
    CCState &State, const SmallVectorImpl<ISD::OutputArg> &Outs) const {
  std::vector<std::vector<ISD::OutputArg>> args;
  GroupArgumentParts(args, Outs);

  size_t opCounter = 0;
  for (size_t i = 0, e = args.size(); i != e; i++) {
    MVT ArgVT = args[i][0].VT;
    ISD::ArgFlagsTy ArgFlags = args[i][0].Flags;
    bool isVarArg = !args[i][0].IsFixed;
    AllocateMultiPartArgument(opCounter, ArgVT, ArgVT, CCValAssign::Full,
                              ArgFlags, State, args[i].size(), isVarArg);
    opCounter += args[i].size();
  }
}

void RL78TargetLowering::AnalyzeCCRLFormalOperands(
    CCState &State, const SmallVectorImpl<llvm::ISD::InputArg> &Ins) const {
  std::vector<std::vector<ISD::InputArg>> args;
  GroupArgumentParts(args, Ins);

  size_t opCounter = 0;
  for (size_t i = 0, e = args.size(); i != e; i++) {
    MVT ArgVT = args[i][0].VT;
    ISD::ArgFlagsTy ArgFlags = args[i][0].Flags;
    AllocateMultiPartArgument(opCounter, ArgVT, ArgVT, CCValAssign::Full,
                              ArgFlags, State, args[i].size());
    opCounter += args[i].size();
  }
}

template <typename T>
void RL78TargetLowering::AnalyzeCCRLReturnOperands(
    CCState &State, const SmallVectorImpl<T> &Ins) const {
  std::vector<T> ret;
  size_t partCount = Ins.size();
  if (partCount == 0)
    return;

  for (size_t i = 0; i < partCount; ++i)
    ret.push_back(Ins[i]);

  MVT ArgVT = ret[0].VT;
  ISD::ArgFlagsTy ArgFlags = ret[0].Flags;
  AllocateMultiPartReturn(ArgVT, ArgVT, CCValAssign::Full,
                          ArgFlags, State, ret.size());
}

// FIXME? Maybe this could be a TableGen attribute on some registers and
// this table could be generated automatically from RegInfo.
Register
RL78TargetLowering::getRegisterByName(const char *RegName, LLT VT,
                                      const MachineFunction &MF) const {
  Register Reg = StringSwitch<unsigned>(RegName)
                     .Case("R0", RL78::R0)
                     .Case("R1", RL78::R1)
                     .Case("R2", RL78::R2)
                     .Case("R3", RL78::R3)
                     .Case("R4", RL78::R4)
                     .Case("R5", RL78::R5)
                     .Case("R6", RL78::R6)
                     .Case("R7", RL78::R7)                     
                     .Default(0);

  if (Reg)
    return Reg;

  report_fatal_error("Invalid register name global variable");
}

//===----------------------------------------------------------------------===//
// TargetLowering Implementation
//===----------------------------------------------------------------------===//

/// IntCondCCodeToICC - Convert a DAG integer condition code to a RL78 ICC
/// condition.
static RL78CC::CondCodes IntCondCCodeToICC(ISD::CondCode CC) {
  switch (CC) {
  default:
    llvm_unreachable("Unknown integer condition code!");
  case ISD::SETEQ:
    return RL78CC::RL78CC_Z;
  case ISD::SETNE:
    return RL78CC::RL78CC_NZ;
  case ISD::SETLT:
    return RL78CC::RL78CC_C;
  case ISD::SETGT:
    return RL78CC::RL78CC_H;
  case ISD::SETLE:
    return RL78CC::RL78CC_NH;
  case ISD::SETGE:
    return RL78CC::RL78CC_NC;
  case ISD::SETULT:
    return RL78CC::RL78CC_C;
  case ISD::SETUGT:
    return RL78CC::RL78CC_H;
  case ISD::SETULE:
    return RL78CC::RL78CC_NH;
  case ISD::SETUGE:
    return RL78CC::RL78CC_NC;
  }
}

static RL78CC::CondCodes AdjustICCForOperandSwitch(RL78CC::CondCodes ICC) {
  switch (ICC) {
  default:
    llvm_unreachable("Unknown integer condition code!");
  case RL78CC::RL78CC_Z:
    return RL78CC::RL78CC_Z;
  case RL78CC::RL78CC_NZ:
    return RL78CC::RL78CC_NZ;
  case RL78CC::RL78CC_C:
    return RL78CC::RL78CC_H;
  case RL78CC::RL78CC_H:
    return RL78CC::RL78CC_C;
  case RL78CC::RL78CC_NH:
    return RL78CC::RL78CC_NC;
  case RL78CC::RL78CC_NC:
    return RL78CC::RL78CC_NH;
  }
}

static unsigned IntCondCCodeSign(ISD::CondCode CC) {
  switch (CC) {
  default:
    llvm_unreachable("Unknown integer condition code!");
  case ISD::SETEQ:
  case ISD::SETNE:
  case ISD::SETULT:
  case ISD::SETULE:
  case ISD::SETUGT:
  case ISD::SETUGE:
    return 0;
  case ISD::SETLT:
  case ISD::SETGT:
  case ISD::SETLE:
  case ISD::SETGE:
    return 1;
  }
}

// Condition result if LHS == RHS.
static bool CondResultLHSeqRHS(ISD::CondCode CC) {
  switch (CC) {
  default:
    llvm_unreachable("Unknown integer condition code!");
  case ISD::SETEQ:
  case ISD::SETULE:
  case ISD::SETUGE:
  case ISD::SETLE:
  case ISD::SETGE:
    return true;
  case ISD::SETNE:
  case ISD::SETULT:
  case ISD::SETUGT:
  case ISD::SETLT:
  case ISD::SETGT:
    return false;
  }
}

RL78TargetLowering::RL78TargetLowering(const TargetMachine &TM,
                                       const RL78Subtarget &STI)
    : TargetLowering(TM), Subtarget(&STI) {
  MVT PtrVT = MVT::getIntegerVT(8 * TM.getPointerSize(0));

  setBooleanContents(ZeroOrOneBooleanContent);

  // Set up the register classes.
  addRegisterClass(MVT::i8, &RL78::RL78RegRegClass);
  addRegisterClass(MVT::i16, &RL78::RL78RPRegsRegClass);

  // __far support.
  setOperationAction(ISD::BUILD_PAIR, MVT::i32, Custom);
  setOperationAction(ISD::ADDRSPACECAST, MVT::i16, Custom);
  setOperationAction(ISD::ADDRSPACECAST, MVT::i32, Custom);
  setOperationAction(ISD::FrameIndex, MVT::i32, Custom);
  setOperationAction(ISD::TargetFrameIndex, MVT::i32, Custom);
  setOperationAction(ISD::EXTRACT_ELEMENT, MVT::i32, Custom);
  setOperationAction(ISD::ADD, MVT::i32, Custom);
  setOperationAction(ISD::INLINEASM, MVT::i32, Custom);

  // Expand var-args ops.
  setOperationAction(ISD::VASTART, MVT::Other, Custom);
  setOperationAction(ISD::VAARG, MVT::Other, Custom);
  // setOperationAction(ISD::VAARG, MVT::Other, Expand);
  // FIXME: ckeck if we can do better with a custom implementation.
  setOperationAction(ISD::VAEND, MVT::Other, Expand);
  setOperationAction(ISD::VACOPY, MVT::Other, Custom);

  setOperationAction(ISD::BSWAP, MVT::i32, Custom);
  setOperationAction(ISD::BSWAP, MVT::i64, Custom);

  for (MVT VT : MVT::integer_valuetypes()) {
    setOperationAction(ISD::CTPOP, VT, Expand);
    setOperationAction(ISD::CTLZ, VT, Expand);
    setOperationAction(ISD::CTTZ, VT, Expand);
  }

  // We want to custom lower some of our intrinsics.
  setOperationAction(ISD::INTRINSIC_WO_CHAIN, MVT::i32, Custom);
  setOperationAction(ISD::INTRINSIC_WO_CHAIN, MVT::i64, Custom);
  setOperationAction(ISD::INTRINSIC_WO_CHAIN, MVT::Other, Custom);
  setOperationAction(ISD::INTRINSIC_VOID, MVT::Other, Custom);
  setOperationAction(ISD::INTRINSIC_W_CHAIN, MVT::Other, Custom);

  // FIXME: ckeck if we can do better with a custom implementation.
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i1, Expand);
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i8, Expand);
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i16, Expand);
  // Unaligned address is not lowered optimally (it uses shit and or).
  setOperationAction(ISD::LOAD, MVT::i16, Custom);
  setOperationAction(ISD::LOAD, MVT::i32, Custom);
  setOperationAction(ISD::STORE, MVT::i16, Custom);
  setOperationAction(ISD::STORE, MVT::i32, Custom);
  // FIXME: ckeck if we can do better with a custom implementation.
  for (MVT VT : MVT::integer_valuetypes()) {
    setLoadExtAction(ISD::EXTLOAD, VT, MVT::i1, Promote);
    setLoadExtAction(ISD::SEXTLOAD, VT, MVT::i1, Promote);
    setLoadExtAction(ISD::ZEXTLOAD, VT, MVT::i1, Promote);
    setLoadExtAction(ISD::EXTLOAD, VT, MVT::i8, Expand);
    setLoadExtAction(ISD::SEXTLOAD, VT, MVT::i8, Expand);
    setLoadExtAction(ISD::ZEXTLOAD, VT, MVT::i8, Expand);
    setLoadExtAction(ISD::EXTLOAD, VT, MVT::i16, Expand);
    setLoadExtAction(ISD::SEXTLOAD, VT, MVT::i16, Expand);
    setLoadExtAction(ISD::ZEXTLOAD, VT, MVT::i16, Expand);
  }

  setTruncStoreAction(MVT::i16, MVT::i8, Expand);

  // To ensure optimal generation of 32 bit add/sub (llmv will use setcc/select
  // instead.
  setOperationAction(ISD::ADDC, MVT::i16, Legal);
  setOperationAction(ISD::ADDE, MVT::i16, Legal);
  setOperationAction(ISD::SUBC, MVT::i16, Legal);
  setOperationAction(ISD::SUBE, MVT::i16, Legal);

  setOperationAction(ISD::SELECT, MVT::i32, Custom);

  // FIXME: set ABS to custom and emit libcall.

  // Expand to UMUL_LOHI.
  setOperationAction(ISD::MULHU, MVT::i8, Expand);
  setOperationAction(ISD::MULHU, MVT::i16, Expand);

  // Expand to SMUL_LOHI (which is expanded in turn as well).
  setOperationAction(ISD::MULHS, MVT::i8, Expand);
  setOperationAction(ISD::MULHS, MVT::i16, Expand);
  setOperationAction(ISD::SMUL_LOHI, MVT::i8, Expand);
  setOperationAction(ISD::SMULO, MVT::i16, Custom);
  setOperationAction(ISD::UMULO, MVT::i16, Custom);
  // We expand BRCOND to BR_CC becuase
  // in some cases we can expand it to  BT/BF/BTCRL.
  setOperationAction(ISD::BRCOND, MVT::Other, Expand);
  setOperationAction(ISD::BR_CC, MVT::i8, Custom);
  setOperationAction(ISD::BR_CC, MVT::i16, Custom);
  //
  setOperationAction(ISD::SELECT_CC, MVT::i8, Custom);
  setOperationAction(ISD::SELECT_CC, MVT::i16, Custom);

  // TODO: custom implementation and i32, i64 ...
  setOperationAction(ISD::SELECT, MVT::i8, Expand);
  setOperationAction(ISD::SELECT, MVT::i16, Expand);
  setOperationAction(ISD::SETCC, MVT::i8, Expand);
  setOperationAction(ISD::SETCC, MVT::i16, Expand);
  // setOperationAction(ISD::SETCC, MVT::i32, Custom);
  // setOperationAction(ISD::SETCC, MVT::i64, Custom);
  // FIXME: ckeck if we can do better with a custom implementation.
  setOperationAction(ISD::BR_JT, MVT::Other, Expand);

  // Custom legalize GlobalAddress.
  setOperationAction(ISD::GlobalAddress, MVT::i16, Custom);
  setOperationAction(ISD::GlobalAddress, MVT::i32, Custom);
  setOperationAction(ISD::TargetGlobalAddress, MVT::i32, Custom);
  setOperationAction(ISD::ConstantPool, PtrVT, Custom);
  setOperationAction(ISD::BlockAddress, PtrVT, Custom);
  setOperationAction(ISD::ExternalSymbol, MVT::i16, Custom);
  setOperationAction(ISD::ExternalSymbol, MVT::i32, Custom);
  setOperationAction(ISD::JumpTable, PtrVT, Custom);

  // Custom lower mul (except i8).
  setOperationAction(ISD::MUL, MVT::i16, Custom);
  setOperationAction(ISD::MUL, MVT::i32, Custom);
  // Promote to i16.
  setOperationAction(ISD::UREM, MVT::i8, Promote);
  //
  if (Subtarget->isRL78S3CoreType()) {
    // Expand to UDIVREM.
    setOperationAction(ISD::UDIV, MVT::i16, Expand);
    setOperationAction(ISD::UREM, MVT::i16, Expand);
    // UMUL_LOHI for i8 see UMUL_LOHI_16_r_r.
    setOperationAction(ISD::UMUL_LOHI, MVT::i16, Legal);
    setOperationAction(ISD::SMUL_LOHI, MVT::i16, Legal);

    setOperationAction(ISD::UDIVREM, MVT::i16, Legal);
    // Set to legal so DivRemPairs leaves it alone.
    setOperationAction(ISD::UDIVREM, MVT::i32, Legal);
    // Promote to i16.
    setOperationAction(ISD::UDIV, MVT::i8, Promote);
    setOperationAction(ISD::SDIV, MVT::i8, Promote);

    setTargetDAGCombine(ISD::MUL);
    // So we can handle combining into divwu.
    setTargetDAGCombine(ISD::UDIV);
    setTargetDAGCombine(ISD::UREM);
  } else {
    //
    setOperationAction(ISD::UDIV, MVT::i16, LibCall);
    setOperationAction(ISD::UREM, MVT::i16, LibCall);
    setOperationAction(ISD::UMUL_LOHI, MVT::i16, Expand);
    setOperationAction(ISD::SMUL_LOHI, MVT::i16, Expand);
    setOperationAction(ISD::UDIVREM, MVT::i16, Expand);
    // Custom LowerCDIV COM_ucdiv and COM_scdiv.
    setOperationAction(ISD::UDIV, MVT::i8, Custom);
    setOperationAction(ISD::SDIV, MVT::i8, Custom);
  }

  setTargetDAGCombine(ISD::TRUNCATE);

  // No signed DIV/MOD available on RL78 do a libcall.
  setOperationAction(ISD::SREM, MVT::i8, Promote);
  setOperationAction(ISD::SDIV, MVT::i16, LibCall);
  setOperationAction(ISD::SREM, MVT::i16, LibCall);
  setOperationAction(ISD::SDIVREM, MVT::i16, Expand);

  // Custom lower floating point rounding ops.
  setOperationAction(ISD::LRINT, MVT::i32, Custom);
  setOperationAction(ISD::LROUND, MVT::i32, Custom);

  setOperationAction(ISD::AND, MVT::i16, Custom);
  setOperationAction(ISD::OR, MVT::i16, Custom);
  setOperationAction(ISD::XOR, MVT::i16, Custom);

  // Custom lower shifts.
  setOperationAction(ISD::SHL, MVT::i8, Custom);
  setOperationAction(ISD::SHL, MVT::i16, Custom);
  setOperationAction(ISD::SRA, MVT::i8, Custom);
  setOperationAction(ISD::SRA, MVT::i16, Custom);
  setOperationAction(ISD::SRL, MVT::i8, Custom);
  setOperationAction(ISD::SRL, MVT::i16, Custom);

  setOperationAction(ISD::SHL_PARTS, MVT::i16, Expand);
  setOperationAction(ISD::SHL_PARTS, MVT::i32, Expand);
  setOperationAction(ISD::SRA_PARTS, MVT::i16, Expand);
  setOperationAction(ISD::SRA_PARTS, MVT::i32, Expand);
  setOperationAction(ISD::SRL_PARTS, MVT::i16, Expand);
  setOperationAction(ISD::SRL_PARTS, MVT::i32, Expand);
  // Custom lower rotate operations.
  setOperationAction(ISD::ROTL, MVT::i8, Custom);
  setOperationAction(ISD::ROTL, MVT::i16, Custom);
  setOperationAction(ISD::ROTR, MVT::i8, Custom);
  setOperationAction(ISD::ROTR, MVT::i16, Custom);

  setOperationAction(ISD::STACKSAVE, MVT::Other, Expand);
  setOperationAction(ISD::STACKRESTORE, MVT::Other, Expand);
  setOperationAction(ISD::DYNAMIC_STACKALLOC, MVT::i16, Custom);

  setTargetDAGCombine(ISD::BR_CC);
  setTargetDAGCombine(ISD::BRCOND);
  setTargetDAGCombine(ISD::INLINEASM);
  setTargetDAGCombine(ISD::TRAP);
  // To eliminate casts between far_code and far_data
  //setTargetDAGCombine(ISD::ADDRSPACECAST);

  // To replace special cases of 16bit ops
  setTargetDAGCombine(ISD::AND);
  setTargetDAGCombine(ISD::OR);
  setTargetDAGCombine(ISD::XOR);
  setTargetDAGCombine(ISD::SHL);

  // To match MACH/MACHU on S3 or other optimizations.
  setTargetDAGCombine(ISD::ADD);

  setTargetDAGCombine(ISD::SUB);

  setStackPointerRegisterToSaveRestore(RL78::SPreg);

  setSchedulingPreference(llvm::Sched::ILP);

  setMinFunctionAlignment(Align(1));

  computeRegisterProperties(Subtarget->getRegisterInfo());

  setLibcallName(RTLIB::ADD_F32, "_COM_fadd");            // was __addsf3
  setLibcallName(RTLIB::ADD_F64, "_COM_dadd");            // was __adddf3
  setLibcallName(RTLIB::SUB_F32, "_COM_fsub");            // was __subsf3
  setLibcallName(RTLIB::SUB_F64, "_COM_dsub");            // was __subdf3
  setLibcallName(RTLIB::MUL_I16, "_COM_imul");            // was __mulhi3
  setLibcallName(RTLIB::MUL_I32, "_COM_lmul");            // was __mulsi3
  setLibcallName(RTLIB::MUL_I64, "_COM_llmul");           // was __muldi3
  setLibcallName(RTLIB::MUL_F32, "_COM_fmul");            // was __mulsf3
  setLibcallName(RTLIB::MUL_F64, "_COM_dmul");            // was __muldf3
  setLibcallName(RTLIB::SDIV_I8, "_COM_scdiv");           // was __divqi3
  setLibcallName(RTLIB::UDIV_I8, "_COM_ucdiv");           // was __udivqi3
  setLibcallName(RTLIB::SDIV_I16, "_COM_sidiv");          // was __divhi3
  setLibcallName(RTLIB::UDIV_I16, "_COM_uidiv");          // was __udivhi3
  setLibcallName(RTLIB::SDIV_I32, "_COM_sldiv");          // was __divsi3
  setLibcallName(RTLIB::UDIV_I32, "_COM_uldiv");          // was __udivsi3
  setLibcallName(RTLIB::SDIV_I64, "_COM_slldiv");         // was __divdi3
  setLibcallName(RTLIB::UDIV_I64, "_COM_ulldiv");         // was __udivdi3
  setLibcallName(RTLIB::DIV_F32, "_COM_fdiv");            // was __divsf3
  setLibcallName(RTLIB::DIV_F64, "_COM_ddiv");            // was __divdf3
  setLibcallName(RTLIB::SREM_I8, "_COM_screm");           // was __modqi3
  setLibcallName(RTLIB::UREM_I8, "_COM_ucrem");           // was __umodqi3
  setLibcallName(RTLIB::SREM_I16, "_COM_sirem");          // was __modhi3
  setLibcallName(RTLIB::UREM_I16, "_COM_uirem");          // was __umodhi3
  setLibcallName(RTLIB::SREM_I32, "_COM_slrem");          // was __modsi3
  setLibcallName(RTLIB::UREM_I32, "_COM_ulrem");          // was __umodsi3
  setLibcallName(RTLIB::SREM_I64, "_COM_sllrem");         // was __moddi3
  setLibcallName(RTLIB::UREM_I64, "_COM_ullrem");         // was __umoddi3
  setLibcallName(RTLIB::SINTTOFP_I32_F32, "_COM_sltof");  // was __floatsisf
  setLibcallName(RTLIB::SINTTOFP_I32_F64, "_COM_sltod");  // was __floatsidf
  setLibcallName(RTLIB::UINTTOFP_I32_F32, "_COM_ultof");  // was __floatunsisf
  setLibcallName(RTLIB::UINTTOFP_I32_F64, "_COM_ultod");  // was __floatunsidf
  setLibcallName(RTLIB::SINTTOFP_I64_F32, "_COM_slltof"); // was __floatdisf
  setLibcallName(RTLIB::SINTTOFP_I64_F64, "_COM_slltod"); // was __floatdidf
  setLibcallName(RTLIB::UINTTOFP_I64_F32, "_COM_ulltof"); // was __floatundisf
  setLibcallName(RTLIB::UINTTOFP_I64_F64, "_COM_ulltod"); // was __floatundidf
  setLibcallName(RTLIB::FPTOSINT_F32_I32, "_COM_ftosl");  // was __fixsfsi
  setLibcallName(RTLIB::FPTOUINT_F32_I32, "_COM_ftoul");  // was __fixunssfsi
  setLibcallName(RTLIB::FPTOSINT_F32_I64, "_COM_ftosll"); // was __fixsfdi
  setLibcallName(RTLIB::FPTOUINT_F32_I64, "_COM_ftoull"); // was __fixunssfdi
  setLibcallName(RTLIB::FPTOSINT_F64_I32, "_COM_dtosl");  // was __fixdfsi
  setLibcallName(RTLIB::FPTOUINT_F64_I32, "_COM_dtoul");  // was __fixunsdfsi
  setLibcallName(RTLIB::FPTOSINT_F64_I64, "_COM_dtosll"); // was __fixdfdi
  setLibcallName(RTLIB::FPTOUINT_F64_I64, "_COM_dtoull"); // was __fixunsdfdi
  setLibcallName(RTLIB::FPEXT_F32_F64, "_COM_ftod");      // was __extendsfdf2
  setLibcallName(RTLIB::FPROUND_F64_F32, "_COM_dtof");    // was __truncdfsf2
  setLibcallName(RTLIB::SRA_I32, "_COM_lsar");            // was __ashrsi3
  setLibcallName(RTLIB::SRL_I32, "_COM_lshr");            // was __lshrsi3
  setLibcallName(RTLIB::SHL_I32, "_COM_lshl");            // was __ashlsi3
  setLibcallName(RTLIB::SRA_I64, "_COM_llsar");           // was __ashrdi3
  setLibcallName(RTLIB::SRL_I64, "_COM_llshr");           // was __lshrdi3
  setLibcallName(RTLIB::SHL_I64, "_COM_llshl");           // was __ashldi3

  // Override MaxLoadsPerMemcmp value (from the default 8) for -O3
  if (TM.getOptLevel() == CodeGenOpt::Aggressive)
    MaxLoadsPerMemcmp = 32;
}

bool RL78TargetLowering::useSoftFloat() const { return true; }

unsigned RL78TargetLowering::getJumpTableEncoding() const {
  return MachineJumpTableInfo::EK_BlockAddress;
}

bool RL78TargetLowering::decomposeMulByConstant(LLVMContext &Context, EVT VT,
                                                SDValue C) const {
  // We have mulu.
  if (VT == MVT::i8)
    return false;
  // We have mulhu/mulh for S3.
  if (VT == MVT::i16 && Subtarget->isRL78S3CoreType())
    return false;
  // For i16 the decomposition might be better than a call.
  // If O3, inline it.
  if (VT == MVT::i16 ||
      getTargetMachine().getOptLevel() == CodeGenOpt::Aggressive)
    return true;
  return false;
}

bool RL78TargetLowering::getTgtMemIntrinsic(IntrinsicInfo &Info,
                                            const CallInst &I,
                                            MachineFunction &MF,
                                            unsigned Intrinsic) const {

  switch (Intrinsic) {
  case Intrinsic::rl78_mului:
  case Intrinsic::rl78_mulsi:
  case Intrinsic::rl78_mulul:
  case Intrinsic::rl78_mulsl:
  case Intrinsic::rl78_divui:
  case Intrinsic::rl78_divul:
  case Intrinsic::rl78_remui:
  case Intrinsic::rl78_remul:
  case Intrinsic::rl78_macui:
  case Intrinsic::rl78_macsi:
    return false;
  case Intrinsic::rl78_mov1:
  case Intrinsic::rl78_and1:
  case Intrinsic::rl78_or1:
  case Intrinsic::rl78_xor1:
  case Intrinsic::rl78_set1:
  case Intrinsic::rl78_clr1:
  case Intrinsic::rl78_not1: {

    const Module &M = *I.getParent()->getParent()->getParent();
    PointerType *PtrTy = cast<PointerType>(I.getArgOperand(0)->getType());
    Info.opc = ISD::INTRINSIC_W_CHAIN;
    // TODO double check type
    Info.memVT = MVT::i8;
    Info.ptrVal = I.getArgOperand(0);
    Info.offset = 0;
    Info.align = Align(M.getDataLayout().getTypeAllocSizeInBits(PtrTy) / 16);
    Info.flags = MachineMemOperand::MOLoad | MachineMemOperand::MOStore;
    return true;
  }
  }
  return false;
}

const char *RL78TargetLowering::getTargetNodeName(unsigned Opcode) const {
  switch ((RL78ISD::NodeType)Opcode) {
  case RL78ISD::FIRST_NUMBER:
    break;
  case RL78ISD::SEL_RB:
    return "RL78ISD::SEL_RB";
  case RL78ISD::CMP:
    return "RL78ISD::CMP";
  case RL78ISD::LOWCMP:
    return "RL78ISD::LOWCMP";
  case RL78ISD::CALL:
    return "RL78ISD::CALL";
  case RL78ISD::CALL_FP:
    return "RL78ISD::CALL_FP";
  case RL78ISD::TAIL_CALL:
    return "RL78ISD::TAIL_CALL";
  case RL78ISD::RET:
    return "RL78ISD::RET";
  case RL78ISD::RETI:
    return "RL78ISD::RETI";
  case RL78ISD::RETB:
    return "RL78ISD::RETB";
  case RL78ISD::BRCC:
    return "RL78ISD::BRCC";
  case RL78ISD::SELECTCC:
    return "RL78ISD::SELECTCC";
  case RL78ISD::BTBF:
    return "RL78ISD::BTBF";
  case RL78ISD::SET1:
    return "RL78ISD::SET1";
  case RL78ISD::CLR1:
    return "RL78ISD::CLR1";
  case RL78ISD::DIVWU:
    return "RL78ISD::DIVWU";
  case RL78ISD::LOW8:
    return "RL78ISD::LOW8";
  case RL78ISD::LOW16:
    return "RL78ISD::LOW16";
  case RL78ISD::HI16:
    return "RL78ISD::HI16";
  case RL78ISD::CALLT:
    return "RL78ISD::CALLT";
  case RL78ISD::MOV1TOCY:
    return "RL78ISD::MOV1TOCY";
  case RL78ISD::MOV1FROMCY:
    return "RL78ISD::MOV1FROMCY";
  case RL78ISD::LOAD1TOCY:
    return "RL78ISD::LOAD1TOCY";
  case RL78ISD::STORE1FROMCY:
    return "RL78ISD::STORE1FROMCY";
  case RL78ISD::AND1CY:
    return "RL78ISD::AND1CY";
  case RL78ISD::OR1CY:
    return "RL78ISD::OR1CY";
  case RL78ISD::XOR1CY:
    return "RL78ISD::XOR1CY";
  case RL78ISD::NOT1CY:
    return "RL78ISD::NOT1CY";
  case RL78ISD::XCHW:
    return "RL78ISD::XCHW";
  case RL78ISD::ANDMEM:
    return "RL78ISD::ANDMEM";
  case RL78ISD::ORMEM:
    return "RL78ISD::ORMEM";
  case RL78ISD::XORMEM:
    return "RL78ISD::XORMEM";
  case RL78ISD::MACH:
    return "RL78ISD::MACH";
  case RL78ISD::MACHU:
    return "RL78ISD::MACHU";
  case RL78ISD::INC:
    return "RL78ISD::INC";
  }
  return nullptr;
}

EVT RL78TargetLowering::getSetCCResultType(const DataLayout &, LLVMContext &,
                                           EVT VT) const {
  // TODO: is this OK?
  if (!VT.isVector())
    return MVT::i16;
  return VT.changeVectorElementTypeToInteger();
}

/// isMaskedValueZeroForTargetNode - Return true if 'Op & Mask' is known to
/// be zero. Op is expected to be a target specific node. Used by DAG
/// combiner.
void RL78TargetLowering::computeKnownBitsForTargetNode(
    const SDValue Op, KnownBits &Known, const APInt &DemandedElts,
    const SelectionDAG &DAG, unsigned Depth) const {
  KnownBits Known2;
  Known.resetAll();

  // switch (Op.getOpcode()) {
  // default:
  //  break;
  //  // case SPISD::SELECT_ICC:
  //  // case SPISD::SELECT_XCC:
  //  // case SPISD::SELECT_FCC:
  //  //  DAG.computeKnownBits(Op.getOperand(1), Known, Depth+1);
  //  //  DAG.computeKnownBits(Op.getOperand(0), Known2, Depth+1);

  //  //  // Only known if known in both the LHS and RHS.
  //  //  Known.One &= Known2.One;
  //  //  Known.Zero &= Known2.Zero;
  //  break;
  //}
}

// Convert to a target node and set target flags.
SDValue RL78TargetLowering::withTargetFlags(SDValue Op, unsigned TF,
                                            SelectionDAG &DAG) const {
  if (const GlobalAddressSDNode *GA = dyn_cast<GlobalAddressSDNode>(Op))
    return DAG.getTargetGlobalAddress(GA->getGlobal(), SDLoc(GA), MVT::i16,
                                      GA->getOffset(), TF);

  if (const ConstantPoolSDNode *CP = dyn_cast<ConstantPoolSDNode>(Op))
    return DAG.getTargetConstantPool(CP->getConstVal(), CP->getValueType(0),
                                     CP->getAlign(), CP->getOffset(), TF);

  if (const BlockAddressSDNode *BA = dyn_cast<BlockAddressSDNode>(Op))
    return DAG.getTargetBlockAddress(BA->getBlockAddress(), Op.getValueType(),
                                     0, TF);

  if (const ExternalSymbolSDNode *ES = dyn_cast<ExternalSymbolSDNode>(Op))
    return DAG.getTargetExternalSymbol(ES->getSymbol(), ES->getValueType(0),
                                       TF);

  llvm_unreachable("Unhandled address SDNode");
}

// Build SDNodes for producing an address from a GlobalAddress, ConstantPool,
// or ExternalSymbol SDNode.
SDValue RL78TargetLowering::makeAddress(SDValue Op, SelectionDAG &DAG) const {
  SDLoc DL(Op);
  // Op.dump();
  EVT VT = getPointerTy(DAG.getDataLayout(), RL78AS::Near); // i16 also with -mfar-data
  const GlobalValue *GV = cast<GlobalAddressSDNode>(Op)->getGlobal();
  int64_t Offset = cast<GlobalAddressSDNode>(Op)->getOffset();

  const auto *V = dyn_cast<GlobalVariable>(GV);
  if (V) {
    // unsigned AS = V->getAddressSpace();

    // See if we have a pragma address with the saddr range
    bool PragmaAddressInSaddrRange = false;
    if (V->hasSection()) {
      StringRef SectionName = V->getSection();
      size_t nameOffset =
          SectionName.startswith(".bss_AT")
              ? std::string(".bss_AT").size()
              : SectionName.startswith(".bssf_AT")
                    ? std::string(".bssf_AT").size()
                    : SectionName.startswith(".const_AT")
                          ? std::string(".const_AT").size()
                          : SectionName.startswith(".constf_AT")
                                ? std::string(".constf_AT").size()
                                : 0;
      uint64_t Address;
      PragmaAddressInSaddrRange =
          to_integer(SectionName.substr(nameOffset), Address, 16) &&
          (0xFFE20 <= Address && Address <= 0xFFF1F);
    }

    if (V->hasAttribute("saddr") || PragmaAddressInSaddrRange) {
      // Since we don't know if the address will be used for 8 or 16 bit
      // operations we can't decide if we should use VK_RL78_SAD or
      // VK_RL78_SADW. We correct this in RL78MCExpr::getFixupForKind
      SDValue Result = DAG.getTargetGlobalAddress(GV, DL, VT, Offset,
                                                  RL78MCExpr::VK_RL78_SADW);
      return DAG.getNode(RL78ISD::LOW8, DL, VT, Result);
    }
  } 
  else {
    //FIXME: temp fix for correct plt selection until we get rid of the plt.
    SDValue Result = DAG.getTargetGlobalAddress(GV, SDLoc(Op), VT, Offset,
                                                RL78MCExpr::VK_RL78_FUNCTION);
    return DAG.getNode(RL78ISD::LOW16, SDLoc(Op), VT, Result);
  }

  SDValue Result = DAG.getTargetGlobalAddress(GV, SDLoc(Op), VT, Offset,
                                              RL78MCExpr::VK_RL78_LOWW);
  return DAG.getNode(RL78ISD::LOW16, SDLoc(Op), VT, Result);

  // This is one of the absolute code models.
  switch (getTargetMachine().getCodeModel()) {
  default:
    llvm_unreachable("Unsupported absolute code model");
  case CodeModel::Small:
    // SDValue Result = DAG.getTargetGlobalAddress(GV, SDLoc(Op), VT, Offset);
    // return DAG.getNode(RL78ISD::LOW16, DL, VT, withTargetFlags(Op,
    // RL78MCExpr::VK_RL78_LOW16, DAG));
    return DAG.getTargetGlobalAddress(GV, SDLoc(Op), VT, Offset);
    // case CodeModel::Medium: {
    //}
    // case CodeModel::Large: {
    //}
  }
}

SDValue RL78TargetLowering::LowerExternalSymbol(SDValue Op,
                                                SelectionDAG &DAG) const {
  ExternalSymbolSDNode *S = cast<ExternalSymbolSDNode>(Op);
  EVT VT = getPointerTy(DAG.getDataLayout(), RL78AS::Near); // i16 also with -mfar-data
  SDValue Result =
      DAG.getTargetExternalSymbol(S->getSymbol(), Op.getValueType());
  return DAG.getNode(RL78ISD::LOW16, SDLoc(Op), VT, Result);
}

SDValue RL78TargetLowering::LowerGlobalAddress(SDValue Op,
                                               SelectionDAG &DAG) const {
  return makeAddress(Op, DAG);
}

SDValue RL78TargetLowering::LowerConstantPool(SDValue Op,
                                              SelectionDAG &DAG) const {
  ConstantPoolSDNode *CP = cast<ConstantPoolSDNode>(Op);
  EVT VT = Op.getValueType();
  SDValue Result = DAG.getTargetConstantPool(
      CP->getConstVal(), VT, CP->getAlign(), CP->getOffset());
  return DAG.getNode(RL78ISD::LOW16, SDLoc(Op), VT, Result);
}

SDValue RL78TargetLowering::LowerBlockAddress(SDValue Op,
                                              SelectionDAG &DAG) const {
  const BlockAddress *BA = cast<BlockAddressSDNode>(Op)->getBlockAddress();
  int64_t Offset = cast<BlockAddressSDNode>(Op)->getOffset();
  EVT VT = getPointerTy(DAG.getDataLayout(), RL78AS::Near); // i16 also with -mfar-data
  SDValue Result = DAG.getTargetBlockAddress(BA, VT, Offset);
  return DAG.getNode(RL78ISD::LOW16, SDLoc(Op), VT, Result);
}

SDValue RL78TargetLowering::LowerJumpTable(SDValue Op,
                                           SelectionDAG &DAG) const {
  const JumpTableSDNode *JT = cast<JumpTableSDNode>(Op);
  EVT VT = getPointerTy(DAG.getDataLayout(), RL78AS::Near); // i16 also with -mfar-data
  //
  SDValue Result = DAG.getTargetJumpTable(JT->getIndex(), VT);
  return DAG.getNode(RL78ISD::LOW16, SDLoc(Op), VT, Result);
}

static SDValue SwitchCMPOperands(SDLoc DL, unsigned cc, SDValue CCSign,
                                 SDValue &LHS, SDValue &RHS, SelectionDAG &DAG,
                                 SDValue &TargetCC) {
  SDValue Cmp;
  // Heuristic to aid the matcher's cmp a, mem pattern matching
  // If we would have cmp mem, a, switch lhs/rhs and flip the condition
  if (LHS.getOpcode() == ISD::LOAD && RHS.getOpcode() == ISD::CopyFromReg) {
    TargetCC = DAG.getConstant(AdjustICCForOperandSwitch((RL78CC::CondCodes)cc),
                               DL, MVT::i8);
    Cmp = DAG.getNode(RL78ISD::CMP, DL, MVT::Glue, RHS, LHS, CCSign);
  } else {
    Cmp = DAG.getNode(RL78ISD::CMP, DL, MVT::Glue, LHS, RHS, CCSign);
  }
  return Cmp;
}

static SDValue LowerBR_CC(SDValue Op, SelectionDAG &DAG) {
  SDValue Chain = Op.getOperand(0);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
  SDValue LHS = Op.getOperand(2);
  SDValue RHS = Op.getOperand(3);
  SDValue Dest = Op.getOperand(4);
  SDLoc dl(Op);
  unsigned cc = IntCondCCodeToICC(CC);
  SDValue TargetCC = DAG.getConstant(cc, dl, MVT::i8);
  unsigned cmpSign = IntCondCCodeSign(CC);
  SDValue CCSign = DAG.getConstant(cmpSign, dl, MVT::i8);

  // If " == 0" or " != 0".
  if (((CC == ISD::SETEQ) || (CC == ISD::SETNE)) && isa<ConstantSDNode>(RHS) &&
      (cast<ConstantSDNode>(RHS)->getZExtValue() == 0)) {
    // If AND with power of 2.
    if ((LHS.getOpcode() == ISD::AND) &&
        isa<ConstantSDNode>(LHS.getOperand(1)) &&
        isPowerOf2_64(LHS.getConstantOperandVal(1))) {
      // Checking that a bit and equals to 0 tranlates to BF Not BT so
      // we need to reverse the condition.
      cc = (cc == RL78CC::RL78CC_Z) ? RL78CC::RL78CC_NZ : RL78CC::RL78CC_Z;
      if (LHS.getValueType() == MVT::i8) {
        TargetCC = DAG.getConstant(cc, dl, MVT::i8);
        SDValue constVal = DAG.getConstant(
            Log2_64(LHS.getConstantOperandVal(1)), dl, LHS.getValueType());
        return DAG.getNode(RL78ISD::BTBF, dl, MVT::Other, Chain, Dest, TargetCC,
                           LHS.getOperand(0), constVal);
      } else if (LHS.getValueType() == MVT::i16) {
        TargetCC = DAG.getConstant(cc, dl, MVT::i8);
        EVT HalfVT = MVT::i8;
        // Byte offset (0 or 1).
        unsigned offset = (LHS.getConstantOperandVal(1) >= 0x100) ? 1 : 0;
        SDValue index = DAG.getConstant(offset, dl, HalfVT);
        // FIXME: this can generate shrw ax, 8 bf r0.0 instead of bf r1.0,
        // improve it.
        SDValue op0Half = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, HalfVT,
                                      LHS.getOperand(0), index);
        SDValue constVal = DAG.getConstant(
            Log2_64(LHS.getConstantOperandVal(1) >> (offset * 8)), dl, HalfVT);
        return DAG.getNode(RL78ISD::BTBF, dl, MVT::Other, Chain, Dest, TargetCC,
                           op0Half, constVal);
      }
    }
  }

  // If signed comparison with 0 we can use BT/BF.
  if (cmpSign && isa<ConstantSDNode>(RHS) &&
      LHS.getValueType().bitsGE(MVT::i8) &&
      ((cast<ConstantSDNode>(RHS)->getZExtValue() == 0 && CC == ISD::SETLT) ||
       (cast<ConstantSDNode>(RHS)->getSExtValue() == -1 && CC == ISD::SETGT))) {
    SDValue constVal = DAG.getConstant(7, dl, MVT::i8);
    SDValue topHalf = LHS;
    while (topHalf.getValueType().bitsGT(MVT::i8)) {
      MVT halfVT = topHalf.getValueType()
                       .getHalfSizedIntegerVT(*DAG.getContext())
                       .getSimpleVT();
      SDValue hiIndex = DAG.getConstant(1, dl, halfVT);
      topHalf = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, halfVT, topHalf, hiIndex);
    }
    TargetCC = DAG.getConstant(
        CC == ISD::SETLT ? RL78CC::RL78CC_Z : RL78CC::RL78CC_NZ, dl, MVT::i8);
    return DAG.getNode(RL78ISD::BTBF, dl, MVT::Other, Chain, Dest, TargetCC,
                       topHalf, constVal);
  }

  // Comparisons with imm values can be done more efficiently for imm = { 0, 1}
  // (see LowerSignedCMPWImm) op < 2 can be replaced with op <= 1. op < 1 can be
  // replaced with op <= 0 (OBS. llvm already does this for unsigned
  // comparison). OBS. if we remove LowerSignedCMPWImm this has no effect.
  if ((CC == ISD::SETLT) && (LHS.getValueType() == MVT::i16) &&
      isa<ConstantSDNode>(RHS) &&
      ((cast<ConstantSDNode>(RHS)->getZExtValue() == 1) ||
       (cast<ConstantSDNode>(RHS)->getZExtValue() == 2))) {
    //
    RHS = DAG.getConstant(cast<ConstantSDNode>(RHS)->getZExtValue() - 1, dl,
                          LHS.getValueType());
    // Change CC from '<' to '<='
    cc = IntCondCCodeToICC(ISD::SETLE);
    TargetCC = DAG.getConstant(cc, dl, MVT::i8);
  }
  // if LHS == RHS we don't need a conditional instruction, also we don't have
  // CMP(W) instrutions on RL78 which accept the same register for both
  // operands; so we really need to check for this here as a safety net.
  // FIXME: this should be eliminated much eariler (recheck in newer LLVM) Saw
  // this with gcc.c-torture\execute\920428-1.c and
  // gcc.c-torture\execute\921112-1.c on -O3.
  if (LHS == RHS) {
    if ((CC == ISD::SETLE) || (CC == ISD::SETGE) || (CC == ISD::SETEQ))
      return DAG.getNode(ISD::BR, dl, MVT::Other, Chain, Dest);
  }
  // Create the CMP node.
  SDValue Cmp = SwitchCMPOperands(dl, cc, CCSign, LHS, RHS, DAG, TargetCC);
  // DAG.dump();
  //
  return DAG.getNode(RL78ISD::BRCC, dl, MVT::Other, Chain, Dest, TargetCC, Cmp);
}

static SDValue LowerSELECT_CC(SDValue Op, SelectionDAG &DAG) {
  SDValue LHS = Op.getOperand(0);
  SDValue RHS = Op.getOperand(1);
  SDValue TVal = Op.getOperand(2);
  SDValue FVal = Op.getOperand(3);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(4))->get();
  SDLoc dl(Op);
  unsigned cc = IntCondCCodeToICC(CC);
  SDValue TargetCC = DAG.getConstant(cc, dl, MVT::i8);
  unsigned cmpSign = IntCondCCodeSign(CC);
  SDValue CCSign = DAG.getConstant(cmpSign, dl, MVT::i8);
  // Create the CMP node.
  SDValue Cmp = SwitchCMPOperands(dl, cc, CCSign, LHS, RHS, DAG, TargetCC);
  // DAG.dump();
  //
  return DAG.getNode(RL78ISD::SELECTCC, dl, Op.getValueType(), TVal, FVal,
                     TargetCC, Cmp);
}

static SDValue LowerVASTART(SDValue Op, SelectionDAG &DAG,
                            const RL78TargetLowering &TLI) {
  MachineFunction &MF = DAG.getMachineFunction();
  RL78MachineFunctionInfo *FuncInfo = MF.getInfo<RL78MachineFunctionInfo>();

  // use a 16-bit ptr also for -mfar-data
  auto PtrVT = TLI.getPointerTy(DAG.getDataLayout(),
                                DAG.getDataLayout().getAllocaAddrSpace());

  // Need frame address to find the address of VarArgsFrameIndex.
  // MF.getFrameInfo().setFrameAddressIsTaken(true);

  // vastart just stores the address of the VarArgsFrameIndex slot into the
  // memory location argument.
  SDLoc DL(Op);
  const Value *SV = cast<SrcValueSDNode>(Op.getOperand(2))->getValue();
  SDValue FI = DAG.getFrameIndex(FuncInfo->getVarArgsFrameOffset(), PtrVT);

  return DAG.getStore(Op.getOperand(0), DL, FI, Op.getOperand(1),
                      MachinePointerInfo(SV), 0);
}

static SDValue LowerVAARG(SDValue Op, SelectionDAG &DAG) {
  SDNode *Node = Op.getNode();
  EVT VT = Node->getValueType(0);
  SDValue InChain = Node->getOperand(0);
  SDValue VAListPtr = Node->getOperand(1);
  EVT PtrVT = VAListPtr.getValueType();
  const Value *SV = cast<SrcValueSDNode>(Node->getOperand(2))->getValue();
  SDLoc DL(Node);
  SDValue VAList =
      DAG.getLoad(PtrVT, DL, InChain, VAListPtr, MachinePointerInfo(SV));
  // Decrement the pointer, VAList, to the next vaarg.
  unsigned ArgSizeInBytes =
      DAG.getDataLayout().getTypeAllocSize(VT.getTypeForEVT(*DAG.getContext()));
  SDValue NextPtr = DAG.getNode(
      ISD::ADD, DL, VAList.getValueType(), VAList,
      DAG.getConstant(alignTo(ArgSizeInBytes, 2), DL, VAList.getValueType()));
  // Store the incremented VAList to the legalized pointer.
  InChain = DAG.getStore(VAList.getValue(1), DL, NextPtr, VAListPtr,
                         MachinePointerInfo(SV));
  // Load the actual argument out of the pointer VAList.
  // We can't count on greater alignment than the word size.
  return DAG.getLoad(VT, DL, InChain, VAList, MachinePointerInfo(),
                     std::min(PtrVT.getSizeInBits(), VT.getSizeInBits()) / 8);
}

// this is basically a copy of SelectionDAG::expandVACopy(),
// but with 16-bit ptr type with or without -mfar-data
static SDValue LowerVACOPY(SDValue Op, SelectionDAG &DAG,
                           const RL78TargetLowering &TLI) {
  SDLoc dl(Op);

  const Value *VD = cast<SrcValueSDNode>(Op->getOperand(3))->getValue();
  const Value *VS = cast<SrcValueSDNode>(Op->getOperand(4))->getValue();

  auto PtrVT = TLI.getPointerTy(DAG.getDataLayout(),
                                DAG.getDataLayout().getAllocaAddrSpace());

  SDValue Tmp1 = DAG.getLoad(PtrVT, dl, Op->getOperand(0), Op->getOperand(2),
                             MachinePointerInfo(VS));
  return DAG.getStore(Tmp1.getValue(1), dl, Tmp1, Op->getOperand(1),
                      MachinePointerInfo(VD));
}

static SDValue getFRAMEADDR(uint64_t depth, SDValue Op, SelectionDAG &DAG,
                            const RL78Subtarget *Subtarget) {
  MachineFrameInfo &MFI = DAG.getMachineFunction().getFrameInfo();

  MFI.setFrameAddressIsTaken(true);

  EVT VT = Op.getValueType();
  SDLoc dl(Op);
  unsigned FrameReg =
      Subtarget->getRegisterInfo()->getFrameRegister(DAG.getMachineFunction());

  if (depth == 0)
    return DAG.getCopyFromReg(DAG.getEntryNode(), dl, FrameReg, VT);
  return SDValue();
}

static SDValue LowerFRAMEADDR(SDValue Op, SelectionDAG &DAG,
                              const RL78Subtarget *Subtarget) {
  unsigned level = Op.getConstantOperandVal(0);
  if (level > 0) {
    DAG.getContext()->emitError("__builtin_frame_address is supported only for "
                                "current function (level = 0)");
    return SDValue();
  }
  return getFRAMEADDR(0, Op, DAG, Subtarget);
}

// This can be called with __builtin_return_address, currently we made a change
// in Intrinsics.td to fix the following assert from Instructions.td: for
// (unsigned i = 0; i != Args.size(); ++i) assert((i >= FTy->getNumParams() ||
//    FTy->getParamType(i) == Args[i]->getType()) &&
//    "Calling a function with a bad signature!");
static SDValue LowerRETURNADDR(SDValue Op, SelectionDAG &DAG,
                               const RL78TargetLowering &TLI,
                               const RL78Subtarget *Subtarget) {
  MachineFunction &MF = DAG.getMachineFunction();
  MachineFrameInfo &MFI = MF.getFrameInfo();
  MFI.setReturnAddressIsTaken(true);

  if (TLI.verifyReturnAddressArgumentIsConstant(Op, DAG))
    return SDValue();

  unsigned level = Op.getConstantOperandVal(0);
  if (level > 0) {
    DAG.getContext()->emitError("__builtin_return_address is supported only "
                                "for current function (level = 0)");
    return SDValue();
  }
  SDLoc dl(Op);

  // Need frame address to find return address of the caller.
  SDValue FrameAddr = getFRAMEADDR(0, Op, DAG, Subtarget);
  int FI = MFI.CreateFixedObject(2, -2, true);
  SDValue FIN = DAG.getFrameIndex(FI, MVT::i16);

  return DAG.getLoad(Op.getValueType(), dl, DAG.getEntryNode(), FIN,
                     MachinePointerInfo());
}

SDValue RL78TargetLowering::LowerLibCall(SDValue Op, SelectionDAG &DAG,
                                         const char *libFunctionName,
                                         bool IsSigned,
                                         unsigned OperandIndex) const {
  if (Op.getNumOperands() == 1)
    return LowerLibCall(Op, DAG, libFunctionName, IsSigned, {Op.getOperand(0)});
  else
    return LowerLibCall(
        Op, DAG, libFunctionName, IsSigned,
        {Op.getOperand(OperandIndex), Op.getOperand(OperandIndex + 1)});
}

SDValue RL78TargetLowering::LowerLibCall(SDValue Op, SelectionDAG &DAG,
                                         const char *libFunctionName,
                                         bool IsSigned,
                                         ArrayRef<SDValue> Ops) const {
  SDLoc dl(Op);
  Type *opType = Op.getValueType().getTypeForEVT(*DAG.getContext());
  TargetLowering::ArgListTy Args;

  for (unsigned i = 0, e = Ops.size(); i != e; ++i) {
    TargetLowering::ArgListEntry Entry;
    Entry.Ty = Ops[i].getValueType().getTypeForEVT(*DAG.getContext());
    Entry.IsSExt = IsSigned;
    Entry.IsZExt = !IsSigned;
    Entry.Node = Ops[i];
    Args.push_back(Entry);
  }
  SDValue Chain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other);
  TargetLowering::CallLoweringInfo CLI(DAG);
  CLI.setDebugLoc(dl).setChain(Chain).setLibCallee(
      CallingConv::C, opType,
      DAG.getExternalSymbol(
          libFunctionName,
          getPointerTy(DAG.getDataLayout(),
                       DAG.getDataLayout().getProgramAddressSpace())),
      std::move(Args));

  std::pair<SDValue, SDValue> CallResult = LowerCallTo(CLI);
  // CallResult.first.dump();
  // CallResult.second.dump();
  // Is unary operation?
  if (Op.getNumOperands() == 1) {
    return CallResult.first;
  } else {
    SDValue Ops[] = {CallResult.first, CallResult.second};
    return DAG.getMergeValues(Ops, dl);
  }
}

SDValue RL78TargetLowering::LowerMULO(SDValue Op, SelectionDAG &DAG) const {
  // TODO: Copied from the default TargetLowering::expandMULO implementation,
  // with a minor change. We needed to do this because the default expand passed
  // the arguments to the libcall without setting their OrigArgIndex correctly,
  // to signal that they were split up because type legalization (i32 -> 2xi16).
  // We expect them to be passed to lowerCall having OrigArgIndex = {1, 1, 2,
  // 2}, but they are passed as {1, 2, 3, 4}. We need to know that they once
  // belonged together, since the CC-RL calling convention wants arguments
  // passed through registers or through stack, but never split up between
  // register and stack.

  SDValue Result, Overflow;
  SDLoc dl(Op);
  EVT VT = Op.getNode()->getValueType(0);
  EVT SetCCVT = getSetCCResultType(DAG.getDataLayout(), *DAG.getContext(), VT);
  SDValue LHS = Op.getOperand(0);
  SDValue RHS = Op.getOperand(1);
  bool isSigned = Op.getOpcode() == ISD::SMULO;

  // For power-of-two multiplications we can use a simpler shift expansion.
  if (ConstantSDNode *RHSC = isConstOrConstSplat(RHS)) {
    const APInt &C = RHSC->getAPIntValue();
    // mulo(X, 1 << S) -> { X << S, (X << S) >> S != X }.
    if (C.isPowerOf2()) {
      // smulo(x, signed_min) is same as umulo(x, signed_min).
      bool UseArithShift = isSigned && !C.isMinSignedValue();
      EVT ShiftAmtTy = getShiftAmountTy(VT, DAG.getDataLayout());
      SDValue ShiftAmt = DAG.getConstant(C.logBase2(), dl, ShiftAmtTy);
      Result = DAG.getNode(ISD::SHL, dl, VT, LHS, ShiftAmt);
      Overflow = DAG.getSetCC(dl, SetCCVT,
                              DAG.getNode(UseArithShift ? ISD::SRA : ISD::SRL,
                                          dl, VT, Result, ShiftAmt),
                              LHS, ISD::SETNE);
      return DAG.getNode(ISD::MERGE_VALUES, dl, DAG.getVTList(VT, VT), Result,
                         Overflow);
    }
  }

  EVT WideVT =
      EVT::getIntegerVT(*DAG.getContext(), VT.getScalarSizeInBits() * 2);
  if (VT.isVector())
    WideVT =
        EVT::getVectorVT(*DAG.getContext(), WideVT, VT.getVectorNumElements());

  SDValue BottomHalf;
  SDValue TopHalf;
  static const unsigned Ops[2][3] = {
      {ISD::MULHU, ISD::UMUL_LOHI, ISD::ZERO_EXTEND},
      {ISD::MULHS, ISD::SMUL_LOHI, ISD::SIGN_EXTEND}};
  if (isOperationLegalOrCustom(Ops[isSigned][0], VT)) {
    BottomHalf = DAG.getNode(ISD::MUL, dl, VT, LHS, RHS);
    TopHalf = DAG.getNode(Ops[isSigned][0], dl, VT, LHS, RHS);
  } else if (isOperationLegalOrCustom(Ops[isSigned][1], VT)) {
    BottomHalf =
        DAG.getNode(Ops[isSigned][1], dl, DAG.getVTList(VT, VT), LHS, RHS);
    TopHalf = BottomHalf.getValue(1);
  } else if (isTypeLegal(WideVT)) {
    LHS = DAG.getNode(Ops[isSigned][2], dl, WideVT, LHS);
    RHS = DAG.getNode(Ops[isSigned][2], dl, WideVT, RHS);
    SDValue Mul = DAG.getNode(ISD::MUL, dl, WideVT, LHS, RHS);
    BottomHalf = DAG.getNode(ISD::TRUNCATE, dl, VT, Mul);
    SDValue ShiftAmt =
        DAG.getConstant(VT.getScalarSizeInBits(), dl,
                        getShiftAmountTy(WideVT, DAG.getDataLayout()));
    TopHalf = DAG.getNode(ISD::TRUNCATE, dl, VT,
                          DAG.getNode(ISD::SRL, dl, WideVT, Mul, ShiftAmt));
  } else {

    // We can fall back to a libcall with an illegal type for the MUL if we
    // have a libcall big enough.
    // Also, we can fall back to a division in some cases, but that's a big
    // performance hit in the general case.
    RTLIB::Libcall LC = RTLIB::UNKNOWN_LIBCALL;
    if (WideVT == MVT::i16)
      LC = RTLIB::MUL_I16;
    else if (WideVT == MVT::i32)
      LC = RTLIB::MUL_I32;
    else if (WideVT == MVT::i64)
      LC = RTLIB::MUL_I64;
    else if (WideVT == MVT::i128)
      LC = RTLIB::MUL_I128;
    assert(LC != RTLIB::UNKNOWN_LIBCALL && "Cannot expand this operation!");

    SDValue HiLHS;
    SDValue HiRHS;
    if (isSigned) {
      // The high part is obtained by SRA'ing all but one of the bits of low
      // part.
      unsigned LoSize = VT.getSizeInBits();
      HiLHS = DAG.getNode(
          ISD::SRA, dl, VT, LHS,
          DAG.getConstant(LoSize - 1, dl, getPointerTy(DAG.getDataLayout())));
      HiRHS = DAG.getNode(
          ISD::SRA, dl, VT, RHS,
          DAG.getConstant(LoSize - 1, dl, getPointerTy(DAG.getDataLayout())));
    } else {
      HiLHS = DAG.getConstant(0, dl, VT);
      HiRHS = DAG.getConstant(0, dl, VT);
    }

    // Here we're passing the 2 arguments explicitly as 4 arguments that are
    // pre-lowered to the correct types. This all depends upon WideVT not
    // being a legal type for the architecture and thus has to be split to
    // two arguments.
    SDValue Ret;
    TargetLowering::MakeLibCallOptions CallOptions;
    CallOptions.setSExt(isSigned);
    CallOptions.setIsPostTypeLegalization(true);

    // TODO: main difference between the default expand and our custom one:
    // Here we use build_pair instead of passing them as:
    // SDValue Args[] = { LHS, HiLHS, RHS, HiRHS };
    // This way the type legalizer kicks in again and correctly sets the
    // OrigArgIndex for the high/low parts.
    SDValue WideLHS = DAG.getNode(ISD::BUILD_PAIR, dl, WideVT, LHS, HiLHS);
    SDValue WideRHS = DAG.getNode(ISD::BUILD_PAIR, dl, WideVT, RHS, HiRHS);

    SDValue Args[] = {WideLHS, WideRHS};
    Ret = makeLibCall(DAG, LC, WideVT, Args, CallOptions, dl).first;
    assert(Ret.getOpcode() == ISD::MERGE_VALUES &&
           "Ret value is a collection of constituent nodes holding result.");
    BottomHalf = Ret.getOperand(0);
    TopHalf = Ret.getOperand(1);
  }

  Result = BottomHalf;
  if (isSigned) {
    SDValue ShiftAmt = DAG.getConstant(
        VT.getScalarSizeInBits() - 1, dl,
        getShiftAmountTy(BottomHalf.getValueType(), DAG.getDataLayout()));
    SDValue Sign = DAG.getNode(ISD::SRA, dl, VT, BottomHalf, ShiftAmt);
    Overflow = DAG.getSetCC(dl, SetCCVT, TopHalf, Sign, ISD::SETNE);
  } else
    Overflow = DAG.getSetCC(dl, SetCCVT, TopHalf, DAG.getConstant(0, dl, VT),
                            ISD::SETNE);

  // Truncate the result if SetCC returns a larger type than needed.
  EVT RType = Op.getNode()->getValueType(1);
  if (RType.getSizeInBits() < Overflow.getValueSizeInBits())
    Overflow = DAG.getNode(ISD::TRUNCATE, dl, RType, Overflow);

  assert(RType.getSizeInBits() == Overflow.getValueSizeInBits() &&
         "Unexpected result type for S/UMULO legalization");
  return DAG.getNode(ISD::MERGE_VALUES, dl, DAG.getVTList(VT, VT), Result,
                     Overflow);
}

SDValue RL78TargetLowering::LowerMul(SDValue Op, SelectionDAG &DAG) const {
  bool isS3Core = Subtarget->isRL78S3CoreType();
  // Op.dump();
  // DAG.dump();
  assert(Op.getValueType() == MVT::i16);
  // In case of zero extend we can use MULU, MULU_zext_16_r_r.
  if ((Op.getOperand(0).getOpcode() == ISD::ZERO_EXTEND) &&
      (Op.getOperand(1).getOpcode() == ISD::ZERO_EXTEND))
    return Op;

  if (isS3Core) {
    // if S3 core we can use MULHU (or MULH), MUL16_r_r.
    return Op;
  } else {
    if (!DAG.getMachineFunction().getFunction().hasOptSize())
      return Op;
    else
      return LowerLibCall(Op, DAG, getLibcallName(RTLIB::MUL_I16), true);
  }
}

SDValue RL78TargetLowering::LowerCDIV(SDValue Op, SelectionDAG &DAG,
                                      unsigned int opcode) const {
  RTLIB::Libcall LC = opcode == ISD::UDIV ? RTLIB::UDIV_I8 : RTLIB::SDIV_I8;
  return LowerLibCall(Op, DAG, getLibcallName(LC), true);
}

SDValue RL78TargetLowering::LowerAndOrXor(SDValue Op, SelectionDAG &DAG,
                                          unsigned int opcode) const {
  // Op.dump();
  if (ConstantSDNode *CN = dyn_cast<ConstantSDNode>(Op.getOperand(1))) {
    return Op;
  }
  SDLoc dl(Op);
  SDNode *N = Op.getNode();
  const SDValue &logicalOp = N->getOperand(0);
  EVT VT = Op->getValueType(0);
  if (logicalOp->getOpcode() == ISD::LOAD && VT == MVT::i16) {
    LoadSDNode *LD = cast<LoadSDNode>(logicalOp);
    if (!LD->isVolatile()) {
      SDValue and_2 =
          DAG.getNode(opcode, dl, VT, Op.getOperand(0), Op.getOperand(1));
      return and_2;
    }
  }
  return Op;
}

SDValue RL78TargetLowering::LowerShift(SDValue Op, SelectionDAG &DAG) const {
  SDLoc dl(Op);
  // Op.dump();
  // Op.getOperand(1).dump();
  // If shift amount is constant we can do this using one instruction.
  if (ConstantSDNode *CN = dyn_cast<ConstantSDNode>(Op.getOperand(1))) {
    return Op;
  }
  RTLIB::Libcall LC;
  bool is8Bit = Op.getSimpleValueType() == MVT::i8;
  switch (Op.getOpcode()) {
  case ISD::SHL:
    LC = is8Bit ? RTLIB::SHL_I8 : RTLIB::SHL_I16;
    break;
  case ISD::SRL:
    LC = is8Bit ? RTLIB::SRL_I8 : RTLIB::SRL_I16;
    break;
  case ISD::SRA:
    LC = is8Bit ? RTLIB::SRA_I8 : RTLIB::SRA_I16;
    break;
  default:
    llvm_unreachable("Invalid shift opcode!");
  }
  if (!DAG.getMachineFunction().getFunction().hasOptSize())
    return Op;
  else
    return LowerLibCall(Op, DAG, getLibcallName(LC), false);
}

// We don't have a RTLIB Libcall name for this so we provide our own version.
const char *GetRotLibCallName(unsigned int Opcode, EVT valueType) {
  if (Opcode == ISD::ROTL) {
    if (valueType == MVT::i8)
      return "__rotlqi3";
    else if (valueType == MVT::i16)
      return "__rotlhi3";
  } else if (Opcode == ISD::ROTR) {
    if (valueType == MVT::i8)
      return "__rotrqi3";
    else if (valueType == MVT::i16)
      return "__rotrhi3";
  }
  //
  llvm_unreachable("Invalid Rotate instruction!");
}

SDValue RL78TargetLowering::LowerRotate(SDValue Op, SelectionDAG &DAG) const {
  SDLoc dl(Op);
  // Op.dump();
  // DAG.dump();
  // if rotate amount is constant we can do this using a few instructions.
  if (ConstantSDNode *CN = dyn_cast<ConstantSDNode>(Op.getOperand(1))) {
    // For i8 we do this for all 8 possible values 0 through 7.
    // For i16 we do this only in 3 cases when the amount in 1, 8 or 15.
    // OBS. 8 is a special case handled with BSWAP so no need to do it here.
    if ((Op.getValueType() == MVT::i8) || (CN->getZExtValue() == 1) ||
        (CN->getZExtValue() == 15))
      return Op;
  }
  // else emit a library call.
  if (!DAG.getMachineFunction().getFunction().hasOptSize())
    return Op;
  else
    return LowerLibCall(
        Op, DAG, GetRotLibCallName(Op.getOpcode(), Op.getValueType()), false);
}

static SDValue LowerIntrinsicAddrOp(SDValue addrOp, SDLoc &DL,
                                    SelectionDAG &DAG) {
  SDNode *MN;
  if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(addrOp)) {
    const GlobalValue *GV = G->getGlobal();
    if (!isa<GlobalVariable>(GV) ||
        !dyn_cast<GlobalVariable>(GV)->hasAttribute("saddr")) {
      int64_t Offset = G->getOffset();
      MN = DAG.getMachineNode(
          RL78::MOVW_rp_imm, DL, addrOp.getValueType(),
          DAG.getTargetGlobalAddress(GV, DL, MVT::i16, Offset));
      addrOp = SDValue(MN, 0);
    }
  } else if (FrameIndexSDNode *FIN = dyn_cast<FrameIndexSDNode>(addrOp)) {
    int FI = cast<FrameIndexSDNode>(FIN)->getIndex();
    EVT VT = FIN->getValueType(0);
    SDValue TFI = DAG.getTargetFrameIndex(FI, VT);
    SDValue Imm = DAG.getTargetConstant(0, DL, MVT::i16);
    MN = DAG.getMachineNode(RL78::MOVW_rp_stack_slot, DL, VT, TFI, Imm);
    addrOp = SDValue(MN, 0);
  }
  return addrOp;
}

static SDValue LowerBitOpIntrinsic(unsigned int Opcode, SDValue Op,
                                   SelectionDAG &DAG) {
  SDLoc DL(Op);
  SDValue addrOp = Op.getOperand(2);
  addrOp = LowerIntrinsicAddrOp(addrOp, DL, DAG);

  SDValue movToCY =
      DAG.getNode(RL78ISD::MOV1TOCY, DL, MVT::Other, Op.getOperand(0),
                  Op.getOperand(4), Op.getOperand(5));
  SDValue opCY =
      DAG.getNode(Opcode, DL, MVT::Other, movToCY, Op.getOperand(3), addrOp);

  SDValue movFromCY = DAG.getNode(RL78ISD::STORE1FROMCY, DL, MVT::Other, opCY,
                                  Op.getOperand(3), addrOp);
  return movFromCY;
}

SDValue RL78TargetLowering::LowerIntrinsicWithChain(SDValue Op,
                                                    SelectionDAG &DAG) const {
  SDLoc DL(Op);
  // Op.dump();
  unsigned IntNo = cast<ConstantSDNode>(Op.getOperand(1))->getZExtValue();
  switch (IntNo) {
  case Intrinsic::rl78_getpswisp: {

    SDValue getPSW = DAG.getNode(
        ISD::INTRINSIC_W_CHAIN, DL,
        DAG.getVTList(Op.getValueType(), Op.getOperand(0).getValueType()),
        Op.getOperand(0),
        DAG.getTargetConstant(Intrinsic::rl78_getpsw, DL, MVT::i16));

    SDValue shr1 = DAG.getNode(ISD::SRL, DL, MVT::i8, getPSW,
                               DAG.getConstant(1, DL, MVT::i8));

    SDValue And3 = DAG.getNode(ISD::AND, DL, MVT::i8, shr1,
                               DAG.getConstant(3, DL, MVT::i8));

    return DAG.getNode(
        ISD::MERGE_VALUES, DL,
        DAG.getVTList(Op.getValueType(), Op.getOperand(0).getValueType()), And3,
        Op.getOperand(0));
  }
  case Intrinsic::rl78_pswie: {

    SDValue GetPSW = DAG.getNode(
        ISD::INTRINSIC_W_CHAIN, DL,
        DAG.getVTList(Op.getValueType(), Op.getOperand(0).getValueType()),
        Op.getOperand(0),
        DAG.getTargetConstant(Intrinsic::rl78_getpsw, DL, MVT::i16));

    SDValue SRL = DAG.getNode(ISD::SRL, DL, MVT::i8, GetPSW,
                              DAG.getConstant(7, DL, Op.getValueType()));

    return DAG.getNode(
        ISD::MERGE_VALUES, DL,
        DAG.getVTList(Op.getValueType(), Op.getOperand(0).getValueType()), SRL,
        Op.getOperand(0));
  }
  case Intrinsic::rl78_mov1: {
    SDValue addrOp = Op.getOperand(2);
    addrOp = LowerIntrinsicAddrOp(addrOp, DL, DAG);
    SDValue movToCY =
        DAG.getNode(RL78ISD::MOV1TOCY, DL, MVT::Other, Op.getOperand(0),
                    Op.getOperand(4), Op.getOperand(5));
    SDValue store1FromCY = DAG.getNode(RL78ISD::STORE1FROMCY, DL, MVT::Other,
                                       movToCY, Op.getOperand(3), addrOp);
    return store1FromCY;
  }
  case Intrinsic::rl78_and1:
    return LowerBitOpIntrinsic(RL78ISD::AND1CY, Op, DAG);
  case Intrinsic::rl78_or1:
    return LowerBitOpIntrinsic(RL78ISD::OR1CY, Op, DAG);
  case Intrinsic::rl78_xor1:
    return LowerBitOpIntrinsic(RL78ISD::XOR1CY, Op, DAG);
  case Intrinsic::rl78_set1:
  case Intrinsic::rl78_clr1: {
    // Op.dump();
    // Op.getOperand(0).dump();
    // Op.getOperand(2).dump();
    SDValue bitOp = Op.getOperand(3);
    if (!isa<ConstantSDNode>(Op.getOperand(3))) {
      if (IntNo == Intrinsic::rl78_set1)
        DAG.getContext()->emitError("set1 2nd argument must be constant");
      else
        DAG.getContext()->emitError("clr1 2nd argument must be constant");
      // Chose bit 0 so we can still select the instruction so we don't end up
      // with a much uglier "Cannot select" fatal error.
      bitOp = DAG.getConstant(0, DL, MVT::i8);
    }
    SDValue addrOp = Op.getOperand(2);
    if (FrameIndexSDNode *FIN = dyn_cast<FrameIndexSDNode>(Op.getOperand(2))) {
      int FI = cast<FrameIndexSDNode>(FIN)->getIndex();
      EVT VT = FIN->getValueType(0);
      SDValue TFI = DAG.getTargetFrameIndex(FI, VT);
      SDValue Imm = DAG.getTargetConstant(0, DL, MVT::i16);
      SDNode *MN =
          DAG.getMachineNode(RL78::MOVW_rp_stack_slot, DL, VT, TFI, Imm);
      addrOp = SDValue(MN, 0);
    }
    return DAG.getNode((IntNo == Intrinsic::rl78_set1) ? RL78ISD::SET1
                                                       : RL78ISD::CLR1,
                       DL, MVT::i8, Op.getOperand(0), bitOp, addrOp);
  }
  case Intrinsic::rl78_not1: {
    SDValue addrOp = Op.getOperand(2);
    if (GlobalAddressSDNode *G =
            dyn_cast<GlobalAddressSDNode>(Op.getOperand(2))) {
      const GlobalValue *GV = G->getGlobal();
      int64_t Offset = G->getOffset();

      if (isa<GlobalVariable>(GV) &&
          dyn_cast<GlobalVariable>(GV)->hasAttribute("saddr")) {
        // we can use xor saddr, #byte
        SDValue Mask = DAG.getTargetConstant(1 << Op.getConstantOperandVal(3),
                                             DL, MVT::i8);
        return SDValue(DAG.getMachineNode(
                           RL78::XOR_saddr_imm, DL, MVT::Other,
                           DAG.getTargetGlobalAddress(GV, DL, MVT::i16, Offset),
                           Mask, Op.getOperand(0)),
                       0);
      }

      SDNode *MN = DAG.getMachineNode(
          RL78::MOVW_rp_imm, DL, Op.getOperand(2).getValueType(),
          DAG.getTargetGlobalAddress(GV, DL, MVT::i16, Offset));
      addrOp = SDValue(MN, 0);
    } else if (FrameIndexSDNode *FIN =
                   dyn_cast<FrameIndexSDNode>(Op.getOperand(2))) {
      int FI = cast<FrameIndexSDNode>(FIN)->getIndex();
      EVT VT = FIN->getValueType(0);
      SDValue TFI = DAG.getTargetFrameIndex(FI, VT);
      SDValue Imm = DAG.getTargetConstant(0, DL, MVT::i16);
      SDNode *MN =
          DAG.getMachineNode(RL78::MOVW_rp_stack_slot, DL, VT, TFI, Imm);
      addrOp = SDValue(MN, 0);
    } else if (ConstantSDNode *CN =
                   dyn_cast<ConstantSDNode>(Op.getOperand(2))) {
      uint64_t imm = CN->getZExtValue() & 0xFFFF;
      if (imm < 0xFF00) {
        SDNode *MN = DAG.getMachineNode(
            RL78::MOVW_rp_imm, DL, Op.getOperand(2).getValueType(),
                                        DAG.getTargetConstant(imm, DL, MVT::i16));
        addrOp = SDValue(MN, 0);
      }
    }
    SDValue loadToCY = DAG.getNode(RL78ISD::LOAD1TOCY, DL, MVT::Other,
                                   Op.getOperand(0), Op.getOperand(3), addrOp);
    SDValue notCY = DAG.getNode(RL78ISD::NOT1CY, DL, MVT::Other, loadToCY);
    SDValue store1FromCY = DAG.getNode(RL78ISD::STORE1FROMCY, DL, MVT::Other,
                                       notCY, Op.getOperand(3), addrOp);
    return store1FromCY;
  }
  }
  return SDValue();
}

static bool isConstantZero(SDValue operand) {
  ConstantSDNode *divisor = dyn_cast<ConstantSDNode>(operand);
  return divisor != nullptr && divisor->getZExtValue() == 0;
}

SDValue
RL78TargetLowering::LowerIntrinsicWithoutChain(SDValue Op,
                                               SelectionDAG &DAG) const {
  SDLoc DL(Op);
  // Op.dump();
  unsigned IntNo = cast<ConstantSDNode>(Op.getOperand(0))->getZExtValue();
  switch (IntNo) {
  case Intrinsic::rl78_rolb: {
    if (!DAG.getMachineFunction().getFunction().hasOptSize())
      return DAG.getNode(ISD::ROTL, DL, MVT::i8, Op.getOperand(1),
                         Op.getOperand(2));
    else
      return LowerLibCall(Op, DAG, GetRotLibCallName(ISD::ROTL, MVT::i8), false,
                          1);
  }
  case Intrinsic::rl78_rorb: {
    if (!DAG.getMachineFunction().getFunction().hasOptSize())
      return DAG.getNode(ISD::ROTR, DL, MVT::i8, Op.getOperand(1),
                         Op.getOperand(2));
    else
      return LowerLibCall(Op, DAG, GetRotLibCallName(ISD::ROTR, MVT::i8), false,
                          1);
  }
  case Intrinsic::rl78_rolw: {
    if (!DAG.getMachineFunction().getFunction().hasOptSize())
      return DAG.getNode(ISD::ROTL, DL, MVT::i16, Op.getOperand(1),
                         Op.getOperand(2));
    else
      return LowerLibCall(Op, DAG, GetRotLibCallName(ISD::ROTL, MVT::i16),
                          false, 1);
  }
  case Intrinsic::rl78_rorw: {
    if (!DAG.getMachineFunction().getFunction().hasOptSize())
      return DAG.getNode(ISD::ROTR, DL, MVT::i16, Op.getOperand(1),
                         Op.getOperand(2));
    else
      return LowerLibCall(Op, DAG, GetRotLibCallName(ISD::ROTR, MVT::i16),
                          false, 1);
  }
  case Intrinsic::rl78_mulu: {
    // Op.getOperand(0).dump();
    SDValue Op0Zext =
        DAG.getNode(ISD::ZERO_EXTEND, DL, MVT::i16, Op.getOperand(1));
    SDValue Op1Zext =
        DAG.getNode(ISD::ZERO_EXTEND, DL, MVT::i16, Op.getOperand(2));
    return DAG.getNode(ISD::MUL, DL, MVT::i16, Op0Zext, Op1Zext);
  }
  case Intrinsic::rl78_divui: {
    if (isConstantZero(Op.getOperand(2))) {
      // CC-RL: When divisor y is 0, 0xFFFF is returned.
      return DAG.getConstant(0xFFFF, DL, MVT::i16);
    }
    if (Subtarget->isRL78S3CoreType()) {
      SDValue ZExt =
          DAG.getNode(ISD::ZERO_EXTEND, DL, MVT::i16, Op.getOperand(2));
      return DAG.getNode(ISD::UDIV, DL, MVT::i16, Op->getOperand(1), ZExt);
    } else {
      return LowerLibCall(Op, DAG, "_COM_divui", false,
                          {Op.getOperand(1), Op.getOperand(2)});
    }
  }
  case Intrinsic::rl78_remui: {
    if (isConstantZero(Op.getOperand(2))) {
      // CC-RL: When divisor y is 0, the lower-order 8 bits of dividend x are
      // returned.
      return DAG.getNode(ISD::EXTRACT_ELEMENT, DL, MVT::i8, Op.getOperand(1),
                         DAG.getConstant(0, DL, MVT::i8));
    }
    if (Subtarget->isRL78S3CoreType()) {
      SDValue ZExt =
          DAG.getNode(ISD::ZERO_EXTEND, DL, MVT::i16, Op.getOperand(2));
      SDValue URem =
          DAG.getNode(ISD::UREM, DL, MVT::i16, Op->getOperand(1), ZExt);
      return DAG.getNode(ISD::TRUNCATE, DL, MVT::i8, URem);
    } else {
      return LowerLibCall(Op, DAG, "_COM_remui", false,
                          {Op.getOperand(1), Op.getOperand(2)});
    }
  }
  case Intrinsic::rl78_remul: {
    if (isConstantZero(Op.getOperand(2))) {
      // CC-RL: When divisor y is 0, the lower-order 16 bits of dividend x are
      // returned.
      return DAG.getNode(ISD::EXTRACT_ELEMENT, DL, MVT::i16, Op.getOperand(1),
                         DAG.getConstant(0, DL, MVT::i16));
    }
    // TODO: optimize for S3 and S1/S2 compiler-rt.
    return LowerLibCall(Op, DAG, "_COM_remul", false,
                        {Op.getOperand(1), Op.getOperand(2)});
  }
  }
  return SDValue();
}

SDValue RL78TargetLowering::LowerIntrinsicVoid(SDValue Op,
                                               SelectionDAG &DAG) const {
  SDLoc DL(Op);
  // Op.dump();
  unsigned IntNo = cast<ConstantSDNode>(Op.getOperand(1))->getZExtValue();
  switch (IntNo) {
  case Intrinsic::rl78_setpswisp: {

    SDValue and3 = DAG.getNode(ISD::AND, DL, MVT::i8, Op.getOperand(2),
                               DAG.getConstant(3, DL, MVT::i8));

    SDValue shl1 = DAG.getNode(ISD::SHL, DL, MVT::i8, and3,
                               DAG.getConstant(1, DL, MVT::i8));

    SDValue getPSW = DAG.getNode(
        ISD::INTRINSIC_W_CHAIN, DL,
        DAG.getVTList(MVT::i8, Op.getOperand(0).getValueType()),
        Op.getOperand(0),
        DAG.getTargetConstant(Intrinsic::rl78_getpsw, DL, MVT::i16));

    SDValue getPSWand = DAG.getNode(ISD::AND, DL, MVT::i8, getPSW,
                                    DAG.getConstant(249, DL, MVT::i8));
    SDValue orPSW = DAG.getNode(ISD::OR, DL, MVT::i8, shl1, getPSWand);
    SDValue setPSW =
        DAG.getNode(ISD::INTRINSIC_VOID, DL, MVT::Other, Op.getOperand(0),
                    DAG.getTargetConstant(Intrinsic::rl78_setpsw, DL,
                                          getPointerTy(DAG.getDataLayout())),
                    orPSW);

    return setPSW;
  }
  }
  return SDValue();
}

SDValue RL78TargetLowering::LowerLOAD(SDValue Op, SelectionDAG &DAG) const {
  LoadSDNode *LD = cast<LoadSDNode>(Op);
  EVT MemVT = LD->getMemoryVT();
  SDValue Chain = LD->getChain();
  SDValue Ptr = LD->getBasePtr();
  Align align = LD->getAlign();
  SDLoc dl(Op);
  // If this is an unaligned load and the target doesn't support it,
  // expand it.
  if (!allowsMemoryAccess(*DAG.getContext(), DAG.getDataLayout(), MemVT,
                          LD->getAddressSpace(), align)) {
    unsigned IncrementSize = (MemVT.getSizeInBits() >> 1) / 8;

    // Load the value in two parts (little endian).
    SDValue Lo =
        DAG.getLoad(MVT::i8, dl, Chain, Ptr, LD->getPointerInfo(), align,
                    LD->getMemOperand()->getFlags(), LD->getAAInfo());
    SDValue HiPtr = DAG.getObjectPtrOffset(dl, Ptr, TypeSize::Fixed(IncrementSize));
    SDValue Hi = DAG.getLoad(MVT::i8, dl, Chain, HiPtr,
                             LD->getPointerInfo().getWithOffset(IncrementSize),
                             MinAlign(align.value(), IncrementSize),
                             LD->getMemOperand()->getFlags(), LD->getAAInfo());

    SDValue SubRegHi = DAG.getTargetConstant(RL78::sub_hi, dl, MVT::i8);
    SDValue SubRegLow = DAG.getTargetConstant(RL78::sub_lo, dl, MVT::i8);

    SDValue In16 =
        DAG.getTargetConstant(RL78::RL78RPRegsRegClassID, dl, MVT::i16);
    SDValue Regs[5] = {In16, Hi, SubRegHi, Lo, SubRegLow};
    SDNode *node =
        DAG.getMachineNode(TargetOpcode::REG_SEQUENCE, dl, MVT::i16, Regs);

    SDValue OutChains[2] = {SDValue(Hi.getNode(), 1), SDValue(Lo.getNode(), 1)};
    SDValue OutChain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other, OutChains);
    SDValue Ops[2] = {SDValue(node, 0), OutChain};
    SDValue lowered = DAG.getMergeValues(Ops, dl);
    return lowered;
  }
  return Op;
}

SDValue RL78TargetLowering::LowerSTORE(SDValue Op, SelectionDAG &DAG) const {
  StoreSDNode *ST = cast<StoreSDNode>(Op);
  EVT MemVT = ST->getMemoryVT();
  SDValue Chain = ST->getChain();
  SDValue Ptr = ST->getBasePtr();
  Align align = ST->getAlign();
  SDLoc dl(Op);
  if (!allowsMemoryAccess(*DAG.getContext(), DAG.getDataLayout(), MemVT,
                          ST->getAddressSpace(), align)) {

    SDValue SubRegHi = DAG.getTargetConstant(RL78::sub_hi, dl, MVT::i8);
    SDValue SubRegLow = DAG.getTargetConstant(RL78::sub_lo, dl, MVT::i8);

    SDNode *Hi = DAG.getMachineNode(TargetOpcode::EXTRACT_SUBREG, dl, MVT::i8,
                                    ST->getValue(), SubRegHi);
    SDNode *Lo = DAG.getMachineNode(TargetOpcode::EXTRACT_SUBREG, dl, MVT::i8,
                                    ST->getValue(), SubRegLow);

    unsigned IncrementSize = (MemVT.getSizeInBits() >> 1) / 8;
    SDValue Store1 =
        DAG.getTruncStore(Chain, dl, SDValue(Lo, 0), Ptr, ST->getPointerInfo(),
                          MVT::i8, align, ST->getMemOperand()->getFlags());
    Ptr = DAG.getObjectPtrOffset(dl, Ptr, TypeSize::Fixed(IncrementSize));
    SDValue Store2 =
        DAG.getTruncStore(Chain, dl, SDValue(Hi, 0), Ptr,
                          ST->getPointerInfo().getWithOffset(IncrementSize),
                          MVT::i8, MinAlign(align.value(), IncrementSize),
                          ST->getMemOperand()->getFlags(), ST->getAAInfo());

    SDValue lowered =
        DAG.getNode(ISD::TokenFactor, dl, MVT::Other, Store1, Store2);
    return lowered;
  }
  return Op;
}

SDValue RL78TargetLowering::LowerSETCC(SDValue Op, SelectionDAG &DAG) const {
  if (Op.getOperand(0).getValueType() == MVT::i64) {
  }
  llvm_unreachable("Should not custom lower this SETCC!");
}

static SDValue LowerLOW16(SDValue Op, SelectionDAG &DAG) {
  // Op.dump();
  // Op.getOperand(0).dump();
  // VK_RL78_LOW16

  // SDValue Result = DAG.getTargetGlobalAddress(GV, SDLoc(Op), VT, Offset);
  return Op;
}

SDValue RL78TargetLowering::PerformBRCCCombine(SDNode *N,
                                               DAGCombinerInfo &DCI) const {
  // TODO: revisit this in GCC-1920
  // Convert a ? (0-b) back to a + b ? 0
  if (N->getOpcode() == ISD::BR_CC &&
      (N->getOperand(2)->getOpcode() == ISD::SUB &&
          N->getOperand(2)->hasOneUse() &&
           N->getOperand(2)->getOperand(0).getOpcode() == ISD::Constant &&
           N->getOperand(2)->getConstantOperandVal(0) == 0 ||
       N->getOperand(3)->getOpcode() == ISD::SUB &&
          N->getOperand(3)->hasOneUse() &&
           N->getOperand(3)->getOperand(0).getOpcode() == ISD::Constant &&
           N->getOperand(3)->getConstantOperandVal(0) == 0)) {
    SDLoc dl(N);
    SDValue Chain = N->getOperand(0);
    ISD::CondCode CC = cast<CondCodeSDNode>(N->getOperand(1))->get();
    SDValue Dest = N->getOperand(4);
    SDValue A, B;
    if (N->getOperand(2)->getOpcode() == ISD::SUB) {
      A = N->getOperand(3);
      B = N->getOperand(2)->getOperand(1);
      CC = ISD::getSetCCSwappedOperands(CC);
    } else {
      A = N->getOperand(2);
      B = N->getOperand(3)->getOperand(1);
    }
    EVT VT = A.getValueType();
    SDValue Sum = DCI.DAG.getNode(ISD::ADD, dl, VT, A, B);
    return DCI.DAG.getNode(ISD::BR_CC, SDLoc(N), MVT::Other, Chain,
                           DCI.DAG.getCondCode(CC), Sum,
                           DCI.DAG.getConstant(0, dl, VT), Dest);
  }
  return SDValue();
}

SDValue RL78TargetLowering::PerformBRCONDCombine(SDNode *N, DAGCombinerInfo &DCI) const {
  // TODO: revisit this in GCC-1920
  if (N->getOpcode() == ISD::BRCOND &&
      N->getOperand(1)->getOpcode() == ISD::SETCC &&
      N->getOperand(1)->getOperand(0).getValueType() == MVT::i32) {
    // Combine:
    // i1 = setcc t5, Imm, CC
    // ch = brcond t0, t8,
    // to:
    // CMP HIGHW(t5), HIGW(Imm)
    // SKNZ
    // CMP LOWW(t5), LOWW(Imm)
    // ch = brcond t0, t8,

    SDLoc dl(N);
    SDValue SetCC = N->getOperand(1);
    SDValue Chain = N->getOperand(0);
    SDValue Dest = N->getOperand(2);

    SDValue LoIndex = DCI.DAG.getConstant(0, dl, MVT::i16);
    SDValue HiIndex = DCI.DAG.getConstant(1, dl, MVT::i16);

    SDValue LowLHS = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                     SetCC->getOperand(0), LoIndex);
    SDValue HighLHS = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                      SetCC->getOperand(0), HiIndex);
    SDValue LowRHS = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                     SetCC->getOperand(1), LoIndex);
    SDValue HighRHS = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                      SetCC->getOperand(1), HiIndex);
    ISD::CondCode CC =
        cast<CondCodeSDNode>(N->getOperand(1)->getOperand(2))->get();

    // defer <0 and >=0 to LowerBR_CC
    if (SetCC->getOperand(1).getOpcode() == ISD::Constant &&
        ((cast<ConstantSDNode>(SetCC->getOperand(1))->getZExtValue() == 0 &&
          CC == ISD::SETLT) ||
         (cast<ConstantSDNode>(SetCC->getOperand(1))->getSExtValue() == 0 &&
          CC == ISD::SETGE) ||
         (cast<ConstantSDNode>(SetCC->getOperand(1))->getSExtValue() == -1 &&
          CC == ISD::SETGT))) {
      return SDValue();
    }


    SDValue HighCompare =  DCI.DAG.getConstant(IntCondCCodeSign(CC), dl, MVT::i8);
    SDValue Cmp = DCI.DAG.getNode(RL78ISD::CMP, dl, MVT::Glue, HighLHS, HighRHS,
                                  HighCompare);
    SDValue LowCmp = DCI.DAG.getNode(RL78ISD::LOWCMP, dl, MVT::Glue, LowLHS,
                                     LowRHS, Cmp);

    SDValue TargetCC = DCI.DAG.getConstant(IntCondCCodeToICC(CC), dl, MVT::i8);
    return DCI.DAG.getNode(RL78ISD::BRCC, dl, MVT::Other, Chain, Dest, TargetCC,
                           LowCmp);
  }

  return SDValue();
}

static SDValue AsMULHCandidate(SDValue op, ISD::NodeType opcode,
                               SelectionDAG &DAG, SDLoc dl) {
  assert(opcode == ISD::ZERO_EXTEND || opcode == ISD::SIGN_EXTEND);
  if (op->getOpcode() == ISD::Constant) {
    if (opcode == ISD::ZERO_EXTEND &&
        cast<ConstantSDNode>(op)->getZExtValue() <= UINT16_MAX)
      return DAG.getConstant(cast<ConstantSDNode>(op)->getZExtValue(), dl,
                             MVT::i16);

    if (opcode == ISD::SIGN_EXTEND &&
        cast<ConstantSDNode>(op)->getSExtValue() >= INT16_MIN &&
        cast<ConstantSDNode>(op)->getSExtValue() <= INT16_MAX)
      return DAG.getConstant(cast<ConstantSDNode>(op)->getSExtValue(), dl,
                             MVT::i16);
  }
  if (op->getOpcode() == opcode &&
      op.getOperand(0).getValueType() == MVT::i16) {
    return op.getOperand(0);
  }
  return SDValue();
}

SDValue RL78TargetLowering::PerformMULCombine(SDNode *N,
                                              DAGCombinerInfo &DCI) const {
  SDLoc dl(N);
  ISD::NodeType op = ISD::DELETED_NODE;
  SDValue RHS, LHS;

  if (N->getOpcode() == ISD::MUL && N->getValueType(0) == MVT::i32) {
    RHS = AsMULHCandidate(N->getOperand(0), ISD::SIGN_EXTEND, DCI.DAG, dl);
    LHS = AsMULHCandidate(N->getOperand(1), ISD::SIGN_EXTEND, DCI.DAG, dl);
    if (RHS && LHS)
      op = ISD::SMUL_LOHI;
    else {
      RHS = AsMULHCandidate(N->getOperand(0), ISD::ZERO_EXTEND, DCI.DAG, dl);
      LHS = AsMULHCandidate(N->getOperand(1), ISD::ZERO_EXTEND, DCI.DAG, dl);
      if (RHS && LHS)
        op = ISD::UMUL_LOHI;
    }
  }
  if (op != ISD::DELETED_NODE) {

    SDValue LoHi = DCI.DAG.getNode(
        op, dl, DCI.DAG.getVTList(MVT::i16, MVT::i16), RHS, LHS);
    return DCI.DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, LoHi.getValue(0),
                           LoHi.getValue(1));
  } else {
    return SDValue();
  }
}

SDValue
RL78TargetLowering::PerformUDIVREMCombine(SDNode *N, DAGCombinerInfo &DCI,
                                          ISD::NodeType otherNodeType) const {
  SDValue Op0 = N->getOperand(0);
  SDValue Op1 = N->getOperand(1);
  SDValue combined, div, remainder;
  unsigned Opcode = N->getOpcode();
  unsigned DivRemOpc = RL78ISD::DIVWU;
  EVT VT = Op0.getValueType();
  SDLoc dl(N);

  if (VT != MVT::i32)
    return combined;

  SDVTList VTs = DCI.DAG.getVTList(MVT::i16, MVT::i16, MVT::i16, MVT::i16);
  SDValue high = DCI.DAG.getConstant(1, dl, MVT::i16);
  SDValue low = DCI.DAG.getConstant(0, dl, MVT::i16);
  SDValue op0lo = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                  N->getOperand(0), low);
  SDValue op0hi = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                  N->getOperand(0), high);
  SDValue op1lo = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                  N->getOperand(1), low);
  SDValue op1hi = DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                  N->getOperand(1), high);

  for (SDNode::use_iterator UI = Op0.getNode()->use_begin(),
                            UE = Op0.getNode()->use_end();
       UI != UE; ++UI) {
    SDNode *User = *UI;
    if (User == N || User->getOpcode() == ISD::DELETED_NODE ||
        User->use_empty())
      continue;

    unsigned UserOpc = User->getOpcode();
    if ((UserOpc == Opcode || UserOpc == otherNodeType ||
         UserOpc == DivRemOpc) &&
        User->getOperand(0) == Op0 && User->getOperand(1) == Op1) {
      if (!combined) {
        if (UserOpc == otherNodeType) {
          combined = DCI.DAG.getNode(DivRemOpc, SDLoc(N), VTs, op0lo, op0hi,
                                     op1lo, op1hi);

          div = DCI.DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32,
                                combined.getValue(0), combined.getValue(1));
          remainder =
              DCI.DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32,
                              combined.getValue(2), combined.getValue(3));

        } else if (UserOpc == DivRemOpc) {
          combined = SDValue(User, 0);
        } else {
          assert(UserOpc == Opcode);
          continue;
        }
      }
      if (UserOpc == ISD::UDIV)
        DCI.CombineTo(User, div);
      else if (UserOpc == ISD::UREM)
        DCI.CombineTo(User, remainder);
    }
  }
  if (!combined) {
    // Even if we don't need the other results, using divwu is beneficial.
    combined =
        DCI.DAG.getNode(DivRemOpc, SDLoc(N), VTs, op0lo, op0hi, op1lo, op1hi);

    div = DCI.DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, combined.getValue(0),
                          combined.getValue(1));
    remainder = DCI.DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32,
                                combined.getValue(2), combined.getValue(3));
  }

  return Opcode == ISD::UDIV ? div : remainder;
}

SDValue RL78TargetLowering::PerformMULADDCombine(SDNode *N,
                                                 DAGCombinerInfo &DCI) const {
  SDLoc dl(N);
  unsigned op = ISD::DELETED_NODE;
  SDValue MulA, MulB, AddX;
  // Try to combine into MACH/MACHU
  // Assume that the multiplication was already combined to (u/s)mul_lohi.
  if (Subtarget->isRL78S3CoreType() && N->getOpcode() == ISD::ADD &&
      N->getValueType(0) == MVT::i32) {
    if (N->getOperand(0)->getOpcode() == ISD::BUILD_PAIR &&
        (N->getOperand(0)->getOperand(0)->getOpcode() == ISD::SMUL_LOHI ||
         N->getOperand(0)->getOperand(0)->getOpcode() == ISD::UMUL_LOHI)) {
      op = N->getOperand(0)->getOperand(0)->getOpcode() == ISD::SMUL_LOHI
               ? RL78ISD::MACH
               : RL78ISD::MACHU;
      MulA = N->getOperand(0)->getOperand(0)->getOperand(0);
      MulB = N->getOperand(0)->getOperand(0)->getOperand(1);
      AddX = N->getOperand(1);
    } else if (N->getOperand(1)->getOpcode() == ISD::BUILD_PAIR &&
               (N->getOperand(1)->getOperand(0)->getOpcode() ==
                    ISD::SMUL_LOHI ||
                N->getOperand(1)->getOperand(0)->getOpcode() ==
                    ISD::UMUL_LOHI)) {
      op = N->getOperand(1)->getOperand(0)->getOpcode() == ISD::SMUL_LOHI
               ? RL78ISD::MACH
               : RL78ISD::MACHU;
      MulA = N->getOperand(1)->getOperand(0)->getOperand(0);
      MulB = N->getOperand(1)->getOperand(0)->getOperand(1);
      AddX = N->getOperand(0);
    }
  }

  if (op != ISD::DELETED_NODE && AddX->getOpcode() != ISD::Constant &&
      AddX->getOpcode() != ISD::LOAD) {

    SDValue high = DCI.DAG.getConstant(1, dl, MVT::i16);
    SDValue low = DCI.DAG.getConstant(0, dl, MVT::i16);
    SDValue XLo =
        DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16, AddX, low);
    SDValue XHi =
        DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16, AddX, high);

    SDValue LoHi = DCI.DAG.getNode(
        op, dl, DCI.DAG.getVTList(MVT::i16, MVT::i16), XLo, XHi, MulA, MulB);
    return DCI.DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, LoHi.getValue(0),
                           LoHi.getValue(1));
  } else {
    return SDValue();
  }
}

SDValue RL78TargetLowering::PerformXORAddCombine(SDNode *N,
                                                 DAGCombinerInfo &DCI) const {
  SDLoc dl(N);
  unsigned op = ISD::DELETED_NODE;
  SDValue X, Y;

  //  X^0xFFFF + Y <=> Y - 1 - X
  if (N->getValueType(0) == MVT::i16 && !DCI.isBeforeLegalizeOps()) {
    if (N->getOperand(0).getOpcode() == ISD::XOR &&
        N->getOperand(0).getOperand(1).getOpcode() == ISD::Constant &&
        N->getOperand(0).getConstantOperandVal(1) == 0xFFFF) {
      X = N->getOperand(0).getOperand(0);
      Y = N->getOperand(1);
    } else if (N->getOperand(1).getOpcode() == ISD::XOR &&
               N->getOperand(1).getOperand(1).getOpcode() == ISD::Constant &&
               N->getOperand(1).getConstantOperandVal(1) == 0xFFFF) {
      X = N->getOperand(1).getOperand(0);
      Y = N->getOperand(0);
    } else {
      return SDValue();
    }
    SDValue One = DCI.DAG.getConstant(1, dl, MVT::i16, true);
    SDValue Sub1 = DCI.DAG.getNode(ISD::SUB, dl, MVT::i16, Y, One);
    return DCI.DAG.getNode(ISD::SUB, dl, MVT::i16, Sub1, X);
  }
  return SDValue();
}

SDValue RL78TargetLowering::PerformADDCombine(SDNode *N,
                                                 DAGCombinerInfo &DCI) const {
  SDValue MulAddCombine = PerformMULADDCombine(N, DCI);
  if (MulAddCombine.getNode())
    return MulAddCombine;

  SDValue XorAddCombine = PerformXORAddCombine(N, DCI);
  if (XorAddCombine.getNode())
    return XorAddCombine;

  // (x << 1) +2
  // can be replaced with with
  // (x + 1) << 1
  if (!DCI.isBeforeLegalizeOps() &&
      N->getValueType(0) == MVT::i8 && N->getOperand(1)->getOpcode() == ISD::Constant &&
      N->getOperand(0)->getOpcode() == ISD::SHL &&
      N->getOperand(0)->getOperand(1).getOpcode() == ISD::Constant) {
      SDLoc dl(N);
      uint64_t ADDImm = N->getConstantOperandVal(1);
      uint64_t SHImm = N->getOperand(0)->getConstantOperandVal(1);
      SDValue ADD = DCI.DAG.getNode(
          ISD::ADD, dl, MVT::i8, N->getOperand(0)->getOperand(0),
          DCI.DAG.getConstant(ADDImm >> SHImm, dl, MVT::i8));
      return DCI.DAG.getNode(ISD::SHL, dl, MVT::i8, ADD,
                             DCI.DAG.getConstant(SHImm, dl, MVT::i8));
  }

  return SDValue();
}

SDValue RL78TargetLowering::PerformSUBCombine(SDNode *N,
                                                 DAGCombinerInfo &DCI) const {
  // (0 - (x&1) 
  // replace
  // (x << 7/15) >> 7/15 for 8/16 bit
  if (N->getOperand(0)->getOpcode() == ISD::Constant &&
      N->getConstantOperandVal(0) == 0 &&
      N->getOperand(1)->getOpcode() == ISD::AND &&
      N->getOperand(1)->getOperand(1).getOpcode() == ISD::Constant &&
      N->getOperand(1)->getConstantOperandVal(1) == 1) {
    SDLoc dl(N);
    uint16_t SHAmmount;
    EVT VT = N->getValueType(0);
    if (VT == MVT::i16)
      SHAmmount = 15;
    else if (VT == MVT::i8)
      SHAmmount = 7;
    else
      return SDValue();
    SDValue SHL =
        DCI.DAG.getNode(ISD::SHL, dl, VT, N->getOperand(1)->getOperand(0),
                        DCI.DAG.getConstant(SHAmmount, dl, VT));
    return DCI.DAG.getNode(ISD::SRA, dl, VT, SHL,
                           DCI.DAG.getConstant(SHAmmount, dl, VT));
  }

  return SDValue();
}


SDValue RL78TargetLowering::PerformTruncateCombine(SDNode *N,
                                                   DAGCombinerInfo &DCI) const {
  // Trunc (i32 >> 16) to i16 => extract high(i32).
  if (N->getOpcode() == ISD::TRUNCATE && N->getValueType(0) == MVT::i16 &&
      N->getOperand(0)->getOpcode() == ISD::SRL &&
      N->getOperand(0)->getValueType(0) == MVT::i32 &&
      N->getOperand(0)->getOperand(1)->getOpcode() == ISD::Constant &&
      N->getOperand(0)->getConstantOperandVal(1) == 16) {
    SDLoc dl(N);
    SDValue high = DCI.DAG.getConstant(1, dl, MVT::i16);
    return DCI.DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                           N->getOperand(0)->getOperand(0), high);
  }
  return SDValue();
}

bool RL78TargetLowering::isDesirableToCommuteWithShift(
    const SDNode *N, CombineLevel Level) const {
  // Disable reverting and/shl switch made in PerformANDCombine
  if (Level >= CombineLevel::AfterLegalizeTypes &&   
      N->getValueType(0) == MVT::i16 &&
      N->getOpcode() == ISD::SHL &&
      N->getOperand(1)->getOpcode() == ISD::Constant &&
      N->getOperand(0)->getOpcode() == ISD::AND &&
      N->getOperand(0)->getOperand(1)->getOpcode() == ISD::Constant &&
      N->getOperand(0)->getConstantOperandVal(1) < 0x100 && 
      N->getOperand(0)->getOperand(0)->getOpcode() != ISD::SRL) {
    return false;
  }

  // Disable reverting add/shl switch made in PerformADDCombine
  if (Level >= CombineLevel::AfterLegalizeTypes &&
      N->getValueType(0) == MVT::i8 &&
      N->getOpcode() == ISD::SHL &&
      N->getOperand(1)->getOpcode() == ISD::Constant &&
      N->getOperand(0)->getOpcode() == ISD::ADD &&
      N->getOperand(0)->getOperand(1)->getOpcode() == ISD::Constant)
    return false;

  return true;
}

SDValue RL78TargetLowering::PerformANDCombine(SDNode *N,
                                              DAGCombinerInfo &DCI) const {
  SDLoc dl(N);
  assert(N->getOpcode() == ISD::AND);

  if (!DCI.isBeforeLegalizeOps() && N->getValueType(0) == MVT::i16) {

    bool isXNeg =
        N->getOperand(0)->getOpcode() == ISD::XOR &&
        N->getOperand(0)->getOperand(1).getOpcode() == ISD::Constant &&
        N->getOperand(0)->getConstantOperandVal(1) == 0xFFFF;
    bool isYNeg =
        N->getOperand(1)->getOpcode() == ISD::XOR &&
        N->getOperand(1)->getOperand(1).getOpcode() == ISD::Constant &&
        N->getOperand(1)->getConstantOperandVal(1) == 0xFFFF;

    SDValue X = isXNeg ? N->getOperand(0)->getOperand(0) : N->getOperand(0);
    SDValue Y = isYNeg ? N->getOperand(1)->getOperand(0) : N->getOperand(1);

    // (~X & ~Y) change to ~(X | Y)
    if (isXNeg && isYNeg) {
      SDValue OR = DCI.DAG.getNode(ISD::OR, dl, MVT::i16, X, Y);
      return DCI.DAG.getNode(ISD::XOR, dl, MVT::i16, OR,
                             DCI.DAG.getConstant(0xFFFF, dl, MVT::i16));
    }

    // (~X & Y) change to ((X | Y) - X)
    if (isXNeg && !isYNeg) {
      SDValue OR = DCI.DAG.getNode(ISD::OR, dl, MVT::i16, X, Y);
      return DCI.DAG.getNode(ISD::SUB, dl, MVT::i16, OR, X);
    }

     // (X & ~Y) change to (X - (X & Y))
     if (!isXNeg && isYNeg) {
      SDValue AND = DCI.DAG.getNode(ISD::AND, dl, MVT::i16, X, Y);
      return DCI.DAG.getNode(ISD::SUB, dl, MVT::i16, X, AND);
    }

    if (N->getOperand(1)->getOpcode() == ISD::Constant) {
      uint64_t ANDImm = N->getConstantOperandVal(1);
      switch (N->getOperand(0)->getOpcode()) {
      default:
        return SDValue();
      // %0 = SHLW A, 1
      // %1 = AND %0, 0x1XX
      // to
      // %1 = AND %0, 0xXX
      // %0 = SHLW A, 1
      case ISD::SHL:
        if (N->getOperand(0)->getOperand(1).getOpcode() == ISD::Constant &&
            N->getOperand(0)->getOperand(0).getOpcode() != ISD::SRL) {
          uint64_t SHImm = N->getOperand(0)->getConstantOperandVal(1);
          if (((ANDImm >> SHImm) < 0x100) && ((ANDImm & 0x00FF) != 0) && ((ANDImm & 0xFF00) != 0)) {
            // Switch order of AND and SHL
            SDValue AND = DCI.DAG.getNode(
                ISD::AND, dl, MVT::i16, 
                N->getOperand(0)->getOperand(0),
                DCI.DAG.getConstant(ANDImm >> SHImm, dl, MVT::i16));
            return DCI.DAG.getNode(ISD::SHL, dl, MVT::i16, AND,
                                   DCI.DAG.getConstant(SHImm, dl, MVT::i16));
          }
        }
      }
    }
  }
  return SDValue();
}

SDValue RL78TargetLowering::PerformORCombine(SDNode *N,
                                             DAGCombinerInfo &DCI) const {
    SDLoc dl(N);
    assert(N->getOpcode() == ISD::OR);
    
    // if haveNoCommonBitsSet(mask_a, mask_b)
    // Replace
    //   (a & mask_a) or (b & mask_b)
    // with
    //   (a & mask_a) add (b & mask_b)
    if (!DCI.isBeforeLegalizeOps() &&
        N->getValueType(0) == MVT::i16 &&
        DCI.DAG.haveNoCommonBitsSet(N->getOperand(0), N->getOperand(1))) {
    return DCI.DAG.getNode(ISD::ADD, dl, MVT::i16, N->getOperand(0),
                           N->getOperand(1));
    }

    if (!DCI.isBeforeLegalizeOps() && N->getValueType(0) == MVT::i8 &&
        DCI.DAG.haveNoCommonBitsSet(N->getOperand(0), N->getOperand(1)) &&
        N->getOperand(1).getOpcode() == ISD::Constant &&
        N->getConstantOperandVal(1) == 1) {
      auto a = N->getConstantOperandVal(1);
      return DCI.DAG.getNode(RL78ISD::INC, dl, MVT::i8, N->getOperand(0),
                             DCI.DAG.getTargetConstant(1, dl, MVT::i8));
    }

    return SDValue();
}


SDValue RL78TargetLowering::PerformXORCombine(SDNode *N,
                                              DAGCombinerInfo &DCI) const {
    assert(N->getOpcode() == ISD::XOR);
    
    return SDValue();
}

SDValue RL78TargetLowering::PerformSHLCombine(SDNode *N,
                                              DAGCombinerInfo &DCI) const {
  assert(N->getOpcode() == ISD::SHL);
  if (N->getValueType(0) == MVT::i16 &&
      N->getOperand(1).getOpcode() == ISD::Constant &&
      N->getConstantOperandVal(1) == 8 && 
      N->getOperand(0).getOpcode() == ISD::ANY_EXTEND &&
      N->getOperand(0).getOperand(0).getValueType() == MVT::i8) {
    SDLoc dl(N);
    SDValue High = N->getOperand(0).getOperand(0);
    SDValue Low = DCI.DAG.getConstant(0, dl, MVT::i8);
    return DCI.DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i16, Low, High);
  }
  return SDValue();
}

SDValue RL78TargetLowering::PerformDAGCombine(SDNode *N,
                                              DAGCombinerInfo &DCI) const {
  switch (N->getOpcode()) {
  case ISD::BR_CC:
    return PerformBRCCCombine(N, DCI);
  case ISD::BRCOND:
    return PerformBRCONDCombine(N, DCI);
  case ISD::MUL:
      return PerformMULCombine(N, DCI);
  case ISD::UDIV:
      return PerformUDIVREMCombine(N, DCI, ISD::UREM);
  case ISD::UREM:
      return PerformUDIVREMCombine(N, DCI, ISD::UDIV);
  case ISD::ADD:
      return PerformADDCombine(N, DCI);
  case ISD::SUB:
      return PerformSUBCombine(N, DCI);
  case ISD::TRUNCATE:
      return PerformTruncateCombine(N, DCI);
  case ISD::SHL:
      return PerformSHLCombine(N, DCI);
  case ISD::TRAP:
      // A trap will be inserted in a naked function if the trap-unreachable
      // options is specified. In case of pragma inline_asm, this is not what we
      // want, so we combine them here.
      if (DCI.DAG.getMachineFunction().getFunction().hasFnAttribute(
              "inline_asm")) {
      if (N->getOperand(0)->getOpcode() == ISD::INLINEASM)
        return N->getOperand(0);
      if (N->getOperand(0)->getOpcode() == ISD::INTRINSIC_VOID) {
        unsigned IntNo = cast<ConstantSDNode>(N->getOperand(0).getOperand(1))
                             ->getZExtValue();
        // Keep in sync with RL78TargetLowering::ExpandInlineAsm
        switch (IntNo) {
        case Intrinsic::rl78_nop:
        case Intrinsic::rl78_halt:
        case Intrinsic::rl78_stop:
        case Intrinsic::rl78_brk:
        case Intrinsic::rl78_ei:
        case Intrinsic::rl78_di:
          return N->getOperand(0);
        default:
          break;
        }
      }
      }
      return SDValue();            

  case ISD::INLINEASM: {
      // Since the targetexternal symbol was created in the program address
      // space, which can be __far, we need to replace the i32 reference with a
      // i16 reference.
      assert(N->getOperand(1)->getOpcode() == ISD::TargetExternalSymbol);
      if (N->getOperand(1)->getValueType(0) != MVT::i32)
      return SDValue();

      SDLoc dl(N);
      std::vector<SDValue> AsmNodeOperands;
      for (int i = 0; i < N->getNumOperands(); i++) {
      if (N->getOperand(i)->getOpcode() == ISD::TargetExternalSymbol &&
          N->getOperand(i)->getValueType(0) == MVT::i32) {
        ExternalSymbolSDNode *E =
            dyn_cast<ExternalSymbolSDNode>(N->getOperand(i));
        // We use VK_RL78_LAST to create a new node and to not reuse the old,
        // i32 one.
        // TODO: maybe we should fix this at the origin
        // (SelectionDAGBuilder::visitInlineAsm)?
        AsmNodeOperands.push_back(DCI.DAG.getTargetExternalSymbol(
            E->getSymbol(), MVT::i16, RL78MCExpr::VK_RL78_LAST));
      } else {
        AsmNodeOperands.push_back(N->getOperand(i));
      }
      }

      SDValue InlineAsm = DCI.DAG.getNode(
          ISD::INLINEASM, dl, DCI.DAG.getVTList(MVT::Other, MVT::Glue),
          AsmNodeOperands);
      return InlineAsm;
  }
  /*case ISD::ADDRSPACECAST: {
      AddrSpaceCastSDNode* CastNode = dyn_cast<AddrSpaceCastSDNode>(N);
      if(CastNode->getSrcAddressSpace() == RL78AS::FarCode && CastNode->getDestAddressSpace() == RL78AS::FarData || 
         CastNode->getSrcAddressSpace() == RL78AS::FarData && CastNode->getDestAddressSpace() == RL78AS::FarCode) 
          return CastNode->getOperand(0);
  }*/
  case ISD::AND:
      return PerformANDCombine(N, DCI);
  case ISD::OR:
      return PerformORCombine(N, DCI);
  case ISD::XOR:
      return PerformXORCombine(N, DCI);
  default:
      return SDValue();
  }
}

SDValue RL78TargetLowering::LowerDYNAMIC_STACKALLOC(SDValue Op,
                                              SelectionDAG &DAG) const {
  Register SPReg = getStackPointerRegisterToSaveRestore();
  assert(SPReg && "Target cannot require DYNAMIC_STACKALLOC expansion and"
          " not tell us which reg is the stack pointer!");
  SDLoc dl(Op);
  SDNode *Node = Op.getNode();
  EVT VT = Node->getValueType(0);
  SDValue Tmp1 = SDValue(Node, 0);
  SDValue Tmp2 = SDValue(Node, 1);
  SDValue Tmp3 = Node->getOperand(2);
  SDValue Chain = Tmp1.getOperand(0);

  // Chain the dynamic stack allocation so that it doesn't modify the stack
  // pointer when other instructions are using the stack.
  Chain = DAG.getCALLSEQ_START(Chain, 0, 0, dl);

  SDValue Size  = Tmp2.getOperand(1);
  SDValue SP = DAG.getCopyFromReg(Chain, dl, SPReg, VT);
  Chain = SP.getValue(1);
  Align Alignment = cast<ConstantSDNode>(Tmp3)->getAlignValue();
  const TargetFrameLowering *TFL = DAG.getSubtarget().getFrameLowering();
  // TODO: RL78 once we set the stack growth direction back to StackGrowsDown, we 
  // will no longer need to treat this as Custom.
  unsigned Opc = ISD::SUB;

  Align StackAlign = TFL->getStackAlign();
  Tmp1 = DAG.getNode(Opc, dl, VT, SP, Size);       // Value
  if (Alignment > StackAlign)
    Tmp1 = DAG.getNode(ISD::AND, dl, VT, Tmp1,
                       DAG.getConstant(-Alignment.value(), dl, VT));
  Chain = DAG.getCopyToReg(Chain, dl, SPReg, Tmp1);     // Output chain

  Tmp2 = DAG.getCALLSEQ_END(Chain, 0, 0, SDValue(), dl);

  return DAG.getNode(ISD::MERGE_VALUES, dl, DAG.getVTList(VT, MVT::Other), Tmp1,
                         Tmp2);
}

SDValue RL78TargetLowering::LowerOperation(SDValue Op,
                                           SelectionDAG &DAG) const {
  // RL78Core coreType = Subtarget->GetCoreType();
  // Op.dump();
  switch (Op.getOpcode()) {
  default:
    LLVM_DEBUG(Op.dump());
    llvm_unreachable("Should not custom lower this!");
  // TODO: remove.
  case RL78ISD::HI16:
  case RL78ISD::LOW16: {
    SDValue Result =
        withTargetFlags(Op.getOperand(0), RL78MCExpr::VK_RL78_LOWW, DAG);
    return DAG.getNode(RL78ISD::LOW16, SDLoc(Op), MVT::i16, Result);
  }
  // case RL78ISD::HI16: {
  //  SDValue Result = withTargetFlags(Op.getOperand(0),
  //  RL78MCExpr::VK_RL78_HI8, DAG); return DAG.getNode(RL78ISD::HI16,
  //  SDLoc(Op), MVT::i16, Result);
  //}
  case ISD::ADDRSPACECAST:
    if (Op.getValueType() != Op.getOperand(0).getValueType()) {
      llvm_unreachable("Unexpected address space cast");
    }
    return Op.getOperand(0);
  case ISD::SETCC:
    return LowerSETCC(Op, DAG);
  case ISD::LOAD:
    return LowerLOAD(Op, DAG);
  case ISD::STORE:
    return LowerSTORE(Op, DAG);
  case ISD::RETURNADDR:
    return LowerRETURNADDR(Op, DAG, *this, Subtarget);
  case ISD::FRAMEADDR:
    return LowerFRAMEADDR(Op, DAG, Subtarget);
  case ISD::ExternalSymbol:
    return LowerExternalSymbol(Op, DAG);
  case ISD::GlobalAddress:
    return LowerGlobalAddress(Op, DAG);
  case ISD::BlockAddress:
    return LowerBlockAddress(Op, DAG);
  case ISD::JumpTable:
    return LowerJumpTable(Op, DAG);
  case ISD::ConstantPool:
    return LowerConstantPool(Op, DAG);
  case ISD::BR_CC:
    return LowerBR_CC(Op, DAG);
  case ISD::SELECT_CC:
    return LowerSELECT_CC(Op, DAG);
  case ISD::VASTART:
    return LowerVASTART(Op, DAG, *this);
  case ISD::VAARG:
    return LowerVAARG(Op, DAG);
  case ISD::VACOPY:
    return LowerVACOPY(Op, DAG, *this);
  case ISD::AND:
    return LowerAndOrXor(Op, DAG, RL78ISD::ANDMEM);
  case ISD::OR:
    return LowerAndOrXor(Op, DAG, RL78ISD::ORMEM);
  case ISD::XOR:
    return LowerAndOrXor(Op, DAG, RL78ISD::XORMEM);
  case ISD::UDIV:
    return LowerCDIV(Op, DAG, ISD::UDIV);
  case ISD::SDIV:
    return LowerCDIV(Op, DAG, ISD::SDIV);
  case ISD::MUL:
    return LowerMul(Op, DAG);
  case ISD::UMULO:
  case ISD::SMULO:
    return LowerMULO(Op, DAG);

  case ISD::SRA:
  case ISD::SRL:
  case ISD::SHL:
    return LowerShift(Op, DAG);
  case ISD::ROTL:
  case ISD::ROTR:
    return LowerRotate(Op, DAG);
  case ISD::INTRINSIC_W_CHAIN:
    return LowerIntrinsicWithChain(Op, DAG);
  case ISD::INTRINSIC_WO_CHAIN:
    return LowerIntrinsicWithoutChain(Op, DAG);
  case ISD::INTRINSIC_VOID:
    return LowerIntrinsicVoid(Op, DAG);
  case ISD::DYNAMIC_STACKALLOC:
      return LowerDYNAMIC_STACKALLOC(Op, DAG);
  }
}

MachineBasicBlock *RL78TargetLowering::LowerRotate_r_imm(MachineInstr &MI,
                                                         MachineBasicBlock *BB,
                                                         bool rotl) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  // MI.dump();
  // BB->dump();
  assert(MI.getOperand(2).isImm());
  //
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(1));
  //
  unsigned rotAmmount =
      rotl ? MI.getOperand(2).getImm() : 8 - MI.getOperand(2).getImm();
  switch (rotAmmount) {
  case 1:
    BuildMI(*BB, MI, DL, TII->get(RL78::ROL_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    break;
  case 2:
    BuildMI(*BB, MI, DL, TII->get(RL78::ROL_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROL_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    break;
  case 3:
    // Build 3 x rol a, 1.
    BuildMI(*BB, MI, DL, TII->get(RL78::ROL_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROL_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROL_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    break;
  case 4:
    BuildMI(*BB, MI, DL, TII->get(RL78::CLRB_r), RL78::R0);
    BuildMI(*BB, MI, DL, TII->get(RL78::SHRW_rp_i), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill)
        .addImm(4);
    BuildMI(*BB, MI, DL, TII->get(RL78::OR_r_r), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
    break;
  case 5:
    BuildMI(*BB, MI, DL, TII->get(RL78::ROR_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROR_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROR_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    break;
  case 6:
    BuildMI(*BB, MI, DL, TII->get(RL78::ROR_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROR_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    break;
  case 7:
    BuildMI(*BB, MI, DL, TII->get(RL78::ROR_r_1), RL78::R1)
        .addReg(RL78::R1, RegState::Kill);
    break;
  default:
    llvm_unreachable("Invalid imm value for 8 bit rotation!");
  }
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::R1, RegState::Kill);
  // The pseudo instruction is gone now.
  MI.eraseFromParent();
  // BB->dump();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerRotate16_rp_imm(
    MachineInstr &MI, MachineBasicBlock *BB, bool rotl) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  // MI.dump();
  assert(MI.getOperand(2).isImm());
  //
  unsigned rotAmmount =
      rotl ? MI.getOperand(2).getImm() : 16 - MI.getOperand(2).getImm();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(1));

  switch (rotAmmount) {
  case 1: {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV1_cy_r)).addReg(RL78::R1).addImm(7);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROLWC_rp_1), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill);
    break;
  }
  case 2: {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV1_cy_r)).addReg(RL78::R1).addImm(7);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROLWC_rp_1), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROLWC_rp_1), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill);
    break;
  }
  case 3: {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV1_cy_r)).addReg(RL78::R1).addImm(7);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROLWC_rp_1), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROLWC_rp_1), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROLWC_rp_1), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill);
    break;
  }
  case 4:
  case 5:
  case 6:
  case 10:
  case 11:
  case 12:
  case 13:
  case 14: {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOVW_rp_AX), RL78::RP2)
        .addReg(RL78::RP0, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::SHLW_rp_imm), RL78::RP2)
        .addReg(RL78::RP2, RegState::Kill)
        .addImm(rotAmmount); // 4, 5, 6, 10, 11, 12, 13, 14
    BuildMI(*BB, MI, DL, TII->get(RL78::SHRW_rp_i), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill)
        .addImm(16 - rotAmmount); // 12, 11, 10, 6, 5, 4, 3, 2
    BuildMI(*BB, MI, DL, TII->get(RL78::ADDW_rp_rp), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill)
        .addReg(RL78::RP2, RegState::Kill);
    break;
  }
  case 7: {
    BuildMI(*BB, MI, DL, TII->get(RL78::SHRW_rp_i), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill)
        .addImm(0x01);
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV1_r_cy), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
    break;
  }
  case 8:
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
    break;
  case 9: {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV1_cy_r)).addReg(RL78::R1).addImm(7);
    BuildMI(*BB, MI, DL, TII->get(RL78::ROLWC_rp_1), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
    break;
  }
  case 15: {
    // Do right shift with 1 first, this will take care of the lower 15 bits,
    // CY will contain the value which needs to go at the top.
    BuildMI(*BB, MI, DL, TII->get(RL78::SHRW_rp_i), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill)
        .addImm(1);
    // Copy the value of CY into bit 7 of high part.
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV1_r_cy), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;
  }
  default:
    llvm_unreachable("Invalid imm value for 16 bit rotation!");
  }
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  // The pseudo instruction is gone now.
  MI.eraseFromParent();
  // BB->dump();
  return BB;
}

MachineBasicBlock *
RL78TargetLowering::LowerAndOrXor16_rp_rp(unsigned int opcode, MachineInstr &MI,
                                          MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  // MI.dump();
  //
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(1));

  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(MI.getOperand(2).getReg(), 0, RL78::sub_hi);

  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(MI.getOperand(2).getReg(), 0, RL78::sub_lo);

  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);

  // The pseudo instruction is gone now.
  MI.eraseFromParent();
  // BB->dump();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerAndOrXor16_rp_memri(
    unsigned int opcode, unsigned int opcode2, MachineInstr &MI,
    MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  // MI.dump();
  // BB->dump();
  unsigned Offset = MI.getOperand(3).getImm();

  if (Offset > 255) {
    BuildMI(*BB, MI, DL, TII->get(RL78::LOAD16_rp_rbci), RL78::RP0)
        .add(MI.getOperand(2))
        .addImm(Offset);

    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP4).add(MI.getOperand(1));

    BuildMI(*BB, MI, DL, TII->get(opcode2), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R5, RegState::Kill);

    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);

    BuildMI(*BB, MI, DL, TII->get(opcode2), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R4, RegState::Kill);

  } else {

    // First insert the copies into AX and HL:
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(1));
    MI.getOperand(1).ChangeToRegister(RL78::RP0, false);

    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP6).add(MI.getOperand(2));
    MI.getOperand(2).ChangeToRegister(RL78::RP6, false);

    if (isFPUsed(BB)) {
      BuildMI(*BB, MI, DL, TII->get(RL78::PUSH_rp))
          .addReg(RL78::RP6, RegState::Kill);
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::POP_rp), RL78::RP6);
    }

    BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::RP6)
        .addImm(Offset + 1);

    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);

    BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::RP6, RegState::Kill)
        .addImm(Offset);
  }

  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);

  // The pseudo instruction is gone now.
  MI.eraseFromParent();
  // BB->dump();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerAndOrXor16_rp_abs16(
    unsigned int opcode, MachineInstr &MI, MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

  unsigned Rs1 = MI.getOperand(1).getReg();
  const GlobalValue *global = MI.getOperand(2).getGlobal();
  unsigned offset = MI.getOperand(2).getOffset();
  unsigned Rd = MI.getOperand(0).getReg();

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
      .addReg(Rs1, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addGlobalAddress(global, offset + 1);

  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addGlobalAddress(global, offset);

  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Rd)
      .addReg(RL78::RP0, RegState::Kill);

  MI.eraseFromParent();
  return BB;
}

static bool IsMemr(MachineInstr &MI) {
  return MI.getOpcode() == RL78::CMPW_rp_memri ||
         MI.getOpcode() == RL78::CMP_r_memri ||
         MI.getOpcode() == RL78::CMP_r_memrr;
}

MachineBasicBlock *
RL78TargetLowering::LowerSignedCMP0(bool cmpw, MachineInstr &MI,
                                    MachineBasicBlock *BB) const {
  // The sign operand is the last explicit operand.
  if (MI.getOperand(MI.getNumExplicitOperands() - 1).getImm() == 0)
    return BB;
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  if (MI.getOpcode() == RL78::CMP0_r) {
    // BB->dump();
    bool isKill = MI.getOperand(0).isKill();
    MI.getOperand(0).setIsKill(false);
    unsigned Rs0 = MI.getOperand(0).getReg();
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(Rs0, isKill ? RegState::Kill : 0)
        .addImm(7);
    // BB->dump();
    return BB;
  } else if (MI.getOpcode() == RL78::CMP0_abs16) {
    BuildMI(*BB, MI, DL, TII->get(RL78::LOAD8_r_abs16), RL78::R1)
        .add(MI.getOperand(0));
    // Change instruction: CMP0_abs16 -> CMP0_r.
    BuildMI(*BB, MI, DL, TII->get(RL78::CMP0_r)).addReg(RL78::R1);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    MI.eraseFromParent();
    // BB->dump();
    return BB;

  } else if (MI.getOpcode() == RL78::CMP0_saddr) {
    // BB->dump();
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_saddrx))
        .add(MI.getOperand(0))
        .addImm(7);
    // BB->dump();
    return BB;
  }
  return BB;
}

// Signed comparison: Insert 2 xor1 instructions to
// handle the sign bit as follows: xor1 CY, <op0> + xor1 CY, <op1> for example
// if we compare 1 and 0xFF and let's consider the condition is LT, then CY
// flag needs to be 1: CMP operation is dst - src => 1 - 0xFF => 2 and borrow
// out of bit 7 so CY is set to 1. If the comparison is unsigned (1 - 255) the
// result is correct for LT (1 < 255). If the comparison is signed (1 - (-1))
// the result is incorrect for LT (because 1 > -1), this is why we need take
// the sign bits into consideration: xor1 CY, 0 (sign bit of 1) => CY = 1 xor1
// CY, 1 (sign bit of 0xFF) => CY = 0 which is the correct result for LT (1 >
// -1) Another solution would be to insert xor <op0>, #0x80 + xor <op1>, #0x80
// before the CMP hower that solution requires writing those registers so the
// unchanged values need to be backed up if they are used later on (decreased
// reg pressure).
MachineBasicBlock *
RL78TargetLowering::LowerSignedCMP(MachineInstr &MI,
                                   MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

  // If unsigned comparison nothing to do.
  // The sign operand is the last explicit operand.
  if (MI.getOperand(MI.getNumExplicitOperands() - 1).getImm() == 0) {
    if (MI.getOperand(0).isReg()) {
      BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1)
          .add(MI.getOperand(0));
      MI.getOperand(0).ChangeToRegister(RL78::R1, false);
    }
    if (MI.getOpcode() != RL78::CMP_r_r) {
      if (MI.getOperand(1).isReg()) {
        BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP6)
            .add(MI.getOperand(1));
        MI.getOperand(1).ChangeToRegister(RL78::RP6, false);
      }
      if (MI.getOperand(2).isReg()) {
        BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R2)
            .add(MI.getOperand(2));
        MI.getOperand(2).ChangeToRegister(RL78::R2, false);
      }
    }
    return BB;
  }

  switch (MI.getOpcode()) {
  default:
    llvm_unreachable("Cannot lower this instruction!");
  case RL78::CMP_saddr_imm:
    // Change instruction: CMP_saddr_imm ->
    // mov a, 0x80
    // xor a, saddr
    // cmp a, ((imm ^ 0x80)+1)
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV_r_imm), RL78::R1).addImm(0x80);
    BuildMI(*BB, MI, DL, TII->get(RL78::XOR_r_saddr), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .add(MI.getOperand(0));
    BuildMI(*BB, MI, DL, TII->get(RL78::CMP_r_imm))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(((MI.getOperand(1).getImm() & 0xFF) ^ 0x80));
    MI.eraseFromParent();
    break;
  case RL78::CMP_abs16_imm:
    if (MI.getOperand(1).getImm() & 0x80) {
      BuildMI(*BB, MI, DL, TII->get(RL78::MOV_r_imm), RL78::R1).addImm(0x80);
      BuildMI(*BB, MI, DL, TII->get(RL78::XOR_r_abs16), RL78::R1)
          .addReg(RL78::R1, RegState::Kill)
          .add(MI.getOperand(0));
      BuildMI(*BB, MI, DL, TII->get(RL78::CMP_r_imm))
          .addReg(RL78::R1, RegState::Kill)
          .addImm(((MI.getOperand(1).getImm() & 0xFF) ^ 0x80));
    } else {
      BuildMI(*BB, MI, DL, TII->get(RL78::LOAD8_r_abs16), RL78::R1)
          .add(MI.getOperand(0));
      BuildMI(*BB, MI, DL, TII->get(RL78::CMP_r_imm))
          .addReg(RL78::R1)
          .add(MI.getOperand(1));
      BuildMI(*BB, MI, DL, TII->get(RL78::XOR1_cy_r))
          .addReg(RL78::R1, RegState::Kill)
          .addImm(7);
      if (MI.getOperand(1).getImm() & 0x80)
        BuildMI(*BB, MI, DL, TII->get(RL78::NOT1_cy));
    }
    MI.eraseFromParent();
    break;

  case RL78::CMP_r_imm:
      // Change op0 to A.
      // xor1_cy_A.
      // if imm negative, NOT1_cy.
      BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1)
          .add(MI.getOperand(0));
      MI.getOperand(0).ChangeToRegister(RL78::R1, false);
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::XOR1_cy_r))
          .addReg(RL78::R1, RegState::Kill)
          .addImm(7);
      if (MI.getOperand(1).getImm() & 0x80)
        BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
                TII->get(RL78::NOT1_cy));
    break;

  case RL78::CMP_r_r:
    // Change op0 to A.
    // Next: xor1_cy_a.
    // Next: mov_A_op1.
    // Next: xor1_cy_a.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::R1, false);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::MOV_A_r), RL78::R1)
        .add(MI.getOperand(1));
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;

  case RL78::CMP_r_abs16:
    // Change op0 to A.
    // Next: xor1_cy_A.
    // Next: mov_A_op1.
    // Next: xor1_cy_A.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::R1, false);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::LOAD8_r_abs16), RL78::R1)
        .add(MI.getOperand(1));
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;

  case RL78::CMP_r_saddr:
    // Change op0 to A.
    // Next: xor1_cy_A.
    // Next: xor1_cy_op1.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::R1, false);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_saddrx))
        .add(MI.getOperand(1))
        .addImm(7);
    break;

  case RL78::CMP_r_memri:
    // Change op0 to A.
    // Next: xor1_cy_A.
    // Next: mov_A_op1.
    // Next: xor1_cy_A.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::R1, false);

    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP6).add(MI.getOperand(1));
    MI.getOperand(1).ChangeToRegister(RL78::RP6, false);

    if (isFPUsed(BB)) {
      BuildMI(*BB, MI, DL, TII->get(RL78::PUSH_rp))
          .addReg(RL78::RP6, RegState::Kill);
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::POP_rp), RL78::RP6);
    }

    if (MI.getOperand(2).getImm() == 0) {
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::XOR1_cy_memr))
          .add(MI.getOperand(1))
          .addImm(7);
    } else {
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::XOR1_cy_r))
          .addReg(RL78::R1, RegState::Kill)
          .addImm(7);
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::LOAD8_r_memHLi), RL78::R1)
          .add(MI.getOperand(1))
          .add(MI.getOperand(2));
    }
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;

  case RL78::CMP_r_memrr:
    // Change op0 to A.
    // Next: xor1_cy_A.
    // Next: MOV_A_op1.
    // Next: xor1_cy_A.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::R1, false);

    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP6).add(MI.getOperand(1));
    MI.getOperand(1).ChangeToRegister(RL78::RP6, false);

    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R2).add(MI.getOperand(2));
    MI.getOperand(2).ChangeToRegister(RL78::R2, false);

    if (isFPUsed(BB)) {
      BuildMI(*BB, MI, DL, TII->get(RL78::PUSH_rp))
          .addReg(RL78::RP6, RegState::Kill);
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::POP_rp), RL78::RP6);
    }

    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::LOAD8_r_memrr), RL78::R1)
        .add(MI.getOperand(1))
        .add(MI.getOperand(2));

    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;
  }

  return BB;
}

MachineBasicBlock *
RL78TargetLowering::LowerSignedCMPW(MachineInstr &MI,
                                    MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  // TODO: think about volatile if we can use xor1 with saddr 8 bit load.
  // If unsigned comparison nothing to do.
  // The sign operand is the last explicit operand.
  if (MI.getOperand(MI.getNumExplicitOperands() - 1).getImm() == 0) {
    if (MI.getOperand(0).isReg()) {
      BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
          .add(MI.getOperand(0));
      MI.getOperand(0).ChangeToRegister(RL78::RP0, false);
    }
    return BB;
  }
  
  switch (MI.getOpcode()) {
  default:
    llvm_unreachable("Cannot lower this instruction!");

  case RL78::CMPW_rp_imm:
    // Change op0 to AX.
    // xor1_cy_A.
    // if imm negative, NOT1_cy.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::RP0, false);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        // RP0 instead of R1 to track register liveness.
        // We revert it to R1 in RL78InsertExchangeInstructions
        .addReg(RL78::RP0)
        .addImm(7);
    if (MI.getOperand(1).getImm() & 0x8000)
      BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
              TII->get(RL78::NOT1_cy));
    break;

  case RL78::CMPW_rp_rp:
    // Change op0 to AX.
    // Next: xor1_cy_AX.hi.
    // Next: MOV_A_op1.hi.
    // Next: xor1_cy_a.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::RP0, false);
    MI.getOperand(1).setIsKill(false);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::COPY))
        .addReg(RL78::R1, RegState::Define)
        .addReg(MI.getOperand(1).getReg(), 0, RL78::sub_hi);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;

  case RL78::CMPW_rp_abs16:
    // Change op0 to AX.
    // Next: xor1_cy_A.
    // Next: load ax, abs16.
    // Next: xor1_cy_A.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::RP0, false);

    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::LOAD16_rp_abs16), RL78::RP0)
        .add(MI.getOperand(1));
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;

  case RL78::CMPW_rp_saddr:
    // Change op0 to AX.
    // Next: xor1_cy_A.
    // Next: load AX, saddr.
    // Next: xor1_cy_A.
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::RP0, false);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::LOAD16_rp_saddrp), RL78::RP0)
        .add(MI.getOperand(1));
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::XOR1_cy_r))
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;
  }

  return BB;
}


MachineBasicBlock *
RL78TargetLowering::LowerSignedCMPWMem(MachineInstr &MI,
                                       MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  // BB->dump();
  // First insert the copies into AX and HL:
  // AX = COPY %0.
  // HL = COPY %1.
  // CMPW AX, [HL+byte].

  bool fpUsed = isFPUsed(BB);
  if (fpUsed) {
    BuildMI(*BB, MI, DL, TII->get(RL78::PUSH_rp))
        .addReg(RL78::RP6, RegState::Kill);
    // TODO: CFA.
  }

  BB = Lower16bitAXSrc(MI, Lower16bitAXSrc(MI, BB, 1, RL78::RP6));
  // If unsigned comparison nothing else to do.
  assert(MI.getOperand(3).isImm() && "Invalid CMPW instruction operand(3)!");
  if (MI.getOperand(3).getImm() == 0)
    return BB;
  // Second we insert XOR1 instrucitons (see LowerSignedCMP for a detailed
  // explanation) The final sequence will look like this: AX = COPY %0 HL = COPY
  // %1 CMPW AX, [HL+byte] XOR1 Cy, A.7 MOV A, [HL+byte+1] XOR1 Cy, A.7.
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::XOR1_cy_r))
      .addReg(RL78::R1, RegState::Kill)
      .addImm(7);
  //
  assert(MI.getOperand(2).isImm() && (MI.getOperand(2).getImm() % 2 == 0) &&
         "Invalid CMPW instruction operand(2)!");
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::LOAD16_rp_memHLi), RL78::RP0)
      .addReg(RL78::RP6, RegState::Kill)
      .addImm(MI.getOperand(2).getImm());
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::XOR1_cy_r))
      .addReg(RL78::R1, RegState::Kill)
      .addImm(7);

  if (fpUsed) {
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI), 2), DL,
            TII->get(RL78::POP_rp), RL78::RP6);
    // TODO: CFA.
  }
  //
  // BB->dump();
  return BB;
}

static bool LowerXorSpecialCases(unsigned int opcode, MachineInstr &MI, MachineBasicBlock *BB) {
    if(MI.getOpcode() != RL78::XOR16_rp_imm)
        return false;

    DebugLoc DL = MI.getDebugLoc();
    MachineFunction *MF = BB->getParent();
    const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

    //~X <=> X ^ 0xFFFF <=> -1 - X.
    if ((MI.getOperand(2).getImm() & 0xFFFF) == 0xFFFF) {
        BuildMI(*BB, MI, DL, TII->get(RL78::MOVW_rp_imm), RL78::RP0).addImm(0xFFFF);
        BuildMI(*BB, MI, DL, TII->get(RL78::SUBW_rp_rp), RL78::RP0)
            .addReg(RL78::RP0)
            .add(MI.getOperand(1));
        BuildMI(*BB, MI, DL, TII->get(RL78::COPY))
            .add(MI.getOperand(0))
            .addReg(RL78::RP0, RegState::Kill);
        MI.eraseFromParent();
        return true;
    }

    return false;
}

MachineBasicBlock *RL78TargetLowering::LowerAndOrXor16_rp_imm(
    unsigned int opcode, MachineInstr &MI, MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  // BB->dump();
  unsigned ImmLo = (unsigned)MI.getOperand(2).getImm() & 0xFF;
  unsigned ImmHi = ((unsigned)MI.getOperand(2).getImm() >> 8) & 0xFF;

  if(LowerXorSpecialCases(opcode, MI, BB))
      return BB;

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(1));
  // Part Low -> rs = R0    Part High -> rs = R1
  // ImmLo == 0x00 -> AND  -> clrb rs.
  // ImmLo == 0x00 -> OR   -> no instruction needs to be generated.
  // ImmLo == 0x00 -> XOR  -> no instruction needs to be generated.
  // ImmLo == 0xFF -> AND  -> no instruction needs to be generated.
  // ImmLo == 0xFF -> OR   -> mov rs, 0xff
  // ImmLo == 0xFF -> XOR  -> xch r1, r0 && xor r1, ImmLo
  // ImmLo != 0x00 && ImmLo != 0xff  -> xch r1, r0 && opcode r1, ImmLo
  // Part Low
  if (ImmLo == 0x00 && opcode == RL78::AND_r_imm) {
    BuildMI(*BB, MI, DL, TII->get(RL78::CLRB_r), RL78::R0);
  } else if ((ImmLo != 0xff && opcode == RL78::AND_r_imm) ||
             (ImmLo != 0x00 &&
              (opcode == RL78::OR_r_imm || opcode == RL78::XOR_r_imm))) {
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);

    BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addImm(ImmLo);

    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
  } else if (opcode == RL78::OR_r_imm && ImmLo == 0xff) {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV_r_imm), RL78::R0).addImm(ImmLo);
  }
  // Part High
  if (ImmHi == 0x00 && opcode == RL78::AND_r_imm) {
    BuildMI(*BB, MI, DL, TII->get(RL78::CLRB_r), RL78::R1);
  } else if ((ImmHi != 0xff && opcode == RL78::AND_r_imm) ||
             (ImmHi != 0x00 &&
              (opcode == RL78::OR_r_imm || opcode == RL78::XOR_r_imm))) {

    BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addImm(ImmHi);
  } else if (ImmHi == 0xff && opcode == RL78::OR_r_imm) {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV_r_imm), RL78::R1).addImm(ImmHi);
  }

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);

  // The pseudo instruction is gone now.
  MI.eraseFromParent();
  // BB->dump();
  return BB;
}

static bool isCCRegDead(MachineInstr &MI) {
  //
  for (unsigned i = MI.getNumExplicitOperands(), e = MI.getNumOperands();
       i != e; ++i) {
    if (MI.getOperand(i).isReg() &&
        (MI.getOperand(i).getReg() == RL78::CCreg) && MI.getOperand(i).isDef())
      return MI.getOperand(i).isDead();
  }
  //
  return false;
}

static bool IsCarryDead(MachineInstr &MI) {
  for (int i = 0; i < MI.getNumOperands(); i++)
    if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == RL78::CCreg &&
        MI.getOperand(i).isDead())
      return true;
  return false;
}

MachineBasicBlock *
RL78TargetLowering::LowerADDE_SUBE_rp_rp(unsigned int opcode, MachineInstr &MI,
                                         MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

  unsigned Rs1 = MI.getOperand(1).getReg();
  unsigned Rs2 = MI.getOperand(2).getReg();
  unsigned Rd = MI.getOperand(0).getReg();

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
      .addReg(Rs1, RegState::Kill);

  if (IsCarryDead(MI) && getTargetMachine().getOptLevel() == CodeGenOpt::Aggressive) {
    // After changing Op0 and Op1 to RP0, delegate it to expandPostRAPseudo.
    // Since expandPostRAPseudo is using bundle and we disable outlining of bundles,
    // we do this only when optimizing for speed.
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::COPY), Rd)
        .addReg(RL78::RP0);
    MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
    MI.getOperand(1).ChangeToRegister(RL78::RP0, false);
    return BB;

  } else {
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(Rs2, 0, RL78::sub_lo);
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R0, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R0, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(Rs2, 0, RL78::sub_hi);
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Rd)
        .addReg(RL78::RP0, RegState::Kill);

    MI.eraseFromParent();
    return BB;
  }
}

MachineBasicBlock *
RL78TargetLowering::LowerADDE_SUBE_rp_imm(unsigned int opcode, MachineInstr &MI,
                                          MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

  unsigned Rs1 = MI.getOperand(1).getReg();
  unsigned Imm = MI.getOperand(2).getImm() & 0xFFFF;
  unsigned ImmLo = MI.getOperand(2).getImm() & 0xFF;
  unsigned ImmHi = ((unsigned)MI.getOperand(2).getImm() >> 8) & 0xFF;
  unsigned Rd = MI.getOperand(0).getReg();

  if (Imm == 0 || Imm == 0xFFFF) {
    // If the constant is 0 we need to consider only the carry.

    if (IsCarryDead(MI)) {
      // If the carry is dead, we can use skip + ADDW/INCW instead of ADDC's.
      MachineFunction::iterator It = std::next(MachineFunction::iterator(BB));
      const BasicBlock *LLVM_BB = BB->getBasicBlock();
      MachineBasicBlock *CarryAddMBB = MF->CreateMachineBasicBlock(LLVM_BB);
      MachineBasicBlock *sinkMBB = MF->CreateMachineBasicBlock(LLVM_BB);
      MF->insert(It, CarryAddMBB);
      MF->insert(It, sinkMBB);
      sinkMBB->splice(sinkMBB->begin(), BB,
                      std::next(MachineBasicBlock::iterator(MI)), BB->end());
      sinkMBB->transferSuccessorsAndUpdatePHIs(BB);
      BB->addSuccessor(CarryAddMBB);
      BB->addSuccessor(sinkMBB);
      CarryAddMBB->addSuccessor(sinkMBB);

      BuildMI(*BB, MI, DL, TII->get(RL78::BRCC))
          .addMBB(sinkMBB)
          .addImm(Imm == 0xFFFF ? RL78CC::RL78CC_C : RL78CC::RL78CC_NC);

      unsigned carryOpcode;      
      if (Imm == 0 && RL78::SUBC_A_imm == opcode ||
          Imm == 0xFFFF && RL78::ADDC_A_imm == opcode)
        carryOpcode = RL78::DECW_rp;
      else if (Imm == 0 && RL78::ADDC_A_imm == opcode ||
               Imm == 0xFFFF && RL78::SUBC_A_imm == opcode)
        carryOpcode = RL78::INCW_rp;
      else
        llvm_unreachable("Unexpected opcode in LowerADDE_Sube");

      unsigned RPTemp = BB->getParent()->getRegInfo().createVirtualRegister(
          &RL78::RL78RPRegsRegClass);
      BuildMI(*CarryAddMBB, CarryAddMBB->end(), DL, TII->get(carryOpcode),
              RPTemp)
          .addReg(Rs1);

      BuildMI(*sinkMBB, sinkMBB->begin(), DL, TII->get(RL78::PHI), Rd)
          .addReg(RPTemp)
          .addMBB(CarryAddMBB)
          .addReg(Rs1)
          .addMBB(BB);

      MI.eraseFromParent();
      return sinkMBB;
    }
  }

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
      .addReg(Rs1, RegState::Kill);
  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);
  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addImm(ImmLo);
  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);
  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addImm(ImmHi);
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Rd)
      .addReg(RL78::RP0, RegState::Kill);

  MI.eraseFromParent();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerADDE_SUBE_rp_memri(
    unsigned int opcode, MachineInstr &MI, MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

  unsigned Rs1 = MI.getOperand(1).getReg();
  unsigned MemReg = MI.getOperand(2).getReg();
  unsigned Offset = MI.getOperand(3).getImm();
  unsigned Rd = MI.getOperand(0).getReg();

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
      .addReg(Rs1, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);
  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(MemReg)
      .addImm(Offset);
  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);
  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(MemReg, RegState::Kill)
      .addImm(Offset + 1);

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Rd)
      .addReg(RL78::RP0, RegState::Kill);

  MI.eraseFromParent();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerADDE_SUBE_rp_abs16(
    unsigned int opcode, MachineInstr &MI, MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

  unsigned Rs1 = MI.getOperand(1).getReg();
  const GlobalValue *global = MI.getOperand(2).getGlobal();
  unsigned offset = MI.getOperand(2).getOffset();
  unsigned Rd = MI.getOperand(0).getReg();

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
      .addReg(Rs1, RegState::Kill);

  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);
  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addGlobalAddress(global, offset);
  BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
      .addReg(RL78::R0, RegState::Define)
      .addReg(RL78::R1, RegState::Kill)
      .addReg(RL78::R0, RegState::Kill);
  BuildMI(*BB, MI, DL, TII->get(opcode), RL78::R1)
      .addReg(RL78::R1, RegState::Kill)
      .addGlobalAddress(global, offset + 1);

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Rd)
      .addReg(RL78::RP0, RegState::Kill);

  MI.eraseFromParent();
  return BB;
}

// Lower SIGN_EXTEND/ZERO_EXTEND
MachineBasicBlock *
RL78TargetLowering::LowerEXTEND(bool sext, MachineInstr &MI,
                                MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  MachineRegisterInfo &MRI = BB->getParent()->getRegInfo();
  //
  // MI.dump();
  unsigned Rs1 = MRI.createVirtualRegister(&RL78::RL78OddRegRegClass);
  unsigned RPd = MRI.createVirtualRegister(&RL78::RL78RPRegsRegClass);
  unsigned RPd1 = MRI.createVirtualRegister(&RL78::RL78RPRegsRegClass);

  BuildMI(*BB, MI, DL, TII->get(RL78::IMPLICIT_DEF), RPd);
  BuildMI(*BB, MI, DL, TII->get(RL78::INSERT_SUBREG), RPd1)
      .addReg(RPd, RegState::Kill)
      .add(MI.getOperand(1))
      .addImm(sext ? RL78::sub_hi : RL78::sub_lo);

  if (sext) {
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
        .addReg(RPd1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::SARW_rp_i), RL78::RP0)
        .addReg(RL78::RP0, RegState::Kill)
        .addImm(8);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::COPY))
        .add(MI.getOperand(0))
        .addReg(RL78::RP0, RegState::Kill);
  } else {
    BuildMI(*BB, MI, DL, TII->get(RL78::CLRB_r), RL78::R1);
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Rs1)
        .addReg(RL78::R1, RegState::Kill);
    BuildMI(*BB, MI, DL, TII->get(RL78::INSERT_SUBREG))
        .add(MI.getOperand(0))
        .addReg(RPd1, RegState::Kill)
        .addReg(Rs1, RegState::Kill)
        .addImm(RL78::sub_hi);
  }
  // The pseudo instruction is gone now.
  MI.eraseFromParent();
  // BB->dump();
  return BB;
}

MachineBasicBlock *
RL78TargetLowering::LowerSELECTCC(bool isI8, MachineInstr &MI,
                                  MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  MachineRegisterInfo &MRI = BB->getParent()->getRegInfo();
  //
  // MI.dump();
  unsigned Rd = MI.getOperand(0).getReg();
  unsigned RPd = MRI.createVirtualRegister(isI8 ? &RL78::RL78RegRegClass
                                                : &RL78::RL78RPRegsRegClass);
  unsigned RPd2 = MRI.createVirtualRegister(isI8 ? &RL78::RL78RegRegClass
                                                 : &RL78::RL78RPRegsRegClass);
  // thisMBB:
  //  ...
  //  %val = Tval
  //  b** sinkBB
  //  fallthrough --> copy0MBB
  MachineBasicBlock *thisMBB = BB;
  const BasicBlock *LLVM_BB = BB->getBasicBlock();
  MachineFunction::iterator It = ++BB->getIterator();
  MachineFunction *F = BB->getParent();
  MachineBasicBlock *copy0MBB = F->CreateMachineBasicBlock(LLVM_BB);
  MachineBasicBlock *sinkMBB = F->CreateMachineBasicBlock(LLVM_BB);
  F->insert(It, copy0MBB);
  F->insert(It, sinkMBB);
  // Transfer the remainder of BB and its successor edges to sinkMBB.
  sinkMBB->splice(sinkMBB->begin(), BB,
                  std::next(MachineBasicBlock::iterator(MI)), BB->end());
  sinkMBB->transferSuccessorsAndUpdatePHIs(BB);
  // Add the true and fallthrough blocks as its successors.
  BB->addSuccessor(copy0MBB);
  BB->addSuccessor(sinkMBB);
  //
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RPd).add(MI.getOperand(1));
  // Although it's only 1 COPY instruction it can be expanded to several
  // mov/movw or xch/xchw, the branch expand pass will insert a skip instruciton
  // if possible.
  // BuildMI(*BB, MI, DL,
  // TII->get(RL78::SK_cc)).addMBB(sinkMBB).add(MI.getOperand(3));
  BuildMI(*BB, MI, DL, TII->get(RL78::BRCC))
      .addMBB(sinkMBB)
      .add(MI.getOperand(3));
  // copy0MBB:
  //  %val2 = COPY Fval
  //  fallthrough --> sinkMBB
  BuildMI(*copy0MBB, copy0MBB->begin(), DL, TII->get(RL78::COPY), RPd2)
      .add(MI.getOperand(2));
  // Update machine-CFG edges
  copy0MBB->addSuccessor(sinkMBB);

  // sinkMBB:
  //  %Result = phi [ %val2, copy0MBB ], [ %val, thisMBB ]
  //  ...
  BuildMI(*sinkMBB, sinkMBB->begin(), DL, TII->get(RL78::PHI), Rd)
      .addReg(RPd2)
      .addMBB(copy0MBB)
      .addReg(RPd)
      .addMBB(thisMBB);
  // The pseudo instruction is gone now.
  MI.eraseFromParent();
  //
  // F->dump();
  return sinkMBB;
}

// In order to implement the very stric register class constraints for the
// various instructions we first started by writing in tablegen the real
// constraints (i.e. RL78AReg for ADD dest). This made it impossible for the
// both register allocators (greedy, pbpqp) to find any soluition even in simple
// cases we ended up with errors like (even when disabling the register
// coalescer):
//
// Assertion failed : MO->isDead() && "Cannot fold physreg def",
// Assertion failed : !MIS.empty() && "Unexpected empty span of instructions!",
// fatal error : error in backend : ran out of registers during register
// allocation
//
// Next step was to relax the constratints and added
// RL78InsertExchangeInstructionsPass. A further optimization was to use the
// physical reg directly in cases were we have a single choice (which also means
// less work for the register allocator):
//
// let Defs = [R1, CCreg], Uses = [R1] in{
// def ADD_r_r : InstRL78_8bit<0x00,
// (outs), (ins RL78RExceptA : $rsrc2),
// "add a, $rsrc2",
// [(set R1, (add R1, i8:$rsrc2))]>;
// }
//
// This worked for a few instructions but later we ended up with the following
// error (beside tablegen crashing): "Trying to add an operand to a machine
// instr that is already done!" The solution implemented below is basically the
// same as above just implemented differently so we don't get the above error.
MachineBasicBlock *RL78TargetLowering::LowerMUL8(MachineInstr &MI,
                                                 MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R0).add(MI.getOperand(2));
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(1));
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::R0, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::R0, true);
  MI.getOperand(1).ChangeToRegister(RL78::R1, false);
  MI.getOperand(2).ChangeToRegister(RL78::R0, false);
  //
  // BB->dump();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerMUL16(MachineInstr &MI,
                                                  MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();

  if (Subtarget->isUseMDA()) {

    // After changing Op0 and Op1 to RP0, delegate it to expandPostRAPseudo.
    // If we get here we should not be optimizing for size, so bundles should be
    // ok.
    unsigned Rs1 = MI.getOperand(1).getReg();
    unsigned Rs2 = MI.getOperand(2).getReg();
    unsigned Rd = MI.getOperand(0).getReg();
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).addReg(Rs1);
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::COPY), Rd)
        .addReg(RL78::RP0);
    MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
    MI.getOperand(1).ChangeToRegister(RL78::RP0, false);
    return BB;

  } else {

    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP2).add(MI.getOperand(2));
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(1));

    //  xch  a, c
    //  movw  de, ax
    //  xch  a, b
    //  mulu  x
    //  xchw  ax, bc
    //  mulu  x
    //  xchw  ax, de
    //  mulu  x
    //  add  a, e
    //  add  a, c

    // The A register contents and C register contents are exchanged.
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R2, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R2, RegState::Kill);

    // AX register contents is transferred to the DE register.
    BuildMI(*BB, MI, DL, TII->get(RL78::MOVW_rp_AX), RL78::RP4)
        .addReg(RL78::RP0, RegState::Kill);

    // The A register contents and B register contents are exchanged.
    BuildMI(*BB, MI, DL, TII->get(RL78::XCH_A_r), RL78::R1)
        .addReg(RL78::R3, RegState::Define)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R3, RegState::Kill);

    // The A register contents and the X register contents are multiplied and
    // the result is stored in the AX register.
    BuildMI(*BB, MI, DL, TII->get(RL78::MULU_r), RL78::R0);

    // The memory contents of the AX register are exchanged with those of the BC
    // register.
    BuildMI(*BB, MI, DL, TII->get(RL78::XCHW_AX_rp), RL78::RP0)
        .addReg(RL78::RP2, RegState::Define)
        .addReg(RL78::RP0, RegState::Kill)
        .addReg(RL78::RP2, RegState::Kill);

    // The A register contents and the X register contents are multiplied and
    // the result is stored in the AX register.
    BuildMI(*BB, MI, DL, TII->get(RL78::MULU_r), RL78::R0);

    // The memory contents of the AX register are exchanged with those of the DE
    // register.
    BuildMI(*BB, MI, DL, TII->get(RL78::XCHW_AX_rp), RL78::RP0)
        .addReg(RL78::RP4, RegState::Define)
        .addReg(RL78::RP0, RegState::Kill)
        .addReg(RL78::RP4, RegState::Kill);

    // The A register contents and the X register contents are multiplied and
    // the result is stored in the AX register.
    BuildMI(*BB, MI, DL, TII->get(RL78::MULU_r), RL78::R0);

    // The A register contents is added to the E register contents and the
    // result is stored in the CY flag and in the A register.
    BuildMI(*BB, MI, DL, TII->get(RL78::ADD_r_r), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R4, RegState::Kill);

    // The A register contents is added to the C register contents and the
    // result is stored in the CY flag and in the A register.
    BuildMI(*BB, MI, DL, TII->get(RL78::ADD_r_r), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addReg(RL78::R2, RegState::Kill);
  }
  //
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  //
  MI.eraseFromParent();
  // BB->dump();
  return BB;
}



MachineBasicBlock *
RL78TargetLowering::LowerShiftOrRotateForSpeed(MachineInstr &MI,
                                               MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  MachineRegisterInfo &MRI = BB->getParent()->getRegInfo();
  unsigned Rd = MI.getOperand(0).getReg();
  unsigned Rs1 = MI.getOperand(1).getReg();
  unsigned Rs2 = MI.getOperand(2).getReg();

  Register NewRd =
      MRI.getRegClass(MI.getOperand(0).getReg()) == &RL78::RL78RPRegsRegClass
          ? RL78::RP0
          : RL78::R1;

  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R3).addReg(Rs2);
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), NewRd).addReg(Rs1);
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY), Rd)
      .addReg(NewRd);

  MI.getOperand(0).ChangeToRegister(NewRd, true);
  MI.getOperand(1).ChangeToRegister(NewRd, false);
  MI.getOperand(2).ChangeToRegister(RL78::R3, false);

  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerShift_Or_LowerRotate_rp_rp(
    MachineInstr &MI, MachineBasicBlock *BB, unsigned int opcode,
    bool isI8) const {

  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  MachineRegisterInfo &MRI = BB->getParent()->getRegInfo();

  unsigned Rd = MI.getOperand(0).getReg();
  unsigned Rd1 = MI.getOperand(1).getReg();
  unsigned Rd2 = MI.getOperand(2).getReg();
  const TargetRegisterClass *RC =
      isI8 ? &RL78::RL78RegRegClass : &RL78::RL78RPRegsRegClass;
  const TargetRegisterClass *RC2 = &RL78::RL78RegRegClass;
  Register RV1 = MRI.createVirtualRegister(RC);
  Register RV2 = MRI.createVirtualRegister(RC2);
  Register RV4 = MRI.createVirtualRegister(RC2);
  Register RV5 = MRI.createVirtualRegister(RC);
  Register RV6 = MRI.createVirtualRegister(RC2);
  Register RV7 = MRI.createVirtualRegister(RC);
  Register RV8 = MRI.createVirtualRegister(RC);
  Register RP0 = isI8 ? RL78::R1 : RL78::RP0;
  Register RP2 = RL78::R2;
  //
  const BasicBlock *LLVM_BB = BB->getBasicBlock();
  MachineFunction::iterator It = std::next(MachineFunction::iterator(BB));
  MachineBasicBlock *sinkMBB2 = MF->CreateMachineBasicBlock(LLVM_BB);
  MachineBasicBlock *sinkMBB3 = MF->CreateMachineBasicBlock(LLVM_BB);
  MachineBasicBlock *sinkMBB = MF->CreateMachineBasicBlock(LLVM_BB);
  //
  // Insert the blocks.
  MF->insert(It, sinkMBB2);
  MF->insert(It, sinkMBB3);
  MF->insert(It, sinkMBB);

  // Transfer the remainder of BB and its successor edges to sinkMBB.
  sinkMBB->splice(sinkMBB->begin(), BB,
                  std::next(MachineBasicBlock::iterator(MI)), BB->end());
  sinkMBB->transferSuccessorsAndUpdatePHIs(BB);

  // BB add the true successor.
  BB->addSuccessor(sinkMBB2);

  // sinkMBB2 add the true and fallthrough blocks as its successors.
  sinkMBB2->addSuccessor(sinkMBB);
  sinkMBB2->addSuccessor(sinkMBB3);

  // sinkMBB3 add the true and fallthrough blocks as its successors.
  sinkMBB3->addSuccessor(sinkMBB3);
  sinkMBB3->addSuccessor(sinkMBB);

  // sinkMBB2:
  // RV8 = COPY Rd1.
  BuildMI(*sinkMBB2, sinkMBB2->begin(), DL, TII->get(RL78::COPY), RV8)
      .addReg(Rd1, RegState::Kill);

  // RV4 = COPY Rd2.
  BuildMI(*sinkMBB2, sinkMBB2->end(), DL, TII->get(RL78::COPY), RV4)
      .addReg(Rd2);

  // RP2 = COPY Rd2.
  BuildMI(*sinkMBB2, sinkMBB2->end(), DL, TII->get(RL78::COPY), RP2)
      .addReg(Rd2, RegState::Kill);

  // CMP0 R2 == 0 => Z flag = 1.
  BuildMI(*sinkMBB2, sinkMBB2->end(), DL, TII->get(RL78::CMP0_r))
      .addReg(RL78::R2)
      .addImm(0);

  // if Z flag == 1 => go to sinkMBB.
  BuildMI(*sinkMBB2, sinkMBB2->end(), DL, TII->get(RL78::BRCC))
      .addMBB(sinkMBB)
      .addImm(2);

  // sinkMBB3:
  //  RV1 = phi [ RV8, sinkMBB2 ], [ RV5, sinkMBB3 ].
  BuildMI(*sinkMBB3, sinkMBB3->begin(), DL, TII->get(RL78::PHI), RV1)
      .addReg(RV8)
      .addMBB(sinkMBB2)
      .addReg(RV5)
      .addMBB(sinkMBB3);

  //  RV2 = phi [ RV4, sinkMBB2 ], [ RV6, sinkMBB3 ].
  BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::PHI), RV2)
      .addReg(RV4)
      .addMBB(sinkMBB2)
      .addReg(RV6)
      .addMBB(sinkMBB3);

  // RP0 = COPY RV1.
  BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::COPY), RP0)
      .addReg(RV1, RegState::Kill);

  switch (opcode) {
  case RL78::SHLW_rp_imm:
  case RL78::SHRW_rp_i:
  case RL78::SARW_rp_i:
  case RL78::SHL_r_imm:
  case RL78::SHR_r_i:
  case RL78::SAR_r_i:
    // RP0 = Op RP0, 1.
    BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(opcode), RP0)
        .addReg(RP0, RegState::Kill)
        .addImm(1);
    break;
  case RL78::ROL_r_1:
  case RL78::ROR_r_1:
      BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(opcode), RP0)
        .addReg(RP0, RegState::Kill);
    break;
  case RL78::ROTL16_rp_rp:
    // MOV1 CY, a.7.
    BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::MOV1_cy_r))
        .addReg(RL78::R1)
        .addImm(7);
    // RP0 = ROLWC RP0, 1.
    BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::ROLWC_rp_1), RP0)
        .addReg(RP0, RegState::Kill);
    break;

  case RL78::ROTR16_rp_rp:
    // RP0 = SHRW RP0, 1.
    BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::SHRW_rp_i), RP0)
        .addReg(RP0, RegState::Kill)
        .addImm(1);
    // MOV1 a.7, CY.
    BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::MOV1_r_cy), RL78::R1)
        .addReg(RL78::R1, RegState::Kill)
        .addImm(7);
    break;
  }

  // RV5 = COPY RP0.
  BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::COPY), RV5)
      .addReg(RP0, RegState::Kill);

  // RP2 = COPY RV2.
  BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::COPY), RP2)
      .addReg(RV2, RegState::Kill);

  // R2 = DEC_r R2.
  BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::DEC_r), RL78::R2)
      .addReg(RL78::R2, RegState::Kill);

  // RV6 = COPY RP2.
  BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::COPY), RV6)
      .addReg(RP2, RegState::Kill);

  // go to sinkMBB3.
  BuildMI(*sinkMBB3, sinkMBB3->end(), DL, TII->get(RL78::B_BNZ))
      .addMBB(sinkMBB3)
      .addImm(3);

  // sinkMBB:
  //  Rd = RV7.
  BuildMI(*sinkMBB, sinkMBB->begin(), DL, TII->get(RL78::COPY), Rd)
      .addReg(RV7, RegState::Kill);

  //  RV7 = phi [ RV8, sinkMBB2 ], [ RV5, sinkMBB3 ].
  BuildMI(*sinkMBB, sinkMBB->begin(), DL, TII->get(RL78::PHI), RV7)
      .addReg(RV8)
      .addMBB(sinkMBB2)
      .addReg(RV5)
      .addMBB(sinkMBB3);
  //
  MI.eraseFromParent();
  return sinkMBB;
}

MachineBasicBlock *
RL78TargetLowering::LowerMUL8Zext16(MachineInstr &MI,
                                    MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R0).add(MI.getOperand(2));
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(1));
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
  MI.getOperand(1).ChangeToRegister(RL78::R1, false);
  MI.getOperand(2).ChangeToRegister(RL78::R0, false);
  //
  // BB->dump();
  return BB;
}

MachineBasicBlock *
RL78TargetLowering::LowerUMUL_LOHI16(MachineInstr &MI,
                                     MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R0).add(MI.getOperand(3));
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(2));
  // First operand is the low part so it needs to go into R0.
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::R0, RegState::Kill);
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(1))
      .addReg(RL78::R1, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::R0, true);
  MI.getOperand(1).ChangeToRegister(RL78::R1, true);
  MI.getOperand(2).ChangeToRegister(RL78::R1, false);
  MI.getOperand(3).ChangeToRegister(RL78::R0, false);
  //
  // BB->dump();
  return BB;
}

// Lower all 8 bit operations of the form: A <- A op <...>.
MachineBasicBlock *
RL78TargetLowering::Lower8BitOpAA(MachineInstr &MI,
                                  MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1).add(MI.getOperand(1));
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::R1, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::R1, true);
  MI.getOperand(1).ChangeToRegister(RL78::R1, false);
  //
  // BB->dump();
  return BB;
}

// Lower all 16 bit operations of the form: AX <- AX op <...>.
MachineBasicBlock *
RL78TargetLowering::Lower16BitOpAXAX(MachineInstr &MI,
                                     MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(1));
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
  MI.getOperand(1).ChangeToRegister(RL78::RP0, false);
  //
  // BB->dump();
  return BB;
}

// Lower all 8 bit operations of the form: A <- op <...>.
MachineBasicBlock *
RL78TargetLowering::Lower8bitADst(MachineInstr &MI,
                                  MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::R1, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::R1, true);
  //
  // BB->dump();
  return BB;
}

// Lower all 16 bit operations of the form: AX <- op <...>.
MachineBasicBlock *
RL78TargetLowering::Lower16bitAXDst(MachineInstr &MI,
                                    MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
  //
  // BB->dump();
  return BB;
}

// Lower all 8 bit operations of the form: <...> <- A op <...>.
MachineBasicBlock *RL78TargetLowering::Lower8bitASrc(MachineInstr &MI,
                                                     MachineBasicBlock *BB,
                                                     unsigned OpNum,
                                                     unsigned Reg) const {

  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Reg).add(MI.getOperand(OpNum));
  //
  MI.getOperand(OpNum).ChangeToRegister(Reg, false);
  MI.getOperand(OpNum).setIsKill();
  //
  // BB->dump();
  return BB;
}

// Lower all 16 bit operations of the form: <...> <- AX op <...>.
MachineBasicBlock *RL78TargetLowering::Lower16bitAXSrc(MachineInstr &MI,
                                                       MachineBasicBlock *BB,
                                                       unsigned OpNum,
                                                       unsigned Reg) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Reg).add(MI.getOperand(OpNum));
  //
  MI.getOperand(OpNum).ChangeToRegister(Reg, false);
  //
  // BB->dump();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerESSrc(MachineInstr &MI,
                                                  MachineBasicBlock *BB,
                                                  unsigned OpNum) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  if (MI.getOperand(OpNum).isReg()) {
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::R1)
        .addReg(MI.getOperand(OpNum).getReg(),
                MI.getOperand(OpNum).isKill() ? RegState::Kill : 0,
                RL78::sub_lo);
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV_es_A), RL78::ES)
        .addReg(RL78::R1, RegState::Kill);
  } else
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV_es_imm), RL78::ES)
        .add(MI.getOperand(OpNum));
  //
  MI.getOperand(OpNum).ChangeToRegister(RL78::ES, false);
  //
  // BB->dump();
  return BB;
}

MachineBasicBlock *
RL78TargetLowering::LowerCallCSRP(MachineInstr &MI,
                                  MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  if (MI.getOperand(1).isReg()) {
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::CS)
        .addReg(MI.getOperand(1).getReg(),
                MI.getOperand(1).isKill() ? RegState::Kill : 0, RL78::sub_lo);
  } else {
    BuildMI(*BB, MI, DL, TII->get(RL78::MOV_cs_imm), RL78::CS)
        .add(MI.getOperand(1));
  }
  MI.getOperand(1).ChangeToRegister(RL78::CS, false);
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerMULDIV16(MachineInstr &MI,
                                                     MachineBasicBlock *BB,
                                                     unsigned srcIndex) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  unsigned Reg2 =
      (MI.getOpcode() == RL78::UDIVREM16_r_r) ? RL78::RP4 : RL78::RP2;
  //
  // BB->dump();
  // Copy from generic reg class to AX/BC reg classes respectively.
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0)
      .add(MI.getOperand(srcIndex));
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), Reg2)
      .add(MI.getOperand(srcIndex + 1));
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
  MI.getOperand(srcIndex).ChangeToRegister(RL78::RP0, false);
  MI.getOperand(srcIndex + 1).ChangeToRegister(Reg2, false);

  if (MI.getOpcode() == RL78::MUL16_rp_rp)
    MI.addRegisterDead(RL78::RP2,
                       MF->getSubtarget<RL78Subtarget>().getRegisterInfo());

  if (srcIndex == 2) {
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
            TII->get(RL78::COPY))
        .add(MI.getOperand(1))
        .addReg(Reg2, RegState::Kill);
    MI.getOperand(1).ChangeToRegister(Reg2, true);
  }
  //
  // BB->dump();
  return BB;
}

MachineBasicBlock *RL78TargetLowering::LowerDIVWU(MachineInstr &MI,
                                                  MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  // BB->dump();

  bool fpUsed = isFPUsed(BB);
  if (fpUsed) {
    BuildMI(*BB, MI, DL, TII->get(RL78::PUSH_rp))
        .addReg(RL78::RP6, RegState::Kill);
    // TODO: CFA.
  }
  //
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(4));
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP2).add(MI.getOperand(5));
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP4).add(MI.getOperand(6));
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP6).add(MI.getOperand(7));
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(3))
      .addReg(RL78::RP6, RegState::Kill);
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(2))
      .addReg(RL78::RP4, RegState::Kill);
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(1))
      .addReg(RL78::RP2, RegState::Kill);
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
  MI.getOperand(1).ChangeToRegister(RL78::RP2, true);
  MI.getOperand(2).ChangeToRegister(RL78::RP4, true);
  MI.getOperand(3).ChangeToRegister(RL78::RP6, true);
  MI.getOperand(4).ChangeToRegister(RL78::RP0, false);
  MI.getOperand(5).ChangeToRegister(RL78::RP2, false);
  MI.getOperand(6).ChangeToRegister(RL78::RP4, false);
  MI.getOperand(7).ChangeToRegister(RL78::RP6, false);
  if (fpUsed) {
    BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI), 2), DL,
            TII->get(RL78::POP_rp), RL78::RP6);
    // TODO: CFA.
  }
  //
  // BB->dump();
  return BB;
}

MachineBasicBlock *
RL78TargetLowering::LowerBSWAP32(MachineInstr &MI,
                                 MachineBasicBlock *BB) const {
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  const TargetInstrInfo *TII = MF->getSubtarget<RL78Subtarget>().getInstrInfo();
  //
  BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(2));
  //
  BuildMI(*BB, std::next(MachineBasicBlock::iterator(MI)), DL,
          TII->get(RL78::COPY))
      .add(MI.getOperand(0))
      .addReg(RL78::RP0, RegState::Kill);
  //
  MI.getOperand(0).ChangeToRegister(RL78::RP0, true);
  MI.getOperand(2).ChangeToRegister(RL78::RP0, false);
  //
  return BB;
}

MachineBasicBlock *
RL78TargetLowering::EmitInstrWithCustomInserter(MachineInstr &MI,
                                                MachineBasicBlock *BB) const {
  // MI.dump();
  bool OptForSpeed =  getTargetMachine().getOptLevel() == CodeGenOpt::Aggressive;
  switch (MI.getOpcode()) {
  default:
    llvm_unreachable("Unknown instruction!");
  case RL78::MOVW_rp_stack_slot:
    // FIXME : we can use BC, DE, HL as well.
    return Lower16bitAXDst(MI, BB);
  case RL78::BSWAP32_rp:
    return LowerBSWAP32(MI, BB);
  case RL78::AEXT_8_16:
  case RL78::ZEXT_8_16:
    return LowerEXTEND(false, MI, BB);
  case RL78::SEXT_8_16:
    return LowerEXTEND(true, MI, BB);
  case RL78::ADDE_rp_imm:
    return LowerADDE_SUBE_rp_imm(RL78::ADDC_A_imm, MI, BB);
  case RL78::SUBE_rp_imm:
    return LowerADDE_SUBE_rp_imm(RL78::SUBC_A_imm, MI, BB);
  case RL78::ADDE_rp_memri:
    return LowerADDE_SUBE_rp_memri(RL78::ADDC_r_memri, MI, BB);
  case RL78::SUBE_rp_memri:
    return LowerADDE_SUBE_rp_memri(RL78::SUBC_r_memri, MI, BB);
  case RL78::ADDE_rp_abs16:
    return LowerADDE_SUBE_rp_abs16(RL78::ADDC_r_abs16, MI, BB);
  case RL78::SUBE_rp_abs16:
    return LowerADDE_SUBE_rp_abs16(RL78::SUBC_r_abs16, MI, BB);
  case RL78::ADDE_rp_rp:
    return LowerADDE_SUBE_rp_rp(RL78::ADDC_r_r, MI, BB);
  case RL78::SUBE_rp_rp:
    return LowerADDE_SUBE_rp_rp(RL78::SUBC_r_r, MI, BB);
  case RL78::AND16_rp_imm:
    return LowerAndOrXor16_rp_imm(RL78::AND_r_imm, MI, BB);
  case RL78::OR16_rp_imm:
    return LowerAndOrXor16_rp_imm(RL78::OR_r_imm, MI, BB);
  case RL78::XOR16_rp_imm:
    return LowerAndOrXor16_rp_imm(RL78::XOR_r_imm, MI, BB);
  case RL78::AND2_16_rp_rp:
  case RL78::AND16_rp_rp:
    return LowerAndOrXor16_rp_rp(RL78::AND_r_r, MI, BB);
  case RL78::OR2_16_rp_rp:
  case RL78::OR16_rp_rp:
    return LowerAndOrXor16_rp_rp(RL78::OR_r_r, MI, BB);
  case RL78::XOR2_16_rp_rp:
  case RL78::XOR16_rp_rp:
    return LowerAndOrXor16_rp_rp(RL78::XOR_r_r, MI, BB);
  case RL78::AND16_rp_memri:
    return LowerAndOrXor16_rp_memri(
        RL78::AND_r_memri, RL78::AND_r_r, MI,
        Lower16bitAXSrc(MI, BB, 2,
                        (MI.getOperand(3).getImm() > 255) ? RL78::RP2
                                                          : tryGetRP6(BB)));
  case RL78::AND16_rp_abs16:
    return LowerAndOrXor16_rp_abs16(RL78::AND_r_abs16, MI, BB);
  case RL78::OR16_rp_memri:
    return LowerAndOrXor16_rp_memri(
        RL78::OR_r_memri, RL78::OR_r_r, MI,
        Lower16bitAXSrc(MI, BB, 2,
                        (MI.getOperand(3).getImm() > 255) ? RL78::RP2
                                                          : tryGetRP6(BB)));
  case RL78::OR16_rp_abs16:
    return LowerAndOrXor16_rp_abs16(RL78::OR_r_abs16, MI, BB);
  case RL78::XOR16_rp_memri:
    return LowerAndOrXor16_rp_memri(
        RL78::XOR_r_memri, RL78::XOR_r_r, MI,
        Lower16bitAXSrc(MI, BB, 2,
                        (MI.getOperand(3).getImm() > 255) ? RL78::RP2
                                                          : tryGetRP6(BB)));
  case RL78::XOR16_rp_abs16:
    return LowerAndOrXor16_rp_abs16(RL78::XOR_r_abs16, MI, BB);
  case RL78::CMPW_rp_imm:
  case RL78::CMPW_rp_rp:
  case RL78::CMPW_rp_abs16:
  case RL78::CMPW_rp_saddr:
    return LowerSignedCMPW(MI, BB);
  case RL78::CMPW_rp_memri:
    return LowerSignedCMPWMem(MI, BB);
  case RL78::CMP_abs16_imm:
  case RL78::CMP_r_memri:
  case RL78::CMP_r_memrr:
  case RL78::CMP_r_imm:
  case RL78::CMP_r_abs16:
  case RL78::CMP_r_r:
  case RL78::CMP_r_saddr:
  case RL78::CMP_saddr_imm:
    return LowerSignedCMP(MI, BB);
  case RL78::CMP0_r:
    return LowerSignedCMP0(false, MI, Lower8bitASrc(MI, BB));
  case RL78::CMP0_abs16:
  case RL78::CMP0_saddr:
    return LowerSignedCMP0(false, MI, BB);
  case RL78::SHR_r_i:
    return Lower8BitOpAA(MI, BB);
  case RL78::SHLW_rp_imm:
  case RL78::SHRW_rp_i:
    return Lower16BitOpAXAX(MI, BB);
  case RL78::SAR_r_i:
  case RL78::ROL_r_1:
  case RL78::ROR_r_1:
    return Lower8BitOpAA(MI, BB);
  case RL78::SARW_rp_i:
    return Lower16BitOpAXAX(MI, BB);
  case RL78::ROTL_r_imm:
    return LowerRotate_r_imm(MI, BB, true);
  case RL78::ROTR_r_imm:
    return LowerRotate_r_imm(MI, BB, false);
  case RL78::ROTL16_r_imm:
    return LowerRotate16_rp_imm(MI, BB, true);
  case RL78::ROTR16_r_imm:
    return LowerRotate16_rp_imm(MI, BB, false);
  case RL78::SELECTCC8:
    return LowerSELECTCC(true, MI, BB);
  case RL78::SELECTCC16:
    return LowerSELECTCC(false, MI, BB);
  case RL78::MUL16_rp_rp:
    return LowerMULDIV16(MI, BB, 1);
  case RL78::MUL32_zext_r_r:
    return LowerMULDIV16(MI, BB, 2);
  case RL78::MUL32_sext_r_r:
    return LowerMULDIV16(MI, BB, 2);
  case RL78::UDIVREM16_r_r:
    return LowerMULDIV16(MI, BB, 2);
  case RL78::UDIVREM32_r_r:
    return LowerDIVWU(MI, BB);
  case RL78::MUL8_r_r:
    return LowerMUL8(MI, BB);
  case RL78::MULU_zext_16_r_r:
    return LowerMUL8Zext16(MI, BB);
  case RL78::MUL16_rp_rp_S1_S2:
    return LowerMUL16(MI, BB);
  case RL78::SHLW_rp_rp:
    return OptForSpeed ? LowerShiftOrRotateForSpeed(MI, BB)
                       : LowerShift_Or_LowerRotate_rp_rp(
                             MI, BB, RL78::SHLW_rp_imm, false);
  case RL78::SHRW_rp_rp:
    return OptForSpeed ? LowerShiftOrRotateForSpeed(MI, BB)
                       : LowerShift_Or_LowerRotate_rp_rp(
                             MI, BB, RL78::SHRW_rp_i, false);
  case RL78::SARW_rp_rp:
    return OptForSpeed ? LowerShiftOrRotateForSpeed(MI, BB)
                       : LowerShift_Or_LowerRotate_rp_rp(
                             MI, BB, RL78::SARW_rp_i, false);
  case RL78::SHL_r_r:
    return OptForSpeed
               ? LowerShiftOrRotateForSpeed(MI, BB)
               : LowerShift_Or_LowerRotate_rp_rp(MI, BB, RL78::SHL_r_imm, true);
  case RL78::SHR_r_r:
    return OptForSpeed
               ? LowerShiftOrRotateForSpeed(MI, BB)
               : LowerShift_Or_LowerRotate_rp_rp(MI, BB, RL78::SHR_r_i, true);
  case RL78::SAR_r_r:
    return OptForSpeed
               ? LowerShiftOrRotateForSpeed(MI, BB)
               : LowerShift_Or_LowerRotate_rp_rp(MI, BB, RL78::SAR_r_i, true);
  case RL78::ROTL_rp_rp:
    return OptForSpeed
               ? LowerShiftOrRotateForSpeed(MI, BB)
               : LowerShift_Or_LowerRotate_rp_rp(MI, BB, RL78::ROL_r_1, true);
  case RL78::ROTR_rp_rp:
    return OptForSpeed
               ? LowerShiftOrRotateForSpeed(MI, BB)
               : LowerShift_Or_LowerRotate_rp_rp(MI, BB, RL78::ROR_r_1, true);
  case RL78::ROTL16_rp_rp:
    return OptForSpeed
               ? LowerShiftOrRotateForSpeed(MI, BB)
               : LowerShift_Or_LowerRotate_rp_rp(MI, BB, RL78::ROTL16_rp_rp, false);
  case RL78::ROTR16_rp_rp:
    return OptForSpeed
               ? LowerShiftOrRotateForSpeed(MI, BB)
               : LowerShift_Or_LowerRotate_rp_rp(MI, BB, RL78::ROTR16_rp_rp, false);
  case RL78::UMUL_LOHI_16_r_r:
    return LowerUMUL_LOHI16(MI, BB);
  case RL78::ADD_r_imm:
    return Lower8BitOpAA(MI, BB);
  case RL78::ADD_r_memrr:
  case RL78::SUB_r_memrr:
  case RL78::AND_r_memrr:
  case RL78::OR_r_memrr:
  case RL78::XOR_r_memrr:
    return Lower8BitOpAA(MI,
                         Lower16bitAXSrc(MI, Lower8bitASrc(MI, BB, 3, RL78::R2),
                                         2, tryGetRP6(BB)));
  case RL78::ADD_r_memri:
  case RL78::SUB_r_memri:
  case RL78::AND_r_memri:
  case RL78::OR_r_memri:
  case RL78::XOR_r_memri:
    return Lower8BitOpAA(MI, Lower16bitAXSrc(MI, BB, 2, tryGetRP6(BB)));
  case RL78::AND_r_imm:
  case RL78::OR_r_imm:
  case RL78::XOR_r_imm:
  case RL78::ADD_r_abs16:
  case RL78::ADD_r_r:
  case RL78::ADD_r_saddr:
  case RL78::SUB_r_imm:
  case RL78::SUB_r_abs16:
  case RL78::SUB_r_r:
  case RL78::SUB_r_saddr:
  case RL78::AND_r_abs16:
  case RL78::AND_r_r:
  case RL78::AND_r_saddr:
  case RL78::OR_r_abs16:
  case RL78::OR_r_r:
  case RL78::OR_r_saddr:
  case RL78::XOR_r_abs16:
  case RL78::XOR_r_r:
  case RL78::XOR_r_saddr:
  case RL78::SHL_r_imm:
    return Lower8BitOpAA(MI, BB);
  case RL78::STORE8_saddr_A:
    return Lower8bitASrc(MI, BB, 1);
  case RL78::LOAD8_r_stack_slot:
  case RL78::LOAD8_r_sfr:
    return Lower8bitADst(MI, BB);
  case RL78::STORE8_ri_imm:
    // STORE [HL+byte] or STORE word[BC].
    {
      const MachineOperand &MO = MI.getOperand(1);
      if (MO.isImm() && MO.getImm() > 255 || MO.isGlobal() || MO.isSymbol())
        return Lower16bitAXSrc(MI, BB, 0, RL78::RP2);
      else
        return Lower16bitAXSrc(MI, BB, 0, tryGetRP6(BB));
    }
  case RL78::STORE8_rbci_imm:
        return Lower8bitASrc(MI, BB, 0, RL78::R3);
  case RL78::LOAD8_r_ri:
    // A = LOAD [HL+byte] or A = LOAD word[BC].
    {
      const MachineOperand &MO = MI.getOperand(2);
      if (MO.isImm() && MO.getImm() > 255 || MO.isGlobal() || MO.isSymbol())
        return Lower8bitADst(MI, Lower16bitAXSrc(MI, BB, 1, RL78::RP2));
      else
        return Lower8bitADst(MI, Lower16bitAXSrc(MI, BB, 1, tryGetRP6(BB)));
    }
  case RL78::LOAD8_r_rbci:
       return Lower8bitADst(MI,  Lower8bitASrc(MI, BB, 1, RL78::R3));
  case RL78::LOAD8_r_memrr:
    return Lower8bitADst(MI,
                         Lower16bitAXSrc(MI, Lower8bitASrc(MI, BB, 2, RL78::R3),
                                         1, tryGetRP6(BB)));
  case RL78::STORE8_ri_r:
    // STORE [HL+byte] or STORE word[BC].
    {
      const MachineOperand &MO = MI.getOperand(1);
      if (MO.isImm() && MO.getImm() > 255 || MO.isGlobal() || MO.isSymbol())
        return Lower8bitASrc(MI, Lower16bitAXSrc(MI, BB, 0, RL78::RP2), 2);
      else
        return Lower8bitASrc(MI, Lower16bitAXSrc(MI, BB, 0, tryGetRP6(BB)), 2);
    }
  case RL78::STORE8_rbci_r:
      return Lower8bitASrc(MI,  Lower8bitASrc(MI, BB, 0, RL78::R3), 2);
  case RL78::STORE8_memrr_r:
    return Lower8bitASrc(MI,
                         Lower16bitAXSrc(MI, Lower8bitASrc(MI, BB, 1, RL78::R3),
                                         0, tryGetRP6(BB)),
                         2);
  case RL78::LOAD16_rp_rpi:
    // AX = LOAD [HL+byte] or AX = LOAD word[BC].
    {
      const MachineOperand &MO = MI.getOperand(2);
      if (MO.isImm() && MO.getImm() > 255 || MO.isGlobal() || MO.isSymbol())
        return Lower16bitAXDst(MI, Lower16bitAXSrc(MI, BB, 1, RL78::RP2));
      else
        return Lower16bitAXDst(MI, Lower16bitAXSrc(MI, BB, 1, tryGetRP6(BB)));
    }
  case RL78::LOAD16_rp_rbci:
       return Lower16bitAXDst(MI, Lower16bitAXSrc(MI, BB, 1, RL78::R3));
  case RL78::LOAD16_rp_stack_slot:
  case RL78::LOAD16_rp_sfrp:
    return Lower16bitAXDst(MI, BB);
  case RL78::ADDW_rp_imm:
    return Lower16BitOpAXAX(MI, BB);
  case RL78::ADDW_rp_memri:
  case RL78::SUBW_rp_memri:
    return Lower16BitOpAXAX(MI, Lower16bitAXSrc(MI, BB, 2, tryGetRP6(BB)));
  case RL78::ADDW_rp_rp:
    if (MI.getOperand(1).getReg() == MI.getOperand(2).getReg())
      MI.getOperand(2).ChangeToRegister(RL78::RP0, false);
    return Lower16BitOpAXAX(MI, BB);
  case RL78::ADDW_rp_abs16:
  case RL78::SUBW_rp_imm:
  case RL78::SUBW_rp_rp:
  case RL78::SUBW_rp_abs16:
  case RL78::BSWAP_rp:
  case RL78::ADDW_rp_saddr:
  case RL78::SUBW_rp_saddr:
    return Lower16BitOpAXAX(MI, BB);
  case RL78::STORE16_rpi_rp:
    // STORE [HL+byte] or STORE word[BC].
    {
      const MachineOperand &MO = MI.getOperand(1);
      if (MO.isImm() && MO.getImm() > 255 || MO.isGlobal() || MO.isSymbol())
        return Lower16bitAXSrc(MI, Lower16bitAXSrc(MI, BB, 0, RL78::RP2), 2);
      else
        return Lower16bitAXSrc(MI, Lower16bitAXSrc(MI, BB, 0, tryGetRP6(BB)),
                               2);
    }
  case RL78::STORE16_rbci_rp: 
    return Lower16bitAXSrc(MI,  Lower8bitASrc(MI, BB, 0, RL78::R3), 2);
  case RL78::STORE16_stack_slot_rp:
    return Lower16bitAXSrc(MI, BB, 2);
  case RL78::STORE16_abs16_rp:
  case RL78::STORE16_saddrp_rp:
  case RL78::STORE16_sfrp_rp:
    return Lower16bitAXSrc(MI, BB, 1);
  case RL78::STORE8_abs16_r:
  case RL78::STORE8_sfr_r:
    return Lower8bitASrc(MI, BB, 1);
  case RL78::INC_memri:
  case RL78::DEC_memri:
  case RL78::INCW_memri:
  case RL78::DECW_memri:
    return Lower16bitAXSrc(MI, BB, 0, tryGetRP6(BB));
  case RL78::STORE8_stack_slot_r:
    return Lower8bitASrc(MI, BB, 2);
  case RL78::SET1_esmemr:
  case RL78::CLR1_esmemr:
    return LowerESSrc(MI, Lower16bitAXSrc(MI, BB, 1, tryGetRP6(BB)), 0);
  case RL78::SET1_esaddr16:
  case RL78::CLR1_esaddr16:
    return LowerESSrc(MI, BB, 0);
  case RL78::LOAD16_rp_esrpi:
    return Lower16bitAXDst(
        MI, LowerESSrc(MI,
                       Lower16bitAXSrc(MI, BB, 2,
                                       (MI.getOperand(3).getImm() > 255)
                                           ? RL78::RP2
                                           : tryGetRP6(BB)),
                       1));
  case RL78::LOAD8_r_esrpi:
    return Lower8bitADst(
        MI, LowerESSrc(MI,
                       Lower16bitAXSrc(MI, BB, 2,
                                       (MI.getOperand(3).getImm() > 255)
                                           ? RL78::RP2
                                           : tryGetRP6(BB)),
                       1));
  case RL78::STORE16_esaddr16_rp:
    return Lower16bitAXSrc(MI, LowerESSrc(MI, BB, 0), 2);
  case RL78::STORE16_esrpi_rp:
    return Lower16bitAXSrc(
        MI,
        LowerESSrc(MI,
                   Lower16bitAXSrc(MI, BB, 1,
                                   (MI.getOperand(2).getImm() > 255)
                                       ? RL78::RP2
                                       : tryGetRP6(BB)),
                   0),
        3);
  case RL78::STORE8_esrpi_r:
    return Lower8bitASrc(
        MI,
        LowerESSrc(MI,
                   Lower16bitAXSrc(MI, BB, 1,
                                   (MI.getOperand(2).getImm() > 255)
                                       ? RL78::RP2
                                       : tryGetRP6(BB)),
                   0),
        3);
  case RL78::BTCLR_memr:
  case RL78::BTBF_memr:
  case RL78::BTBF_mem:
    return Lower16bitAXSrc(MI, BB, 2, tryGetRP6(BB));
  case RL78::BTBF:
    return Lower8bitASrc(MI, BB, 2);
  case RL78::CLR1_memr:
  case RL78::SET1_memr:
  case RL78::MOV1_cy_memr:
  case RL78::MOV1_memr_cy:
  case RL78::AND1_cy_memr:
  case RL78::OR1_cy_memr:
  case RL78::XOR1_cy_memr:
    return Lower16bitAXSrc(MI, BB, 0, tryGetRP6(BB));
  case RL78::ONEB_r:
  case RL78::CLRB_r:
    return Lower8bitADst(MI, BB);
  case RL78::MOV1_r_cy:
    return Lower8BitOpAA(MI, BB);
  case RL78::MOV1_cy_r:
    return Lower8bitASrc(MI, BB);
  case RL78::CALL_cs_rp:
    return LowerCallCSRP(MI, BB);
  case RL78::LowCMPW_rp_rp: {
      if(MI.getOperand(0).getReg() == MI.getOperand(1).getReg()) {
          MI.removeFromParent();
          return BB;
      }
      // fallthrough
  }
  case RL78::LowCMPW_rp_imm: 
  case RL78::LowCMPW_rp_saddr:
  case RL78::LowCMPW_rp_abs16:
  case RL78::LowCMPW_rp_memri:{

    MachineFunction *MF = BB->getParent();
    DebugLoc DL = MI.getDebugLoc();
    const TargetInstrInfo *TII =
        MF->getSubtarget<RL78Subtarget>().getInstrInfo();
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(0));
    MI.getOperand(0).ChangeToRegister(RL78::RP0, false);
    return BB;
  }
  case RL78::MACH_CG:
  case RL78::MACHU_CG: {
    MachineFunction *MF = BB->getParent();
    DebugLoc DL = MI.getDebugLoc();
    const TargetInstrInfo *TII =
        MF->getSubtarget<RL78Subtarget>().getInstrInfo();
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP0).add(MI.getOperand(4));
    BuildMI(*BB, MI, DL, TII->get(RL78::COPY), RL78::RP2).add(MI.getOperand(5));
    MI.getOperand(4).ChangeToRegister(RL78::RP0, false);
    MI.getOperand(5).ChangeToRegister(RL78::RP2, false);
    return BB;
  }

  }
}

//===----------------------------------------------------------------------===//
//                         RL78 Inline Assembly Support
//===----------------------------------------------------------------------===//

bool RL78TargetLowering::ExpandInlineAsm(CallInst *CI) const {
  InlineAsm *IA = cast<InlineAsm>(CI->getCalledOperand());
  std::string AsmStr = IA->getAsmString();
  SmallVector<StringRef, 4> AsmPieces;
  SplitString(AsmStr, AsmPieces, " ;\n");
  switch (AsmPieces.size()) {
  default:
    return false;
  case 1:
    AsmStr = AsmPieces[0].lower();
    Module *M = CI->getModule();
    Function *Int;
    // Keep in sync with RL78TargetLowering::PerformDAGCombine ISD::TRAP.
    if (AsmStr.compare("nop") == 0) {
      Int = Intrinsic::getDeclaration(M, Intrinsic::rl78_nop);
    } else if ((AsmStr.compare("halt") == 0)) {
      Int = Intrinsic::getDeclaration(M, Intrinsic::rl78_halt);
    } else if ((AsmStr.compare("stop") == 0)) {
      Int = Intrinsic::getDeclaration(M, Intrinsic::rl78_stop);
    } else if ((AsmStr.compare("brk") == 0)) {
      Int = Intrinsic::getDeclaration(M, Intrinsic::rl78_brk);
    } else if ((AsmStr.compare("ei") == 0)) {
      Int = Intrinsic::getDeclaration(M, Intrinsic::rl78_ei);
    } else if ((AsmStr.compare("di") == 0)) {
      Int = Intrinsic::getDeclaration(M, Intrinsic::rl78_di);
    } else {
        return false;
    }

    Value *Op = CallInst::Create(Int, CI->getName(), CI);
    CI->replaceAllUsesWith(Op);
    CI->eraseFromParent();
    return true;
  }
}

/// getConstraintType - Given a constraint letter, return the type of
/// constraint it is for this target.
RL78TargetLowering::ConstraintType
RL78TargetLowering::getConstraintType(StringRef Constraint) const {
  if (Constraint.size() == 1) {
    switch (Constraint[0]) {
    case 'r':
    case 'R':
      return C_RegisterClass;
    }
  }

  return TargetLowering::getConstraintType(Constraint);
}

TargetLowering::ConstraintWeight
RL78TargetLowering::getSingleConstraintMatchWeight(
    AsmOperandInfo &info, const char *constraint) const {
  ConstraintWeight weight = CW_Invalid;
  Value *CallOperandVal = info.CallOperandVal;
  // If we don't have a value, we can't do a match,
  // but allow it at the lowest weight.
  if (!CallOperandVal)
    return CW_Default;

  // Look at the constraint type.
  switch (*constraint) {
  default:
    weight = TargetLowering::getSingleConstraintMatchWeight(info, constraint);
    break;
  case 'r':
  case 'R':
    weight = CW_Register;
    break;
  }
  return weight;
}

std::pair<unsigned, const TargetRegisterClass *>
RL78TargetLowering::getRegForInlineAsmConstraint(const TargetRegisterInfo *TRI,
                                                 StringRef Constraint,
                                                 MVT VT) const {
  if (Constraint.size() == 1) {
    switch (Constraint[0]) {
    case 'r':
      return std::pair<unsigned, const TargetRegisterClass *>(
          0U, &RL78::RL78RPRegsRegClass);
    case 'R':
      return std::pair<unsigned, const TargetRegisterClass *>(
          0U, &RL78::RL78RegRegClass);
    }
  }
  return TargetLowering::getRegForInlineAsmConstraint(TRI, Constraint, VT);
}

static SDValue createBSWAPNodes(SDValue node, EVT VT, SelectionDAG &DAG,
                                SDLoc &dl) {

  if (VT.getSimpleVT() == MVT::i16) {
    return DAG.getNode(ISD::BSWAP, dl, MVT::i16, node);
  } else {
    EVT halfVT = VT.getHalfSizedIntegerVT(*DAG.getContext());

    SDValue loHalf = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, halfVT, node,
                                 DAG.getConstant(0, dl, halfVT));
    SDValue swappedLoHalf = createBSWAPNodes(loHalf, halfVT, DAG, dl);

    SDValue hiHalf = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, halfVT, node,
                                 DAG.getConstant(1, dl, halfVT));
    SDValue swappedHiHalf = createBSWAPNodes(hiHalf, halfVT, DAG, dl);

    return DAG.getNode(ISD::BUILD_PAIR, dl, VT, swappedHiHalf, swappedLoHalf);
  }
}

/// Replace any address related nodes which don't have the right type with the
/// right one. GlobalAddress etc. will be handled by ReplaceNodeResults because
/// we will always need to replace them however in case of a Constant for example
/// it's OK for it to be in 32 bit wide in case of an 32 bit addition but not in
/// case of a 32 bit address from a load.
static void ReplaceOperand(const SDValue &N, SmallVectorImpl<SDValue> &Results,
                           SelectionDAG &DAG) {
  SDLoc dl(N);
  // N.dump();
  switch (N.getOpcode()) {
  case ISD::ADD: {
    if (N->getValueType(0) == MVT::i32) {
      if ((N.getOperand(1).getOpcode() == ISD::Constant) &&
          (cast<ConstantSDNode>(N.getOperand(1))->getZExtValue() <=
           UINT16_MAX)) {
        SDValue LoIndex = DAG.getConstant(0, dl, MVT::i16);
        SDValue HiIndex = DAG.getConstant(1, dl, MVT::i16);
        SDValue LoHalf = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                     N.getOperand(0), LoIndex);
        SDValue HiHalf = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16,
                                     N.getOperand(0), HiIndex);
        Results.push_back(DAG.getNode(
            RL78ISD::HI16, dl, MVT::i16, HiHalf, LoHalf,
            DAG.getConstant(
                cast<ConstantSDNode>(N.getOperand(1))->getZExtValue(), dl,
                MVT::i16)));
        return;
      }
    }
    // Fall-through.
  }
  default:
    // Default implementation: extract low/high 16-bit part and pair them back
    // together.
    if (N->getValueType(0) == MVT::i32) {
      SDValue LoIndex = DAG.getConstant(0, dl, MVT::i16);
      SDValue HiIndex = DAG.getConstant(1, dl, MVT::i16);
      SDValue LoHalf =
          DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16, N, LoIndex);
      SDValue HiHalf =
          DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i16, N, HiIndex);
      Results.push_back(
          DAG.getNode(RL78ISD::HI16, dl, MVT::i16, HiHalf, LoHalf));
    }
    return;
  case ISD::BUILD_PAIR: {
    // if(N->getValueType(0) == MVT::i32)
    // Results.push_back(N->getOperand(0));
    // Results.push_back(N->getOperand(1));
    if (N->getValueType(0) == MVT::i32 &&
        N->getOperand(1).getOpcode() == RL78ISD::HI16)
      Results.push_back(DAG.getNode(RL78ISD::HI16, dl, MVT::i16,
                                    N->getOperand(1)->getOperand(0),
                                    N->getOperand(0)));
    else
      Results.push_back(DAG.getNode(RL78ISD::HI16, dl, MVT::i16,
                                    N->getOperand(1), N->getOperand(0)));
    return;
  }
  case ISD::UNDEF:
    if (N->getValueType(0) == MVT::i32)
      Results.push_back(DAG.getNode(ISD::UNDEF, dl, MVT::i16));
    // else Results.push_back(N);
    return;
  case ISD::GlobalAddress: {
    if (N->getValueType(0) == MVT::i32) {
      const GlobalValue *GV = cast<GlobalAddressSDNode>(N)->getGlobal();
      int64_t Offset = cast<GlobalAddressSDNode>(N)->getOffset();
      SDValue LowAddress = DAG.getTargetGlobalAddress(
          GV, dl, MVT::i16, Offset, RL78MCExpr::VK_RL78_LOWW);
      SDValue HiAddress = DAG.getTargetGlobalAddress(GV, dl, MVT::i16, Offset,
                                                     RL78MCExpr::VK_RL78_HIGHW);
      SDValue Low16 = DAG.getNode(RL78ISD::LOW16, dl, MVT::i16, LowAddress);
      SDValue Hi8 = DAG.getNode(RL78ISD::HI16, dl, MVT::i16, HiAddress, Low16);
      Results.push_back(Hi8);
    }
    return;
  }
  }
}

static void ReplaceLoadOperands(SDNode *N, SmallVectorImpl<SDValue> &Results,
                                SelectionDAG &DAG) {
  SmallVector<SDValue, 8> OpResults;
  SDValue Ptr = N->getOperand(1), Ofs = N->getOperand(2);
  // if the ptr is a 16-bit frame index (as we custom lowered it)
  // but the offset is a 32-bit undef, we can use the frame index directly
  // (the offset will be recreated as an undef of the same type as the ptr by
  // getExtLoad)
  if (Ptr->getOpcode() == ISD::FrameIndex && Ptr->getValueType(0) == MVT::i16 &&
      Ofs->getOpcode() == ISD::UNDEF && Ofs->getValueType(0) == MVT::i32) {
    OpResults.push_back(Ptr);
  } else {
    ReplaceOperand(Ptr, OpResults, DAG);
  }
  ReplaceOperand(Ofs, OpResults, DAG);
  if (OpResults.size() > 0) {
    LoadSDNode *LD = cast<LoadSDNode>(N);
    SDValue load = DAG.getExtLoad(
        LD->getExtensionType(), SDLoc(N), N->getValueType(0), N->getOperand(0),
        OpResults[0], LD->getPointerInfo(), LD->getMemoryVT(), LD->getAlign(),
        LD->getMemOperand()->getFlags(), LD->getAAInfo());
    Results.push_back(load.getValue(0));
    Results.push_back(load.getValue(1));
  }
}

/// This callback is invoked when a node result type is illegal for the
/// target, and the operation was registered to use 'custom' lowering for that
/// result type.  The target places new result values for the node in Results
/// (their number and types must exactly match those of the original return
/// values of the node), or leaves Results empty, which indicates that the
/// node is not to be custom lowered after all.
///
/// If the target has no operations that require custom lowering, it need not
/// implement this.  The default implementation aborts.
void RL78TargetLowering::ReplaceNodeResults(SDNode *N,
                                            SmallVectorImpl<SDValue> &Results,
                                            SelectionDAG &DAG) const {

  SDLoc dl(N);

  // N->dump();
  switch (N->getOpcode()) {
  default:
    llvm_unreachable("Do not know how to custom type legalize this operation!");
    return;
  case ISD::EXTRACT_ELEMENT:
    return;
  case ISD::TargetGlobalAddress: {
    GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(N);
    const GlobalValue *GV = G->getGlobal();
    int64_t Offset = G->getOffset();
    SDValue Result = DAG.getTargetGlobalAddress(GV, SDLoc(N), MVT::i16, Offset);
    SDValue Low16 =
        DAG.getNode(RL78ISD::LOW16, SDLoc(Result), MVT::i16, Result);
    SDValue High16 =
        DAG.getNode(RL78ISD::HI16, SDLoc(Result), MVT::i16, Result, Low16);
    SDValue Pair =
        DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, Low16, High16);
    Results.push_back(Pair);
    return;
  }
  case ISD::ExternalSymbol: {
    ExternalSymbolSDNode *E = dyn_cast<ExternalSymbolSDNode>(N);
    SDValue Result = DAG.getTargetExternalSymbol(E->getSymbol(), MVT::i16);
    SDValue Low16 =
        DAG.getNode(RL78ISD::LOW16, SDLoc(Result), MVT::i16, Result);
    SDValue High16 =
        DAG.getNode(RL78ISD::HI16, SDLoc(Result), MVT::i16, Result, Low16);
    SDValue Pair =
        DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, Low16, High16);
    Results.push_back(Pair);
    return;
  }
  case ISD::ADDRSPACECAST: {
    assert((N->getValueType(0) == MVT::i32) &&
           "Invalid value type for GlobalAddress!");
    AddrSpaceCastSDNode *CastNode = dyn_cast<AddrSpaceCastSDNode>(N);
    SDValue NullConstant = DAG.getConstant(0x00, dl, MVT::i16);
    SDValue LowValue, HighValue;
    bool IsSrcAddress = CastNode->getDestAddressSpace() == RL78AS::FarCode;
    if (GlobalAddressSDNode *G =
            dyn_cast<GlobalAddressSDNode>(N->getOperand(0))) {
      const GlobalValue *GV = G->getGlobal();
      int64_t Offset = cast<GlobalAddressSDNode>(N->getOperand(0))->getOffset();
      SDValue LowAddress =
          DAG.getTargetGlobalAddress(GV, SDLoc(N->getOperand(0)), MVT::i16,
                                     Offset, RL78MCExpr::VK_RL78_LOWW);
      LowValue =
          DAG.getNode(RL78ISD::LOW16, SDLoc(LowAddress), MVT::i16, LowAddress);
      IsSrcAddress |= GV->getValueType()->isFunctionTy();
    } else {
      LowValue = N->getOperand(0);
    }
    if (IsSrcAddress) {
      HighValue = NullConstant;
    } else {
      SDValue NonNullPrefix = DAG.getConstant(0x0f, dl, MVT::i16);
      // NOTE: we can assume that the frame indexes are nonnull as eliding
      // the null check for these makes a big difference for -mfar-data...
      const auto LowOpcode = LowValue.getOpcode();
      HighValue =
          (LowOpcode == ISD::FrameIndex || LowOpcode == ISD::TargetFrameIndex)
                      ? NonNullPrefix
                      : DAG.getSelect(dl, MVT::i16,
                                      DAG.getSetCC(dl, MVT::i16, LowValue,
                                                   NullConstant, ISD::SETEQ),
                                      NullConstant, NonNullPrefix);
    }
    SDValue Pair =
        DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, LowValue, HighValue);
    Results.push_back(Pair);
    return;
  }
  case ISD::ADD: {
    assert(N->getValueType(0) == MVT::i32 && "i32 expected");
    auto Op0 = N->getOperand(0), Op1 = N->getOperand(1);
    if (Op0->getOpcode() == ISD::FrameIndex && Op1->getValueType(0) == MVT::i32 && isa<ConstantSDNode>(Op1))
    {
      auto Imm = cast<ConstantSDNode>(Op1)->getZExtValue();
      assert(Imm <= UINT16_MAX);
      Results.push_back(
          DAG.getNode(ISD::ADD, dl, MVT::i16, Op0, DAG.getConstant(Imm, dl, MVT::i16))
      );
    }
    return;
  }
  case ISD::LOAD:
  case ISD::STORE:
    // We made 32 bit load/store custom for LowerOperationWrapper.
    return;
  case ISD::INTRINSIC_WO_CHAIN: {
    unsigned IntNo = cast<ConstantSDNode>(N->getOperand(0))->getZExtValue();
    switch (IntNo) {
    case Intrinsic::rl78_mului: {
      if (Subtarget->isRL78S3CoreType()) {
        SDValue umulohi =
            DAG.getNode(ISD::UMUL_LOHI, dl, DAG.getVTList(MVT::i16, MVT::i16),
                        N->getOperand(1), N->getOperand(2));
        SDValue Pair = DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32,
                                   SDValue(umulohi.getNode(), 0),
                                   SDValue(umulohi.getNode(), 1));
        Results.push_back(Pair);
        return;
      }
      // S1/S2 cores.
      Results.push_back(LowerLibCall(SDValue(N, 0), DAG, "_COM_mului", false,
                                     {N->getOperand(1), N->getOperand(2)}));
      return;
    }
    case Intrinsic::rl78_mulsi: {
      if (Subtarget->isRL78S3CoreType()) {
        SDValue umulohi =
            DAG.getNode(ISD::SMUL_LOHI, dl, DAG.getVTList(MVT::i16, MVT::i16),
                        N->getOperand(1), N->getOperand(2));
        SDValue Pair = DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32,
                                   SDValue(umulohi.getNode(), 0),
                                   SDValue(umulohi.getNode(), 1));
        Results.push_back(Pair);
        return;
      }
      // S1/S2 cores.
      Results.push_back(LowerLibCall(SDValue(N, 0), DAG, "_COM_mulsi", true,
                                     {N->getOperand(1), N->getOperand(2)}));
      return;
    }
    case Intrinsic::rl78_mulul: {
      Results.push_back(LowerLibCall(SDValue(N, 0), DAG, "_COM_mulul", false,
                                     {N->getOperand(1), N->getOperand(2)}));
      return;
    }
    case Intrinsic::rl78_mulsl: {
      Results.push_back(LowerLibCall(SDValue(N, 0), DAG, "_COM_mulsl", false,
                                     {N->getOperand(1), N->getOperand(2)}));
      return;
    }

    case Intrinsic::rl78_divul: {
      if (isConstantZero(N->getOperand(2))) {
        // CC-RL: When divisor y is 0, 0xFFFFFFFF is returned.
        Results.push_back(DAG.getConstant(0xFFFF'FFFF, dl, MVT::i32));
        return;
      }
      SDValue ZExt =
          DAG.getNode(ISD::ZERO_EXTEND, dl, MVT::i32, N->getOperand(2));
      // TODO: CCRL may have a dedicated function (without the
      // extension).
      if (Subtarget->isRL78S3CoreType())
        Results.push_back(
            DAG.getNode(ISD::UDIV, dl, MVT::i32, N->getOperand(1), ZExt));
      else
        Results.push_back(LowerLibCall(SDValue(N, 0), DAG,
                                       getLibcallName(RTLIB::UDIV_I32), false,
                                       {N->getOperand(1), ZExt}));
      return;
    }

    case Intrinsic::rl78_macsi: {
      Results.push_back(
          LowerLibCall(SDValue(N, 0), DAG, "_COM_macsi", true,
                       {N->getOperand(1), N->getOperand(2), N->getOperand(3)}));
      return;
    }

    case Intrinsic::rl78_macui: {
      Results.push_back(
          LowerLibCall(SDValue(N, 0), DAG, "_COM_macui", false,
                       {N->getOperand(1), N->getOperand(2), N->getOperand(3)}));
      return;
    }
    default:
      llvm_unreachable("Invalid intrinsic ID");
    }
    return;
  }
  // Frame indexes are 16-bit always
  case ISD::TargetFrameIndex: {
    Results.push_back(DAG.getTargetFrameIndex(cast<FrameIndexSDNode>(N)->getIndex(), MVT::i16));
    return;
  }
  case ISD::FrameIndex: {
    Results.push_back(DAG.getFrameIndex(cast<FrameIndexSDNode>(N)->getIndex(), MVT::i16));
    return;
  }
  // case ISD::Constant: {
  //  assert((N->getValueType(0) != MVT::i32) && "Invalid value type for
  //  Constant!"); return;
  //}
  // case ISD::UNDEF: {
  //  assert((N->getValueType(0) != MVT::i32) && "Invalid value type for
  //  UNDEF!");
  //  // UNDEF by itsels should be of the right type.
  //  // In case like when it's second operand of an LOAD for example it is the
  //  wrong size.
  //  // We hanlde those case in LowerOperationWrapper.
  //  return;
  //}
  case ISD::BUILD_PAIR: {
    return;
  }
  case ISD::GlobalAddress: {
    assert((N->getValueType(0) == MVT::i32) &&
           "Invalid value type for GlobalAddress!");
    const GlobalValue *GV =
        cast<GlobalAddressSDNode>(SDValue(N, 0))->getGlobal();
    int64_t Offset = cast<GlobalAddressSDNode>(SDValue(N, 0))->getOffset();
    SDValue LowAddress = DAG.getTargetGlobalAddress(
        GV, SDLoc(SDValue(N, 0)), MVT::i16, Offset, RL78MCExpr::VK_RL78_LOWW);
    SDValue HiAddress = DAG.getTargetGlobalAddress(
        GV, SDLoc(SDValue(N, 0)), MVT::i16, Offset, RL78MCExpr::VK_RL78_HIGHW);
    SDValue low =
        DAG.getNode(RL78ISD::LOW16, SDLoc(LowAddress), MVT::i16, LowAddress);
    SDValue high = DAG.getNode(RL78ISD::HI16, SDLoc(HiAddress), MVT::i16, HiAddress, low);
    SDValue Pair =
        DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, low, high);
    Results.push_back(Pair);
    return;
  }
  case ISD::SELECT: {
    // TODO: others? ABS?
    // If the select is the only use of the setcc we can safely convert it.
    // SDValue N0 = N->getOperand(0);
    // if (N0->hasOneUse() &&
    //    //(N0->getOperand(1).getValueType() ==
    //    N->getOperand(1).getValueType())
    //    ////&&
    //    (N0->getOperand(0) == N->getOperand(1)) &&
    //    (N0->getOperand(1) == N->getOperand(2))) {
    //  ISD::CondCode CC = cast<CondCodeSDNode>(N0->getOperand(2))->get();
    //  bool isSigned;
    //  // OBS. We don't have a RTLIB Libcall for integer (u)min/(u)max.
    //  const char *libCallName = nullptr;
    //  switch (CC) {
    //  case ISD::SETUGE:
    //  case ISD::SETUGT:
    //    libCallName = "__umax";
    //    isSigned = false;
    //    break;
    //  case ISD::SETGE:
    //  case ISD::SETGT:
    //    libCallName = "__smax";
    //    isSigned = true;
    //    break;
    //  case ISD::SETULE:
    //  case ISD::SETULT:
    //    libCallName = "__umin";
    //    isSigned = false;
    //    break;
    //  case ISD::SETLE:
    //  case ISD::SETLT:
    //    libCallName = "__smin";
    //    isSigned = true;
    //    break;
    //  default:
    //    break;
    //  }
    //  // TODO: we should only do this for code size.
    //  if (libCallName) {
    //    Results.push_back(
    //        LowerLibCall(SDValue(N, 0), DAG, libCallName, isSigned, 1));
    //  }
    //}
    return;
  }
  case ISD::BSWAP: {
    if (N->getSimpleValueType(0) == MVT::i64) {
      Results.push_back(
          createBSWAPNodes(N->getOperand(0), EVT(MVT::i64), DAG, dl));
      return;
    } else {
      // 32-bit BSWAP.
      EVT HalfVT = MVT::i16;
      SDValue one = DAG.getConstant(1, dl, HalfVT);
      SDValue zero = DAG.getConstant(0, dl, HalfVT);
      SDValue op0lo =
          DAG.getNode(ISD::EXTRACT_ELEMENT, dl, HalfVT, N->getOperand(0), zero);
      SDValue op0hi =
          DAG.getNode(ISD::EXTRACT_ELEMENT, dl, HalfVT, N->getOperand(0), one);
      SDValue xchw = DAG.getNode(RL78ISD::XCHW, dl,
                                 DAG.getVTList(HalfVT, HalfVT), op0lo, op0hi);
      SDValue pair = DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, SDValue(xchw.getNode(), 0),
                           SDValue(xchw.getNode(), 1));
      Results.push_back(pair);
      return;
    }
  }
  case ISD::MUL:
    assert(N->getValueType(0) == MVT::i32 &&
           "Invalid value type for multiplication!");
    if (Subtarget->isRL78S3CoreType() &&
        (((N->getOperand(0)->getOpcode() == ISD::ZERO_EXTEND) &&
          (N->getOperand(1)->getOpcode() == ISD::ZERO_EXTEND)) ||
         ((N->getOperand(0)->getOpcode() == ISD::SIGN_EXTEND) &&
          (N->getOperand(1)->getOpcode() == ISD::SIGN_EXTEND)))) {
      return;
    }
    Results.push_back(
        LowerLibCall(SDValue(N, 0), DAG, getLibcallName(RTLIB::MUL_I32),
                     N->getOperand(0)->getOpcode() == ISD::SIGN_EXTEND));
    return;
  case ISD::LRINT:
  case ISD::LROUND: {
    if (N->getOperand(0).getValueType() == MVT::f64) {
      Results.push_back(LowerLibCall(
          SDValue(N, 0), DAG, getLibcallName(RTLIB::FPTOSINT_F64_I32), true));
    } else {
      Results.push_back(LowerLibCall(
          SDValue(N, 0), DAG, getLibcallName(RTLIB::FPTOSINT_F32_I32), true));
    }
    return;
  }
  }
}

// This callback is invoked by the type legalizer to legalize nodes with an
// illegal operand type but legal result types.  It replaces the
// LowerOperation callback in the type Legalizer.
// For RL78 we need this in case of __far data.
void RL78TargetLowering::LowerOperationWrapper(
    SDNode *N, SmallVectorImpl<SDValue> &Results, SelectionDAG &DAG) const {
  SDLoc dl(N);
  switch (N->getOpcode()) {
  default:
    LLVM_DEBUG(N->dump());
    llvm_unreachable("Do not know how to custom type legalize this operation!");
    return;
  case ISD::INLINEASM: {
    // Don't bother if not -mfar-data
    if (DAG.getDataLayout().getPointerSizeInBits() != 32)
      return;

    // Look for any 32-bit addresses and truncate them
    // FIXME: properly support far addresses
    SmallVector<SDValue, 8> Ops;
    for (unsigned i = 0, e = N->getNumOperands(); i != e; ++i) {
      auto Op = N->getOperand(i);
      if (Op.getValueType().isSimple() && Op.getSimpleValueType() == MVT::i32) {
        if (i > 3 && Op->getOpcode() == ISD::BUILD_PAIR &&
            Op->getOperand(1)->getOpcode() == ISD::ZERO_EXTEND &&
            Op->getOperand(1)->getOperand(0)->getOpcode() == ISD::CopyFromReg) {
          Op = Op->getOperand(0); // just replace it with its lower part
        } else {
          ReplaceOperand(Op, Ops, DAG);
          continue;
        }
      }
      Ops.push_back(Op);
    }

    SDValue N2 = DAG.getNode(ISD::INLINEASM, SDLoc(N),
                             DAG.getVTList(MVT::Other, MVT::Glue), Ops);
    Results.push_back(N2.getValue(0)); // Chain
    Results.push_back(N2.getValue(1)); // Flag
    break;
  }
  case ISD::INTRINSIC_WO_CHAIN: {
    switch (N->getConstantOperandVal(0)) {
    case Intrinsic::rl78_remul:
      Results.push_back(LowerIntrinsicWithoutChain(SDValue(N, 0), DAG));
      return;
    default:
      llvm_unreachable("Unexpected intrinsic with chain!");
      break;
    }
    return;
  }
  case ISD::ADDRSPACECAST: {
    assert(N->getValueType(0) == MVT::i16);
    AddrSpaceCastSDNode *CastNode = dyn_cast<AddrSpaceCastSDNode>(N);
    if (CastNode->getDestAddressSpace() != RL78AS::FarCode &&
        CastNode->getDestAddressSpace() != RL78AS::FarData) {
      if (N->getOperand(0).getOpcode() == ISD::GlobalAddress) {
        if (N->getOperand(0)->getValueType(0) == MVT::i32) {
          const GlobalValue *GV =
              cast<GlobalAddressSDNode>(N->getOperand(0))->getGlobal();
          int64_t Offset =
              cast<GlobalAddressSDNode>(N->getOperand(0))->getOffset();
          SDValue TGA = DAG.getTargetGlobalAddress(GV, dl, MVT::i16, Offset);
          SDValue Low16 = DAG.getNode(RL78ISD::LOW16, dl, MVT::i16, TGA);
          Results.push_back(Low16);
        }
      } else {
        SDValue trunc =
            DAG.getNode(ISD::TRUNCATE, dl, MVT::i16, N->getOperand(0));
        Results.push_back(trunc);
      }
    } else {
      llvm_unreachable(
          "Do not know how to custom type legalize this operation!");
    }
    return;
  }
  case ISD::LOAD: {
    ReplaceLoadOperands(N, Results, DAG);
    return;
  }
  case ISD::STORE: {
    SmallVector<SDValue, 8> OpResults;
    SDValue Ptr = N->getOperand(2), Ofs = N->getOperand(3);
    // if the ptr is a 16-bit frame index (as we custom lowered it)
    // but the offset is a 32-bit undef, we can use the frame index directly
    // (the offset will be recreated as an undef of the same type as the ptr by getStore)
    if (Ptr->getOpcode() == ISD::FrameIndex && Ptr->getValueType(0) == MVT::i16 &&
        Ofs->getOpcode() == ISD::UNDEF && Ofs->getValueType(0) == MVT::i32) {
      OpResults.push_back(Ptr);
    } else {
      ReplaceOperand(Ptr, OpResults, DAG);
    }
    ReplaceOperand(Ofs, OpResults, DAG);
    if (OpResults.size() > 0) {
      StoreSDNode *ST = cast<StoreSDNode>(N);
      if (ST->isTruncatingStore())
        Results.push_back(
            DAG.getTruncStore(N->getOperand(0), dl, N->getOperand(1), OpResults[0],
                         ST->getPointerInfo(), ST->getMemoryVT(), ST->getAlign(),
                         ST->getMemOperand()->getFlags(), ST->getAAInfo()));
      else
        Results.push_back(
            DAG.getStore(N->getOperand(0), dl, N->getOperand(1), OpResults[0],
                         ST->getPointerInfo(), ST->getAlign(),
                         ST->getMemOperand()->getFlags(), ST->getAAInfo()));
    }
    return;
  }
  case ISD::EXTRACT_ELEMENT: {
    SmallVector<SDValue, 8> OpResults;
    SDValue I = N->getOperand(1);
    if (I->getValueType(0) == MVT::i32 && isa<ConstantSDNode>(I)) {
      const auto idx = cast<ConstantSDNode>(I)->getZExtValue();
      assert(idx < 2 && "Unexpected index for extract_element");
      SDValue V = N->getOperand(0);
      if (V->getOpcode() == ISD::FrameIndex || V->getOpcode() == ISD::TargetFrameIndex) {
        if (!idx) {
          SDValue TFI = (V->getOpcode() == ISD::FrameIndex)
              ? DAG.getTargetFrameIndex(cast<FrameIndexSDNode>(V)->getIndex(), MVT::i16)
              : N->getOperand(0);
          SDValue Imm = DAG.getTargetConstant(0, dl, MVT::i16);
          MachineSDNode *MN = DAG.getMachineNode(RL78::MOVW_rp_stack_slot, dl, MVT::i16, TFI, Imm);
          Results.push_back(SDValue(MN, 0));
        } else {
          Results.push_back(DAG.getConstant(0xF, dl, MVT::i16));
        }
        return;
      } else if (V->getOpcode() == ISD::BUILD_PAIR) {
        Results.push_back(V->getOperand(idx));
        return;
      } else {
        OpResults.push_back(DAG.getConstant(idx, dl, MVT::i16));
        // fall-through
      }
    }
    if (OpResults.empty())
        ReplaceOperand(N->getOperand(1), OpResults, DAG);
    if (!OpResults.empty()) {
      // N->getOperand(0)->dump();
      Results.push_back(DAG.getNode(ISD::EXTRACT_ELEMENT, dl,
                                    N->getValueType(0), N->getOperand(0),
                                    OpResults[0]));
    }
    return;
  }
  case RL78ISD::CALL_FP:
  case RL78ISD::TAIL_CALL:
  case RL78ISD::CALL: {
    if (N->getOperand(1).getValueType() == MVT::i32) {
      SmallVector<SDValue, 8> OpResults;
      ReplaceOperand(N->getOperand(1), OpResults, DAG);
      SDVTList NodeTys = DAG.getVTList(MVT::Other, MVT::Glue);
      SmallVector<SDValue, 8> Ops;
      Ops.push_back(N->getOperand(0)); // Chain
      Ops.push_back(OpResults[0]);     // Callee
      for (unsigned int i = 2; i < N->getNumOperands(); i++)
        Ops.push_back(N->getOperand(i));
      SDValue callNode = DAG.getNode(N->getOpcode(), dl, NodeTys, Ops);
      Results.push_back(callNode.getValue(0));
      Results.push_back(callNode.getValue(1));
    } else {
      llvm_unreachable(
          "Do not know how to custom type legalize this operation!");
    }
  }
  }
}
