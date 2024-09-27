//==- llvm/lib/Target/RL78/RL78SelectionDAGTargetInfo.h - RL78 SelectionDAG Info
//--*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------------------------===//
//
// This file implements the RL78 specific subclass of SelectionDAGTargetInfo.
//
//===---------------------------------------------------------------------------------------===//

#include "RL78SelectionDAGTargetInfo.h"
#include "RL78.h"
#include "llvm/CodeGen/TargetLowering.h"

using namespace llvm;

RL78SelectionDAGTargetInfo::~RL78SelectionDAGTargetInfo() = default;

// Common implementation for EmitTargetCodeForMemcpy() and EmitTargetCodeForMemmove() below;
// the different elements (i.e. the libcall id and name) are passed as parameters
SDValue
RL78SelectionDAGTargetInfo::EmitTargetCodeForMemcpymove(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1, SDValue Op2,
    SDValue Op3, Align Align, bool isVolatile, bool AlwaysInline,
    MachinePointerInfo DstPtrInfo, MachinePointerInfo SrcPtrInfo,
    unsigned LibCall, const char *FarLibCallName) const {
  if (AlwaysInline)
    return SDValue();

  // FIXME: If the memcpy is volatile (isVol), lowering it to a plain libc
  // memcpy is not guaranteed to be safe. libc memcpys aren't required to
  // respect volatile, so they may do things like read or write memory
  // beyond the given memory regions. But fixing this isn't easy, and most
  // people don't care.

  // Emit a library call.
  TargetLowering::ArgListTy Args;
  TargetLowering::ArgListEntry Entry;

  // If the default pointer size is 32 bits, -mfar-data is in effect
  const auto FarData = DAG.getDataLayout().getPointerSizeInBits() == 32;

  // If that is the case, but we see *any* near pointers, we need to promote them to far
  // as memcpy == _COM_memcpy_ff (i.e. we don't have a func version working w/ near ptrs)
  // NOTE: we do this promotion here as we may optimize it in the future (e.g.
  // have a _COM_memcpy_nn available for this when building with -mfar-data?)
  // NOTE2: we can also get a near/far ptr mix with -mfar-rom or with a ptr to data
  // explicitly marked __far, so also use a general test (if the ptr sizes are different)
  if (FarData ||
      DAG.getDataLayout().getPointerSizeInBits(DstPtrInfo.getAddrSpace()) !=
          DAG.getDataLayout().getPointerSizeInBits(SrcPtrInfo.getAddrSpace())) {
    const auto nearSeg = DAG.getConstant(0xf, dl, MVT::i16);
    if (DAG.getDataLayout().getPointerSizeInBits(DstPtrInfo.getAddrSpace()) == 16) {
      Op1 = DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, Op1, nearSeg);
      DstPtrInfo.AddrSpace = FarData ? 0 : 2;
    }
    if (DAG.getDataLayout().getPointerSizeInBits(SrcPtrInfo.getAddrSpace()) == 16) {
      Op2 = DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, Op2, nearSeg);
      SrcPtrInfo.AddrSpace = FarData ? 0 : 2;
    }
  }

  Entry.Ty = Type::getInt8PtrTy(*DAG.getContext(), DstPtrInfo.getAddrSpace());
  Entry.Node = Op1;
  Args.push_back(Entry);

  Entry.Ty = Type::getInt8PtrTy(*DAG.getContext(), SrcPtrInfo.getAddrSpace());
  Entry.Node = Op2;
  Args.push_back(Entry);

  // -mfar-data makes the default ptr size (in address space 0) 32-bit;
  // in this case, use address space 1 (near) to reflect that size_t remains 16-bit
  Entry.Ty = DAG.getDataLayout().getIntPtrType(*DAG.getContext(), FarData ? 1 : 0);
  Entry.Node = Op3;
  Args.push_back(Entry);

  const char *libcallName =
      DAG.getDataLayout().getPointerSizeInBits(DstPtrInfo.getAddrSpace()) == 32
          ? FarLibCallName
          : DAG.getTargetLoweringInfo().getLibcallName((RTLIB::Libcall)LibCall);

  // FIXME: pass in SDLoc
  TargetLowering::CallLoweringInfo CLI(DAG);
  CLI.setDebugLoc(dl)
      .setChain(Chain)
      .setLibCallee(
          DAG.getTargetLoweringInfo().getLibcallCallingConv(
              (RTLIB::Libcall)LibCall),
          Op1.getValueType().getTypeForEVT(*DAG.getContext()),
          DAG.getExternalSymbol(
              libcallName, DAG.getTargetLoweringInfo().getPointerTy(
                               DAG.getDataLayout(),
                               DAG.getDataLayout().getProgramAddressSpace())),
          std::move(Args))
      .setDiscardResult();

  std::pair<SDValue, SDValue> CallResult =
      DAG.getTargetLoweringInfo().LowerCallTo(CLI);
  return CallResult.second;
}

SDValue RL78SelectionDAGTargetInfo::EmitTargetCodeForMemcpy(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1, SDValue Op2,
    SDValue Op3, Align Align, bool isVolatile, bool AlwaysInline,
    MachinePointerInfo DstPtrInfo, MachinePointerInfo SrcPtrInfo) const {
  return EmitTargetCodeForMemcpymove(
      DAG, dl, Chain, Op1, Op2, Op3, Align, isVolatile, AlwaysInline,
      DstPtrInfo, SrcPtrInfo, RTLIB::MEMCPY, "_COM_memcpy_ff");
}

SDValue RL78SelectionDAGTargetInfo::EmitTargetCodeForMemmove(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1, SDValue Op2,
    SDValue Op3, Align Align, bool isVolatile, MachinePointerInfo DstPtrInfo,
    MachinePointerInfo SrcPtrInfo) const {
  return EmitTargetCodeForMemcpymove(DAG, dl, Chain, Op1, Op2, Op3, Align,
                                     isVolatile, false, DstPtrInfo, SrcPtrInfo,
                                     RTLIB::MEMMOVE, "_COM_memmove_ff");
}

SDValue RL78SelectionDAGTargetInfo::EmitTargetCodeForMemset(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1, SDValue Op2,
    SDValue Op3, Align Align, bool isVolatile,  bool AlwaysInline,
    MachinePointerInfo DstPtrInfo) const {

  // Emit a library call.
  TargetLowering::ArgListTy Args;
  TargetLowering::ArgListEntry Entry;

  // If the default pointer size is 32 bits, -mfar-data is in effect
  const auto FarData = DAG.getDataLayout().getPointerSizeInBits() == 32;

  // If that's the case and we get a near pointer, we need to promote it to far
  // as memset == _COM_memset_f (i.e. we don't have a near-ptr version of memset)
  // NOTE: we do this promotion here as we may optimize it in the future (e.g.
  // have a _COM_memset_n available for this when building with -mfar-data)
  if (FarData && DAG.getDataLayout().getPointerSizeInBits(DstPtrInfo.getAddrSpace()) == 16) {
    const auto nearSeg = DAG.getConstant(0xf, dl, MVT::i16);
    Op1 = DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i32, Op1, nearSeg);
    DstPtrInfo.AddrSpace = 0;
  }

  Entry.Node = Op1;
  Entry.Ty = Type::getInt8PtrTy(*DAG.getContext(), DstPtrInfo.getAddrSpace());
  Args.push_back(Entry);

  Entry.Node = Op2;
  // Here we pass it as i16, despite only the low i8 part being used
  Entry.Ty =
      EVT::getIntegerVT(*DAG.getContext(), 16).getTypeForEVT(*DAG.getContext());
  Args.push_back(Entry);

  Entry.Node = Op3;
  // -mfar-data makes the default ptr size (in address space 0) 32-bit;
  // in this case, use address space 1 (near) to reflect that size_t remains 16-bit
  Entry.Ty = DAG.getDataLayout().getIntPtrType(*DAG.getContext(), FarData ? 1 : 0);
  Args.push_back(Entry);

  const char *libcallName =
      DAG.getDataLayout().getPointerSizeInBits(DstPtrInfo.getAddrSpace()) == 32
          ? "_COM_memset_f"
          : DAG.getTargetLoweringInfo().getLibcallName(RTLIB::MEMSET);

  // FIXME: pass in SDLoc
  TargetLowering::CallLoweringInfo CLI(DAG);
  CLI.setDebugLoc(dl)
      .setChain(Chain)
      .setLibCallee(
          DAG.getTargetLoweringInfo().getLibcallCallingConv(RTLIB::MEMSET),
          Op1.getValueType().getTypeForEVT(*DAG.getContext()),
          DAG.getExternalSymbol(
              libcallName, DAG.getTargetLoweringInfo().getPointerTy(
                               DAG.getDataLayout(),
                               DAG.getDataLayout().getProgramAddressSpace())),
          std::move(Args))
      .setDiscardResult();

  std::pair<SDValue, SDValue> CallResult =
      DAG.getTargetLoweringInfo().LowerCallTo(CLI);
  return CallResult.second;
}
