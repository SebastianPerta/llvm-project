//===-- RL78TargetTransformInfo.cpp - RL78 specific TTI pass ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
/// \file
/// This file implements a TargetTransformInfo analysis pass specific to the
/// RL78 target machine. It uses the target's detailed information to provide
/// more precise answers to certain TTI queries, while letting the target
/// independent and default TTI implementations handle the rest.
///

#include "RL78TargetTransformInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/CodeGen/BasicTTIImpl.h"
#include "llvm/CodeGen/CostTable.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

#define DEBUG_TYPE "RL78tti"

TTI::MemCmpExpansionOptions
RL78TTIImpl::enableMemCmpExpansion(bool OptSize, bool IsZeroCmp) const {
  // Not sure if this expansion ever pays off when opt for size and -mfar-data...
  // FIXME: also, it seems to trigger a bug (missing initialization of the segment
  // register in the second call to foo()) for gcc_c_torture\Input\20050502-1.c
  // Anyway, just disable this combination for now
  if (OptSize && ST->HasFarDataModel())
    return {};

  TTI::MemCmpExpansionOptions Options;
  Options.LoadSizes = { 2, 1 };
  Options.MaxNumLoads = TLI->getMaxExpandSizeMemcmp(OptSize);
  return Options;
}

bool RL78TTIImpl::hasDivRemOp(Type *DataType, bool IsSigned) {
  EVT VT = TLI->getValueType(DL, DataType);
  return !IsSigned && ST->isRL78S3CoreType() &&
         (VT == MVT::i16 || VT == MVT::i32);
}
