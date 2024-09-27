//===-- RL78CallingConv.td - Calling Conventions RL78 ----*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This describes the calling conventions for the RL78 architectures.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// RL78 LLVM calling convention
//===----------------------------------------------------------------------===//

def CC_RL78_LLVM : CallingConv<[
  CCIfType<[i8], CCAssignToReg<[R1, R0, R2, R3, R4, R5]>>,
  CCIfType<[i16, i32, f32], CCAssignToReg<[RP0, RP2, RP4]>>,
  //CCIfInReg<CCIfType<[i8], CCAssignToReg<[R1, R0, R2, R3, R4, R5]>>>,
  //CCIfInReg<CCIfType<[i16, i32, f32], CCAssignToReg<[RP0, RP2, RP4]>>>,
  // Assigned to the stack in 2-byte aligned units.
  CCAssignToStack<2, 2>
]>;

def RetCC_RL78_LLVM : CallingConv<[
  CCIfType<[i8], CCAssignToReg<[R1, R0, R2, R3, R4, R5, R6, R7]>>,
  CCIfType<[i16, i32, f32], CCAssignToReg<[RP0, RP2, RP4, RP6]>>
  //,
  // Assigned to the stack in 2-byte aligned units.
  //CCAssignToStack<2, 2>
]>;
//IPRA does a better job then having CSR register
def CSR : CalleeSavedRegs<(add)>;


//===----------------------------------------------------------------------===//
// RL78 CCRL calling convention - see LowerCall
//===----------------------------------------------------------------------===//
