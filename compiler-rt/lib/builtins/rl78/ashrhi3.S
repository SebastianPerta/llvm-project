//===-- ashrhi3.S - Implement ___ashrhi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___ashrhi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


  .file  "ashrhi3.s"

  .text

  .globl  ___ashrhi3
  .type  ___ashrhi3,@function
___ashrhi3:
   cmp0 c   ; The Z flag is set if the C register value is 0. 
   bz      $.LBB_2   ; When Z = 1, data is branched to the address specified by the operand(.LBB_2).

.LBB_1:

   sarw  ax, 0x01
   dec c
   bnz     $.LBB_1   ; When Z = 0, data is branched to the address specified by the operand(.LBB_1).

.LBB_2:
  ret
.Lfunc_end1:
  .size ___ashrhi3, .Lfunc_end1-___ashrhi3
