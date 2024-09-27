//===-- ashlhi3.S - Implement ___ashlhi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___ashlhi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


  .file   "ashlhi3.s"

  .text
  
  .globl  ___ashlhi3
  .type  ___ashlhi3,@function
___ashlhi3:
  cmp0 c  ; The Z flag is set if the C register value is 0.
  bz  $.LBB_2  ; When Z = 1, data is branched to the address specified by the operand(.LBB_2).

.LBB_1:

  addw  ax, ax
  dec c
  bnz  $.LBB_1  ; When Z = 0, data is branched to the address specified by the operand(.LBB_1).

.LBB_2:
  ret
.Lfunc_end1:
  .size ___ashlhi3, .Lfunc_end1-___ashlhi3
