//===-- REL_f_round.S - Implement _REL_f_round-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_f_round for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_f_round.S"

  .text

  .globl __REL_f_round
  .type  __REL_f_round,@function
__REL_f_round:
  movw  hl,ax   ; mantissa subordinate
  shrw  ax,1    ; set the least significant bit of the mantissa to cy
  mov a,e
  addc  a,#0x7f   ; judgment whether rounding judgment unit + cy is 0x81 or more
  bnc $0f
  incw  hl
  clrw  ax
  cmpw  ax,hl
  sknz
  incw  bc
0:
  pop ax    ; sign (most significant bit of a, other bits are 0)
  or  b,a
  movw  ax,hl   ; mantissa subordinate
  ret
.Lfunc_end1:
  .size __REL_f_round, .Lfunc_end1-__REL_f_round
