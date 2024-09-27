//===-- COM_slltof.S - Implement __floatdisf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatdisf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_slltof.S"
  .extern __REL_lltof
  .extern __REL_llrev

  .text

  .globl __COM_slltof
  .type  __COM_slltof,@function
__COM_slltof:
  movw  ax,sp   ; store the address of the input value in the hl register
  addw  ax,#4
  movw  hl,ax
  
  mov e,#0    ; store sign (positive)
  mov a,[hl+7]  ; store the most significant byte of the input value in the a register
  mov1  cy,a.7
  bnc $0f   ; if the sign bit is 0 (positive), no sign conversion is performed
  
  ; sign inversion
  call  !!__REL_llrev
  mov e,#1    ; store sign (negative)
0:
  br  !!__REL_lltof
.Lfunc_end1:
  .size __COM_slltof, .Lfunc_end1-__COM_slltof

  .weak ___floatdisf
  .type ___floatdisf,@function
  .set  ___floatdisf, __COM_slltof
