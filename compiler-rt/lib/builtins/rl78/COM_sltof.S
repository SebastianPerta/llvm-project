//===-- COM_sltof.S - Implement __floatsisf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatsisf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_sltof.S"
  .extern __REL_ltof

  .text

  .globl __COM_sltof
  .type  __COM_sltof,@function
__COM_sltof:
  xchw  ax,bc
  mov e,#0    ; store sign (positive)
  mov1  cy,a.7
  xchw  ax,bc
  bnc $0f      ; if the sign bit is 0 (positive), no sign conversion is performed

  ; sign inversion
  movw  de,ax
  clrw  ax
  subw  ax,de
  movw  de,ax
  subc  a,a
  mov x,a
  subw  ax,bc
  movw  bc,ax
  movw  ax,de

  mov e,#1    ; store sign (negative)

0:
  br  !!__REL_ltof
.Lfunc_end1:
  .size __COM_sltof, .Lfunc_end1-__COM_sltof

  .weak ___floatsisf
  .type ___floatsisf,@function
  .set  ___floatsisf, __COM_sltof
