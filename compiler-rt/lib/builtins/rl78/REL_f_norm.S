//===-- REL_f_norm.S - Implement _REL_f_norm-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_f_norm for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_f_norm.S"

  .text

  .globl __REL_f_norm
  .type  __REL_f_norm,@function
__REL_f_norm:
  ; normalize the mantissa
  mov h,#0x1    ; index part
  xchw  ax,bc
  xch a,x
0:
  shlw  bc,1    ; shift the mantissa to the left
  rolc  a,1
  dec h   ; subtract the exponent
  bf  a.7,$0b
  shrw  ax,8    ; upper part of mantissa (upper byte is 0)
  xchw  ax,bc
  ret
.Lfunc_end1:
  .size __REL_f_norm, .Lfunc_end1-__REL_f_norm
