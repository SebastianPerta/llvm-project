//===-- REL_d_shl11.S - Implement _REL_d_shl11-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_d_shl11 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_d_shl11.S"

  .text

  .globl __REL_d_shl11
  .type  __REL_d_shl11,@function
__REL_d_shl11:
  mov a,[de+6]  ; mantissa top
  and a,#0x0f   ; cy does not change
  mov1  a.4,cy    ; miser expression
  clrb  x
  shlw  ax,3
  movw  bc,ax
  movw  ax,[de+4]
  shrw  ax,5
  addw  ax,bc
  movw  [de+6],ax
  movw  ax,[de+4]
  shlw  ax,11
  movw  bc,ax
  movw  ax,[de+2]
  shrw  ax,5
  addw  ax,bc
  movw  [de+4],ax
  movw  ax,[de+2]
  shlw  ax,11
  movw  bc,ax
  movw  ax,[de]
  shrw  ax,5
  addw  ax,bc
  movw  [de+2],ax
  movw  ax,[de]
  shlw  ax,11
  movw  [de],ax
  ret
.Lfunc_end1:
  .size __REL_d_shl11, .Lfunc_end1-__REL_d_shl11
