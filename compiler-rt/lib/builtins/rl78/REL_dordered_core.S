//===-- REL_dordered_core.S - Implement _REL_dordered_core-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_dordered_core for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_dordered_core.S"

  .text
  .globl __REL_dordered_core
  .type  __REL_dordered_core,@function
__REL_dordered_core:

  mov  b,#2
  movw  ax,sp
.LBB_1:
  addw  ax,#8
  movw  hl,ax
  movw  ax,[hl+6]
  addw  ax,ax
  shrw  ax,5
  cmpw  ax,#0x07FF
  bz  $.LBB_4  ;INF or NaN
.LBB_2:
  dec  b
  bz  $.LBB_3
  movw  ax,hl
  br  $.LBB_1
.LBB_3:
  oneb  a
  ret
.LBB_4:
  mov  a,[hl+6]
  and  a,#0x0F
  or  a,[hl+5]
  or  a,[hl+4]
  or  a,[hl+3]
  or  a,[hl+2]
  or  a,[hl+1]
  or  a,[hl]
  bz  $.LBB_2
  clrb  a
  ret
.Lfunc_end1:
  .size __REL_dordered_core, .Lfunc_end1-__REL_dordered_core
