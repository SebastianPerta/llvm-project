//===-- REL_fcmp.S - Implement _REL_fcmp-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_fcmp for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_fcmp.S"

  .text
  .globl __REL_fcmp
  .type  __REL_fcmp,@function
__REL_fcmp:
  movw  hl,sp
  movw  ax,[hl+14]
  movw  bc,ax
  mov1  cy,a.7
  movw  ax,[hl+6]
  xor1  cy,a.7
  bc  $.LBB_1

  cmpw  ax,[hl+14]
  movw  ax,[hl+4]
  sknz
  cmpw  ax,[hl+12]
  mov  a,[hl+7]
  skz
  xor1  cy,a.7
  ret
.LBB_1:
  addw  ax,ax
  or  a,x
  or  a,[hl+5]
  or  a,[hl+4]
  shlw  bc,1
  or  a,b
  or  a,c
  or  a,[hl+13]
  or  a,[hl+12]
  cmp0  a
  mov  a,[hl+7]
  skz
  mov1  cy,a.7
  ret
.Lfunc_end1:
  .size __REL_fcmp, .Lfunc_end1-__REL_fcmp