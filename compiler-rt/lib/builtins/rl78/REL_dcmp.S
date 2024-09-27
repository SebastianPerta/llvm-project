//===-- REL_dcmp.S - Implement _REL_dcmp-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_dcmp for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_dcmp.S"

  .text
  .globl __REL_dcmp
  .type  __REL_dcmp,@function
__REL_dcmp:
  movw  hl,sp
  movw  ax,[hl+22]
  movw  bc,ax
  mov1  cy,a.7
  movw  ax,[hl+14]
  xor1  cy,a.7
  bc  $.L_OTHER

  cmpw  ax,bc
  bnz  $.L_NEQ
  movw  ax,[hl+12]
  cmpw  ax,[hl+20]
  bnz  $.L_NEQ
  movw  ax,[hl+10]
  cmpw  ax,[hl+18]
  bnz  $.L_NEQ
  movw  ax,[hl+8]
  cmpw  ax,[hl+16]
.L_NEQ:
  mov  a,[hl+15]
  skz
  xor1  cy,a.7
  ret
.L_OTHER:
  addw  ax,ax
  or  a,x
  or  a,[hl+13]
  or  a,[hl+12]
  or  a,[hl+11]
  or  a,[hl+10]
  or  a,[hl+9]
  or  a,[hl+8]
  shlw  bc,1
  or  a,b
  or  a,c
  or  a,[hl+21]
  or  a,[hl+20]
  or  a,[hl+19]
  or  a,[hl+18]
  or  a,[hl+17]
  or  a,[hl+16]
  cmp0  a
  mov  a,[hl+15]
  skz
  mov1  cy,a.7
  ret
.Lfunc_end1:
  .size __REL_dcmp, .Lfunc_end1-__REL_dcmp
