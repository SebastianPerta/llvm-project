//===-- REL_fordered_core.S - Implement _REL_fordered_core-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_fordered_core for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_fordered_core.S"

  .text
  .globl __REL_fordered_core
  .type  __REL_fordered_core,@function
__REL_fordered_core:
  shlw  bc,1 
  inc  b
  oneb  b
  bz  $.LBB_3
  
.LBB_2:
  cmp0  b
  bz  $.LBB_1
  movw  ax,[sp+14]
  addw  ax,ax
  movw  bc,ax
  movw  ax,[sp+12]
  inc  b
  bz  $.LBB_3

.LBB_1:  
  oneb  a
  ret

.LBB_3:
  or  a,x
  or  a,c
  bz  $.LBB_2
  clrb  a
  ret

.Lfunc_end1:
  .size __REL_fordered_core, .Lfunc_end1-__REL_fordered_core

