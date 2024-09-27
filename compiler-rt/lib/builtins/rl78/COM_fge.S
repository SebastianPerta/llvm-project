//===-- COM_fge.S - Implement _COM_fge-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_fge for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_fge.S"
  .extern __REL_fordered_core
  .extern __REL_fcmp

  .text
  .globl __COM_fge
  .type  __COM_fge,@function
__COM_fge:
  push  bc    ; x
  push  ax    ;
  call  !!__REL_fordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_fcmp
  skc
  oneb  a    ; ret = 1
  sknc
  clrb  a    ; ret = 0
.LBB_1:
  addw  sp,#4
  ret
.Lfunc_end1:
  .size __COM_fge, .Lfunc_end1-__COM_fge
