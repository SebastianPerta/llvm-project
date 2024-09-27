//===-- COM_fle.S - Implement _COM_fle-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_fle for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_fle.S"
  .extern __REL_fordered_core
  .extern __REL_fcmp

  .text
  .globl __COM_fle
  .type  __COM_fle,@function
__COM_fle:
  push  bc    ; x
  push  ax    ;
  call  !!__REL_fordered_core
  cmp0  a
  bz  $.L1
;
  call  !!__REL_fcmp
  skh
  oneb  a    ; ret = 1
  sknh
  clrb  a    ; ret = 0
.L1:
  addw  sp,#4
  ret
.Lfunc_end1:
  .size __COM_fle, .Lfunc_end1-__COM_fle
