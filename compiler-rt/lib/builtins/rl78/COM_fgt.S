//===-- COM_fgt.S - Implement _COM_fgt-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_fgt for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_fgt.S"
  .extern __REL_fordered_core
  .extern __REL_fcmp

  .text
  .globl __COM_fgt
  .type  __COM_fgt,@function
__COM_fgt:
  push  bc    ; x
  push  ax    ;
  call  !!__REL_fordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_fcmp
  sknh
  oneb  a    ; ret = 1
  skh
  clrb  a    ; ret = 0
.LBB_1:
  addw  sp,#4
  ret
.Lfunc_end1:
  .size __COM_fgt, .Lfunc_end1-__COM_fgt
