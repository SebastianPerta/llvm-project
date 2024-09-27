//===-- COM_flt.S - Implement _COM_flt-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_flt for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_flt.S"
  .extern __REL_fordered_core
  .extern __REL_fcmp

  .text
  .globl __COM_flt
  .type  __COM_flt,@function
__COM_flt:
  push  bc    ; x
  push  ax    ;
;
  call  !!__REL_fordered_core
  cmp0  a
  bz  $.L1
;
  call  !!__REL_fcmp
  sknc
  oneb  a    ; ret = 1
  skc
  clrb  a    ; ret = 0
.L1:
  addw  sp,#4
  ret
.Lfunc_end1:
  .size __COM_flt, .Lfunc_end1-__COM_flt
