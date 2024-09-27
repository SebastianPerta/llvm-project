//===-- COM_dle.S - Implement _COM_dle-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dle for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dle.S"
  .extern __REL_dordered_core
  .extern __REL_dcmp

  .text
  .globl __COM_dle
  .type  __COM_dle,@function
__COM_dle:
  call  !!__REL_dordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_dcmp
  skh
  oneb  a  ; ret = 1
  sknh
  clrb  a  ; ret = 0
.LBB_1:
  ret
.Lfunc_end1:
  .size __COM_dle, .Lfunc_end1-__COM_dle
