//===-- COM_dgt.S - Implement _COM_dgt-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dgt for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dgt.S"
  .extern __REL_dordered_core
  .extern __REL_dcmp

  .text
  .globl __COM_dgt
  .type  __COM_dgt,@function
__COM_dgt:
  call  !!__REL_dordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_dcmp
  sknh
  oneb  a  ; ret = 1
  skh
  clrb  a  ; ret = 0
.LBB_1:
  ret
.Lfunc_end1:
  .size __COM_dgt, .Lfunc_end1-__COM_dgt
