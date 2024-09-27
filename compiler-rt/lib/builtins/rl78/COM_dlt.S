//===-- COM_dlt.S - Implement _COM_dlt-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dlt for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dlt.S"
  .extern __REL_dordered_core
  .extern __REL_dcmp

  .text
  .globl __COM_dlt
  .type  __COM_dlt,@function
__COM_dlt:
  call  !!__REL_dordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_dcmp
  sknc
  oneb  a  ; ret = 1
  skc
  clrb  a  ; ret = 0
.LBB_1:
  ret
.Lfunc_end1:
  .size __COM_dlt, .Lfunc_end1-__COM_dlt
