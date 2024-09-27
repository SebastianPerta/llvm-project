//===-- COM_dge.S - Implement _COM_dge-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dge for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dge.S"
  .extern __REL_dordered_core
  .extern __REL_dcmp

  .text
  .globl __COM_dge
  .type  __COM_dge,@function
__COM_dge:
  call  !!__REL_dordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_dcmp
  skc
  oneb  a  ; ret = 1
  sknc
  clrb  a  ; ret = 0
.LBB_1:
  ret
.Lfunc_end1:
  .size __COM_dge, .Lfunc_end1-__COM_dge
