//===-- COM_dne.S - Implement _COM_dne-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dne for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dne.S"
  .extern __REL_dordered_core
  .extern __REL_dcmp

  .text
  .globl __COM_dne
  .type  __COM_dne,@function
__COM_dne:
  call  !!__REL_dordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_dcmp
  sknz
  oneb  a
  skz
  clrb  a
.LBB_1:
  xor  a,#1
  ret
.Lfunc_end1:
  .size __COM_dne, .Lfunc_end1-__COM_dne
