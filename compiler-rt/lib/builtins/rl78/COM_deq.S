//===-- COM_deq.S - Implement _COM_deq-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_deq for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_deq.S"
  .extern __REL_dordered_core
  .extern __REL_dcmp


  .text
  .globl __COM_deq
  .type  __COM_deq,@function
__COM_deq:
  call  !!__REL_dordered_core
  cmp0  a
  bz  $.LBB_1
;
  call  !!__REL_dcmp
  sknz
  oneb  a    ; ret = 1
  skz
  clrb  a    ; ret = 0
.LBB_1:
  ret
.Lfunc_end1:
  .size __COM_deq, .Lfunc_end1-__COM_deq
