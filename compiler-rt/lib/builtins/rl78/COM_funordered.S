//===-- COM_funordered.S - Implement _COM_funordered-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_funordered for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_funordered.S"
  .extern __REL_fordered_core

  .text
  .globl __COM_funordered
  .type  __COM_funordered,@function
__COM_funordered:
  push  bc
  push  ax
  call  !!__REL_fordered_core
  addw  sp,#4
  xor  a,#1    ; ret = !ret
  ret
.Lfunc_end1:
  .size __COM_funordered, .Lfunc_end1-__COM_funordered
