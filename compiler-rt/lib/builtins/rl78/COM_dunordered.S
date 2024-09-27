//===-- COM_dunordered.S - Implement _COM_dunordered-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dunordered for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dunordered.S"
  .extern __REL_dordered_core

  .text
  .globl __COM_dunordered
  .type  __COM_dunordered,@function
__COM_dunordered:
  call  !!__REL_dordered_core
  xor  a,#1    ; ret = !ret
  ret
.Lfunc_end1:
  .size __COM_dunordered, .Lfunc_end1-__COM_dunordered
