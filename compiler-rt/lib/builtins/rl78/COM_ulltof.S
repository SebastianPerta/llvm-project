//===-- COM_ulltof.S - Implement __floatundisf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatundisf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ulltof.S"
  .extern __REL_lltof

  .text

  .globl __COM_ulltof
  .type  __COM_ulltof,@function
__COM_ulltof:
  mov e,#0    ; store sign (always positive)
  movw  ax,sp
  addw  ax,#4
  movw  hl,ax
  br  !!__REL_lltof
.Lfunc_end1:
  .size __COM_ulltof, .Lfunc_end1-__COM_ulltof

  .weak ___floatundisf
  .type ___floatundisf,@function
  .set  ___floatundisf, __COM_ulltof
