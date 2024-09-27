//===-- COM_ftoul.S - Implement __fixunssfsi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixunssfsi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ftoul.S"
  .extern __REL_ftol

  .text

  .globl __COM_ftoul
  .type  __COM_ftoul,@function
__COM_ftoul:
  xchw  ax,bc
  bt  a.7,$0f    ; returns zero if the sign is negative
  xchw  ax,bc
  br  !!__REL_ftol
0:
  clrw  bc
  clrw  ax
  ret
.Lfunc_end1:
  .size __COM_ftoul, .Lfunc_end1-__COM_ftoul

  .weak ___fixunssfsi
  .type ___fixunssfsi,@function
  .set  ___fixunssfsi, __COM_ftoul
