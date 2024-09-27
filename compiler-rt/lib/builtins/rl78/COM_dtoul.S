//===-- COM_dtoul.S - Implement __fixunsdfsi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixunsdfsi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dtoul.S"
  .extern __REL_dtol

  .text

  .globl __COM_dtoul
  .type  __COM_dtoul,@function
__COM_dtoul:
  movw  ax,sp
  addw  ax,#4
  movw  hl,ax
  mov a,[hl+7]
  bt  a.7,$0f    ; returns zero if the sign is negative
  br  !!__REL_dtol
0:
  clrw  bc
  clrw  ax
  ret
.Lfunc_end1:
  .size __COM_dtoul, .Lfunc_end1-__COM_dtoul

  .weak ___fixunsdfsi
  .type ___fixunsdfsi,@function
  .set  ___fixunsdfsi, __COM_dtoul
