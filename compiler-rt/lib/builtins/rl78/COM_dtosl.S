//===-- COM_dtosl.S - Implement __fixdfsi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixdfsi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dtosl.S"
  .extern __REL_dtol
  .extern __REL_ltosl

  .text

  .globl __COM_dtosl
  .type  __COM_dtosl,@function
__COM_dtosl:
  movw  ax,sp
  addw  ax,#4
  movw  hl,ax
  call  !!__REL_dtol
  br  !!__REL_ltosl
.Lfunc_end1:
  .size __COM_dtosl, .Lfunc_end1-__COM_dtosl

  .weak ___fixdfsi
  .type ___fixdfsi,@function
  .set  ___fixdfsi, __COM_dtosl
