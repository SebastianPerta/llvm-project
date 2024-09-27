//===-- COM_ftosl.S - Implement __fixsfsi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixsfsi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ftosl.S"
  .extern __REL_ftol
  .extern __REL_ltosl

  .text

  .globl __COM_ftosl
  .type  __COM_ftosl,@function
__COM_ftosl:
  call  !!__REL_ftol
  br  !!__REL_ltosl
.Lfunc_end1:
  .size __COM_ftosl, .Lfunc_end1-__COM_ftosl

  .weak ___fixsfsi
  .type ___fixsfsi,@function
  .set  ___fixsfsi, __COM_ftosl
