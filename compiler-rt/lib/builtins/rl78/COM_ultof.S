//===-- COM_ultof.S - Implement __floatunsisf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatunsisf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ultof.S"
  .extern   __REL_ltof

  .text

  .globl __COM_ultof
  .type  __COM_ultof,@function
__COM_ultof:
  mov e,#0    ; store sign (always positive)
  br  !!__REL_ltof
.Lfunc_end1:
  .size __COM_ultof, .Lfunc_end1-__COM_ultof

  .weak ___floatunsisf
  .type ___floatunsisf,@function
  .set  ___floatunsisf, __COM_ultof
