//===-- REL_f_inf.S - Implement _REL_f_inf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_f_inf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_f_inf.S"

  .text

  .globl __REL_f_inf
  .type  __REL_f_inf,@function
__REL_f_inf:
  movw  bc,#0x7f80
  pop ax
  or  b,a
  clrw  ax
  ret
.Lfunc_end1:
  .size __REL_f_inf, .Lfunc_end1-__REL_f_inf
