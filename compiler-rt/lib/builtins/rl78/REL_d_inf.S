//===-- REL_d_inf.S - Implement _REL_d_inf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_d_inf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_d_inf.S"

  .text

  .globl __REL_d_inf
  .type  __REL_d_inf,@function
__REL_d_inf:
  ; set infinity
  movw  ax,#0x07ff0 ; ret = 0x7ff0000000000000 (infinity) and sign bit
  mov1  a.7,cy    ; sign
  movw  [de+6],ax
  clrw  ax
  movw  [de+4],ax
  movw  [de+2],ax
  movw  [de],ax
  ret
.Lfunc_end1:
  .size __REL_d_inf, .Lfunc_end1-__REL_d_inf
