//===-- COM_dsub.S - Implement __subdf3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __subdf3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dsub.S"
  .extern __COM_dadd

  .text

  .globl __COM_dsub
  .type  __COM_dsub,@function
__COM_dsub:
#ifdef __FAR_DATA__
  mov   x, a
#else
  movw  de,ax
#endif
  mov a,[sp+19] ; ux - yv -> ux + (-y)v
  mov1  cy,a.7
  not1  cy
  mov1  a.7,cy
  mov [sp+19],a
#ifdef __FAR_DATA__
  mov   a, x
#else
  movw  ax,de
#endif
  br  !!__COM_dadd
.Lfunc_end1:
  .size __COM_dsub, .Lfunc_end1-__COM_dsub

  .weak ___subdf3
  .type ___subdf3,@function
  .set  ___subdf3, __COM_dsub
