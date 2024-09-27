//==-- rotrqi3.S - Implement ___rotrqi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___rotrqi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


    .file   "rotrqi3.s"

  .text
  .globl  ___rotrqi3
  .type   ___rotrqi3,@function
___rotrqi3:
  cmp0  x
  bz    $.LBB_1
.LBB_0:
  ror  a, 1
  dec   x
  bnz   $.LBB_0
.LBB_1:
  ret
.Lfunc_end1:
  .size ___rotrqi3, .Lfunc_end1-___rotrqi3
