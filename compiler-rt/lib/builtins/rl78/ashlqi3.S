//===-- ashlqi3.S - Implement ___ashlqi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___ashlqi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


  .file  "ashlqi3.s"

  .text

  .globl  ___ashlqi3
  .type  ___ashlqi3,@function
___ashlqi3:
  cmp0 x
  bz   $.LBB_2
.LBB_1:
  shl a, 1
  dec x
  bnz  $.LBB_1
.LBB_2:
  ret
.Lfunc_end1:
  .size ___ashlqi3, .Lfunc_end1-___ashlqi3
