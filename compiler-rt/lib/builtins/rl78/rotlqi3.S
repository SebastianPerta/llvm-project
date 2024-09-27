//==-- rotlqi3.S - Implement ___rotlqi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___rotlqi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


  .file	"rotlqi3.s"

  .text
  .globl  ___rotlqi3
  .type   ___rotlqi3,@function
___rotlqi3:
  cmp0  x
  bz    $.LBB_1
.LBB_0:
  rol  a, 1
  dec   x
  bnz   $.LBB_0
.LBB_1:
  ret
.Lfunc_end1:
  .size ___rotlqi3, .Lfunc_end1-___rotlqi3