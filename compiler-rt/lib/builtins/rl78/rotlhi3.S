//==-- rotlhi3.S - Implement ___rotlhi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___rotlhi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


  .file   "rotlhi3.s"

  .text
  .globl  ___rotlhi3
  .type   ___rotlhi3,@function
___rotlhi3:
  cmp0 c
  bz $.LBB_2
.LBB_1:  ; entry
  mov1 CY, a.7
  rolwc ax, 1
  dec c
  bnz $.LBB_1
.LBB_2:  ; entry
  ret
.Lfunc_end1:
  .size ___rotlhi3, .Lfunc_end1-___rotlhi3