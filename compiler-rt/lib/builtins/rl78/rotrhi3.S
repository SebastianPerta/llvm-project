//==-- rotrhi3.S - Implement ___rotrhi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___rotrhi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


  .file   "rotrhi3.s"

  .text
  .globl  ___rotrhi3
  .type   ___rotrhi3,@function
___rotrhi3:
  cmp0  c
  bz    $.LBB_1

.LBB_0:
  shrw ax, 1
  mov1 a.7, cy
  dec  c
  bnz   $.LBB_0

.LBB_1:
  ret
.Lfunc_end1:
  .size ___rotrhi3, .Lfunc_end1-___rotrhi3
