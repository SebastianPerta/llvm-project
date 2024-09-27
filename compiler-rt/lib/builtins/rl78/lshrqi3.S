//===-- lshrqi3.S - Implement ___lshrqi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ___lshrqi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file  "lshrqi3.s"

  .text

  .globl  ___lshrqi3
  .type  ___lshrqi3,@function
___lshrqi3:
   cmp0 x
   bz   $.LBB_2
.LBB_1:
   shr  a, 1

   dec  x
   bnz  $.LBB_1
.LBB_2:
  ret
.Lfunc_end1:
  .size  ___lshrqi3, .Lfunc_end1- ___lshrqi3
