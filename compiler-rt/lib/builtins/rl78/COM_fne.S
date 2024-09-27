//===-- COM_fne.S - Implement _COM_fne-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_fne for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_fne.S"
  .extern __COM_feq

  .text
  .globl __COM_fne
  .type  __COM_fne,@function
__COM_fne:
  movw  de,ax
  movw  ax,[sp+6]
  push  ax
  movw  ax,[sp+6]
  push  ax
  movw  ax,de
  call  !!__COM_feq
  addw  sp,#4
  xor  a,#1
  ret
.Lfunc_end1:
  .size __COM_fne, .Lfunc_end1-__COM_fne
