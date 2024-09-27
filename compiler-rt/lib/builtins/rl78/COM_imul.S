//===-- COM_imul.S - Implement __mulhi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __mulhi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "def.S"

  .file   "COM_imul.S"

  .text

  .globl __COM_imul
  .type  __COM_imul,@function
__COM_imul:
#ifdef __RL78_S3__
  mulhu
  ret
#elif defined(__MDA_ENABLED__)
  push  psw
  di
  clrb  !LOWW(MDUC) ; divmode,macmode,mdsm = 0
  movw  MDAL,ax   ; MDBH-MDBL = MDAL * MDAH
  movw  ax,bc   ;
  movw  MDAH,ax   ;
  nop     ;
  movw  ax,MDBL   ;
  pop psw
  ret
#else
  xch a,c
  movw  de,ax
  xch a,b
  mulu  x   ; x_l * y_h
  xchw  ax,bc
  mulu  x   ; x_h * y_l
  xchw  ax,de
  mulu  x   ; ret = x_l * y_l
  add a,c   ; ret_h += (x_l * y_h)_l + (x_h * y_l)_l
  add a,e   ;
  ret
#endif
.Lfunc_end1:
  .size __COM_imul, .Lfunc_end1-__COM_imul

  .weak ___mulhi3
  .type ___mulhi3,@function
  .set  ___mulhi3, __COM_imul
