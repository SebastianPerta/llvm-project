//===-- COM_mului.S - Implement _COM_mului-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_mului for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "def.S"

  .file   "COM_mului.S"

  .text

  .globl __COM_mului
  .type  __COM_mului,@function
__COM_mului:
#ifdef __RL78_S3__
  mulhu
  ret
#elif defined(__MDA_ENABLED__)
  push  psw
  di
  clrb  !LOWW(MDUC) ; divmode,macmode,mdsm = 0
  movw  MDAL,ax   ; MDBH,MDBL = MDAL * MDAH
  movw  ax,bc   ;
  movw  MDAH,ax   ;
  nop     ;
  movw  bc,!LOWW(MDBH)  ;
  movw  ax,MDBL   ;
  pop psw
  ret
#else
  movw  de,ax   ; x

  ; x_l * y_l
  mov a,c
  mulu  x
  movw  hl,ax   ; hl <= (x_l * y_l)

  ; x_h * y_l
  movw  ax,bc   ; x <= c
  mov a,d
  mulu  x
  xch a,x
  add h,a   ; h <= (x_h * y_l)_l + (x_l * y_l)_h
  clrb  a   ; (x_h * y_l) _h <= 0xfe
  addc  a,x   ; cy does not occur in the addc instruction
  mov c,a   ; c <= (x_h * y_l)_h

  ; x_l * y_h
  movw  ax,de   ; x <= e
  mov a,b
  mulu  x
  xch a,x   ; h <= (x_l * y_h)_l + (x_h * y_l)_l
  add h,a   ; +  (x_l * y_l)_h
  xch a,x   ; c <= (x_l * y_h)_h + (x_h * y_l)_h
  addc  c,a   ; (x_l * y_h)_h + (x_h * y_l)_h
  clrb  a
  addc  a,#0    ; cy

  ; x_h * y_h
  xch a,b   ; b <= cy
  mov x,a
  mov a,d
  mulu  x   ; ret_h = (x_l * y_h)_h + (x_h * y_l)_h
  addw  ax,bc   ;    + (x_h * y_h)
  movw  bc,ax   ; ret_l = (x_l * y_h)_l + (x_h * y_l)_l
  movw  ax,hl   ;    + (x_l * y_l)
  ret
#endif
.Lfunc_end1:
  .size __COM_mului, .Lfunc_end1-__COM_mului
