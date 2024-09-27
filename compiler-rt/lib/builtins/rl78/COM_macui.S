//===-- COM_macui.S - Implement __macui-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __macui for the COMpiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "def.S"

  .file   "COM_macui.S"
#ifdef __RL78_S3__
#include "macr.S"
#else
#ifndef __MDA_ENABLED__
  .extern __COM_mului
#endif
#endif

  .text

  .globl __COM_macui
  .type  __COM_macui,@function
__COM_macui:
#ifdef __RL78_S3__
  movw  de,ax
  movw  ax,[sp+4] ; macr <- z
  push  psw
  di
  movw  MACRL,ax  ;
  movw  ax,[sp+6+2] ;
  movw  MACRH,ax  ;
  movw  ax,de
  machu
  movw  bc,!LOWW(MACRH) ; movw  bc,!addr16
  movw  ax,MACRL  ; movw  ax,sfrp
  pop psw
  ret
#else
#ifdef __MDA_ENABLED__
  push  psw
  di
  mov !LOWW(MDUC),#0x040  ; macmode = 1, mdsm = 0
;
  movw  MDAL,ax   ; MDAL <- x
  movw  ax,[sp+4+2] ; mdc <- z
  movw  !LOWW(MDCL),ax  ;
  movw  ax,[sp+6+2] ; 
  movw  !LOWW(MDCH),ax  ;
  movw  ax,bc   ; MDAH <- y, start calculation
  movw  MDAH,ax   ;
  nop     ; 2clock wait
  nop
  movw  bc,!LOWW(MDCH)  ; bcax <- mdc
  movw  ax,!LOWW(MDCL)  ;
  pop psw
  ret
#else
  call  !!__COM_mului ; ret = x * y
  movw  de,ax   ; ret = ret + z
  movw  ax,[sp+6] ;
  addw  ax,bc   ;
  movw  bc,ax   ;
  movw  ax,[sp+4] ;
  addw  ax,de   ;
  sknc      ;
  incw  bc    ;
  ret
#endif
#endif
.Lfunc_end1:
  .size __COM_macui, .Lfunc_end1-__COM_macui

  .weak ___macui
  .type ___macui,@function
  .set  ___macui, __COM_macui
