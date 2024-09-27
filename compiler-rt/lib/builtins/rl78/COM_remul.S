//===-- COM_remul.S - Implement _COM_remul-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_remul for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "def.S"

  .file   "COM_remul.S"

  .text

  .globl __COM_remul
  .type  __COM_remul,@function
__COM_remul:
  xchw  ax,de
  cmpw  ax,#0
  xchw  ax,de
  sknz
  ret
#ifdef __RL78_S3__
  movw  hl,#0
  divwu
;
  movw  ax,de
  ret
#else
#ifdef __MDA_ENABLED__
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; mda <- x
  movw  ax,bc   ;
  movw  MDAH,ax   ;
  movw  ax,de   ; mdb <- y
  movw  MDBL,ax   ;
  clrw  ax    ;
  movw  MDBH,ax   ;
;
  mov !LOWW(MDUC),#0x081  ; divmode  = 1, divst = 1
0:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$0b
;
  movw  ax,!LOWW(MDCL)  ; ret <- MDCL
  pop psw
  ret
#else
  push  de    ; y
  push  bc    ; x_h
  push  ax    ; x_l
  movw  hl,sp
;
  clrw  bc    ; rem = 0
  mov e,#32   ; count = 16
0:        ; do_until
  movw  ax,[hl]   ; x <<= 1 (div <<= 1) 
  addw  ax,ax   ;
  movw  [hl],ax   ;
  movw  ax,[hl+2] ;
  rolwc ax,1    ;
  movw  [hl+2],ax ;
  rolwc bc,1    ; rem = (rem << 1) | cy
  movw  ax,bc   ; if (rem >= y) then
  subw  ax,[hl+4] ;
  bc  $1f    ;
  movw  bc,ax   ; rem = rem - y
  incw  [hl+0]    ; ++div
1:
  dec e   ; --count
  bnz $0b    ; until (count = 0)
  movw  ax,bc   ; rem
  addw  sp,#6   ; x, y, count
  ret
#endif
#endif
.Lfunc_end1:
  .size __COM_remul, .Lfunc_end1-__COM_remul
