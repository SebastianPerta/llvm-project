//===-- COM_mulsi.S - Implement COM_mulsi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements COM_mulsi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  #include "def.S"

  .file "COM_mulsi.S"
#ifdef __RL78_S3__
#else
#ifdef __MDA_ENABLED__
#else
  .extern __COM_mului
#endif
#endif

  .text

  .globl __COM_mulsi
  .type  __COM_mulsi,@function
__COM_mulsi:
#ifdef __RL78_S3__
  mulh
  ret
#else
#ifdef __MDA_ENABLED__
  push  psw
  di
  mov !LOWW(MDUC),#0x08  ; divmode,macmode = 0, mdsm = 1
;
  movw  MDAL,ax   ; ret = x * y
  movw  ax,bc   ;
  movw  MDAH,ax   ;
  nop     ;
  movw  bc,!LOWW(MDBH) ;
  movw  ax,MDBL   ;
  pop psw
  ret
#else
  mov l,#0    ; sign_flag = 0
  bf  a.7,$1f   ; if (xx < 0) then
  inc l   ; sign_flag = 1
  movw  de,ax   ; x = -x
  clrw  ax    ;
  subw  ax,de   ;
1:
  movw  de,ax   ; x -> de
  movw  ax,bc
  bf  a.7,$2f   ; if (y < 0) then
  inc l   ; sign_flag ^= 1
  clrw  ax    ; y = -y
  subw  ax,bc   ;
  movw  bc,ax   ; y -> bc
2:
  movw  ax,de   ; x -> ax
  push  hl    ; sign_flag
  call  !!__COM_mului ; ret = x * y
  pop hl    ; sign_flag
  dec l
  bnz $3f   ; if (sign_flag == 1) then
  movw  de,ax
  clrw  ax    ; retl = -ret_l
  subw  ax,de   ;
  movw  de,ax
  subc  a,a   ; ret_h = -ret_h
  mov x,a
  subw  ax,bc
  movw  bc,ax
  movw  ax,de
3:
  ret
#endif
#endif
.Lfunc_end1:
  .size __COM_mulsi, .Lfunc_end1-__COM_mulsi
