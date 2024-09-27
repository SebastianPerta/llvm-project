//===-- COM_mulsl.S - Implement COM_mulsl-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements COM_mulsl for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_mulsl.S"
  .extern __COM_mulul
  .extern __REL_llrev

  .text

  .globl __COM_mulsl
  .type  __COM_mulsl,@function
__COM_mulsl:
  push  ax    ; return address
  clrw  ax    ; sign_flag
  push  ax
  movw  ax,[sp+6+4] ; y' <- y
  push  ax    ;
  mov1  cy,a.7    ; sign of y
  movw  ax,[sp+4+6] ;
  push  ax    ;
  movw  hl,sp
;
  bnc $1f ; if (y' < 0) then
  clrw  ax    ; y' <- -y'
  subw  ax,[hl+0]
  movw  [hl],ax
  subc  a,a
  mov x,a
  subw  ax,[hl+2]
  movw  [hl+2],ax
  onew  ax    ; sign_flag = 1
  movw  [hl+4],ax ;
1:
  movw  ax,de   ; if (x < 0) then
  bf  a.7,$2f
  clrw  ax
  subw  ax,bc
  movw  bc,ax
  subc  a,a
  mov x,a
  subw  ax,de
  movw  de,ax
  incw  [hl+4]    ; sign_flag ^= 1
2:
  movw  ax,[hl+6] ; return address 
  call  !!__COM_mulul
  addw  sp,#4
  pop ax    ; sign_flag
  pop hl    ; return address 
  shrw  ax,1
  sknc
  call  !!__REL_llrev ; sign inversion of [hl] 
  ret
.Lfunc_end1:
  .size __COM_mulsl, .Lfunc_end1-__COM_mulsl
