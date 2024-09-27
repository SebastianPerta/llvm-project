//===-- REL_ftol.S - Implement _REL_ftol-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_ftol for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_ftol.S"
  .extern __COM_lshr

  .text

  .globl __REL_ftol
  .type  __REL_ftol,@function
__REL_ftol:
  movw  hl,ax
  movw  ax,bc
  addw  ax,ax   ; index part: a
  mov d,#0
  sknc
  inc d   ; sign: d
  
  ; index range check
  cmp a,#127+32
  bnc $2f    ; overflow when the exponent part is (127 + 32) or more
  sub a,#127    ; if the exponent is smaller than the bias value
  bc  $0f    ; underflow
  
  ; add msb (1) to the mantissa
  shlw  bc,8
  xchw  ax,bc
  set1  a.7
  xchw  ax,bc
  
  ; temporary setting of the number of shifts
  mov x,a
  mov a,#31
  sub a,x
  cmp a,x   ; use the cy that occurs here
  ; set the mantissa (24 bits) with msb (1) in bc-a and clear x
  mov e,a   ; e = number of shifts
  mov a,h
  mov c,a
  mov a,l
  clrb  x
  bc  $1f    ; judging cy of "cmp a, x"
  ; 16 or more right shifts confirmed
  mov a,e   ; finally ax is overwritten with bc, so mov is fine 
  sub a,#16
  mov e,a
  movw  ax,bc
  clrw  bc
1:
  push  de
  call  !!__COM_lshr
  pop de
  ret
2:
  movw  bc,#0xffff
  movw  ax,#0xffff
  mov d,#0
  ret
0:
  clrw  bc
  clrw  ax
  mov d,a
  ret
.Lfunc_end1:
  .size __REL_ftol, .Lfunc_end1-__REL_ftol
