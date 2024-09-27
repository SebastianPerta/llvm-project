//===-- REL_dtol.S - Implement _REL_dtol-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_dtol for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_dtol.S"
  .extern __COM_lshr

  .text

  .globl __REL_dtol
  .type  __REL_dtol,@function
__REL_dtol:
  movw  ax,[hl+6]
  addw  ax,ax
  mov d,#0
  sknc
  inc d   ; sign
  shrw  ax,5    ; ax = exponential part
  
  ; index range check
  subw  ax,#1023  ; if the exponent is smaller than the bias value
  bc  $0f    ; underflow
  cmpw  ax,#32    ; overflow when the exponent part is (1023 + 32) or more
  bnc $2f
  mov a,x
  
  ; set bc-ax to the value obtained by adding msb (1) to the high-order 31 bits of the mantissa
  push  de    ; save sign 
  mov e,a   ; e = Exponential part after subtraction of bias value
  movw  ax,[hl+2]
  shrw  ax,5
  movw  bc,ax
  movw  ax,[hl+4]
  shlw  ax,11
  addw  ax,bc
  push  ax    ; clear the lower level
  
  movw  ax,[hl+4]
  shrw  ax,5
  movw  bc,ax
  movw  ax,[hl+6]
  shlw  ax,11
  addw  ax,bc
  set1  a.7   ; set msb to 1
  movw  bc,ax
  
  ; temporary setting of the number of shifts
  movw  ax,de
  mov a,#31
  sub a,x
  mov e,a   ; number of shifts
  cmp a,x   ; use the cy that occurs here
  pop ax    ; mantissa subordinate
  bc  $1f    ; judging cy of "cmp a, x"
  ; 16 or more right shifts confirmed
  mov a,e   ; finally ax is overwritten with bc, so mov is fine
  sub a,#16
  mov e,a
  movw  ax,bc
  clrw  bc
1:
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
  .size __REL_dtol, .Lfunc_end1-__REL_dtol
