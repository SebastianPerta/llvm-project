//===-- REL_ltof.S - Implement _REL_ltof-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_ltof for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_ltof.S"

  .text

  .globl __REL_ltof
  .type  __REL_ltof,@function
__REL_ltof:
  ;-------------------------------------------------------
  ; check if the input value is 0
  ;-------------------------------------------------------
  addw  ax,bc
  skc
  bz  $0f      ; if the input value is 0, 0 is returned
  subw  ax,bc
  
  ;-------------------------------------------------------
  ; find the value of the exponent part
  ; shift left until the most significant bit of bc-ax is set
  ; decrease the value of the exponent part by the number of left shifts
  ;-------------------------------------------------------
  xchw  ax,bc     ; swap top and bottom
  
  mov d,#127+31   ; initial value of index part
  
  cmpw  ax,#0x00      ; is the upper 16 bits 0?
  bnz $1f
  mov a,#16     ; subtract 16 from the value of the exponent
  sub d,a
  clrb  a     ; 16-bit left shift
  xchw  ax,bc
1:
  bt  a.7,$3f   ; (msb == 1)?
2:
  dec d     ; subtract the value of the exponent part
  addw  ax,ax     ; shift the top part to the left
  shlw  bc,1      ; shift lower to left
  sknc
  incw  ax
  bf  a.7,$2b   ; repeat until the most significant bit is raised
3:
  ;-------------------------------------------------------
  ; round the mantissa
  ;-------------------------------------------------------
  xch a,c
  cmp a,#0x80     ; compare the value of the part discarded by rounding with # 0x80 (intermediate value)
  xch a,c
  bc  $5f     ; if it is smaller than # 0x80, it will not be rounded up
  bnz $4f     ; if it is larger from # 0x80, it will be rounded up

  ; if it matches # 0x80, round it toward an even number
  xchw  ax,bc
  mov1  cy,a.0
  xchw  ax,bc
  bnc $5f
4:
  ; round-up process
  inc b
  bnz $5f
  addw  ax,#1
  sknc
  inc d     ; add the exponent part
5:
  ;-------------------------------------------------------
  ; adjust the bit position according to the format of ieee754
  ;-------------------------------------------------------
  xch a,e
  mov1  cy,a.0      ; get the sign of the input value
  mov a,b
  xch a,x
  xchw  ax,de
  rorc  a,1     ; move the exponent part to the right by 1 bit
  xch a,x
  mov1  a.7,cy      ; store the least significant bit of the exponent
  xch a,x
  movw  bc,ax
  movw  ax,de
0:
  ret
.Lfunc_end1:
  .size __REL_ltof, .Lfunc_end1-__REL_ltof
