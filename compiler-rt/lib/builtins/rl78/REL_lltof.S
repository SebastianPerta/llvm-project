//===-- REL_lltof.S - Implement _REL_lltof-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_lltof for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_lltof.S"
  .extern __REL_setexp_ll

  .text

  .globl __REL_lltof
  .type  __REL_lltof,@function
__REL_lltof:
  ;-------------------------------------------------------
  ; check if the input value is 0
  ;-------------------------------------------------------
  mov a,[hl+7]
  or  a,[hl+6]
  or  a,[hl+5]
  or  a,[hl+4]
  mov c,a   ; for upper 32bit 0 judgment
  or  a,[hl+3]
  or  a,[hl+2]
  or  a,[hl+1]
  or  a,[hl]
  bnz $0f
  clrw  bc
  clrw  ax
  ret     ; if the input value is 0, 0 is returned
0:
  ;-------------------------------------------------------
  ; find the value of the exponent part
  ; shift left until the most significant bit of bc-ax is set
  ; decrease the value of the exponent part by the number of left shifts
  ;-------------------------------------------------------
  call  !!__REL_setexp_ll
  mov a,#127
  add d,a   ; add the bias value (127) of the exponent part
  
  ;-------------------------------------------------------
  ; round the mantissa
  ;-------------------------------------------------------
  ; for the part less than the rounding bit, it is sufficient to know whether it is zero or non-zero,
  ; so if the lower 32 bits are non-zero, 1 is placed at the bottom of the upper 32 bits
  ; therefore, the lower 32 bits are no longer needed, and only the upper 32 bits can be rounded
  mov a,[hl]    ; check if the lower 32 bits are 0
  or  a,[hl+1]
  or  a,[hl+2]
  or  a,[hl+3]
  bz  $1f
  
  ; if the lower 32 bits are non-zero, set the lowest of the upper 32 bits to 1
  mov a,[hl+4]
  or  a,#0x01
  mov [hl+4],a
1:
  mov a,[hl+4]
  cmp a,#0x80   ; compare the value of the part discarded by rounding with # 0x80 (intermediate value)
  bc  $3f   ; if it is smaller than # 0x80, it will not be rounded up
  bnz $2f    ; if it is larger than # 0x80, it will be rounded up

  ; if it matches # 0x80, round it toward an even number
  mov a,[hl+5]
  mov1  cy,a.0
  bnc $3f   ; if the least significant bit of the mantissa is 0, it is not rounded up
2:
  ; round-up process
  inc [hl+5]
  bnz $3f
  movw  ax,[hl+6]
  addw  ax,#1
  movw  [hl+6],ax
  sknc
  inc d   ; add the exponent part
3:
  mov a,[hl+5]
  mov c,a
  movw  ax,[hl+6]

  ;-------------------------------------------------------
  ; adjust the bit position according to the format of ieee754
  ;-------------------------------------------------------
  xch a,e
  mov1  cy,a.0    ; get the sign of the input value
  mov a,x
  mov b,a
  movw  ax,de
  rorc  a,1   ; move the exponent part to the right by 1 bit
  xch a,x
  mov1  a.7,cy    ; stores the least significant bit of the exponent
  xch a,x
  xchw  ax,bc
4:
  ret
.Lfunc_end1:
  .size __REL_lltof, .Lfunc_end1-__REL_lltof
