//===-- COM_dtof.S - Implement __truncdfsf2-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __truncdfsf2 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dtof.S"
  .extern __REL_f_inf
  .extern __REL_f_round

  .text

0:
  pop bc    ; sign (0 other than sign bit)
  clrw  ax
  ret
1:
  ; zero check of mantissa
  mov a,[hl+10]
  shl a,4   ; remove the exponent part
  or  a,[hl+9]
  or  a,[hl+8]
  or  a,[hl+7]
  or  a,[hl+6]
  or  a,[hl+5]
  or  a,[hl+4]
  sknz
2: ; infinite setting
  br  !!__REL_f_inf ; infinity
  ; nan settings
  pop ax    ; sign (not used)
  clrw  ax
  decw  ax
  movw  bc,ax
  ret

  .globl __COM_dtof
  .type  __COM_dtof,@function
__COM_dtof:
  movw  hl,sp
  ; get the value and sign of the exponent part
  movw  ax,[hl+10]
  addw  ax,ax
  clrw  bc
  sknc
  mov b,#0x80
  push  bc    ; save sign
  shrw  ax,5

  ; infinity / nan check
  cmpw  ax,#0x7ff
  bnc $1b

  ; exponent range check
  ; exponent part -> exponent part   mantissa part
  ; 1023 - 126   1   xxxxxxxxxxxxxxxxxxxxxxx
  ; 1023 - 127   0   1xxxxxxxxxxxxxxxxxxxxxx
  ;      :
  ; 1023 - 149   0   00000000000000000000001
  ; 1023 - 150   0   00000000000000000000000 11 (round up)
  ; 1023 - 151   0   00000000000000000000000 01 (underflow)
  ; 
  ; 1023 + 127     254
  ; 1023 + 128     255   (overflow)
  cmpw  ax,#1023-150
  bc  $0b    ; underflow
  cmpw  ax,#1023+128
  bnc $2b   ; overflow

  ; stores the most significant 31 bits of the mantissa with the implicit 1 added to the msb in bcax
  push  ax    ; exponent part
  movw  ax,[hl+8]
  shrw  ax,5
  movw  bc,ax
  movw  ax,[hl+10]
  shlw  ax,11
  addw  ax,bc
  set1  a.7
  push  ax
  movw  ax,[hl+4]
  or  a,x
  or  a,[hl+6]
  mov a,[hl+7]
  skz
  set1  a.0
  shrw  ax,5
  movw  bc,ax
  movw  ax,[hl+8]
  shlw  ax,11
  addw  ax,bc
  pop bc
  pop hl    ; exponent part
  ; changed the bias value of the exponent part from 1023 to 127
  xchw  ax,hl
  subw  ax,#1023-127  ; subtract (1023-127) from the exponent
  xchw  ax,hl   ;
  bh  $4f   ; denormalized number when the exponent part is (1023-127) or less

  ; ---------------------------------------------------------
  ; processing for subnormal numbers
  ; at this point, the exponent part has a value below zero,
  ; so increment it until it reaches zero
  ; shift bcax to the right by the number of increments
  ; ---------------------------------------------------------
  dec l   ; in order to reflect the implicit 1 in the mantissa,
        ; it is necessary to shift one more time
3:
  ; shift bcax to the right
  shrw  ax,1
  xch a,x   ; whether there is a 1 in the part that protrudes due to the shift
  or1 cy,a.0    ; save in the least significant bit of bcax
  mov1  a.0,cy    ; (to be used for rounding up)
  xch a,x
  xchw  ax,bc
  shrw  ax,1
  xchw  ax,bc
  mov1  a.7,cy
  inc l
  bnz $3b
4:
  ; at this point, the sign is [sp+1], the exponent part is l, the mantissa part is bca,
  ; and the rounding judgment is x
  ; match the exponent and mantissa to the ieee754 format
  movw  de,ax
  movw  ax,bc
  addw  ax,ax
  mov x,a
  mov a,l
  shrw  ax,1
  xchw  ax,bc
  mov a,d
  xch a,x
  ; at this point, the sign is [sp + 1], the exponent / mantissa part is bcax,
  ; and the rounding judgment is e
  br  !!__REL_f_round ; rounding
.Lfunc_end1:
  .size __COM_dtof, .Lfunc_end1-__COM_dtof

  .weak ___truncdfsf2
  .type ___truncdfsf2,@function
  .set  ___truncdfsf2, __COM_dtof
