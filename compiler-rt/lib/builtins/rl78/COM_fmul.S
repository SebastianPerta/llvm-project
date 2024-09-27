//===-- COM_fmul.S - Implement __mulsf3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __mulsf3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "def.S"

  .file   "COM_fmul.S"
  .extern __REL_f_inf
  .extern __REL_f_norm
  .extern __REL_f_round

  .text

  .globl __COM_fmul
  .type  __COM_fmul,@function
0:
  pop ax    ; sign (not used)
  clrw  ax    ; ret = 0xffffffff (nan)
  decw  ax
  movw  bc,ax
  ret
;
1:
  ; y is infinite or infinite
  movw  hl,ax   ; higher mantissa of y
  movw  ax,[sp+4+2] ; lower mantissa of y
  or  a,x
  or  a,l
  bnz $0b ; since y is non-number, it returns non-number
  ; y is infinity
2:
  movw  ax,bc   ; higher mantissa of x
  addw  ax,ax
  xch a,x   ; x = exponent part of x
  or  a,d
  or  a,e
  skz
  oneb  a   ; set 1 when the mantissa is not 0
  ; when x is 0, the exponent part is 0 and the mantissa part flag is 0
  ; if x is non-number, the exponent part is 0xff and the mantissa flag is 1
  add a,x
  bz  $0b ; returns a non-number if x is 0 or non-number
  br  !!__REL_f_inf ; returns infinity
;
3:
  ; y is 0 or a subnormal number
  movw  ax,bc   ; exponent part of x
  addw  ax,ax
  cmp0  a
  bz  $4f  ; multiplying between subnormal numbers or 0 returns +- 0
  ; swap x and y to unify the normalization process for subnormalized numbers
  movw  ax,[sp+4+2]
  xchw  ax,de
  movw  [sp+4+2],ax
  movw  ax,[sp+6+2]
  xchw  ax,bc
  movw  [sp+6+2],ax
  br  $6f
;
4:
  ; returns +- 0
  pop bc    ; sign
  clrb  c
  clrw  ax
  ret
;
5:
  ; x is 0 or subnormal, y is normal
  mov a,x
  or  a,d
  or  a,e
  bz  $4b
  ; x is a subnormal number
  movw  ax,de   ; subordinate to the mantissa of x
  call  !!__REL_f_norm  ; normalize x
  movw  de,ax   ; subordinate to the mantissa of x
  mov a,h   ; exponent part of x
  sarw  ax,8    ;
  mov h,#0    ; exponent part of x + exponent part of y
  addw  ax,hl   ;
  movw  hl,ax   ;
  br  $7f    ; join the normalization process
;
; this is the entrance to the function
__COM_fmul:
  ; [special return value]
  ; (1) if x or y is nan, nan is the return value
  ; (2) in the case of multiplication of 0 and infinity, nan is the return value
  ; (3) for multiplications other than 0 and infinity, +- 0 is the return value
  ; (4) for multiplications other than infinity and 0, +- infinity is the return value

  movw  de,ax   ; subordinate to x
  ; return sign setting
  mov a,[sp+7]  ; sign of y
  xor a,b   ; sign of x
  and a,#0x80
  push  ax    ; return sign
  movw  ax,[sp+8] ; exponent part of y
6:
  ; special value judgment of y
  addw  ax,ax
  inc a
  bz  $1b ; y is infinite or infinite
  dec a
  bz  $3b  ; y is 0 or a subnormal number
  ; after that, y is the processing of the normalized number
  mov l,a   ; l = exponent part of y
  oneb  a   ; reset the mantissa with a stingy expression
  shrw  ax,1    ; set 0 in the exponent area (for mantissa multiplication)
  movw  [sp+8],ax ;
  ; special value judgment of x
  movw  ax,bc   ; exponent part of x
  addw  ax,ax
  inc a
  bz  $2b ; x is infinite or infinite
  dec a
  bz  $5b  ; x is 0 or subnormal
  add l,a   ; exponent part of x + exponent part of y
  clrb  a   ;
  rolc  a,1   ;
  mov h,a   ;
#if defined(__RL78_S3__) || defined(__MDA_ENABLED__)
  oneb  a
  shrw  ax,1
  movw  bc,ax   ; miser expression + higher mantissa of x
#else
  mov a,#0x80
  or  c,a   ; miser expression
#endif
7:
  push  hl    ; exponential part of calculation result
  ; multiply the mantissa
  ; [sp+0]:operation result index part [sp+3]:operation result code
  ; [sp+4]:return address[sp+8]:mantissa of y
#ifdef __RL78_S3__
  ; x_hl * y_hl
  movw  ax,bc   ; higher mantissa of x
  mov a,[sp+10] ; higher mantissa of y
  mulu  x
  movw  hl,ax   ; calculation result 47-32bit
  ; x_h(higher byte is 0) * y_l
  movw  ax,[sp+8] ; lower mantissa of y
  mulhu
  xchw  ax,de   ; de = calculation result 31-16bit
  xchw  ax,bc   ; bc = subordinate to the mantissa of x
  addw  ax,hl   ; calculation result 47-32bit
  movw  hl,ax   ;
  ; x_l * y_h(higher byte is 0)
  push  bc    ; subordinate to the mantissa of x
  movw  ax,[sp+10+2]  ; higher mantissa of y
  mulhu
  addw  ax,de   ; calculation result 31-16bit
  movw  de,ax   ;
  mov a,c   ; calculation result 47-32bit
  addc  l,a   ;
  mov a,b   ;
  addc  h,a   ;
  ; x_l * y_l
  pop bc    ; subordinate to the mantissa of x
  movw  ax,[sp+8] ; lower mantissa of y
  mulhu
  xchw  ax,bc
  addw  ax,de   ; calculation result 31-16bit
  movw  de,ax   ;
  sknc
  incw  hl    ; calculation result 47-32bit
  clrw  ax
  cmpw  ax,bc
  skz     ; set the least significant bit of the rounding judgment area (23-16bit)
  oneb  a   ;
  or  e,a   ;
  movw  ax,hl   ; calculation result 47-32bit
  movw  bc,ax   ;
  pop hl    ; exponent part
  bt  a.7,$8f  ; there are 2 bits of stingy expression, so justify it to the left
  movw  ax,de   ; operation result bcde is shifted to the left
  addw  ax,ax   ;
  movw  de,ax   ;
  rolwc bc,1    ;
  sknc      ; be sure to skip because cy does not stand
8:
  incw  hl    ; since there were 2 bits of stingy expression, the exponent part was corrected
#elif defined(__MDA_ENABLED__)
  ; x_l * y_l
  movw  ax,[sp+8] ; lower mantissa of y
  push  psw
  di
  clrb  !LOWW(MDUC) ; divmode,macmode,mdsm = 0
  movw  MDAL,ax   ; MDBH,MDBL = MDAL * MDAH
  movw  ax,de   ; subordinate to the mantissa of x
  movw  MDAH,ax   ;
  nop     ;
  movw  hl,!LOWW(MDBL)  ; operation result 15-0bit
  movw  ax,MDBH   ; calculation result 31-16bit
  pop psw
  push  hl    ; operation result 15-0bit
  ; x_l * y_h(higher byte is 0)
  xchw  ax,de   ; de = calculation result 31-16bit
  push  psw
  di
  clrb  !LOWW(MDUC) ; divmode,macmode,mdsm = 0
  movw  MDAL,ax   ; MDBH,MDBL = MDAL * MDAH
  movw  ax,[sp+10+4]  ; higher mantissa of y
  movw  MDAH,ax   ;
  nop     ;
  movw  hl,!LOWW(MDBH)  ; calculation result 47-32bit
  movw  ax,MDBL   ; calculation result 31-16bit
  pop psw
  addw  ax,de   ; calculation result 31-16bit
  movw  de,ax   ;
  sknc
  incw  hl    ; calculation result 47-32bit
  ; x_hl * y_hl
  movw  ax,bc   ; higher mantissa of x
  mov a,[sp+10+2] ; higher mantissa of y
  mulu  x
  addw  ax,hl   ; calculation result 47-32bit
  xchw  ax,bc   ; higher mantissa of x
  ; x_h(higher byte is 0) * y_l
  push  psw
  di
  clrb  !LOWW(MDUC) ; divmode,macmode,mdsm = 0
  movw  MDAL,ax   ; MDBH,MDBL = MDAL * MDAH
  movw  ax,[sp+8+4] ; lower mantissa of y
  movw  MDAH,ax   ;
  nop     ;
  movw  hl,!LOWW(MDBH)  ; calculation result 47-32bit
  movw  ax,MDBL   ; calculation result 31-16bit
  pop psw
  addw  ax,de   ; calculation result 31-16bit
  movw  de,ax   ;
  mov a,l   ; calculation result 47-32bit
  addc  c,a   ;
  mov a,h   ;
  addc  b,a   ;
  pop ax    ; operation result 15-0bit
  or  a,x   ; if the operation result 15-0bit is not 0
  skz     ; set the least significant bit of the rounding judgment area (23-16bit)
  oneb  a   ;
  or  e,a   ;
  pop hl    ; operation result index part
  mov a,b   ; judgment of the most significant bit of the operation result
  bt  a.7,$8f  ; there are 2 bits of stingy expression, so justify it to the left
  movw  ax,de   ; operation result bcde is shifted to the left
  addw  ax,ax   ;
  movw  de,ax   ;
  rolwc bc,1    ;
  sknc      ; be sure to skip because cy does not stand
8:
  incw  hl    ; since there were 2 bits of stingy expression, the exponent part was corrected
#else
  ; x_hl * y_lh
  movw  ax,bc   ; x_hl
  mov a,[sp+9]  ; y_lh
  mulu  x
  movw  hl,ax   ; calculation result 39-24bit
  ; x_lh * y_hl
  movw  ax,[sp+10]  ; y_hl
  mov a,d   ; x_lh
  mulu  x
  addw  ax,hl   ; calculation result 39-24bit
  push  ax    ;
  ; x_hl * y_hl
  movw  ax,bc   ; x_hl
  mov a,[sp+10+2] ; y_hl
  mulu  x
  addc  a,#0    ; cy when addw the previous operation result
  movw  hl,ax   ; calculation result 47-32bit
  ; x_ll * y_hl
  movw  ax,de   ; x_ll
  mov a,[sp+10+2] ; y_hl
  mulu  x
  ; x_hl * y_ll
  xchw  ax,bc   ; bc = calculation result 31-16bit, x = x_hl
  mov a,[sp+8+2]  ; y_ll
  mulu  x
  addw  ax,bc   ; calculation result 31-16bit
  movw  bc,ax   ;
  sknc
  incw  hl    ; calculation result 47-32bit
  ; x_ll * y_ll
  movw  ax,de   ; x_ll
  mov a,[sp+8+2]  ; y_ll
  mulu  x
  push  ax    ; operation result 15-0bit
  ; x_lh * y_ll
  movw  ax,[sp+8+4] ; y_ll
  mov a,d   ; x_lh
  mulu  x
  push  de    ; subordinate to the mantissa of x
  xchw  ax,de   ; de = calculation result 23-8bit, x = x_ll
  mov a,[sp+3]  ; calculation result 15-8bit
  add e,a   ;
  sknc
  inc d   ; calculation result 23-16bit
  ; x_ll * y_lh
  mov a,[sp+9+6]  ; y_lh
  mulu  x
  addw  ax,de   ; calculation result 23-8bit
  movw  de,ax   ;
  ; x_lh * y_lh
  pop ax    ; subordinate to the mantissa of x(x_lh)
  mov x,a   ;
  mov a,[sp+9+4]  ; y_lh
  mulu  x
  addc  a,#0    ; cy when addw the previous operation result
  addw  ax,bc   ; calculation result 31-16bit
  movw  bc,ax   ;
  sknc
  incw  hl    ; calculation result 47-32bit
  movw  ax,de   ; calculation result 23-16bit
  shrw  ax,8    ;
  addw  ax,bc   ; calculation result 31-16bit
  movw  bc,ax   ;
  sknc
  incw  hl    ; calculation result 47-32bit
  pop ax    ; operation result 15-0bit
  mov a,e   ; if the lower 16 bits of the calculation result are not 0,
  or  a,x   ; the least significant bit of the rounding judgment area is set
  skz     ;
  oneb  a   ;
  or  c,a   ;
  pop ax    ; calculation result 39-24bit
  xch a,x
  add b,a   ; calculation result 31-24bit
  sknc
  incw  hl    ; calculation result 47-32bit
  clrb  a
  addw  ax,hl   ; calculation result 47-32bit
  pop hl    ; exponent part
  cmp a,#0x80
  xchw  ax,bc
  bnc $8f
  addw  ax,ax
  rolwc bc,1
  sknc      ; be sure to skip because cy does not stand
8:
  incw  hl    ; since there were 2 bits of stingy expression, correct the exponent part
  movw  de,ax
#endif
  ; bcde:mantissa, hl:exponent part, [sp+1]:sign
  movw  ax,hl
  subw  ax,#128   ; bias value + 1
  bt  a.7,$10f  ; subnormal number
  incw  ax    ; bias value correction
  cmpw  ax,#255   ; overflow judgment
  skc
  br  !!__REL_f_inf ; returns infinity
9:
  ; at this point, the sign is [sp+1], the exponential part is x,
  ; the mantissa part is bcd, and the rounding judgment is e
  ; set exponential part and mantissa part in the format of ieee754
  mov a,b
  add a,a
  xch a,x
  shrw  ax,1
  xchw  ax,bc
  mov a,d
  xch a,x
  ; at this point, the sign is [sp + 1], the exponent / mantissa part is bcax,
  ; and the rounding judgment is e
  br  !!__REL_f_round
;
10:
  ; the operation result is a subnormal number
  cmpw  ax,#0xffe8  ; if (exponent part-1) is -25 or less, the solution is extinguished
  sknc
  br  $!4b ; extinction solution
  xchw  ax,de
  ; mantissa part bcax, exponent part e
  ; shift the mantissa to the right until the exponent becomes 0
11:
  xchw  ax,bc
  shrw  ax,1
  xchw  ax,bc
  rorc  a,1
  xch a,x
  rorc  a,1
  sknc      ; if the rounding bit overflows, reset it to the least significant bit
  set1  a.0   ;
  xch a,x
  inc e   ; exponent part
  bnz $11b
  xchw  ax,de
  ; at this point, the sign is [sp+1], the exponential part is x (0),
  ; the mantissa part is bcd, and the rounding judgment is e
  br  $9b
.Lfunc_end1:
  .size __COM_fmul, .Lfunc_end1-__COM_fmul

  .weak ___mulsf3
  .type ___mulsf3,@function
  .set  ___mulsf3, __COM_fmul
