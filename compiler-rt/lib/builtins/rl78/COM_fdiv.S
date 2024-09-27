//===-- COM_fdiv.S - Implement __divsf3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __divsf3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "def.S"

  .file   "COM_fdiv.S"
  .extern __REL_f_inf
  .extern __REL_f_norm
  .extern __REL_f_round

  .text

  .globl __COM_fdiv
  .type  __COM_fdiv,@function
0:
  pop ax    ; sign (not used)
  clrw  ax    ; ret = 0xffffffff (nan)
  decw  ax
  movw  bc,ax
  ret
;
1:
  movw  hl,ax   ; higher mantissa of y
  movw  ax,[sp+4+2] ; lower mantissa of y
  or  a,x
  or  a,l
  bnz $0b ; since y is non-number, it returns non-number
  ; y is infinity
  movw  ax,bc   ; exponent part of x
  addw  ax,ax   ;
  inc a
  bz  $0b ; infinity / infinity or nan / infinity returns a non-number
  sknz      ; be sure to branch
2:
  pop ax    ; exponent part (not used)
3:
  ; returns +- 0
  pop bc    ; sign
  clrb  c
  clrw  ax
  ret
;
4:
  ; y is 0 or a subnormal number
  movw  hl,ax   ; higher mantissa of y
  movw  ax,[sp+4+2] ; lower mantissa of y
  or  a,x
  or  a,l
  bz  $6f  ; y is 0
  push  bc    ; higher mantissa of x
  mov a,[sp+6+4]  ; higher mantissa of y
  mov c,a   ;
  movw  ax,[sp+4+4] ; lower mantissa of y
  call  !!__REL_f_norm  ; normalize y
  movw  [sp+4+4],ax ; lower mantissa of y
  movw  ax,bc   ; higher mantissa of y (higher byte is 0)
  movw  [sp+6+4],ax ;
  pop bc    ; higher mantissa of x
  mov a,h   ; exponent part of y
  sarw  ax,8
  push  ax
  br  $8f
;
5:
  ; x is non-number or infinity, y is normal or subnormal
  pop ax    ; exponent part (not used)
6:
  movw  ax,bc   ; higher mantissa of x
  addw  ax,ax
  xch a,x
  or  a,d   ; subordinate to the mantissa of x
  or  a,e   ;
  skz
  oneb  a   ; set 1 when the mantissa is not 0
  ; when x is 0, the exponent part is 0 and the mantissa part flag is 0
  ; if x is non-number, the exponent part is 0xff and the mantissa flag is 1
  add a,x
  bz  $0b ; returns a non-number if x is 0 or non-number
  br  !!__REL_f_inf ; returns infinity
;
7:
  ; x is 0 or subnormal, y is normal or subnormal
  mov a,x
  or  a,d
  or  a,e
  bz  $2b  ; x is 0
  ; x is a subnormal number
  movw  ax,de   ; subordinate to the mantissa of x
  call  !!__REL_f_norm  ; normalize x
  movw  de,ax   ; subordinate to the mantissa of x
  mov a,h   ; exponent part of x
  sarw  ax,8
  movw  hl,ax
  br  $9f
;
; this is the entrance to the function
__COM_fdiv:
  ; [special return value]
  ; (1) if x or y is nan, nan is the return value
  ; (2) if (+- 0) / (+- 0), nan is the return value
  ; (3) if (+- infinity) / (+- infinity), nan is the return value
  ; (4) if the division is infinity, infinity is the return value and the sign is valid
  ; (5) if the dividend is 0, 0 is the return value and the sign is valid
  ; (6) if the divisor is infinity, 0 is the return value and the sign is valid
  ; (7) if the divisor is 0, infinity is the return value and the sign is valid
  ; if the return value is something other than nan, the sign will be the divisor and the xor of the divisor

  movw  de,ax   ; subordinate to x
  ; return sign setting
  mov a,[sp+7]  ; sign of y
  xor a,b   ; sign of x
  and a,#0x80
  push  ax    ; return sign
  ; special value judgment of y
  movw  ax,[sp+6+2] ; exponent part of y
  addw  ax,ax
  inc a
  bz  $1b ; y is infinite or infinite
  dec a
  bz  $4b  ; y is 0 or a subnormal number
  mov l,a   ; exponent part of y
  oneb  a   ; reset the mantissa of y with a stingy expression
  shrw  ax,1    ; set 0 in the exponent area (for mantissa division)
  movw  [sp+6+2],ax ;
  mov h,a   ; set 0 at the top of the exponent part of y
  push  hl    ; exponent part of y
8:
  ; special value judgment of x
  movw  ax,bc   ; exponent part of x
  addw  ax,ax
  inc a
  bz  $5b ; x is infinite or infinite
  dec a
  bz  $7b  ; x is 0 or subnormal
  mov l,a
  oneb  a   ; reset the mantissa of x with a stingy expression
  shrw  ax,1    ; set 0 in the exponent area (for mantissa division)
  movw  bc,ax   ;
  mov h,a   ; set 0 at the top of the exponent part of x
9:
  movw  ax,hl   ; exponent part of x
  pop hl    ; exponent part of y
  subw  ax,hl   ; exponential part of operation result = exponent part of x - exponential part of y
  movw  hl,ax   ;
  ; divide the mantissa by 1 bit of stingy expression
  ; if x >= y, then x - y, if x < y, then 2x - y (exponent part-1)
  movw  ax,[sp+4+2] ; lower mantissa of y
  xchw  ax,de
  subw  ax,de   ; subordinate to the mantissa of x - lower mantissa of y
  push  ax
  mov a,[sp+6+4]  ; higher mantissa of y
  subc  c,a   ; higher mantissa of x - higher mantissa of y
  pop ax
  bnc $10f
  ; if x < y, then 2 (x - y) + y = 2x - y (exponent part-1)
  addw  ax,ax
  rolwc bc,1
  addw  ax,de
  push  ax
  mov a,[sp+6+4]  ; higher mantissa of y
  addc  c,a
  pop ax
  decw  hl    ; exponential part of calculation result
10:
  push  hl    ; exponential part of calculation result
#ifdef __RL78_S3__
  ; set the division to bcax left-justified (lowest byte is 0)
  shlw  bc,8
  mov c,a
  shlw  ax,8
  ; [sp+0]: exponential part of return value, [sp+3]: flag (sign), [sp+4]: return address
  ; [sp+8]: mantissa part of y, bcax: division
  ; set the divisor to hlde right justified
  movw  hl,ax
  movw  ax,[sp+6+4] ; higher mantissa of y
  xchw  ax,hl
  ; dst0 / src = ret1(8bit), rem1(24bit)
  divwu
  push  ax    ; ret1(8bit), high byte is 0
  mov a,l   ; dst1(bcax) = rem1(hlde) << 8
  mov b,a
  mov a,d
  mov c,a
  movw  ax,[sp+6+6] ; higher mantissa of y
  movw  hl,ax
  movw  ax,[sp+4+6] ; lower mantissa of y
  xchw  ax,de
  shlw  ax,8
  ; dst1 / src = ret2(8bit), rem2(24bit)
  divwu
  push  ax    ; ret2(8bit)
  mov a,l   ; dst2(bcax) = rem2(hlde) << 8
  mov b,a
  mov a,d
  mov c,a
  movw  ax,[sp+6+8] ; higher mantissa of y
  movw  hl,ax
  movw  ax,[sp+4+8] ; lower mantissa of y
  xchw  ax,de
  shlw  ax,8
  ; dst2 / src = ret3(8bit), rem3(24bit)
  divwu
  pop bc    ; ret2(8bit)
  mov a,c   ;
  xchw  ax,de   ; ret2-ret3(16bit)
  or  a,x   ; rem3
  or  a,h   ;
  or  l,a   ;
  pop bc    ; ret1(8bit), high byte is 0
#else // __RL78_S3__
#ifdef __MDA_ENABLED__
  ; set the division to bcax left-justified (lowest byte is 0)
  shlw  bc,8
  mov c,a
  shlw  ax,8
  ; [sp+0]: exponential part of return value, [sp+3]: flag (sign), [sp+4]: return address
  ; [sp+8]: mantissa part of y, bcax: division
  ; dst0 / src = ret1(8bit), rem1(24bit)
  push  psw
  di
  mov !LOWW(MDUC),#0x80 ; divmode = 1, divst = 0
  movw  MDAL,ax
  movw  ax,bc
  movw  MDAH,ax
  movw  ax,de
  movw  MDBL,ax
  movw  ax,[sp+6+6]
  movw  MDBH,ax
  mov !LOWW(MDUC),#0x81 ; divmode = 1, divst = 1
11:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$11b
  movw  hl,!LOWW(MDAL)  ; l = ret1(8bit)
  movw  bc,!LOWW(MDCH)  ; dst1(24bit)
  movw  ax,!LOWW(MDCL)  ;
  pop psw
  shlw  bc,8    ; left justified
  mov c,a   ;
  shlw  ax,8    ;
  ; dst1 / src = ret2(8bit), rem2(24bit)
  push  psw
  di
  mov !LOWW(MDUC),#0x80 ; divmode = 1, divst = 0
  movw  MDAL,ax
  movw  ax,bc
  movw  MDAH,ax
  movw  ax,de
  movw  MDBL,ax
  movw  ax,[sp+6+6]
  movw  MDBH,ax
  mov !LOWW(MDUC),#0x81 ; divmode = 1, divst = 1
12:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$12b
  movw  de,!LOWW(MDAL)  ; e = ret2(8bit)
  movw  bc,!LOWW(MDCH)  ; dst2(24bit)
  movw  ax,!LOWW(MDCL)  ;
  pop psw
  shlw  bc,8    ; left justified
  mov c,a   ;
  shlw  ax,8    ;
  ; dst2 / src = ret3(8bit), rem3(24bit)
  push  hl    ; ret1(8bit), high byte is 0
  push  psw
  di
  mov !LOWW(MDUC),#0x80 ; divmode = 1, divst = 0
  movw  MDAL,ax
  movw  ax,bc
  movw  MDAH,ax
  movw  ax,[sp+4+8]
  movw  MDBL,ax
  movw  ax,[sp+6+8]
  movw  MDBH,ax
  mov !LOWW(MDUC),#0x81 ; divmode = 1, divst = 1
13:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$13b
  movw  hl,!LOWW(MDCH)  ; rem3(32bit)
  movw  bc,!LOWW(MDCL)  ;
  movw  ax,MDAL   ; ret3(8bit)
  pop psw
  mov a,e   ; ret2(8bit)
  movw  de,ax   ; ret2-ret3(16bit)
  movw  ax,bc   ; rem3
  or  a,x   ;
  or  a,h   ;
  or  l,a   ;
  pop bc    ; ret1(8bit), high byte is 0
#else // __MDA_ENABLED__
  clrb  b
  movw  hl,ax   ; subordinate to the mantissa part (division) of x
  clrw  ax
  movw  de,#0x100 ; ret_l and lower loop counter
  ; bchl: division x, [sp+0]: ret_h and loop counter top, [sp+2]: return value exponent
  ; [sp+5]: sign, [sp+6]: return address, [sp+10]: divisor y
  ; repeat the following process 24 times
  ; (1) shift the division to the left
  ; (2) if division >= divisor, subtract the divisor from the division
  ;     shift the quotient and counter to the left and increase the quotient by 1
  ;     if the division is less than the divisor, shift the quotient and counter to the left
14:
  push  ax    ; ret_h and upper loop counter
  ; shift the division to the left
  movw  ax,hl
  addw  ax,ax
  movw  hl,ax
  rolwc bc,1
  movw  ax,[sp+12]  ; higher than y
  cmpw  ax,bc   ; top of x
  bnz $15f
  movw  ax,[sp+10]  ; subordinate to y
  cmpw  ax,hl   ; subordinate to x
15:
  bh  $16f
  ; ff division >= divisor, subtract the divisor from the division
  movw  ax,[sp+10]  ; subordinate to y
  xchw  ax,hl   ; subordinate to x
  subw  ax,hl
  movw  hl,ax   ; subordinate to x
  mov a,[sp+12] ; top l of y
  subc  c,a   ; top l of x
  mov a,[sp+13] ; higher h of y
  subc  b,a   ; higher h of x
  ; shift the quotient and counter to the left and increase the quotient by 1
  movw  ax,de
  addw  ax,ax
  incw  ax    ; quotient + 1
  movw  de,ax
  pop ax
  rolwc ax,1
  bnc $14b
  br  $17f
16:
  ; shift left quotient and counter
  movw  ax,de
  addw  ax,ax
  movw  de,ax
  pop ax
  rolwc ax,1
  bnc $14b
17:
  xchw  ax,bc   ; top division (remainder of division result)
  or  a,x   ;
  or  a,h   ;
  or  l,a   ;
#endif  // __MDA_ENABLED__
#endif  // __RL78_S3__
  ; [sp+0]: exponential part of return value, [sp+3]: flag (sign), [sp+4]: return address
  ; cde: mantissa part, e.0 and l: rounding judgment area
  pop ax    ; exponent part
  addw  ax,#126   ; bias value - 1
  bt  a.7,$19f  ; subnormal number
  incw  ax    ; bias value correction
  cmpw  ax,#0xff
  skc
  br  !!__REL_f_inf ; set infinity
  ; format as ieee754
  mov a,c   ; higher mantissa
  xch a,x
  shrw  ax,1
  movw  bc,ax
  movw  ax,de   ; mantissa subordinate
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  ; do not use l because the division result will not be an intermediate value
  ; round up the mantissa if the least significant bit of e is set
  bnc $18f
  addw  ax,#1
  sknc
  incw  bc
18:
  movw  de,ax   ; mantissa subordinate
  pop ax    ; sign
  or  b,a
  movw  ax,de   ; mantissa subordinate
  ret
;
19:
  ; the operation result is a subnormal number
  ; when (exponent part-1) is -25 or less, the calculation result is +- 0
  cmpw  ax,#0xffe8  ; -24
  sknc
  br  $!3b
  dec x   ; loop count correction (shift right at least twice)
  mov a,l
  xch a,x
  xchw  ax,de
  oneb  b   ; miser expression
20:
  ; right shift
  xchw  ax,bc   ; higher mantissa
  shrw  ax,1
  xchw  ax,bc   ; mantissa subordinate
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  xch a,e
  rorc  a,1
  sknc
  set1  a.0
  xch a,e
  inc d
  bnz $20b
  ; at this point, the sign is [sp+1], the exponent / mantissa part is bcax, and the rounding judgment is e
  br  !!__REL_f_round
.Lfunc_end1:
  .size __COM_fdiv, .Lfunc_end1-__COM_fdiv

  .weak ___divsf3
  .type ___divsf3,@function
  .set  ___divsf3, __COM_fdiv
