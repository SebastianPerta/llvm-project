//===-- COM_ddiv.s - Implement _COM_ddiv ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_ddiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_ddiv
//
//	double _COM_ddiv(double x, double y);
//
//	input:
//		x = [SP+4]
//		y = [SP+12]
//	output:
//		[AX] ([A:DE] for far data)
//===----------------------------------------------------------------------===//
  #include "def.S"

#ifdef __FAR_DATA__
#define __COM_ddiv  __COM_ddiv_nd
#endif

  .PUBLIC __COM_ddiv
  .EXTERN __REL_d_check
  .EXTERN __REL_d_inf
  .EXTERN __REL_d_round
  
  .text
#ifdef __OPTIMIZE_SIZE__
0:
  pop ax      ; flag (stack adjustment)
  clrw  ax      ; ret = 0xffffffffffffffff (nan)
  decw  ax
  movw  [de+6],ax
  movw  [de+4],ax
  movw  [de+2],ax
  movw  [de],ax
  ret
;
1:
  ; processed if y is nan, infinity
  mov1  cy,[hl].6
  and1  cy,[hl].7
  bc  $0b     ; if 0 / 0, nan is used as the return value
  br  $5f      ; ret = +-0
;
2:
  bf  [hl].3,$0b    ; x is nan
  ; x is infinity
  bt  [hl].5,$0b    ; y is infinity * nan
3:
  mov1  cy,[hl].0   ; return sign
  xor1  cy,[hl].4   ;
  pop ax      ; flag (stack adjustment)
  br  !!__REL_d_inf   ; set double type infinity to [de]
;
4:
  ; processed if x is infinity and nan
  bf  [hl].7,$0b    ; y is nan
  ; y is infinity
5:
  mov1  cy,[hl].0   ; return sign
  xor1  cy,[hl].4   ;
  pop ax      ; flag (stack adjustment)
  clrw  ax
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  mov1  a.7,cy
  movw  [de+6],ax
  ret
;

; this is the entrance to the function
  .globl __COM_ddiv
  .type  __COM_ddiv,@function
__COM_ddiv:
  ; [special return value]
  ; (1) if x or y is nan, the return value is nan
  ; (2) in the case of (+- 0) / (+- 0), nan is used as the return value
  ; (3) in the case of (+- infinity) / (+- infinity), nan is used as the return value
  ; (4) if the division is infinity, infinity is the return value and the sign is valid
  ; (4) if the dividend is 0, 0 is the return value and the sign is valid
  ; (5) if the divisor is infinity, 0 is the return value and the sign is valid
  ; (6) if the divisor is 0, infinity is the return value and the sign is valid
  ; if the return value is something other than nan, the sign is the xor of the dividend and the divisor

  ; check the sign of x, y, and the formal part is 0 or 0x7ff
  ; let the stack [hl] be the flag for determining the special solution
  ; the contents of the flag are as follows
  ;   if [hl].0 = 0, x is positive, if [hl].0 = 1, x is negative
  ;   if [hl].1 = 1 and [hl].3 = 1, x is infinity
  ;   if [hl].1 = 1 and [hl].3 = 0, x is nan
  ;   if [hl].2 = 1 and [hl].3 = 1 then x is 0
  ;   if [hl].2 = 1 and [hl].3 = 0, x is a subnormal number
  ;   if [hl].4 = 0, y is positive, if [hl].4 = 1, y is negative
  ;   if [hl].5 = 1 and [hl].7 = 1, y is infinity
  ;   if [hl].5 = 1 and [hl].7 = 0, y is nan
  ;   if [hl].6 = 1 and [hl].7 = 1 then y is 0
  ;   if [hl].6 = 1 and [hl].7 = 0, y is a subnormal number
  movw  de,ax   ; return address
  push  ax    ; flag
  movw  hl,sp
  call  !!__REL_d_check

  ; when x is nan * infinity
  bt  [hl].1,$2b
  ; when y is nan * infinity
  bt  [hl].5,$4b
  ; if x is 0
  mov1  cy,[hl].2
  and1  cy,[hl].3
  bc  $1b
  ; if y is 0
  mov1  cy,[hl].6
  and1  cy,[hl].7
  bc  $3b
  ; this is the end of special solution processing

  ; x ... [hl 13] ~ [hl 6], sign ... [hl].0
  ; y ... [hl 21] ~ [hl 14], sign ... [hl].4
  ; change the meaning of the flag here as follows
  ;   [hl].0 = 0 if x is positive, if [hl].0 = 1, x is negative (continue)
  ;   [hl].2 = 1 then x is a subnormal number (if 0, it has been processed)
  ;   [hl].4 = 0 if y is positive, if [hl].4 = 1, y is negative (continue)
  ;   [hl].6 = 1 then y is a subnormal number (if 0, it has been processed)
  ;   [hl].7 = 0 if the sign of the return value is positive, if [hl].7 = 1, the sign of the return value is negative
  mov a,[hl]
  and a,#0x055    ; clear [hl].1, [hl].3, [hl].5, [hl].7
  mov1  cy,a.0    ; return sign
  xor1  cy,a.4    ;
  mov1  a.7,cy    ;
  mov [hl],a

  ; subtract the exponent
  movw  ax,[hl+20]  ; y
  addw  ax,ax
  shrw  ax,5
  movw  bc,ax
  movw  ax,[hl+12]  ; x
  addw  ax,ax
  shrw  ax,5
  subw  ax,bc
  addw  ax,#1023  ; bias
  movw  bc,ax
  ; divide the mantissa
  ; add miser expression above the mantissa part of x and y (52nd bit)
  ; for non-normal mantissa, do not add miser expression
  mov a,[hl+12] ; x
  and a,#0x0f   ; clear other than the mantissa
  mov1  cy,[hl].2 ; miser expression
  not1  cy
  mov1  a.4,cy
  shrw  ax,8
  movw  [hl+12],ax
  mov a,[hl+20] ; y
  and a,#0x0f   ; clear other than the mantissa
  mov1  cy,[hl].6 ; miser expression
  not1  cy
  mov1  a.4,cy
  shrw  ax,8
  movw  [hl+20],ax
;
  bf  [hl].2,$7f
6:
  ; in the case of subnormal mantissa, the mantissa part is left-shifted until 1 comes to the 52nd bit
  ; decrease the exponent part by the amount shifted to the left
  movw  ax,[hl+6] ; x
  addw  ax,ax
  movw  [hl+6],ax
  movw  ax,[hl+8]
  rolwc ax,1
  movw  [hl+8],ax
  movw  ax,[hl+10]
  rolwc ax,1
  movw  [hl+10],ax
  mov a,[hl+12]
  rolc  a,1
  mov [hl+12],a
  decw  bc    ; flags do not change in decw
  bf  a.4,$6b  ; loop until the 52nd bit becomes 1
  incw  bc    ; exponent part adjustment for stingy expression
7:
  bf  [hl].6,$9f
8:
  ; in the case of subnormal mantissa, the mantissa part is left-shifted until 1 comes to the 52nd bit
  ; increase the exponent part by the amount shifted to the left
  movw  ax,[hl+14]  ; y
  addw  ax,ax
  movw  [hl+14],ax
  movw  ax,[hl+16]
  rolwc ax,1
  movw  [hl+16],ax
  movw  ax,[hl+18]
  rolwc ax,1
  movw  [hl+18],ax
  mov a,[hl+20]
  rolc  a,1
  mov [hl+20],a
  incw  bc    ; flags do not change in decw
  bf  a.4,$8b  ; loop until the 52nd bit becomes 1
  decw  bc    ; exponent part adjustment for stingy expression
9:
  movw  ax,bc   ; exponent part of return value
  bt  a.7,$10f
  cmp a,#0x08   ; overflow if the exponent is 0x800 or higher
  bc  $11f
  mov1  cy,[hl].7 ; sign
  pop ax    ; flag (stack adjustment)
  br  !!__REL_d_inf ; set double type infinity to [de]
10:
  cmpw  ax,#0x0ffcc ; underflow if the exponent part is -53 or less
  bnc $11f
  mov1  cy,[hl].7 ; sign
  pop ax    ; flag (stack adjustment)
  clrw  ax    ; ret = +-0
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  rorc  a,1   ; sign
  movw  [de+6],ax
  ret
11:
  ; division of mantissa
  ; [hl+6] ... division, [hl+14] ... divisor, [hl].7 ... sign, bc ... return exponent part
  ; [de] ... division result
  ; repeat the following process 64 times or 65 times
  ; (1) if division >= divisor, subtract the divisor / division and quotient 1
  ; (2) shift the division and quotient to the left until the 63rd quotient stands out

  ; initialization of division result
  clrw  ax
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  ; if the mantissa part of x < the mantissa part of y, decrement the exponential part of the return value by 1
  mov a,[hl+12] ; x_hh (the most significant 1 byte is 0)
  cmp a,[hl+20] ; y_hh (the most significant 1 byte is 0)
  bnz $12f
  movw  ax,[hl+10]  ; x_hl
  cmpw  ax,[hl+18]  ; y_hl
  bnz $12f
  movw  ax,[hl+8] ; x_lh
  cmpw  ax,[hl+16]  ; y_lh
  bnz $12f
  movw  ax,[hl+6] ; x_ll
  cmpw  ax,[hl+14]  ; y_ll
12:
  sknc
  decw  bc    ; return value of exponent part
13:
  movw  ax,[hl+12]  ; x_hh
  cmpw  ax,[hl+20]  ; y_hh
  bnz $14f
  movw  ax,[hl+10]  ; x_hl
  cmpw  ax,[hl+18]  ; y_hl
  bnz $14f
  movw  ax,[hl+8] ; x_lh
  cmpw  ax,[hl+16]  ; y_lh
  bnz $14f
  movw  ax,[hl+6] ; x_ll
  cmpw  ax,[hl+14]  ; y_ll
14:
  bc  $15f
  ; x -= y
  movw  ax,[hl+6] ; x_ll
  subw  ax,[hl+14]  ; y_ll
  movw  [hl+6],ax
  movw  ax,[hl+8] ; x_lh
  xch a,x
  subc  a,[hl+16] ; y_lh
  xch a,x
  subc  a,[hl+17]
  movw  [hl+8],ax
  movw  ax,[hl+10]  ; x_hl
  xch a,x
  subc  a,[hl+18] ; y_hl
  xch a,x
  subc  a,[hl+19]
  movw  [hl+10],ax
  movw  ax,[hl+12]  ; x_hh
  sknc
  decw  ax
  subw  ax,[hl+20]  ; y_hh
  movw  [hl+12],ax
  movw  ax,[de]   ; quotient 1
  incw  ax    ;
  movw  [de],ax   ;
15:
  movw  ax,[de+6]
  bt  a.7,$16f
  ; shift the division
  movw  ax,[hl+6] ; x_ll
  addw  ax,ax
  movw  [hl+6],ax
  movw  ax,[hl+8] ; x_lh
  rolwc ax,1
  movw  [hl+8],ax
  movw  ax,[hl+10]  ; x_hl
  rolwc ax,1
  movw  [hl+10],ax
  movw  ax,[hl+12]  ; x_hh
  rolwc ax,1
  movw  [hl+12],ax
  ; shift quotient
  movw  ax,[de]
  addw  ax,ax
  movw  [de],ax
  movw  ax,[de+2]
  rolwc ax,1
  movw  [de+2],ax
  movw  ax,[de+4]
  rolwc ax,1
  movw  [de+4],ax
  movw  ax,[de+6]
  rolwc ax,1
  movw  [de+6],ax
  br  $13b
16:
  ; de ... return address, bc ... exponent part, [de] ... mantissa part, [hl].7 ... code
  movw  ax,bc   ; return value of exponent part
  bt  a.7,$17f  ; if the exponent part is negative, move on to processing the subnormal number
  cmpw  ax,#0x0
  bz  $17f  ; if the exponent part is 0, move to the processing of the subnormal number
  cmpw  ax,#0x07ff
  bc  $19f
  mov1  cy,[hl].7 ; sign
  pop ax    ; flag (stack adjustment)
  br  !!__REL_d_inf ; set double type infinity to [de]
17:
  ; for subnormal mantissa, adjust the mantissa
  decw  bc    ; since the stingy expression of the subnormal mantissa is 0, the number of shifts is 1
18:
  ; shift the mantissa to the right
  movw  ax,[de+6]
  shrw  ax,1
  movw  [de+6],ax
  movw  ax,[de+4]
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  [de+4],ax
  movw  ax,[de+2]
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  [de+2],ax
  movw  ax,[de]
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  [de],ax
  incw  bc    ; exponent part
  clrw  ax
  cmpw  ax,bc
  bnz $18b
19:
  ; round the calculation result
  ; mantissa part [de] -> [hl], exponent part bc -> de, code [hl].7 -> a.7
  movw  ax,bc
  xchw  ax,de
  movw  hl,ax
  pop ax    ; sign
  mov a,x
  ; fit to ieee754 format
  br  !!__REL_d_round ; after rounding, fit to the ieee754 format
#else
.L_NAN:
  POP AX
  CLRW AX
  DECW AX
  MOVW [DE+6], AX
  MOVW [DE+4], AX
  MOVW [DE+2], AX
  MOVW [DE], AX
  RET
.L_X_ZERO:
  MOV1 CY, [HL].6
  AND1 CY, [HL].7
  BC $.L_NAN
  BR $.L_ZERO
.L_X_NAN_INF:
  BF [HL].3, $.L_NAN
  BT [HL].5, $.L_NAN
.L_Y_ZERO:
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  POP AX
  BR !!__REL_d_inf
.L_Y_NAN_INF:
  BF [HL].7, $.L_NAN
.L_ZERO:
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  POP AX
  CLRW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  MOV1 A.7, CY
  MOVW [DE+6], AX
  RET
  
.L_EXP_UNDERFLOW:
  MOV1 CY, [HL].7
  POP AX
  CLRW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  RORC A, 1
  MOVW [DE+6], AX
  RET
__COM_ddiv:
  
  MOVW DE, AX
  PUSH AX
  MOVW HL, SP
  CALL !!__REL_d_check
  
  MOV1 CY, [HL].1
  SKNC
  BR $.L_X_NAN_INF
  MOV1 CY, [HL].5
  SKNC
  BR $.L_Y_NAN_INF
  MOV1 CY, [HL].2
  AND1 CY, [HL].3
  SKNC
  BR $.L_X_ZERO
  MOV1 CY, [HL].6
  AND1 CY, [HL].7
  SKNC
  BR $.L_Y_ZERO
  
  
  MOV A, [HL]
  AND A, #0x055
  MOV1 CY, A.0
  XOR1 CY, A.4
  MOV1 A.7, CY
  MOV [HL], A
  
  MOVW AX, [HL+20]
  ADDW AX, AX
  SHRW AX, 5
  MOVW BC, AX
  MOVW AX, [HL+12]
  ADDW AX, AX
  SHRW AX, 5
  SUBW AX, BC
  ADDW AX, #1023
  MOVW BC, AX
  MOV A, [HL+12]
  AND A, #0x0F
  MOV1 CY, [HL].2
  NOT1 CY
  MOV1 A.4, CY
  SHRW AX, 8
  MOVW [HL+12], AX
  MOV A, [HL+20]
  AND A, #0x0F
  MOV1 CY, [HL].6
  NOT1 CY
  MOV1 A.4, CY
  SHRW AX, 8
  MOVW [HL+20], AX
  BF [HL].2, $.L1
.L_X_LOOP:
  MOVW AX, [HL+6]
  ADDW AX, AX
  MOVW [HL+6], AX
  MOVW AX, [HL+8]
  ROLWC AX, 1
  MOVW [HL+8], AX
  MOVW AX, [HL+10]
  ROLWC AX, 1
  MOVW [HL+10], AX
  MOV A, [HL+12]
  ROLC A, 1
  MOV [HL+12], A
  DECW BC
  BF A.4, $.L_X_LOOP
  INCW BC
.L1:
  BF [HL].6, $.L2
.L_Y_LOOP:
  MOVW AX, [HL+14]
  ADDW AX, AX
  MOVW [HL+14], AX
  MOVW AX, [HL+16]
  ROLWC AX, 1
  MOVW [HL+16], AX
  MOVW AX, [HL+18]
  ROLWC AX, 1
  MOVW [HL+18], AX
  MOV A, [HL+20]
  ROLC A, 1
  MOV [HL+20], A
  INCW BC
  BF A.4, $.L_Y_LOOP
  DECW BC
.L2:
  MOVW AX, BC
  MOV1 CY, A.7
  SKNC
  BR $.L_EXP_MIN
  CMP A, #0x08
  BC $.L3
  MOV1 CY, [HL].7
  POP AX
  BR !!__REL_d_inf
.L_EXP_MIN:
  CMPW AX, #0x0FFCC
  SKNC
  BR $!.L_EXP_UNDERFLOW
  
.L3:
  
  CLRW AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  MOVW [DE+6], AX
  MOV A, [HL+12]
  CMP A, [HL+20]
  BNZ $.L_CMP1
  MOVW AX, [HL+10]
  CMPW AX, [HL+18]
  BNZ $.L_CMP1
  MOVW AX, [HL+8]
  CMPW AX, [HL+16]
  BNZ $.L_CMP1
  MOVW AX, [HL+6]
  CMPW AX, [HL+14]
.L_CMP1:
  SKNC
  DECW BC
  push bc
  clrw bc
.L_DIVLOOP:
  MOVW AX, [HL+12]
  CMPW AX, [HL+20]
  BNZ $.L_CMP2
  MOVW AX, [HL+10]
  CMPW AX, [HL+18]
  BNZ $.L_CMP2
  MOVW AX, [HL+8]
  CMPW AX, [HL+16]
  BNZ $.L_CMP2
  MOVW AX, [HL+6]
  CMPW AX, [HL+14]
.L_CMP2:
  BC $.L_SUBSKIP
  MOVW AX, [HL+6]
  SUBW AX, [HL+14]
  MOVW [HL+6], AX
  MOVW AX, [HL+8]
  XCH A, X
  SUBC A, [HL+16]
  XCH A, X
  SUBC A, [HL+17]
  MOVW [HL+8], AX
  MOVW AX, [HL+10]
  XCH A, X
  SUBC A, [HL+18]
  XCH A, X
  SUBC A, [HL+19]
  MOVW [HL+10], AX
  MOVW AX, [HL+12]
  SKNC
  DECW AX
  SUBW AX, [HL+20]
  MOVW [HL+12], AX
  incw bc
.L_SUBSKIP:
  MOVW AX, [DE+6]
  MOV1 CY, A.7
  SKNC
  BR $.L_DIVEND
  MOVW AX, [HL+6]
  ADDW AX, AX
  MOVW [HL+6], AX
  MOVW AX, [HL+8]
  ROLWC AX, 1
  MOVW [HL+8], AX
  MOVW AX, [HL+10]
  ROLWC AX, 1
  MOVW [HL+10], AX
  MOVW AX, [HL+12]
  ROLWC AX, 1
  MOVW [HL+12], AX
  shlw bc, 1
  MOVW AX, [DE+2]
  ROLWC AX, 1
  MOVW [DE+2], AX
  MOVW AX, [DE+4]
  ROLWC AX, 1
  MOVW [DE+4], AX
  MOVW AX, [DE+6]
  ROLWC AX, 1
  MOVW [DE+6], AX
  BR $.L_DIVLOOP
.L_DIVEND:
  movw ax, bc
  movw [de], ax
  pop bc
  MOVW AX, BC
  MOV1 CY, A.7
  SKNC
  BR $.L_DENORM
  CMPW AX, #0x0
  SKNZ
  BR $.L_DENORM
  CMPW AX, #0x07FF
  BC $.L_ROUNDING
  MOV1 CY, [HL].7
  POP AX
  BR !!__REL_d_inf
.L_DENORM:
  DECW BC
.L_DENORM_LOOP:
  MOVW AX, [DE+6]
  SHRW AX, 1
  MOVW [DE+6], AX
  MOVW AX, [DE+4]
  RORC A, 1
  XCH A, X
  RORC A, 1
  XCH A, X
  MOVW [DE+4], AX
  MOVW AX, [DE+2]
  RORC A, 1
  XCH A, X
  RORC A, 1
  XCH A, X
  MOVW [DE+2], AX
  MOVW AX, [DE]
  RORC A, 1
  XCH A, X
  RORC A, 1
  XCH A, X
  MOVW [DE], AX
  INCW BC
  CLRW AX
  CMPW AX, BC
  BNZ $.L_DENORM_LOOP
.L_ROUNDING:
  MOVW AX, BC
  XCHW AX, DE
  MOVW HL, AX
  POP AX
  MOV A, X
  BR !!__REL_d_round
#endif
.Lfunc_end1:
  .size __COM_ddiv, .Lfunc_end1-__COM_ddiv

#ifdef __FAR_DATA__
#undef __COM_ddiv
  .globl __COM_ddiv
  .type  __COM_ddiv,@function
__COM_ddiv:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
#ifdef __OPTIMIZE_SIZE__
  mov   e, #8         ; copy args using a loop
1:
  movw  ax,[sp+30]
  push  ax
  dec   e
  bnz   $1b
#else
  movw  ax,[sp+30]    ; copy arg 2
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]    ; copy arg 1
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
#endif
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #20
  call  !!__COM_ddiv_nd
  addw  sp, #16       ; get rid of the arg copies from the stack
  pop   hl            ; get the addr of org retval in ES:HL
  pop   ax
  mov   es, a
  pop   ax            ; copy the tmp retval to the org one
  movw  es:[hl], ax
  pop   ax
  movw  es:[hl+2], ax
  pop   ax
  movw  es:[hl+4], ax
  pop   ax
  movw  es:[hl+6], ax
  ret
.Lfunc_end2:
  .size __COM_ddiv, .Lfunc_end2-__COM_ddiv
#endif

  .weak ___divdf3
  .type ___divdf3,@function
  .set  ___divdf3, __COM_ddiv

