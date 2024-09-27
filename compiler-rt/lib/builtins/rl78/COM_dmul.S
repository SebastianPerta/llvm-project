//===-- COM_dmul.s - Implement _COM_dmul ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dmul for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_dmul
//
//	double _COM_dmul(double x, double y);
//
//	input:
//		x = [SP+4]
//		y = [SP+12]
//	output:
//		[AX] ([A:DE] for far data)
//===----------------------------------------------------------------------===//
  #include "def.S"

#ifdef __FAR_DATA__
#define __COM_dmul  __COM_dmul_nd
#endif

  .PUBLIC __COM_dmul
  .EXTERN __COM_mulul
  .EXTERN __REL_d_check
  .EXTERN __REL_d_inf
  .EXTERN __REL_d_shl11
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
  mov1  cy,[hl].0   ; return sign
  xor1  cy,[hl].4   ;
  pop ax      ; flag (stack adjustment)
  clrw  ax
  clrw  ax
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  mov1  a.7,cy      ; sign
  movw  [de+6],ax
  ret
;
2:
  ; x is infinity, y is infinity * nan
  bf  [hl].7,$0b    ; y is nan
  mov1  cy,[hl].0   ; return sign
  xor1  cy,[hl].4   ;
  pop ax      ; flag (stack adjustment)
  br  !!__REL_d_inf   ; set double type infinity to [de]
;
3:
  bf  [hl].3,$0b    ; x is nan
  ; x is infinity
  bt  [hl].5,$2b  ; y is infinity * nan
  mov1  cy,[hl].6   ; y is 0
  and1  cy,[hl].7   ;
  bc  $0b     ; if infinity * 0, the return value is nan
  mov1  cy,[hl].0   ; return sign
  xor1  cy,[hl].4   ;
  pop ax      ; flag (stack adjustment)
  br  !!__REL_d_inf   ; set double type infinity to [de]
;
4:
  ; processed if x is infinity and nan
  bf  [hl].7,$0b    ; y is nan
  ; y is infinity
  mov1  cy,[hl].2   ; x is 0
  and1  cy,[hl].3   ;
  bc  $0b     ; if infinity * 0, the return value is nan
  mov1  cy,[hl].0   ; return sign
  xor1  cy,[hl].4   ;
  pop ax      ; flag (stack adjustment)
  br  !!__REL_d_inf   ; set double type infinity to [de]
;

  ; this is the entrance to the function
  .globl __COM_dmul
  .type  __COM_dmul,@function
__COM_dmul:
  ; [special return value]
  ; (1) if x or y is nan, the return value is nan
  ; (2) in the case of multiplication of 0 and infinity, nan is used as the return value
  ; (3) for multiplications other than 0 and infinity, 0 is the return value
  ; (4) for multiplications other than infinity and 0, +- infinity is the return value

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
  bt  [hl].1,$3b
  ; when y is nan * infinity
  bt  [hl].5,$4b
  ; if x is 0
  mov1  cy,[hl].2
  and1  cy,[hl].3
  bc  $1b
  ; if y is 0
  mov1  cy,[hl].6
  and1  cy,[hl].7
  bc  $1b
  ; this is the end of special solution processing

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

  ; x... [hl 6], y... [hl 14]
  ; add the exponent part
  movw  ax,[hl+20]  ; y
  addw  ax,ax
  shrw  ax,5
  movw  bc,ax
  movw  ax,[hl+12]  ; x
  addw  ax,ax
  shrw  ax,5
  addw  ax,bc
  ; multiply the mantissa
  push  de    ; return address
  push  ax    ; exponent part
  ; add a miser expression above the mantissa of x and y, and left justify the mantissa
  ; for non-normal mantissa, do not add miser expression
  movw  ax,hl   ; address of x
  addw  ax,#6
  movw  de,ax
  mov1  cy,[hl].2 ; miser expression
  not1  cy    ;
  call  !!__REL_d_shl11
  movw  ax,hl   ; address of y
  addw  ax,#14
  movw  de,ax
  mov1  cy,[hl].6 ; miser expression
  not1  cy    ;
  call  !!__REL_d_shl11
  pop bc    ; exponent part
  pop de    ; return address
;
  bf  [hl].2,$6f
5:
  ; for subnormal mantissa, shift the mantissa to the left until 1 comes to the top
  ; decrease the index part by the amount shifted to the left
  movw  ax,[hl+6] ; x
  addw  ax,ax
  movw  [hl+6],ax
  movw  ax,[hl+8]
  rolwc ax,1
  movw  [hl+8],ax
  movw  ax,[hl+10]
  rolwc ax,1
  movw  [hl+10],ax
  movw  ax,[hl+12]
  rolwc ax,1
  movw  [hl+12],ax
  decw  bc    ; flags do not change in decw
  bf  a.7,$5b
  incw  bc    ; index part adjustment for miser expression
6:
  bf  [hl].6,$8f
7:
  ; for subnormal mantissa, shift the mantissa to the left until 1 comes to the top
  ; decrease the index part by the amount shifted to the left
  movw  ax,[hl+14]  ; y
  addw  ax,ax
  movw  [hl+14],ax
  movw  ax,[hl+16]
  rolwc ax,1
  movw  [hl+16],ax
  movw  ax,[hl+18]
  rolwc ax,1
  movw  [hl+18],ax
  movw  ax,[hl+20]
  rolwc ax,1
  movw  [hl+20],ax
  decw  bc    ; flags do not change in decw
  bf  a.7,$7b
  incw  bc    ; index part adjustment for miser expression
8:
  ; extinction solution judgment
  movw  ax,bc   ; exponent part of return value
  bt  a.7,$9f ; if the exponent part is a negative number, the solution disappears
  cmpw  ax,#1023-53 ; a value that cannot be expressed even with a subnormalized number
  bnc $10f
9:
  mov1  cy,[hl].7 ; sign
  pop ax    ; flag (stack adjustment)
  clrw  ax    ; ret = +- 0
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  rorc  a,1   ; sign
  movw  [de+6],ax
  ret
10:
  cmpw  ax,#1023+2047
  bc  $11f
  mov1  cy,[hl].7 ; sign
  pop ax    ; flag (stack adjustment)
  br  !!__REL_d_inf ; set double type infinity to [de]
11:
  ; multiplication of mantissa
  push  bc    ; exponent part of return value
  push  de    ; return address
  subw  sp,#8   ; mantissa multiplication result lower 8 bytes
  ; x_l * y_l
  movw  bc,sp
  movw  ax,[hl+16]  ; y_l
  push  ax    ;
  movw  ax,[hl+14]  ;
  push  ax    ;
  movw  ax,[hl+8] ; x_l
  movw  de,ax   ;
  movw  ax,[hl+6] ;
  xchw  ax,bc   ;
  call  !!__COM_mulul ; return value [ax] (64-bit), argument de-bc, [sp+4]
  ; x_l * y_h
  subw  sp,#4
  movw  de,sp   ; [de+8]... mantissa part multiplication result lower 8 bytes
  movw  ax,[de+34+6]  ; [de+16]... return address, [de+18]... exponential part
  push  ax    ; [de+20]... flag, [de+26]... x, [de+34]... y
  movw  ax,[de+34+4]  ;
  push  ax    ; y_h
  movw  ax,[de+26+0]    ; x_l
  movw  bc,ax   ;
  movw  ax,[de+26+2]  ;
  xchw  ax,de   ;
  call  !!__COM_mulul ; return value [ax] (64-bit), argument de-bc, [sp+4]
  addw  sp,#4
  movw  hl,sp   ; [hl+8]... mantissa part multiplication result lower 8 bytes
  movw  ax,[hl+16]  ; [hl+16]... return address, [hl+18]... exponent
  movw  de,ax   ; [hl+20]... flag, [hl+26]... x, [hl+34]... y
  movw  ax,[hl]   ; use the return value area for the upper 8 bytes of the mantissa multiplication result
  addw  ax,[hl+8+4] ;
  movw  [hl+8+4],ax ; (x_l * y_l)_h + (x_l * y_h)_l
  movw  ax,[hl+2] ;
  xch a,x   ;
  addc  a,[hl+8+6]  ;
  xch a,x   ;
  addc  a,[hl+8+7]  ;
  movw  [hl+8+6],ax ;
  movw  ax,[hl+4] ; (x_l * y_h)_h + cy
  sknc      ; 0xffffffff * 0xffffffff = 0xfffffffe00000001
  addw  ax,#1   ; so even if you increment the upper 8 bytes
  movw  [de],ax   ; top digit overflow does not occur
  movw  ax,[hl+6] ;
  sknc      ;
  incw  ax    ; 
  movw  [de+2],ax ;
  ; x_h * y_l
  movw  de,sp
  movw  ax,[de+34+2]  ; [de+8]... mantissa part multiplication result lower 8 bytes
  push  ax    ; [de+16]... return address, [de+18]... exponential part
  movw  ax,[de+34+0]  ; [de+20]... flag, [de+26]... x, [de+34]... y
  push  ax    ; y_l
  movw  ax,[de+26+4]  ; x_h
  movw  bc,ax
  movw  ax,[de+26+6]
  xchw  ax,de
  call  !!__COM_mulul ; return value [ax] (64-bit), argument de-bc, [sp+4]
  addw  sp,#4
  movw  hl,sp   ; [hl+8]... mantissa part multiplication result lower 8 bytes
  movw  ax,[hl+16]  ; [hl+16]... return address, [hl+18]... exponent
  movw  de,ax   ; [hl+20]... flag, [hl+26]... x, [hl+34]... y
  movw  ax,[hl]   ; use the return value area for the upper 8 bytes of the mantissa multiplication result
  addw  ax,[hl+8+4] ;
  movw  [hl+8+4],ax ; (x_l * y_l)_h + (x_l * y_h)_l + (x_h * y_l)_l
  movw  ax,[hl+2] ;
  xch a,x   ;
  addc  a,[hl+8+6]  ;
  xch a,x   ;
  addc  a,[hl+8+7]  ;
  movw  [hl+8+6],ax ;
  movw  ax,[de]   ; (x_l * y_h)_h + (x_h * y_l)_h
  xch a,x   ;
  addc  a,[hl+4]  ;
  xch a,x   ;
  addc  a,[hl+5]  ;
  movw  [de],ax   ;
  movw  ax,[de+2] ;
  xch a,x   ;
  addc  a,[hl+6]  ;
  xch a,x   ;
  addc  a,[hl+7]  ;
  movw  [de+2],ax ;
  clrw  ax    ; cy
  rolwc ax,1    ;
  movw  [de+4],ax ;
  ; x_h * y_h
  movw  de,sp
  movw  ax,[de+34+6]  ; [de+8]... mantissa part multiplication result lower 8 bytes
  push  ax    ; [de+16]... return address, [de+18]... exponential part
  movw  ax,[de+34+4]  ; [de+20]... flag, [de+26]... x, [de+34]... y
  push  ax    ; y_h
  movw  ax,[de+26+4]  ; x_h
  movw  bc,ax
  movw  ax,[de+26+6]
  xchw  ax,de
  call  !!__COM_mulul ; return value [ax] (64-bit), argument de-bc, [sp+4]
  addw  sp,#4
  movw  ax,[sp+16]  ; return address
  movw  hl,ax
  pop ax    ; operation result of _com_mulul
  addw  ax,[hl+0] ; (x_l * y_h)_h + (x_h * y_l)_h + (x_h * y_h)_l
  movw  [hl],ax
  pop ax    ; operation result of _com_mulul
  xch a,x
  addc  a,[hl+2]
  xch a,x
  addc  a,[hl+3]
  movw  [hl+2],ax
  sknc
  incw  [hl+4]    ; (x_h * y_h)_h + cy
  pop ax    ; operation result of _com_mulul
  addw  ax,[hl+4]
  movw  [hl+4],ax
  pop ax    ; operation result of _com_mulul
  sknc
  incw  ax
  movw  [hl+6],ax
  ; if the lower 8 bytes of the multiplication result are other than 0,
  ; set 1 to the least significant bit of the upper 8 bytes
  pop ax
  or  a,x
  pop bc
  or  a,b
  or  a,c
  pop bc
  or  a,b
  or  a,c
  pop bc
  or  a,b
  or  a,c
  skz
  set1  [hl].0
;
  pop de    ; return address(de = hl)
  pop bc    ; exponent part
  incw  bc    ; add the exponent part
  mov a,[hl+7]
  bt  a.7,$12f
  ; there are 2 bits of miser expression, so justify it to the left
  movw  ax,[hl]
  addw  ax,ax
  movw  [hl],ax
  movw  ax,[hl+2]
  rolwc ax,1
  movw  [hl+2],ax
  movw  ax,[hl+4]
  rolwc ax,1
  movw  [hl+4],ax
  movw  ax,[hl+6]
  rolwc ax,1
  movw  [hl+6],ax
  decw  bc    ; when the most significant bit is 0,
        ; it is not necessary to add the exponent part, so restore it
12:
  ; overflow check by exponential addition
  movw  ax,bc
  cmpw  ax,#1023+2047
  bc  $13f
  pop ax    ; flag
  mov a,x
  mov1  cy,a.7    ; sign
  br  !!__REL_d_inf ; set double type infinity to [de]
13:
  subw  ax,#1023  ; bias adjustment
  bh  $15f
  ; subnormal mantissa part adjustment processing
  decw  ax    ; the miser representation of the subnormal number is 0, so the number of shifts is 1
  movw  bc,ax
14:
  ; mantissa [hl], exponent de
  ; add until the exponent becomes 0 and shift the mantissa to the right
  movw  ax,[hl+6]
  shrw  ax,1
  movw  [hl+6],ax
  movw  ax,[hl+4]
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  [hl+4],ax
  movw  ax,[hl+2]
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  [hl+2],ax
  movw  ax,[hl]
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  [hl],ax
  inc c
  bnz $14b
  clrw  ax    ; exponent part = 0
15:
  ; round the calculation result
  movw  de,ax   ; exponent part
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
.L_ZERO:
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  POP AX
  CLRW AX
  CLRW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  MOV1 A.7, CY
  MOVW [DE+6], AX
  RET
.L_INF_INF:
  BF [HL].7, $.L_NAN
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  POP AX
  BR !!__REL_d_inf
.L_X_NAN_INF:
  BF [HL].3, $.L_NAN
  BT [HL].5, $.L_INF_INF
  MOV1 CY, [HL].6
  AND1 CY, [HL].7
  BC $.L_NAN
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  POP AX
  BR !!__REL_d_inf
.L_Y_NAN_INF:
  BF [HL].7, $.L_NAN
  MOV1 CY, [HL].2
  AND1 CY, [HL].3
  BC $.L_NAN
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  POP AX
  BR !!__REL_d_inf
.L_UNDER:
  MOV1 CY, [HL].7
  POP AX
  CLRW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  RORC A, 1
  MOVW [DE+6], AX
  RET
.L_OVER:
  MOV1 CY, [HL].7
  POP AX
  BR !!__REL_d_inf
__COM_dmul:
  
  MOVW DE, AX
  PUSH AX
  MOVW HL, SP
  CALL !!__REL_d_check
  
  MOV1 CY, [HL].1
  SKNC
  BR $.L_X_NAN_INF
  MOV1 CY, [HL].5
  SKNC
  BR $!.L_Y_NAN_INF
  MOV1 CY, [HL].2
  AND1 CY, [HL].3
  SKNC
  BR $.L_ZERO
  MOV1 CY, [HL].6
  AND1 CY, [HL].7
  SKNC
  BR $.L_ZERO
  
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
  ADDW AX, BC
  PUSH DE
  PUSH AX
  MOVW AX, HL
  ADDW AX, #6
  MOVW DE, AX
  MOV1 CY, [HL].2
  NOT1 CY
  CALL !!__REL_d_shl11
  MOVW AX, HL
  ADDW AX, #14
  MOVW DE, AX
  MOV1 CY, [HL].6
  NOT1 CY
  CALL !!__REL_d_shl11
  POP BC
  POP DE
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
  MOVW AX, [HL+12]
  ROLWC AX, 1
  MOVW [HL+12], AX
  DECW BC
  BF A.7, $.L_X_LOOP
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
  MOVW AX, [HL+20]
  ROLWC AX, 1
  MOVW [HL+20], AX
  DECW BC
  BF A.7, $.L_Y_LOOP
  INCW BC
.L2:
  MOVW AX, BC
  MOV1 CY, A.7
  SKNC
  BR $!.L_UNDER
  CMPW AX, #1023-53
  SKNC
  BR $!.L_UNDER
.L3:
  CMPW AX, #1023+2047
  SKC
  BR $!.L_OVER
.L4:
  PUSH BC
  PUSH DE
  SUBW SP, #8
  MOVW BC, SP
  SUBW SP, #8
  MOVW AX, [HL+8]
  PUSH AX
  MOVW AX, [HL+6]
  PUSH AX
  MOVW AX, [HL+16]
  MOVW DE, AX
  MOVW AX, [HL+14]
  XCHW AX, BC
  CALL !!__COM_mulul
  addw SP, #4
  MOVW DE, SP
  MOVW AX, [DE+34+4]
  MOVW BC, AX
  MOVW AX, [DE+34+6]
  
  XCHW AX, DE
  SUBW SP, #4
  CALL !!__COM_mulul
  ADDW SP, #4
  MOVW HL, SP
  MOVW AX, [HL+16]
  MOVW DE, AX
  MOVW AX, [HL]
  ADDW AX, [HL+8+4]
  MOVW [HL+8+4], AX
  MOVW AX, [HL+2]
  XCH A, X
  ADDC A, [HL+8+6]
  XCH A, X
  ADDC A, [HL+8+7]
  MOVW [HL+8+6], AX
  MOVW AX, [HL+4]
  SKNC
  ADDW AX, #1
  MOVW [DE], AX
  MOVW AX, [HL+6]
  SKNC
  INCW AX
  MOVW [DE+2], AX
  MOVW DE, SP
  MOVW AX, [DE+26+6]
  PUSH AX
  MOVW AX, [DE+26+4]
  PUSH AX
  MOVW AX, [DE+34+0]
  MOVW BC, AX
  MOVW AX, [DE+34+2]
  XCHW AX, DE
  CALL !!__COM_mulul
  ADDW SP, #4
  MOVW HL, SP
  MOVW AX, [HL+16]
  MOVW DE, AX
  MOVW AX, [HL]
  ADDW AX, [HL+8+4]
  MOVW [HL+8+4], AX
  MOVW AX, [HL+2]
  XCH A, X
  ADDC A, [HL+8+6]
  XCH A, X
  ADDC A, [HL+8+7]
  MOVW [HL+8+6], AX
  MOVW AX, [DE]
  XCH A, X
  ADDC A, [HL+4]
  XCH A, X
  ADDC A, [HL+5]
  MOVW [DE], AX
  MOVW AX, [DE+2]
  XCH A, X
  ADDC A, [HL+6]
  XCH A, X
  ADDC A, [HL+7]
  MOVW [DE+2], AX
  CLRW AX
  ROLWC AX, 1
  MOVW [DE+4], AX
  MOVW DE, SP
  subw SP, #4
  MOVW AX, [DE+34+4]
  MOVW BC, AX
  MOVW AX, [DE+34+6]
  XCHW AX, DE
  CALL !!__COM_mulul
  ADDW SP, #4
  MOVW AX, [SP+16]
  MOVW HL, AX
  POP AX
  ADDW AX, [HL+0]
  MOVW [HL], AX
  POP AX
  XCH A, X
  ADDC A, [HL+2]
  XCH A, X
  ADDC A, [HL+3]
  MOVW [HL+2], AX
  SKNC
  INCW [HL+4]
  POP AX
  ADDW AX, [HL+4]
  MOVW [HL+4], AX
  POP AX
  SKNC
  INCW AX
  MOVW [HL+6], AX
  POP AX
  OR A, X
  POP BC
  OR A, B
  OR A, C
  POP BC
  OR A, B
  OR A, C
  POP BC
  OR A, B
  OR A, C
  SKZ
  SET1 [HL].0
  POP DE
  POP BC
  INCW BC
  MOV A, [HL+7]
  BT A.7, $.L_EXP_INC
  MOVW AX, [HL]
  ADDW AX, AX
  MOVW [HL], AX
  MOVW AX, [HL+2]
  ROLWC AX, 1
  MOVW [HL+2], AX
  MOVW AX, [HL+4]
  ROLWC AX, 1
  MOVW [HL+4], AX
  MOVW AX, [HL+6]
  ROLWC AX, 1
  MOVW [HL+6], AX
  DECW BC
.L_EXP_INC:
  MOVW AX, BC
  CMPW AX, #1023+2047
  SKC
  BR $.L_EXP_OVER
.L_NORMALIZE:
  SUBW AX, #1023
  BH $.L_ROUNDING
  DECW AX
  MOVW BC, AX
.L_RET_LOOP:
  MOVW AX, [HL+6]
  SHRW AX, 1
  MOVW [HL+6], AX
  MOVW AX, [HL+4]
  RORC A, 1
  XCH A, X
  RORC A, 1
  XCH A, X
  MOVW [HL+4], AX
  MOVW AX, [HL+2]
  RORC A, 1
  XCH A, X
  RORC A, 1
  XCH A, X
  MOVW [HL+2], AX
  MOVW AX, [HL]
  RORC A, 1
  XCH A, X
  RORC A, 1
  XCH A, X
  MOVW [HL], AX
  INC C
  BNZ $.L_RET_LOOP
  CLRW AX
.L_ROUNDING:
  MOVW DE, AX
  POP AX
  MOV A, X
  BR !!__REL_d_round
  
  
.L_EXP_OVER:
  POP AX
  MOV A, X
  MOV1 CY, A.7
  BR !!__REL_d_inf
#endif
.Lfunc_end1:
  .size __COM_dmul, .Lfunc_end1-__COM_dmul

#ifdef __FAR_DATA__
#undef __COM_dmul
  .globl __COM_dmul
  .type  __COM_dmul,@function
__COM_dmul:
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
  call  !!__COM_dmul_nd
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
  .size __COM_dmul, .Lfunc_end2-__COM_dmul
#endif

  .weak ___muldf3
  .type ___muldf3,@function
  .set  ___muldf3, __COM_dmul
  
