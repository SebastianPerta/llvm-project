//===-- COM_dadd.s - Implement _COM_dadd ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_dadd for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_dadd
//
//	double _COM_dadd(double x, double y);
//
//	input:
//		x = [SP+4]
//		y = [SP+12]
//	output:
//		[AX] ([A:DE] for far data)
//===----------------------------------------------------------------------===//
  #include "def.S"

#ifdef __FAR_DATA__
#define __COM_llshr __COM_llshr_nd
#define __COM_dadd  __COM_dadd_nd
#endif

  .PUBLIC __COM_dadd
  .EXTERN __COM_llshr
  .EXTERN __REL_d_check
  .EXTERN __REL_d_shl11
  .EXTERN __REL_d_inf
  .EXTERN __REL_d_round
  
  .text
#ifdef __OPTIMIZE_SIZE__
0:
  pop ax    ; flag (stack adjustment)
  clrw  ax    ; ret = 0xffffffff (nan)
  decw  ax
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  ret
;
1:
  pop ax    ; flag (stack adjustment)
  movw  ax,[hl+14]  ; returns y
  movw  [de],ax
  movw  ax,[hl+16]
  movw  [de+2],ax
  movw  ax,[hl+18]
  movw  [de+4],ax
  movw  ax,[hl+20]
  movw  [de+6],ax
  ret
;
2:
  pop ax    ; flag (stack adjustment)
  movw  ax,[hl+6] ; returns x
  movw  [de],ax
  movw  ax,[hl+8]
  movw  [de+2],ax
  movw  ax,[hl+10]
  movw  [de+4],ax
  movw  ax,[hl+12]
  movw  [de+6],ax
  ret
;
3:
  bf  [hl].3,$0b  ; x is nan
  bf  [hl].5,$2b  ; if y is not infinity or nan, the return value is x (infinity)
4:
  bf  [hl].7,$0b  ; y is nan
  bf  [hl].1,$1b  ; if x is not infinity or nan, the return value is y (infinity)
  mov1  cy,[hl].0 ; if both x and y are infinity and have different signs, the return value is nan
  xor1  cy,[hl].4
  bc  $0b
  br  $2b ; returns x (infinity) if the signs are the same
;
5:
  mov1  cy,[hl].6 ; returns y if y is not 0
  and1  cy,[hl].7
  bnc $1b
  mov1  cy,[hl].0 ; if both x and y are 0, return + 0 if the signs are different
  xor1  cy,[hl].4
  bnc $1b
6:
  pop ax    ; flag
  clrw  ax    ; ret = 0x00000000
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  ret
;

  ; this is the entrance to the function
  .globl __COM_dadd
  .type  __COM_dadd,@function
__COM_dadd:
  ; [special return value]
  ; (1) if x or y is nan, nan is the return value
  ; (2) if x or y is infinity, infinity is the return value and the sign is inherited
  ;     however, if x and y are both infinity and the signs are different, nan is used as the return value
  ; (3) if x or y is 0, the other is the return value
  ;     however, if x and y are both 0 and the signs are different, + 0 is used as the return value

  ; check if the sign of x, y and the magnitude part are 0 or 0x7ff
  ; let the stack [hl] be the flag for determining the special solution
  ; the contents of the flag are as follows
  ;   [hl].0 = 0 if x is positive,[hl].0 = 1 if x is negative
  ;   [hl].1 = 1 and [hl].3 = 1 if x is infinity
  ;   [hl].1 = 1 and [hl].3 = 0 if x is nan
  ;   [hl].2 = 1 and [hl].3 = 1 if x is 0
  ;   [hl].2 = 1 and [hl].3 = 0 if x is a subnormal number
  ;   [hl].4 = 0 if y is positive,[hl].4 = 1 if y is negative
  ;   [hl].5 = 1 and [hl].7 = 1 if y is infinity
  ;   [hl].5 = 1 and [hl].7 = 0 if y is nan
  ;   [hl].6 = 1 and [hl].7 = 1 if y is 0
  ;   [hl].6 = 1 and [hl].7 = 0 if y is a subnormal number
  movw  de,ax   ; return address
  push  ax    ; flag
  movw  hl,sp
  call  !!__REL_d_check ; flag setting

  ; if x is nan or infinity
  bt  [hl].1,$3b
  ; if y is nan or infinity
  bt  [hl].5,$4b
  ; if x is 0
  mov1  cy,[hl].2
  and1  cy,[hl].3
  bc  $5b
  ; if y is 0
  mov1  cy,[hl].6
  and1  cy,[hl].7
  bc  $2b
  ; this is the end of special solution processing

  ; x ... sign [hl].0, exponent part b, mantissa part c-de
  ; y ... sign [hl].4, exponential part [sp+7], mantissa part [sp+6] ~ [sp+4]
  ; from here, change the meaning of flag as follows
  ;   [hl].0 = 0 if x is positive, [hl].0 = 1 if x is negative (continue)
  ;   [hl].1 = 0 if add (same sign), [hl].1 = 1 if subtraction (sign is different)
  ;   [hl].2 = 1 if x is a subnormal number (if 0, it has been processed)
  ;   [hl].4 = 0 if y is positive, [hl].4 = 1 if y is negative (continue)
  ;   [hl].5 = 0 if operate based on x, [hl].5 = 1 if calculate based on y
  ;   [hl].6 = 1 if y is a subnormal number (if 0, it has been processed)
  ;   [hl].7 = 0 if the sign of the return value is positive, [hl].7 = 1 if the sign of the return value is negative
  mov a,[hl]
  and a,#0x055    ; clear [hl].1, [hl].3, [hl].5, [hl].7
  mov1  cy,a.0    ; add if the signs of x and y are the same, subtract if they are different
  xor1  cy,a.4    ;
  mov1  a.1,cy    ;
  mov [hl],a
;
  movw  ax,[hl+20]  ; to find out which mantissa is used as the reference
  addw  ax,ax   ; compare absolute values
  movw  bc,ax   ; compare with | x | - | y |
  movw  ax,[hl+12]
  addw  ax,ax
  cmpw  ax,bc
  bnz $7f
  movw  ax,[hl+10]
  cmpw  ax,[hl+18]
  bnz $7f
  movw  ax,[hl+8]
  cmpw  ax,[hl+16]
  bnz $7f
  movw  ax,[hl+6]
  cmpw  ax,[hl+14]
7:
  bnz $10f  ; if x = y, another process
  ; processing when x == y
  ; for addition, add 1 to the exponent part of x and finish (overflow check required)
  ; Returns + 0 for subtraction
  bt  [hl].1,$6b ; if the sign is different
  ; if the sign is the same, double (exponent part is 1)
  bt  [hl].2,$9f
  movw  ax,bc   ; the most significant 2 bytes of y shifted to the left by 1 bit
  addw  ax,#0x020 ; exponent part + 1
  bnc $8f
  ; overflow
  mov1  cy,[hl].0 ; sign of x
  pop ax    ; flag
  br  !!__REL_d_inf ; set infinity of double type to [de]
8:
  shrw  ax,1
  mov1  cy,[hl].0 ; sign of x
  mov1  a.7,cy
  movw  [de+6],ax
  movw  ax,[hl+10]
  movw  [de+4],ax
  movw  ax,[hl+8]
  movw  [de+2],ax
  movw  ax,[hl+6]
  movw  [de],ax
  pop ax    ; flag
  ret
9:
  ; double the mantissa for subnormalized numbers
  ; if the most significant bit of the mantissa is set, set the exponent to 1
  ; (the most significant bit of the mantissa moves to the least
  ; significant bit of the exponent part as it is)
  movw  ax,[hl+6]
  addw  ax,ax
  movw  [de],ax
  movw  ax,[hl+8]
  rolwc ax,1
  movw  [de+2],ax
  movw  ax,[hl+10]
  rolwc ax,1
  movw  [de+4],ax
  movw  ax,[hl+12]
  rolwc ax,1
  mov1  a.7,cy    ; sign
  movw  [de+6],ax
  pop ax    ; flag
  ret
10:
  ; processing when x != y
  bc  $11f
  mov1  cy,[hl].0 ; set the sign of x to the sign of the return value
  br  $12f
11:
  set1  [hl].5    ; calculated based on y
  mov1  cy,[hl].4 ; set the sign of y to the sign of the return value
12:
  mov1  [hl].7,cy ; set the sign of the return value
  push  de    ; return address
  movw  ax,bc   ; upper 2 bytes of y (1 bit shifted to the left)
  shrw  ax,5    ; exponent part of y
  movw  bc,ax   ;
  movw  ax,[hl+12]  ; upper 2 bytes of x
  addw  ax,ax   ; exponent part of x
  shrw  ax,5    ;
  mov1  cy,[hl].5
  sknc
  xchw  ax,bc   ; larger exponent part -> ax, smaller exponential part -> bc
  push  ax    ; exponent part of return value
  subw  ax,bc   ; find the difference in the exponential part (carry does not occur)
13:
  cmpw  ax,#54    ; when the width exceeds the width of (miser expression + mantissa 52bit + rounding)
  bc  $14f
  ; if the difference in the exponential part is too large, treat it as addition or subtraction with 0
  ; returns the value with the larger exponent part as it is
  movw  ax,hl
  addw  ax,#6   ; hl <- hl + 6 (address of x)
  mov1  cy,[hl].5 ; cy = 1 if the standard of operation is y
  sknc
  addw  ax,#8   ; hl <- hl + 6 + 8 (y address)
  movw  hl,ax
;
  addw  sp,#6   ; return address, exponent, flag
  movw  ax,[hl]   ; set to return value
  movw  [de],ax
  movw  ax,[hl+2]
  movw  [de+2],ax
  movw  ax,[hl+4]
  movw  [de+4],ax
  movw  ax,[hl+6]
  movw  [de+6],ax
  ret
14:
  ; [sp+4]... flag, [sp+2]... return address, [sp+0]... return exponent part
  push  ax    ; exponent difference
  ; x: [hl+6] and y: [hl+14] clear the sign and exponent part and leave only the mantissa part
  ; add a stingy expression to the upper part of the mantissa
  ; (0 for non-normalized numbers) and left justify
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
  pop bc    ; exponent difference
;
  ; the mantissa with the smaller absolute value is shifted to the right by the difference in the exponent
  ; use _COM_llshr for right shift
  mov1  cy,[hl].2 ; if both x and y are subnormal mantissa, shift number -1 is
  and1  cy,[hl].6 ; correct because it is not necessary
  sknc
  inc c   ; correction of the number of shifts
  bt  [hl].5,$15f
  ; shift the mantissa part of y to the right to calculate based on x
  mov1  cy,[hl].6 ; y is the subnormal mantissa if shift count - 1
  sknc      ;
  dec c   ;
  movw  ax,hl   ; save the pointer used for addition and subtraction after shifting
  addw  ax,#14    ; address of shift target (y)
  movw  de,ax
  push  de
  subw  ax,#8   ; address not subject to shift (x)
  push  ax
  push  hl    ; register save to call function _COM_llshr
  movw  ax,[hl+20]  ; mantissa of y
  push  ax
  movw  ax,[hl+18]
  push  ax
  movw  ax,[hl+16]
  push  ax
  movw  ax,[hl+14]
  push  ax
  movw  ax,de
  call  !!__COM_llshr ; right shift
  br  $16f
15:
  ; shift the mantissa part of x to the right to calculate based on y
  mov1  cy,[hl].2 ; x is the subnormal mantissa if shift count - 1
  sknc      ;
  dec c   ;
  movw  ax,hl   ; save the pointer used for addition and subtraction after shifting
  addw  ax,#6   ; address of shift target (x)
  movw  de,ax
  push  de
  addw  ax,#8   ; address not subject to shift (y)
  push  ax
  push  hl    ; register save to call function _COM_llshr
  movw  ax,[hl+12]  ; mantissa part of x
  push  ax
  movw  ax,[hl+10]
  push  ax
  movw  ax,[hl+8]
  push  ax
  movw  ax,[hl+6]
  push  ax
  movw  ax,de
  call  !!__COM_llshr ; right shift
16:
  addw  sp,#8
  pop hl
  pop bc    ; large data address
  pop de    ; small data address
  movw  ax,[sp+2] ; return address
  xchw  ax,de
  ; [sp+4]... flag, [sp+2] / de... return address, [sp+0]... return exponent part
  ; hl = sp + 4 [hl]... flag, [hl+6]... x, [hl+14]... y
  ;bc... large data address, ax... small data address
  bt  [hl].1,$18f  ; subtraction
  ; addition
  ; [de] = x + y
  movw  ax,[hl+6]
  addw  ax,[hl+14]
  movw  [de],ax
  movw  ax,[hl+8]
  xch a,x
  addc  a,[hl+16]
  xch a,x
  addc  a,[hl+17]
  movw  [de+2],ax
  movw  ax,[hl+10]
  xch a,x
  addc  a,[hl+18]
  xch a,x
  addc  a,[hl+19]
  movw  [de+4],ax
  movw  ax,[hl+12]
  xch a,x
  addc  a,[hl+20]
  xch a,x
  addc  a,[hl+21]
  movw  [de+6],ax
  pop de    ; exponent part
  pop hl    ; return address
  bnc $17f
  ; 1-bit right shift and exponent part + 1
  ; no need to transfer from cy because the most significant bit is not used
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
  incw  de    ; exponent part addition
  movw  ax,#0x07ff  ; overflow check
  cmpw  ax,de   ; 
  bnz $20f
  ; overflow handling
  movw  ax,hl
  movw  de,ax
  pop ax    ; flag
  mov a,x
  mov1  cy,a.7    ; return sign
  br  !!__REL_d_inf ; set infinity of double type to [de]
17:
  ; if the result of operation between subnormal numbers
  ; is a normalized number, set the exponent part to 1
  mov b,a   ; mantissa top
  clrw  ax
  cmpw  ax,de   ; is the exponent part 0?
  bnz $20f
  mov a,b
  bf  a.7,$20f
  incw  de    ; exponent part = 1
  br  $20f
18:
  ; subtraction
  ; [de] = [bc]-[ax]
  movw  hl,ax
  movw  ax,0[bc]
  subw  ax,[hl+0]
  movw  [de],ax
  movw  ax,2[bc]
  xch a,x
  subc  a,[hl+2]
  xch a,x
  subc  a,[hl+3]
  movw  [de+2],ax
  movw  ax,4[bc]
  xch a,x
  subc  a,[hl+4]
  xch a,x
  subc  a,[hl+5]
  movw  [de+4],ax
  movw  ax,6[bc]
  xch a,x
  subc  a,[hl+6]
  xch a,x
  subc  a,[hl+7]
  movw  [de+6],ax
  pop de    ; exponent part
  pop hl    ; return address
  clrw  ax
  cmpw  ax,de
  bz  $20f  ; do not shift for subnormal numbers
  movw  ax,[hl+6] ; mantissa top
19:
  bt  a.7,$20f
  decw  de    ; exponent part
  clrw  ax
  cmpw  ax,de
  bz  $20f  ; do not shift when it becomes a subnormal number
  ; shift the mantissa part 1 bit to the left
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
  br  $19b
20:
  pop ax    ; flag
  mov a,x   ;
  ; match the format of ieee754
  br  !!__REL_d_round ; after rolling to fit the format of ieee754
#else
.L_NAN:
  POP AX
  CLRW AX
  DECW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  MOVW [DE+6], AX
  RET
.L_RET_Y:
  POP AX
  MOVW AX, [HL+14]
  MOVW [DE], AX
  MOVW AX, [HL+16]
  MOVW [DE+2], AX
  MOVW AX, [HL+18]
  MOVW [DE+4], AX
  MOVW AX, [HL+20]
  MOVW [DE+6], AX
  RET
.L_RET_X:
  POP AX
  MOVW AX, [HL+6]
  MOVW [DE], AX
  MOVW AX, [HL+8]
  MOVW [DE+2], AX
  MOVW AX, [HL+10]
  MOVW [DE+4], AX
  MOVW AX, [HL+12]
  MOVW [DE+6], AX
  RET
.L_X_NAN_INF:
  BF [HL].3, $.L_NAN
  BF [HL].5, $.L_RET_X
.L_Y_NAN_INF:
  BF [HL].7, $.L_NAN
  BF [HL].1, $.L_RET_Y
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  BC $.L_NAN
  BR $.L_RET_X
.L_X_ZERO:
  MOV1 CY, [HL].6
  AND1 CY, [HL].7
  BNC $.L_RET_Y
  MOV1 CY, [HL].0
  XOR1 CY, [HL].4
  BNC $.L_RET_Y
.L_ZERO:
  POP AX
  CLRW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  MOVW [DE+6], AX
  RET
  
.L_XEQY:
  BT [HL].1, $.L_ZERO
  BT [HL].2, $.L_2X_DENORMAL
  MOVW AX, BC
  ADDW AX, #0x020
  BNC $.L_2X
  MOV1 CY, [HL].0
  POP AX
  BR !!__REL_d_inf
.L_2X:
  SHRW AX, 1
  MOV1 CY, [HL].0
  MOV1 A.7, CY
  MOVW [DE+6], AX
  MOVW AX, [HL+10]
  MOVW [DE+4], AX
  MOVW AX, [HL+8]
  MOVW [DE+2], AX
  MOVW AX, [HL+6]
  MOVW [DE], AX
  POP AX
  RET
.L_2X_DENORMAL:
  MOVW AX, [HL+6]
  ADDW AX, AX
  MOVW [DE], AX
  MOVW AX, [HL+8]
  ROLWC AX, 1
  MOVW [DE+2], AX
  MOVW AX, [HL+10]
  ROLWC AX, 1
  MOVW [DE+4], AX
  MOVW AX, [HL+12]
  ROLWC AX, 1
  MOV1 A.7, CY
  MOVW [DE+6], AX
  POP AX
  RET
  
.L_OVER54:
  MOVW AX, HL
  ADDW AX, #6
  MOV1 CY, [HL].5
  SKNC
  ADDW AX, #8
  MOVW HL, AX
  ADDW SP, #6
  MOVW AX, [HL]
  MOVW [DE], AX
  MOVW AX, [HL+2]
  MOVW [DE+2], AX
  MOVW AX, [HL+4]
  MOVW [DE+4], AX
  MOVW AX, [HL+6]
  MOVW [DE+6], AX
  RET
  
  
__COM_dadd:
  
  MOVW DE, AX
  PUSH AX
  MOVW HL, SP
  CALL !!__REL_d_check
  
  MOV1 CY, [HL].1
  SKNC
  BR !!.L_X_NAN_INF
  MOV1 CY, [HL].5
  SKNC
  BR !!.L_Y_NAN_INF
  MOV1 CY, [HL].2
  AND1 CY, [HL].3
  SKNC
  BR !!.L_X_ZERO
  MOV1 CY, [HL].6
  AND1 CY, [HL].7
  SKNC
  BR !!.L_RET_X
  
  
  MOV A, [HL]
  AND A, #0x055
  MOV1 CY, A.0
  XOR1 CY, A.4
  MOV1 A.1, CY
  MOV [HL], A
  MOVW AX, [HL+20]
  ADDW AX, AX
  MOVW BC, AX
  MOVW AX, [HL+12]
  ADDW AX, AX
  CMPW AX, BC
  SKZ
  BR $.L_X_NE_Y
  MOVW AX, [HL+10]
  CMPW AX, [HL+18]
  SKZ
  BR $.L_X_NE_Y
  MOVW AX, [HL+8]
  CMPW AX, [HL+16]
  SKZ
  BR $.L_X_NE_Y
  MOVW AX, [HL+6]
  CMPW AX, [HL+14]
.L_XY_CMP:
  SKNZ
  BR !!.L_XEQY
  
.L_X_NE_Y:
  BC $.L_SET_Y_FLAG
  MOV1 CY, [HL].0
  BR $.L3
.L_SET_Y_FLAG:
  SET1 [HL].5
  MOV1 CY, [HL].4
.L3:
  MOV1 [HL].7, CY
  PUSH DE
  MOVW AX, BC
  SHRW AX, 5
  MOVW BC, AX
  MOVW AX, [HL+12]
  ADDW AX, AX
  SHRW AX, 5
  MOV1 CY, [HL].5
  SKNC
  XCHW AX, BC
  PUSH AX
  SUBW AX, BC
.L4:
  CMPW AX, #54
  SKC
  BR !!.L_OVER54
  
.L5:
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
  MOV1 CY, [HL].2
  AND1 CY, [HL].6
  SKNC
  INC C
  BT [HL].5, $.L_X_SHIFT
  MOV1 CY, [HL].6
  SKNC
  DEC C
  MOVW AX, HL
  ADDW AX, #14
  MOVW DE, AX
  PUSH DE
  SUBW AX, #8
  PUSH AX
  PUSH HL
  MOVW AX, [HL+20]
  PUSH AX
  MOVW AX, [HL+18]
  PUSH AX
  MOVW AX, [HL+16]
  PUSH AX
  MOVW AX, [HL+14]
  PUSH AX
  MOVW AX, DE
  CALL !!__COM_llshr
  BR $.L_ADDSUB
.L_X_SHIFT:
  MOV1 CY, [HL].2
  SKNC
  DEC C
  MOVW AX, HL
  ADDW AX, #6
  MOVW DE, AX
  PUSH DE
  ADDW AX, #8
  PUSH AX
  PUSH HL
  MOVW AX, [HL+12]
  PUSH AX
  MOVW AX, [HL+10]
  PUSH AX
  MOVW AX, [HL+8]
  PUSH AX
  MOVW AX, [HL+6]
  PUSH AX
  MOVW AX, DE
  CALL !!__COM_llshr
.L_ADDSUB:
  ADDW SP, #8
  POP HL
  POP BC
  POP DE
  MOVW AX, [SP+2]
  XCHW AX, DE
  BT [HL].1, $.L_SUB
  MOVW AX, [HL+6]
  ADDW AX, [HL+14]
  MOVW [DE], AX
  MOVW AX, [HL+8]
  XCH A, X
  ADDC A, [HL+16]
  XCH A, X
  ADDC A, [HL+17]
  MOVW [DE+2], AX
  MOVW AX, [HL+10]
  XCH A, X
  ADDC A, [HL+18]
  XCH A, X
  ADDC A, [HL+19]
  MOVW [DE+4], AX
  MOVW AX, [HL+12]
  XCH A, X
  ADDC A, [HL+20]
  XCH A, X
  ADDC A, [HL+21]
  MOVW [DE+6], AX
  POP DE
  POP HL
  BNC $.L_ADD_AFTER
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
  INCW DE
  MOVW AX, #0x07FF
  CMPW AX, DE
  BNZ $.L_ROUNDING
  MOVW AX, HL
  MOVW DE, AX
  POP AX
  MOV A, X
  MOV1 CY, A.7
  BR !!__REL_d_inf
.L_ADD_AFTER:
  MOV B, A
  CLRW AX
  CMPW AX, DE
  BNZ $.L_ROUNDING
  MOV A, B
  BF A.7, $.L_ROUNDING
  INCW DE
  BR $.L_ROUNDING
.L_SUB:
  MOVW HL, AX
  MOVW AX, 0[BC]
  SUBW AX, [HL+0]
  MOVW [DE], AX
  MOVW AX, 2[BC]
  XCH A, X
  SUBC A, [HL+2]
  XCH A, X
  SUBC A, [HL+3]
  MOVW [DE+2], AX
  MOVW AX, 4[BC]
  XCH A, X
  SUBC A, [HL+4]
  XCH A, X
  SUBC A, [HL+5]
  MOVW [DE+4], AX
  MOVW AX, 6[BC]
  XCH A, X
  SUBC A, [HL+6]
  XCH A, X
  SUBC A, [HL+7]
  MOVW [DE+6], AX
  POP DE
  POP HL
  CLRW AX
  CMPW AX, DE
  BZ $.L_ROUNDING
  MOVW AX, [HL+6]
.L_SUB_LOOP:
  BT A.7, $.L_ROUNDING
  DECW DE
  CLRW AX
  CMPW AX, DE
  BZ $.L_ROUNDING
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
  BR $.L_SUB_LOOP
.L_ROUNDING:
  POP AX
  MOV A, X
  BR !!__REL_d_round
#endif
.Lfunc_end1:
  .size __COM_dadd, .Lfunc_end1-__COM_dadd

#ifdef __FAR_DATA__
#undef __COM_dadd
  .globl __COM_dadd
  .type  __COM_dadd,@function
__COM_dadd:
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
  call  !!__COM_dadd_nd
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
  .size __COM_dadd, .Lfunc_end2-__COM_dadd
#endif

  .weak ___adddf3
  .type ___adddf3,@function
  .set  ___adddf3, __COM_dadd
