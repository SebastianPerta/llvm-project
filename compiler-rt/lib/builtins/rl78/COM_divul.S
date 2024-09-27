//===-- COM_divul.s - Implement _COM_divul --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_divul for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_divul
//
//	unsigned long _COM_divul(unsigned long x, unsigned int y);
//
//	input:
//		x = BC-AX
//		y = DE
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_divul
  
  .text
#ifdef __OPTIMIZE_SIZE__
__COM_divul:
  xchw  ax,de
  cmpw  ax,#0
  xchw  ax,de
  bnz $1f
  clrw  ax
  decw  ax
  movw  bc,ax
  ret
1:
#ifdef __RL78_S3__
  movw  hl,#0
  divwu
;
  ret
#else
#ifdef __MDA_ENABLED__
  push  psw
  di
  mov !LOWW(MDUC),#0x080 ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDA <- x
  movw  ax,bc   ;
  movw  MDAH,ax   ;
  movw  ax,de   ; MDB <- y
  movw  MDBL,ax   ;
  clrw  ax    ;
  movw  MDBH,ax   ;
;
  mov !LOWW(MDUC),#0x081 ; divmode  = 1, divst = 1
2:
  mov a,!LOWW(MDUC)    ; if (divst == 1) then wait
  bt  a.0,$2b
;
  movw  bc,!LOWW(MDAH) ; ret <- MDA
  movw  ax,MDAL   ;
  pop psw
  ret
#else
  push  de    ; y
  push  bc    ; x_h
  push  ax    ; x_l
  movw  hl,sp
;
  clrw  bc    ; rem = 0
  mov e,#32   ; count = 32
2:        ; do_until
  movw  ax,[hl]   ; x <<= 1 (ret <<= 1) 
  addw  ax,ax   ;
  movw  [hl],ax   ;
  movw  ax,[hl+2] ;
  rolwc ax,1    ;
  movw  [hl+2],ax ;
  rolwc bc,1    ; rem = (rem << 1) | cy
  movw  ax,bc   ; if (rem >= y) then
  subw  ax,[hl+4] ;
  bc  $3f   ;
  movw  bc,ax   ; rem = rem - y
  incw  [hl+0]    ; ++ret
3:
  dec e   ; --count
  bnz $2b   ; until (count = 0)
  pop ax    ; ret
  pop bc    ;
  pop de    ; y
  ret
#endif
#endif
#else
.L_ZERODIV:
  MOVW AX, #0xFFFF
  MOVW BC, AX
  RET
  
__COM_divul:
  XCHW AX, DE
  CMPW AX, #0
  XCHW AX, DE
  SKNZ
  BR $.L_ZERODIV
  
  $IF(_RL78_S3)
  MOVW HL, #0
  DIVWU
  RET
  $ELSE
  $IF(_XMULDIV)
  PUSH PSW
  DI
  MOV !LOWW(MDUC), #0x080
  MOVW MDAL, AX
  MOVW AX, BC
  MOVW MDAH, AX
  MOVW AX, DE
  MOVW MDBL, AX
  CLRW AX
  MOVW MDBH, AX
  MOV !LOWW(MDUC), #0x081
.L2:
  MOV A, !LOWW(MDUC)
  BT A.0, $.L2
  MOVW BC, !LOWW(MDAH)
  MOVW AX, MDAL
  POP PSW
  RET
  $ELSE
  PUSH DE
  PUSH BC
  PUSH AX
  MOVW HL, SP
  CLRW BC
  MOV E, #32
.L2:
  MOVW AX, [HL]
  ADDW AX, AX
  MOVW [HL], AX
  MOVW AX, [HL+2]
  ROLWC AX, 1
  MOVW [HL+2], AX
  ROLWC BC, 1
  MOVW AX, BC
  SUBW AX, [HL+4]
  BC $.L3
  MOVW BC, AX
  INCW [HL+0]
.L3:
  DEC E
  BNZ $.L2
  POP AX
  POP BC
  POP DE
  RET
  $ENDIF
  $ENDIF
#endif
.Lfunc_end1:
  .size __COM_divul, .Lfunc_end1-__COM_divul

