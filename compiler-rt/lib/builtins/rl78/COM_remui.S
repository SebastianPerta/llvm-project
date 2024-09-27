//===-- COM_remui.s - Implement _COM_remui --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_remui for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_remui
//
//	unsigned char _COM_remui(unsigned int x, unsigned char y);
//
//	input:
//		x = AX
//		y = C
//	output:
//		A
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_remui
  
  .text

#ifndef __OPTIMIZE_SIZE__
.L_ZERODIV:
  MOV A, X
  RET
#endif
  
__COM_remui:
  CMP0 C
#ifdef __OPTIMIZE_SIZE__
  BNZ $.L1
  MOV A,X
  RET
#else
  SKNZ
  BR $.L_ZERODIV
#endif
.L1:
  $IF(_RL78_S3)
  MOVW DE, AX
  MOVW AX, BC
  CLRB A
  XCHW AX, DE
  DIVHU
  MOV A, E
  RET
  $ELSE
  $IF(_XMULDIV)
  PUSH PSW
  DI
  MOV !LOWW(MDUC), #0x080
  MOVW MDAL, AX
  MOVW AX, BC
  CLRB A
  MOVW MDBL, AX
  CLRW AX
  MOVW MDAH, AX
  MOVW MDBH, AX
  MOV !LOWW(MDUC), #0x81
.L2:
  MOV A, !LOWW(MDUC)
  BT A.0, $.L2
  MOVW AX, !LOWW(MDCL)
  POP PSW
  MOV A, X
  RET
  $ELSE
  CLRB B
  XCHW AX, BC
  MOVW DE, AX
  CLRW AX
  MOV L, #16
.L2:
  SHLW BC, 1
  ROLWC AX, 1
  CMPW AX, DE
  BC $.L3
  SUBW AX, DE
  INC C
.L3:
  DEC L
  BNZ $.L2
  MOV A, X
  RET
  $ENDIF
  $ENDIF
.Lfunc_end1:
  .size __COM_remui, .Lfunc_end1-__COM_remui
