//===-- COM_uidiv.s - Implement _COM_uidiv --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_uidiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_uidiv
//
//	unsigned int _COM_uidiv(unsigned int x, unsigned int y);
//
//	input:
//		x = AX
//		y = BC
//	output:
//		AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_uidiv
  
  .text
.L_ZERODIV:
  DECW AX
  RET
__COM_uidiv:
  MOVW DE, AX
  CLRW AX
  CMPW AX, BC
#ifdef __OPTIMIZE_SIZE__
  BZ $.L_ZERODIV
#else
  SKNZ
  BR $.L_ZERODIV
#endif
  $IF(_RL78_S3)
  MOVW AX, BC
  XCHW AX, DE
  DIVHU
  RET
  $ELSEIF(_XMULDIV)
  MOVW AX, DE
  PUSH PSW
  DI
  MOV !LOWW(MDUC), #0x080
  MOVW MDAL, AX
  MOVW AX, BC
  MOVW MDBL, AX
  CLRW AX
  MOVW MDAH, AX
  MOVW MDBH, AX
  MOV !LOWW(MDUC), #0x81
.L1:
  MOV A, !LOWW(MDUC)
  BT A.0, $.L1
  MOVW AX, MDAL
  POP PSW
  RET
  $ELSE
  MOVW AX, DE
  XCHW AX, BC
  MOVW DE, AX
  CLRW AX
  MOV L, #16
.L1:
  SHLW BC, 1
  ROLWC AX, 1
  CMPW AX, DE
  BC $.L2
  SUBW AX, DE
  INC C
.L2:
  DEC L
  BNZ $.L1
  MOVW AX, BC
  RET
  $ENDIF
.Lfunc_end1:
  .size __COM_uidiv, .Lfunc_end1-__COM_uidiv
  
  .weak  ___udivhi3
  .type  ___udivhi3,@function
  .set  ___udivhi3, __COM_uidiv

