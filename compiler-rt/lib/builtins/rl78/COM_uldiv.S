//===-- COM_uldiv.s - Implement _COM_uldiv --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_uldiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_uldiv
//
//	unsigned long _COM_uldiv(unsigned long x, unsigned long y);
//
//	input:
//		x = BC-AX
//		y = [SP+4]
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_uldiv
  
  .text
.L_ZERODIV:
  POP AX
  CLRW AX
  DECW AX
  MOVW BC, AX
  RET
__COM_uldiv:
  PUSH AX
  MOVW HL, SP
  MOVW AX, [SP+6]
  OR A, X
  OR A, [HL+8]
  OR A, [HL+9]
#ifdef __OPTIMIZE_SIZE__
  BZ	$.L_ZERODIV
#else
  SKNZ
  BR $.L_ZERODIV
#endif
  $IF(_RL78_S3)
  MOVW AX, [HL+6]
  MOVW DE, AX
  MOVW AX, [HL+8]
  MOVW HL, AX
  POP AX
  DIVWU
  RET
  $ELSEIF(_XMULDIV)
  POP AX
  PUSH PSW
  DI
  MOV !LOWW(MDUC), #0x080
  MOVW MDAL, AX
  MOVW AX, BC
  MOVW MDAH, AX
  MOVW AX, [HL+6]
  MOVW MDBL, AX
  MOVW AX, [HL+8]
  MOVW MDBH, AX
  MOV !LOWW(MDUC), #0x081
.L1:
  MOV A, !LOWW(MDUC)
  BT A.0, $.L1
  MOVW BC, !LOWW(MDAH)
  MOVW AX, MDAL
  POP PSW
  RET
  $ELSE
  MOV X, #32
  PUSH AX
  PUSH BC
  MOVW HL, SP
  CLRW AX
  MOVW BC, AX
  MOVW DE, AX
.L1:
  MOVW AX, [HL+4]
  ADDW AX, AX
  MOVW [HL+4], AX
  MOVW AX, [HL]
  ROLWC AX, 1
  MOVW [HL], AX
  MOVW AX, DE
  ROLWC AX, 1
  ROLWC BC, 1
  XCHW AX, BC
  CMPW AX, [HL+12]
  XCHW AX, BC
  BC $.L3
  BNZ $.L2
  CMPW AX, [HL+10]
  BC $.L3
.L2:
  XCHW AX, BC
  SUBW AX, [HL+12]
  XCHW AX, BC
  SUBW AX, [HL+10]
  SKNC
  DECW BC
  INCW [HL+4]
.L3:
  MOVW DE, AX
  DEC [HL+2]
  BNZ $.L1
  POP BC
  POP AX
  POP AX
  RET
  $ENDIF
.Lfunc_end1:
  .size __COM_uldiv, .Lfunc_end1-__COM_uldiv

  .weak ___udivsi3
  .type ___udivsi3,@function
  .set  ___udivsi3, __COM_uldiv

