//===-- COM_ulrem.s - Implement _COM_ulrem --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_ulrem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_ulrem
//
//	unsigned long _COM_ulrem(unsigned long x, unsigned long y);
//
//	input:
//		x = BC-AX
//		y = [SP+4]
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_ulrem
  
  .text
.L_ZERODIV:
  POP AX
  RET
__COM_ulrem:
  PUSH AX
  MOVW HL, SP
  MOVW AX, [SP+6]
  OR A, X
  OR A, [HL+8]
  OR A, [HL+9]
#ifdef __OPTIMIZE_SIZE__
  BZ $.L_ZERODIV
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
  MOVW AX, HL
  MOVW BC, AX
  MOVW AX, DE
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
  MOVW BC, !LOWW(MDCH)
  MOVW AX, !LOWW(MDCL)
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
  ADDW SP, #6
  RET
  $ENDIF
.Lfunc_end1:
  .size __COM_ulrem, .Lfunc_end1-__COM_ulrem

  .weak ___umodsi3
  .type ___umodsi3,@function
  .set  ___umodsi3, __COM_ulrem

