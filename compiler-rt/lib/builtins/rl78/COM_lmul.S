//===-- COM_lmul.s - Implement _COM_lmul ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_lmul for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_lmul
//
//	long _COM_lmul(long x, long y);
//
//	input:
//		x = BC-AX
//		y = [SP+4]
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_lmul
  
  .text
__COM_lmul:
  $IF(_RL78_S3)
  MOVW HL, AX
  MOVW AX, [SP+4]
  MULHU
  MOVW DE, AX
  MOVW AX, HL
  MOVW BC, AX
  MOVW AX, [SP+6]
  MULHU
  ADDW AX, DE
  XCHW AX, HL
  MOVW BC, AX
  MOVW AX, [SP+4]
  MULHU
  XCHW AX, BC
  ADDW AX, HL
  XCHW AX, BC
  RET
  $ELSE
  $IF(_XMULDIV)
  PUSH PSW
  DI
  CLRB !LOWW(MDUC)
  MOVW MDAL, AX
  MOVW AX, [SP+6+2]
  MOVW MDAH, AX
  NOP
  MOVW DE, !LOWW(MDBL)
  MOVW AX, [SP+4+2]
  MOVW MDAH, AX
  NOP
  MOVW AX, MDBH
  ADDW AX, DE
  MOVW DE, AX
  MOVW AX, MDBL
  XCHW AX, BC
  MOVW MDAL, AX
  NOP
  MOVW AX, MDBL
  POP PSW
  ADDW AX, DE
  XCHW AX, BC
  RET
  $ELSE
  MOVW DE, AX
  MOVW AX, [SP+4]
  MOV A, B
  MULU X
  MOVW HL, AX
  MOVW AX, BC
  MOV A, [SP+5]
  MULU X
  ADDW AX, HL
  MOVW HL, AX
  MOVW AX, [SP+6]
  MOV A, D
  MULU X
  ADDW AX, HL
  MOVW HL, AX
  MOVW AX, DE
  MOV A, [SP+7]
  MULU X
  ADDW AX, HL
  SHLW AX, 8
  MOVW HL, AX
  MOVW AX, [SP+4]
  MOV A, C
  MULU X
  ADDW AX, HL
  MOVW HL, AX
  MOV A, D
  MOV X, A
  MOV A, [SP+5]
  MULU X
  ADDW AX, HL
  MOVW HL, AX
  MOVW AX, [SP+6]
  MOV A, E
  MULU X
  ADDW AX, HL
  MOVW BC, AX
  MOVW AX, [SP+4]
  MOV A, D
  MULU X
  MOVW HL, AX
  MOVW AX, DE
  MOV A, [SP+5]
  MULU X
  ADDW AX, HL
  MOVW HL, AX
  SKNC
  INC B
  SHRW AX, 8
  ADDW AX, BC
  MOVW BC, AX
  MOVW AX, [SP+4]
  MOV A, E
  MULU X
  ADD A, L
  SKNC
  INCW BC
  RET
  $ENDIF
  $ENDIF
.Lfunc_end1:
  .size __COM_lmul, .Lfunc_end1-__COM_lmul

.weak ___mulsi3
.type ___mulsi3,@function
.set  ___mulsi3, __COM_lmul

