//===-- COM_slrem.s - Implement _COM_slrem --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_slrem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_slrem
//
//	long _COM_slrem(long x, long y);
//
//	input:
//		x = BC-AX
//		y = [SP+4]
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_slrem
  $IFN(_RL78_S3)
  .EXTERN __COM_ulrem
  $ENDIF
  
  .text

.L_ZERODIV:
  POP AX
  MOVW AX, DE
  RET
__COM_slrem:
  MOVW DE, AX
  CLRW AX
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
  MOV A, B
  BF A.7, $.L1
  INC [HL+0]
  CLRW AX
  SUBW AX, DE
  MOVW DE, AX
  SUBC A, A
  MOV X, A
  SUBW AX, BC
  MOVW BC, AX
.L1:
  MOVW AX, [HL+8]
  BF A.7, $.L2
  CLRW AX
  SUBW AX, [HL+6]
  MOVW [HL+6], AX
  SUBC A, A
  MOV X, A
  SUBW AX, [HL+8]
.L2:
  $IF(_RL78_S3)
  MOVW HL, AX
  MOVW AX, [SP+6]
  XCHW AX, DE
  DIVWU
  POP BC
  DEC C
  MOVW AX, HL
  BNZ $.L_END
  CLRW AX
  SUBW AX, DE
  MOVW DE, AX
  SUBC A, A
  MOV X, A
  SUBW AX, HL
.L_END:
  MOVW BC, AX
  MOVW AX, DE
  RET
  $ELSE
  PUSH AX
  MOVW AX, [HL+6]
  PUSH AX
  MOVW AX, DE
  CALL !!__COM_ulrem
  ADDW SP, #4
  POP DE
  DEC E
  BNZ $.L_END
  MOVW DE, AX
  CLRW AX
  SUBW AX, DE
  MOVW DE, AX
  SUBC A, A
  MOV X, A
  SUBW AX, BC
  MOVW BC, AX
  MOVW AX, DE
.L_END:
  RET
  $ENDIF
.Lfunc_end1:
  .size __COM_slrem, .Lfunc_end1-__COM_slrem

  .weak ___modsi3
  .type ___modsi3,@function
  .set  ___modsi3, __COM_slrem

