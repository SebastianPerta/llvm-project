//===-- COM_mulul.s - Implement _COM_mulul --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_mulul for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_mulul
//
//	unsigned long long _COM_mulul(unsigned long x, unsigned long y);
//	input:
//		x = DE-BC
//		y = [SP+4]
//
//	output:
//		[AX]
//
//===----------------------------------------------------------------------===//
  
  #include "def.S"
  
  .PUBLIC __COM_mulul
  .EXTERN __COM_mului
  
  .text
__COM_mulul:
  $IF(_RL78_S3)
  PUSH BC
  MOVW HL, AX
  $ELSE
  PUSH DE
  PUSH BC
  PUSH AX
  $ENDIF
  
  $IF(_RL78_S3)
  MOVW AX, [SP+6]
  MULHU
  $ELSE
  MOVW AX, [SP+10]
  CALL !!__COM_mului
  POP HL
  $ENDIF
  MOVW [HL], AX
  MOVW AX, BC
  MOVW [HL+2], AX
  $IF(_RL78_S3)
  MOVW AX, DE
  MOVW BC, AX
  MOVW AX, [SP+6]
  MULHU
  $ELSE
  PUSH HL
  MOVW AX, [SP+4]
  MOVW BC, AX
  MOVW AX, [SP+10]
  CALL !!__COM_mului
  POP HL
  $ENDIF
  ADDW AX, [HL+2]
  MOVW [HL+2], AX
  SKNC
  INCW BC
  MOVW AX, BC
  MOVW [HL+4], AX
  $IF(_RL78_S3)
  MOVW AX, [SP+0]
  MOVW BC, AX
  MOVW AX, [SP+8]
  MULHU
  $ELSE
  PUSH HL
  MOVW AX, [SP+2]
  MOVW BC, AX
  MOVW AX, [SP+12]
  CALL !!__COM_mului
  POP HL
  $ENDIF
  ADDW AX, [HL+2]
  MOVW [HL+2], AX
  SKNC
  INCW BC
  MOVW AX, [HL+4]
  ADDW AX, BC
  MOVW [HL+4], AX
  CLRW AX
  ROLWC AX, 1
  MOVW [HL+6], AX
  $IF(_RL78_S3)
  MOVW AX, DE
  MOVW BC, AX
  MOVW AX, [SP+8]
  MULHU
  $ELSE
  PUSH HL
  MOVW AX, [SP+4]
  MOVW BC, AX
  MOVW AX, [SP+12]
  CALL !!__COM_mului
  POP HL
  $ENDIF
  ADDW AX, [HL+4]
  MOVW [HL+4], AX
  SKNC
  INCW BC
  MOVW AX, BC
  ADDW AX, [HL+6]
  MOVW [HL+6], AX
  
  $IF(_RL78_S3)
  ADDW SP, #2
  $ELSE
  ADDW SP, #4
  $ENDIF
  RET
.Lfunc_end1:
  .size __COM_mulul, .Lfunc_end1-__COM_mulul  
