//===-- COM_screm.s - Implement _COM_screm --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_screm for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_screm
//
//	char _COM_screm(char x, char y);
//
//	input:
//		x = A
//		y = X
//	output:
//		A
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_screm
  $IFN(_RL78_S3)
  .EXTERN __COM_ucrem
  $ENDIF
  
  .text

__COM_screm:
  CMP0 X
#ifdef __OPTIMIZE_SIZE__
  BZ $.L_END
#else
  SKNZ
  BR $.L_END
#endif
  CLRB C
  BF A.7, $.L1
  INC C
  XOR A, #0x0FF
  INC A
.L1:
  XCH A, X
  BF A.7, $.L2
  XOR A, #0x0FF
  INC A
.L2:
  $IF(_RL78_S3)
  MOV E, A
  CLRB A
  MOV D, A
  DIVHU
  MOV A, E
  $ELSE
  XCH A, X
  CALL !!__COM_ucrem
  $ENDIF
  DEC C
  BNZ $.L_END
  XOR A, #0x0FF
  INC A
.L_END:
  RET
.Lfunc_end1:
  .size __COM_screm, .Lfunc_end1-__COM_screm

