//===-- COM_ucrem.s - Implement _COM_ucrem --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_ucrem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_ucrem
//
//	unsigned char _COM_ucrem(unsigned char x, unsigned char y);
//
//	input:
//		x = A
//		y = X
//	output:
//		A
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_ucrem
  
  .text
__COM_ucrem:
  CMP0 X
#ifdef __OPTIMIZE_SIZE__
  BZ $.L_ZERODIV
#else
  SKNZ
  BR $.L_ZERODIV
#endif  
  $IF(_RL78_S3)
  MOVW DE, AX
  SHRW AX, 8
  MOV D, A
  DIVHU
  MOV A, E
  $ELSEIF(_XMULDIV)
  MOVW DE, AX
  SHRW AX, 8
  MOV D, A
  PUSH PSW
  DI
  MOV !LOWW(MDUC), #0x080
  MOVW MDAL, AX
  MOVW AX, DE
  MOVW MDBL, AX
  CLRW AX
  MOVW MDAH, AX
  MOVW MDBH, AX
  MOV !LOWW(MDUC), #0x81
.L1:
  MOV A, !LOWW(MDUC)
  BT A.0, $.L1
  MOVW AX, !LOWW(MDCL)
  POP PSW
  MOV A, X
  $ELSE
  MOVW DE, AX
  MOV D, #8
  CLRB X
  XCH A, X
.L1:
  ADDW AX, AX
  CMP A, E
  BC $.L2
  SUB A, E
  INC X
.L2:
  DEC D
  BNZ $.L1
  $ENDIF
  
.L_ZERODIV:
  RET
.Lfunc_end1:
  .size __COM_ucrem, .Lfunc_end1-__COM_ucrem

