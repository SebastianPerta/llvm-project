//===-- COM_lsar.s - Implement _COM_lsar ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_lsar for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_lsar
//
//	signed long __far _COM_lsar(signed long x, unsigned char n);
//
//	input:
//		x = BC-AX
//		n = E
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_lsar
  
  .text
  

#ifndef __OPTIMIZE_SIZE__
.L_24OVER:
  sub a, #24
  mov e, a
  xchw ax, bc
  sarw ax, 8
  mov b, a
  mov c, a
  xch a, e
  br $.L_LESSTHAN08
.L_16OVER:
  sub a, #16
  xch a, e
  movw ax, bc
  sarw ax, 15
  xchw ax, bc
  xch a, e
  br $.L_LESSTHAN08
#endif
  
__COM_lsar:
  XCH A, E
#ifndef __OPTIMIZE_SIZE__
  cmp a, #24
  bnc $.L_24OVER
  cmp a, #16
  bnc $.L_16OVER
  CMP A, #8
  bc $.L_LESSTHAN08
  
  SUB A, #8
  XCH A, E
  MOV X, A
  MOV A, C
  XCHW AX, BC
  SARW AX, 8
  XCHW AX, BC
  XCH A, E
#endif
.L_LESSTHAN08:
  CMP0 A
  XCH A, E
  BZ $.L2
.L1:
  SHRW AX, 1
  XCHW AX, BC
  SARW AX, 1
  XCHW AX, BC
  MOV1 A.7, CY
  DEC E
  BNZ $.L1
.L2:
  RET
.Lfunc_end1:
  .size __COM_lsar, .Lfunc_end1-__COM_lsar

  .weak ___ashrsi3
  .type ___ashrsi3,@function
  .set  ___ashrsi3, __COM_lsar

