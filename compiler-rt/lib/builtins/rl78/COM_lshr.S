//===-- COM_lshr.s - Implement _COM_lshr ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_lshr for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_lshr
//
//	unsigned long __far _COM_lshr(unsigned long x, unsigned char n);
//
//	input:
//		x = BC-AX
//		n = E
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_lshr
  
  .text
#ifndef __OPTIMIZE_SIZE__
.L_24OVER:
  sub a, #24
  mov e, a
  mov a, b
  mov x, a
  clrb a
  clrw bc
  xch a, e
  br $.L_LESSTHAN08
.L_16OVER:
  sub a, #16
  xch a, e
  movw ax, bc
  clrw bc
  xch a, e
  br $.L_LESSTHAN08
#endif
  
__COM_lshr:
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
  SHRW AX, 8
  XCH A, B
  XCH A, C
  xch a, e
#endif
.L_LESSTHAN08:
  CMP0 A
  XCH A, E
  BZ $.L2
.L1:
  SHRW AX, 1
  XCHW AX, BC
  SHRW AX, 1
  XCHW AX, BC
  MOV1 A.7, CY
  DEC E
  BNZ $.L1
.L2:
  RET
.Lfunc_end1:
  .size __COM_lshr, .Lfunc_end1-__COM_lshr

  .weak ___lshrsi3
  .type ___lshrsi3,@function
  .set  ___lshrsi3, __COM_lshr
