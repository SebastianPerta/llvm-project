//===-- COM_lshl.s - Implement _COM_lshl ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_lshl for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_lshl
//
//	long __far _COM_lshl(long x, unsigned char n);
//
//	input:
//		x = BC-AX
//		n = E
//	output:
//		BC-AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_lshl
  
  .text

#ifndef __OPTIMIZE_SIZE__
.L_24OVER:
  sub a, #24
  mov e, a
  clrb c
  mov a, x
  mov b, a
  clrw ax
  xch a, e
  br $.L_LESSTHAN08
.L_16OVER:
  sub a, #16
  xch a, e
  movw bc, ax
  clrw ax
  xch a, e
  br $.L_LESSTHAN08
#endif  
__COM_lshl:
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
  SHLW BC, 8
  MOV C, A
  SHLW AX, 8
  xch a, e
#endif
.L_LESSTHAN08:
  CMP0 A
  XCH A, E
  BZ $.L2
.L1:
  ADDW AX, AX
  ROLWC BC, 1
  DEC E
  BNZ $.L1
.L2:
  RET
.Lfunc_end1:
  .size __COM_lshl, .Lfunc_end1-__COM_lshl

  .weak ___ashlsi3
  .type ___ashlsi3,@function
  .set  ___ashlsi3, __COM_lshl
