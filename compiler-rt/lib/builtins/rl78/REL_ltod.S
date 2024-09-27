//===-- REL_ltod.s - Implement _REL_ltod ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_ltod for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_REL_ltod
//
//	input:
//		BC-AX: 入力値(32bit型整数)
//		HL:    戻り値のアドレス
//		E:     符号(0: 正  1: 負)
//	output:
//		[HL]
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __REL_ltod
  
  .text
  
.L_ZERORETURN:
  CLRW AX
  MOVW [HL], AX
  MOVW [HL+2], AX
  MOVW [HL+4], AX
  MOVW [HL+6], AX
  RET
  
__REL_ltod:
  XCHW AX, BC
  ADDW AX, BC
  SKC
  BZ $.L_ZERORETURN
.SL_TOP:
  SUBW AX, BC
  
  MOV D, #31
  
  CMPW AX, #0x00
  BNZ $.SL
  MOV A, #16
  SUB D, A
  CLRB A
  XCHW AX, BC
.SL:
  BT A.7, $.STOR
.LOOP1:
  DEC D
  ADDW AX, AX
  SHLW BC, 1
  SKNC
  INCW AX
  BF A.7, $.LOOP1
.STOR:
  PUSH AX
  PUSH BC
  
  XCHW AX, BC
  SHLW BC, 5
  SHRW AX, 11
  ADDW AX, BC
  MOVW [HL+4], AX
  
  POP AX
  SHLW AX, 5
  MOVW [HL+2], AX
  
  CLRW AX
  MOVW [HL], AX
  
  POP AX
  SHLW AX, 1
  SHRW AX, 12
  MOVW BC, AX
  CLRB X
  MOV A, D
  SHRW AX, 4
  ADDW AX, #0x3FF0
  ADDW AX, BC
  DEC E
  SKNZ
  SET1 A.7
  MOVW [HL+6], AX
  
  RET
.Lfunc_end1:
  .size __REL_ltod, .Lfunc_end1-__REL_ltod

