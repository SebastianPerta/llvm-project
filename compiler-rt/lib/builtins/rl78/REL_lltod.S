//===-- REL_lltod.s - Implement _REL_lltod --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_lltod for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//       _REL_lltod
//
//       input:
//              HL: Address of input value (64bit integer)
//              DE: return address
//              B: sign (0: positive 1: negative)
//       work:
//               AX,C
//       output:
//               [DE]
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __REL_lltod
  .EXTERN __REL_setexp_ll
  .EXTERN __REL_d_round
  
  .text
  
.L_ZERORETURN:
  CLRW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  MOVW [DE+6], AX
  RET
  
__REL_lltod:
  MOVW AX, [HL+6]
  OR A, X
  OR A, [HL+5]
  OR A, [HL+4]
  MOV C, A
  OR A, [HL+3]
  OR A, [HL+2]
  OR A, [HL+1]
  OR A, [HL]
  BZ $.L_ZERORETURN
.SL_TOP:
  PUSH DE
  PUSH BC
  CALL !!__REL_setexp_ll
  MOV A, D
  SHRW AX, 8
  ADDW AX, #1023
  MOVW DE, AX
  
  POP AX
  SHL A, 7
  CALL !!__REL_d_round
  POP DE
  MOVW AX, [HL+6]
  MOVW [DE+6], AX
  MOVW AX, [HL+4]
  MOVW [DE+4], AX
  MOVW AX, [HL+2]
  MOVW [DE+2], AX
  MOVW AX, [HL]
  MOVW [DE], AX
  
  RET
.Lfunc_end1:
  .size __REL_lltod, .Lfunc_end1-__REL_lltod

