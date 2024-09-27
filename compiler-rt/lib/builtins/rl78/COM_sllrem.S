//===-- COM_sllrem.s - Implement _COM_sllrem ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_sllrem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_sllrem
//
//	signed long long _COM_sllrem(signed long long x, signed long long y);
//
//	input:
//		x = [SP+4]
//		y = [SP+12]
//	output:
//		[AX] ([A:DE] for far data)
//===----------------------------------------------------------------------===//
  #include "def.S"
  
#ifdef __FAR_DATA__
#define __COM_sllrem  __COM_sllrem_nd
#endif

  .PUBLIC __COM_sllrem
  .EXTERN __REL_llrem
  .EXTERN __REL_llrev
  
  .text
#ifndef __OPTIMIZE_SIZE__
.L_ZERODIV:
  MOVW AX, [HL+4]
  MOVW [DE], AX
  MOVW AX, [HL+6]
  MOVW [DE+2], AX
  MOVW AX, [HL+8]
  MOVW [DE+4], AX
  MOVW AX, [HL+10]
  MOVW [DE+6], AX
  RET
#endif  
__COM_sllrem:
  MOVW DE, AX
  MOVW HL, SP
  MOVW AX, [HL+12]
  OR A, X
  OR A, [HL+14]
  OR A, [HL+15]
  OR A, [HL+16]
  OR A, [HL+17]
  OR A, [HL+18]
  OR A, [HL+19]
#ifdef __OPTIMIZE_SIZE__
  BNZ	$.L1
  MOVW	AX,[HL+4]	; ret = x
  MOVW	[DE],AX
  MOVW	AX,[HL+6]
  MOVW	[DE+2],AX
  MOVW	AX,[HL+8]
  MOVW	[DE+4],AX
  MOVW	AX,[HL+10]
  MOVW	[DE+6],AX
  RET
#else
  SKNZ
  BR $.L_ZERODIV
#endif
  
.L1:
  CLRB B
  MOV A, [SP+11]
  BF A.7, $.L2
  INC B
  MOVW AX, SP
  ADDW AX, #4
  MOVW HL, AX
  CALL !!__REL_llrev
.L2:
  MOVW AX, SP
  ADDW AX, #12
  MOVW HL, AX
  MOV A, [SP+19]
  BF A.7, $.L3
  CALL !!__REL_llrev
.L3:
  MOVW AX, SP
  ADDW AX, #4
  XCHW AX, DE
  PUSH BC
  CALL !!__REL_llrem
  POP BC
  DEC B
  SKNZ
  CALL !!__REL_llrev
  RET

.Lfunc_end1:
  .size __COM_sllrem, .Lfunc_end1-__COM_sllrem

#ifdef __FAR_DATA__
#undef __COM_sllrem
  .globl __COM_sllrem
  .type  __COM_sllrem,@function
__COM_sllrem:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
#ifdef __OPTIMIZE_SIZE__
  mov   e, #8         ; copy args using a loop
1:
  movw  ax,[sp+30]
  push  ax
  dec   e
  bnz   $1b
#else
  movw  ax,[sp+30]    ; copy arg 2
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]    ; copy arg 1
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
#endif
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #20
  call  !!__COM_sllrem_nd
  addw  sp, #16       ; get rid of the arg copies from the stack
  pop   hl            ; get the addr of org retval in ES:HL
  pop   ax
  mov   es, a
  pop   ax            ; copy the tmp retval to the org one
  movw  es:[hl], ax
  pop   ax
  movw  es:[hl+2], ax
  pop   ax
  movw  es:[hl+4], ax
  pop   ax
  movw  es:[hl+6], ax
  ret
.Lfunc_end2:
  .size __COM_sllrem, .Lfunc_end2-__COM_sllrem
#endif

  .weak ___moddi3
  .type ___moddi3,@function
  .set  ___moddi3, __COM_sllrem

