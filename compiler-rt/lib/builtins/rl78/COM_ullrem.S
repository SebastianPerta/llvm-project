//===-- COM_ullrem.s - Implement _COM_ullrem ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_ullrem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_ullrem
//
//	unsigned long long
//	_COM_ullrem(unsigned long long x, unsigned long long y);
//
//	input:
//		x = [SP+4]
//		y = [SP+12]
//	output:
//		[AX] ([A:DE] for far data)
//===----------------------------------------------------------------------===//
  #include "def.S"
  
#ifdef __FAR_DATA__
#define __COM_ullrem  __COM_ullrem_nd
#endif

  .PUBLIC __COM_ullrem
  .EXTERN __REL_llrem
  
  .text
#ifndef __OPTIMIZE_SIZE__
.L_ZERODIV:
  MOVW AX, [SP+4]
  MOVW [DE], AX
  MOVW AX, [SP+6]
  MOVW [DE+2], AX
  MOVW AX, [SP+8]
  MOVW [DE+4], AX
  MOVW AX, [SP+10]
  MOVW [DE+6], AX
  RET
#endif
  
__COM_ullrem:
  MOVW DE, AX
  MOVW AX, SP
  ADDW AX, #12
  MOVW HL, AX
  MOVW AX, [HL]
  OR A, X
  OR A, [HL+2]
  OR A, [HL+3]
  OR A, [HL+4]
  OR A, [HL+5]
  OR A, [HL+6]
  OR A, [HL+7]
#ifdef __OPTIMIZE_SIZE__
  BNZ $.L1
  MOVW	AX,[SP+4]	; ret = x
  MOVW	[DE],AX
  MOVW	AX,[SP+6]
  MOVW	[DE+2],AX
  MOVW	AX,[SP+8]
  MOVW	[DE+4],AX
  MOVW	AX,[SP+10]
  MOVW	[DE+6],AX
  RET
#else
  SKNZ
  BR $.L_ZERODIV
#endif  
.L1:
  MOVW AX, HL
  SUBW AX, #8
  XCHW AX, DE
  BR !!__REL_llrem
.Lfunc_end1:
  .size __COM_ullrem, .Lfunc_end1-__COM_ullrem

#ifdef __FAR_DATA__
#undef __COM_ullrem
  .globl __COM_ullrem
  .type  __COM_ullrem,@function
__COM_ullrem:
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
  call  !!__COM_ullrem_nd
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
  .size __COM_ullrem, .Lfunc_end2-__COM_ullrem
#endif

  .weak ___umoddi3
  .type ___umoddi3,@function
  .set  ___umoddi3, __COM_ullrem

