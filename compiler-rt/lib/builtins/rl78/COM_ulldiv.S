//===-- COM_ulldiv.s - Implement _COM_ulldiv ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_ulldiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_ulldiv
//
//	unsigned long long
//	_COM_ulldiv(unsigned long long x, unsigned long long y);
//
//	input:
//		x = [SP+4]
//		y = [SP+12]
//	output:
//		[AX] ([A:DE] for far data)
//===----------------------------------------------------------------------===//
  #include "def.S"
  
#ifdef __FAR_DATA__
#define __COM_ulldiv  __COM_ulldiv_nd
#endif

  .PUBLIC __COM_ulldiv
  .EXTERN __REL_lldiv
  
  .text
#ifndef __OPTIMIZE_SIZE__
.L_ZERODIV:
  DECW AX
  MOVW [DE], AX
  MOVW [DE+2], AX
  MOVW [DE+4], AX
  MOVW [DE+6], AX
  RET
#endif

__COM_ulldiv:
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
  DECW	AX
  MOVW	[DE],AX		; ret = -1
  MOVW	[DE+2],AX
  MOVW	[DE+4],AX
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
  BR !!__REL_lldiv
.Lfunc_end1:
  .size __COM_ulldiv, .Lfunc_end1-__COM_ulldiv

#ifdef __FAR_DATA__
#undef __COM_ulldiv
  .globl __COM_ulldiv
  .type  __COM_ulldiv,@function
__COM_ulldiv:
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
  call  !!__COM_ulldiv_nd
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
  .size __COM_ulldiv, .Lfunc_end2-__COM_ulldiv
#endif

  .weak ___udivdi3
  .type ___udivdi3,@function
  .set  ___udivdi3, __COM_ulldiv

