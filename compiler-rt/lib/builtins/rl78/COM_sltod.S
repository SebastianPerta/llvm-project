//===-- COM_sltod.S - Implement __floatsidf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatsidf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_sltod  __COM_sltod_nd
#endif

  .file   "COM_sltod.S"
  .extern __REL_ltod

  .text

  .globl __COM_sltod
  .type  __COM_sltod,@function
__COM_sltod:
  movw  hl,ax   ; store the return address in the hl register
  movw  ax,de

  mov e,#0    ; store sign (positive)
  mov1  cy,a.7
  bnc $0f    ; if the sign bit is 0 (positive), no sign conversion is performed

  ; sign inversion
  movw  de,ax
  clrw  ax
  subw  ax,bc
  movw  bc,ax
  subc  a,a
  mov x,a
  subw  ax,de
  
  mov e,#1    ; store sign (negative)
0:
  xchw  ax,bc
  br  !!__REL_ltod
.Lfunc_end1:
  .size __COM_sltod, .Lfunc_end1-__COM_sltod

#ifdef __FAR_DATA__
#undef __COM_sltod
  .globl __COM_sltod
  .type  __COM_sltod,@function
__COM_sltod:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
  movw  ax, [sp+16]   ; copy arg to DE:BC
  movw  bc, ax
  movw  ax, [sp+18]
  movw  de, ax
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #4
  call  !!__COM_sltod_nd
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
  .size __COM_sltod, .Lfunc_end2-__COM_sltod
#endif

  .weak ___floatsidf
  .type ___floatsidf,@function
  .set  ___floatsidf, __COM_sltod
