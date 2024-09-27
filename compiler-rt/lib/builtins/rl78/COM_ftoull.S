//===-- COM_ftoull.S - Implement __fixunssfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixunssfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_ftoull  __COM_ftoull_nd
#endif

  .file   "COM_ftoull.S"
  .extern __REL_ftoll

  .text

  .globl __COM_ftoull
  .type  __COM_ftoull,@function
__COM_ftoull:
  movw  hl,ax
  mov a,d
  bt  a.7,$0f    ; returns zero if the sign is negative
  br  !!__REL_ftoll
0:
  clrw  ax
  movw  [hl],ax
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax
  ret
.Lfunc_end1:
  .size __COM_ftoull, .Lfunc_end1-__COM_ftoull

#ifdef __FAR_DATA__
#undef __COM_ftoull
  .globl __COM_ftoull
  .type  __COM_ftoull,@function
__COM_ftoull:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
  movw  ax, [sp+16]   ; copy arg to DE:BC
  movw  bc, ax
  movw  ax, [sp+18]
  movw  de, ax
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #4
  call  !!__COM_ftoull_nd
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
  .size __COM_ftoull, .Lfunc_end2-__COM_ftoull
#endif

  .weak ___fixunssfdi
  .type ___fixunssfdi,@function
  .set  ___fixunssfdi, __COM_ftoull
