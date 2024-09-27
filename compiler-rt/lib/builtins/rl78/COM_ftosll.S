//===-- COM_ftosll.S - Implement __fixsfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixsfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_ftosll  __COM_ftosll_nd
#endif

  .file   "COM_ftosll.S"
  .extern __REL_ftoll
  .extern __REL_lltosll

  .text

  .globl __COM_ftosll
  .type  __COM_ftosll,@function
__COM_ftosll:
  movw  hl,ax
  push  hl
  call  !!__REL_ftoll
  pop hl
  br  !!__REL_lltosll
.Lfunc_end1:
  .size __COM_ftosll, .Lfunc_end1-__COM_ftosll

#ifdef __FAR_DATA__
#undef __COM_ftosll
  .globl __COM_ftosll
  .type  __COM_ftosll,@function
__COM_ftosll:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
  movw  ax, [sp+16]   ; copy arg to DE:BC
  movw  bc, ax
  movw  ax, [sp+18]
  movw  de, ax
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #4
  call  !!__COM_ftosll_nd
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
  .size __COM_ftosll, .Lfunc_end2-__COM_ftosll
#endif

  .weak ___fixsfdi
  .type ___fixsfdi,@function
  .set  ___fixsfdi, __COM_ftosll
