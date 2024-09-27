//===-- COM_ultod.S - Implement __floatunsidf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatunsidf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_ultod  __COM_ultod_nd
#endif

  .file   "COM_ultod.S"
  .extern __REL_ltod

  .text

  .globl __COM_ultod
  .type  __COM_ultod,@function
__COM_ultod:
  movw  hl,ax   ; store the return address in the hl register
  movw  ax,de
  mov e,#0    ; store sign (always positive)

  xchw  ax,bc
  br  !!__REL_ltod
.Lfunc_end1:
  .size __COM_ultod, .Lfunc_end1-__COM_ultod

#ifdef __FAR_DATA__
#undef __COM_ultod
  .globl __COM_ultod
  .type  __COM_ultod,@function
__COM_ultod:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
  movw  ax, [sp+16]   ; copy arg to DE:BC
  movw  bc, ax
  movw  ax, [sp+18]
  movw  de, ax
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #4
  call  !!__COM_ultod_nd
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
  .size __COM_ultod, .Lfunc_end2-__COM_ultod
#endif

  .weak ___floatunsidf
  .type ___floatunsidf,@function
  .set  ___floatunsidf, __COM_ultod
