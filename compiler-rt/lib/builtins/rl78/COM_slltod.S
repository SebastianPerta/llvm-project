//===-- COM_slltod.S - Implement __floatdidf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatdidf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_slltod  __COM_slltod_nd
#endif

  .file   "COM_slltod.S"
  .extern __REL_lltod
  .extern __REL_llrev

  .text

  .globl __COM_slltod
  .type  __COM_slltod,@function
__COM_slltod:
  clrb  b   ; store sign (positive)
  push  ax
  movw  ax,sp
  addw  ax,#6
  movw  hl,ax
  
  mov a,[hl+7]  ; store the most significant byte of the input value in the a register
  mov1  cy,a.7
  bnc $0f   ; if the sign bit is 0 (positive), no sign conversion is performed
  
  ; sign inversion
  call  !!__REL_llrev
  oneb  b   ; store sign (negative)
0:
  pop de
  br  !!__REL_lltod
.Lfunc_end1:
  .size __COM_slltod, .Lfunc_end1-__COM_slltod

#ifdef __FAR_DATA__
#undef __COM_slltod
  .globl __COM_slltod
  .type  __COM_slltod,@function
__COM_slltod:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
#ifdef __OPTIMIZE_SIZE__
  mov   e, #4         ; copy arg using a loop
1:
  movw  ax,[sp+22]
  push  ax
  dec   e
  bnz   $1b
#else
  movw  ax,[sp+22]    ; copy arg
  push  ax
  movw  ax,[sp+22]
  push  ax
  movw  ax,[sp+22]
  push  ax
  movw  ax,[sp+22]
  push  ax
#endif
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #12
  call  !!__COM_slltod_nd
  addw  sp, #8        ; get rid of the arg copy from the stack
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
  .size __COM_slltod, .Lfunc_end2-__COM_slltod
#endif

  .weak ___floatdidf
  .type ___floatdidf,@function
  .set  ___floatdidf, __COM_slltod
