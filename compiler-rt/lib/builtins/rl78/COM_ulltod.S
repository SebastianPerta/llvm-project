//===-- COM_ulltod.S - Implement __floatundidf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatundidf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_ulltod  __COM_ulltod_nd
#endif

  .file   "COM_ulltod.S"
  .extern __REL_lltod

  .text

  .globl __COM_ulltod
  .type  __COM_ulltod,@function
__COM_ulltod:
  clrb  b   ; store sign (always positive)
  movw  de,ax
  movw  ax,sp
  addw  ax,#4
  movw  hl,ax
  br  !!__REL_lltod
.Lfunc_end1:
  .size __COM_ulltod, .Lfunc_end1-__COM_ulltod

#ifdef __FAR_DATA__
#undef __COM_ulltod
  .globl __COM_ulltod
  .type  __COM_ulltod,@function
__COM_ulltod:
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
  call  !!__COM_ulltod_nd
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
  .size __COM_ulltod, .Lfunc_end2-__COM_ulltod
#endif

  .weak ___floatundidf
  .type ___floatundidf,@function
  .set  ___floatundidf, __COM_ulltod
