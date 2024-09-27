//===-- COM_dtosll.S - Implement __fixdfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixdfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_dtosll  __COM_dtosll_nd
#endif

  .file   "COM_dtosll.S"
  .extern __REL_dtoll
  .extern __REL_lltosll

  .text

  .globl __COM_dtosll
  .type  __COM_dtosll,@function
__COM_dtosll:
  push  ax
  movw  de,ax
  movw  ax,sp
  addw  ax,#6
  movw  hl,ax
  call  !!__REL_dtoll
  pop hl      ; return address
  br  !!__REL_lltosll
.Lfunc_end1:
  .size __COM_dtosll, .Lfunc_end1-__COM_dtosll

#ifdef __FAR_DATA__
#undef __COM_dtosll
  .globl __COM_dtosll
  .type  __COM_dtosll,@function
__COM_dtosll:
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
  call  !!__COM_dtosll_nd
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
  .size __COM_dtosll, .Lfunc_end2-__COM_dtosll
#endif

  .weak ___fixdfdi
  .type ___fixdfdi,@function
  .set  ___fixdfdi, __COM_dtosll
