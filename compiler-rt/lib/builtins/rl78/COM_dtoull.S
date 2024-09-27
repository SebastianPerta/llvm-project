//===-- COM_dtoull.S - Implement __fixunsdfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixunsdfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_dtoull  __COM_dtoull_nd
#endif

  .file   "COM_dtoull.S"
  .extern __REL_dtoll

  .text

  .globl __COM_dtoull
  .type  __COM_dtoull,@function
__COM_dtoull:
  movw  de,ax
  movw  ax,sp
  addw  ax,#4
  movw  hl,ax
  mov a,[hl+7]
  bt  a.7,$0f    ; returns zero if the sign is negative
  br  !!__REL_dtoll
0:
  clrw  ax
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  ret
.Lfunc_end1:
  .size __COM_dtoull, .Lfunc_end1-__COM_dtoull

#ifdef __FAR_DATA__
#undef __COM_dtoull
  .globl __COM_dtoull
  .type  __COM_dtoull,@function
__COM_dtoull:
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
  call  !!__COM_dtoull_nd
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
  .size __COM_dtoull, .Lfunc_end2-__COM_dtoull
#endif

  .weak ___fixunsdfdi
  .type ___fixunsdfdi,@function
  .set  ___fixunsdfdi, __COM_dtoull
