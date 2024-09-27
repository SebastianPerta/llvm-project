//===-- REL_lltosll.S - Implement _REL_lltosll-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_lltosll for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_lltosll.S"
  .extern __REL_llrev

  .text

  .globl __REL_lltosll
  .type  __REL_lltosll,@function
__REL_lltosll:
  mov a,[hl+7]
  bt  a.7,$1f  ; is the most significant bit set?
  dec d
  sknz      ; if the sign is positive, return as it is
  call  !!__REL_llrev ; if the sign is negative, sign inversion is performed
  ret
1:
  dec d
  bnz $0f    ; returns zero if the sign is positive and msb is set
  
  ; if the sign is negative, zero is returned if it exceeds 8000000000000000h
  ; if it matches 8000000000000000h, it is returned as it is
  movw  ax,[hl+6]
  shlw  ax,1
  or  a,x
  or  a,[hl+5]
  or  a,[hl+4]
  or  a,[hl+3]
  or  a,[hl+2]
  or  a,[hl+1]
  or  a,[hl]
  sknz
  ret
0:
  clrw  ax
  movw  [hl],ax
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax
  ret
.Lfunc_end1:
  .size __REL_lltosll, .Lfunc_end1-__REL_lltosll
