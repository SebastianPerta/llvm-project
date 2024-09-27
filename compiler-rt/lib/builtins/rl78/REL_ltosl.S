//===-- REL_ltosl.S - Implement _REL_ltosl-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_ltosl for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file "REL_ltosl.S"

  .text

  .globl __REL_ltosl
  .type  __REL_ltosl,@function
__REL_ltosl:
  ; is the most significant bit set?
  xchw  ax,bc
  bt  a.7,$1f
  xchw  ax,bc
  dec d
  skz
  bnz $2f    ; if the sign is positive, return as it is
  
  ; if the sign is negative, sign inversion is performed
  movw  de,ax
  clrw  ax
  subw  ax,de
  movw  de,ax
  subc  a,a
  mov x,a
  subw  ax,bc
  movw  bc,ax
  movw  ax,de
2:
  ret
1:
  dec d
  bnz $0f    ; returns zero if the sign is positive and msb is set
  
  ; if the sign is negative, zero is returned if it exceeds 80000000h
  ; if it matches 80000000h, it is returned as it is
  shlw  ax,1
  addw  ax,bc
  bc  $0f
  mov b,#0x80
  sknz
  ret
0:
  clrw  bc
  clrw  ax
  ret
.Lfunc_end1:
  .size __REL_ltosl, .Lfunc_end1-__REL_ltosl
