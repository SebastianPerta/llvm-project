//===-- REL_setexp_ll.S - Implement _REL_setexp_ll-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_setexp_ll for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_setexp_ll.S"

  .text

  .globl __REL_setexp_ll
  .type  __REL_setexp_ll,@function
__REL_setexp_ll:
  mov d,#63   ; initial value of exponent part (bias value not added)
0:
  cmp0  c   ; upper 32bit 0 judgment
  bnz $1f
  
  movw  ax,[hl+2] ; 32-bit shift to the left
  movw  [hl+6],ax
  movw  ax,[hl]
  movw  [hl+4],ax
  clrw  ax
  movw  [hl+2],ax
  movw  [hl],ax
  
  mov a,#32   ; subtract 32 from the exponent
  sub d,a
1:
  mov a,[hl+6]  ; is the upper 16 bits zero?
  or  a,[hl+7]
  bnz $2f
  
  movw  ax,[hl+4] ; 16-bit shift to the left
  movw  [hl+6],ax
  movw  ax,[hl+2]
  movw  [hl+4],ax
  movw  ax,[hl]
  movw  [hl+2],ax
  clrw  ax
  movw  [hl],ax
  
  mov a,#16   ; subtract 16 from the exponent
  sub d,a
2:
  mov a,[hl+7]
  bt  a.7,$4f
3:
  dec d   ; decrease the value of the index part by 1
  
  movw  ax,[hl]   ; 1-bit shift to the left
  addw  ax,ax
  movw  [hl],ax
  
  movw  ax,[hl+2]
  rolwc ax,1
  movw  [hl+2],ax
  
  movw  ax,[hl+4]
  rolwc ax,1
  movw  [hl+4],ax
  
  movw  ax,[hl+6]
  rolwc ax,1
  movw  [hl+6],ax
  
  bf  a.7,$3b ; repeat until the most significant bit is raised
4:
  ret
.Lfunc_end1:
  .size __REL_setexp_ll, .Lfunc_end1-__REL_setexp_ll
