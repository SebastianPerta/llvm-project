//===-- REL_d_check.S - Implement _REL_d_check-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_d_check for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_d_check.S"

  .text

  .globl __REL_d_check
  .type  __REL_d_check,@function
__REL_d_check:
  ; set [hl] as a flag for determining a special solution
  ; the contents of the flag are as follows
  ;   [hl].0 = 0 if x is positive, [hl].0 = 1 if x is negative
  ;   [hl].1 = 1 and [hl].3 = 1 if x is infinity
  ;   [hl].1 = 1 and [hl].3 = 0 if x is nan
  ;   [hl].2 = 1 and [hl].3 = 1 if x is 0
  ;   [hl].2 = 1 and [hl].3 = 0 if x is a subnormal number
  ;   [hl].4 = 0 if y is positive, [hl].4 = 1 if y is negative
  ;   [hl].5 = 1 and [hl].7 = 1 if y is infinity
  ;   [hl].5 = 1 and [hl].7 = 0 if y is nan
  ;   [hl].6 = 1 and [hl].7 = 1 if y is 0
  ;   [hl].6 = 1 and [hl].7 = 0 if y is a subnormal number
  mov [hl+0],#0 ; flag initialization
;
  movw  ax,[hl+12]  ; top of x
  addw  ax,ax
  mov1  [hl].0,cy ; sign of x
  shrw  ax,5
  cmpw  ax,#0x07ff
  sknz
  set1  [hl].1    ; infinity or nan
  clrw  bc
  cmpw  ax,bc
  sknz
  set1  [hl].2    ; 0 or subnormalized number
  mov a,[hl+12]
  and a,#0x0f
  or  a,[hl+11]
  or  a,[hl+10]
  or  a,[hl+9]
  or  a,[hl+8]
  or  a,[hl+7]
  or  a,[hl+6]
  sknz
  set1  [hl].3    ; 0 or infinity
;
  movw  ax,[hl+20]  ; top of y
  addw  ax,ax
  mov1  [hl].4,cy ; sign of y
  shrw  ax,5
  cmpw  ax,#0x07ff
  sknz
  set1  [hl].5    ; infinity or nan
  cmpw  ax,bc
  sknz
  set1  [hl].6    ; 0 or subnormalized number
  mov a,[hl+20]
  and a,#0x0f
  or  a,[hl+19]
  or  a,[hl+18]
  or  a,[hl+17]
  or  a,[hl+16]
  or  a,[hl+15]
  or  a,[hl+14]
  sknz
  set1  [hl].7    ; 0 or infinity
;
  ret
.Lfunc_end1:
  .size __REL_d_check, .Lfunc_end1-__REL_d_check
