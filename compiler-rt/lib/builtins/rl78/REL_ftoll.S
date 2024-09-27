//===-- REL_ftoll.S - Implement _REL_ftoll-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_ftoll for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_ftoll.S"
  .extern __REL_ftol

  .text

  .globl __REL_ftoll
  .type  __REL_ftoll,@function
__REL_ftoll:
  ; clear the return value to zero
  clrw  ax
  movw  [hl],ax
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax

  ; get the value and sign of the exponent part
  movw  ax,de
  addw  ax,ax   ; index part: a
  mov d,#0
  sknc
  mov d,#0x80
  
  ; index range check
  ; check for underflow with the common function _REL_ftol
  cmp a,#0x0bf
  bnc $0f    ; overflow when exponent > beh
  
  ; when 00h <= exponential part <= 9eh, the common function _REL_ftol is called as it is. 
  sub a,#0x9f
  bc  $1f

  ; -------------------------------------------------------------------
  ; when 9fh <= exponential part <= beh, subtract 8 from the exponent part
  ; until it falls within the range of 97h to 9eh
  ; after adjusting the exponent part, call the common function _REL_ftol
  ; the bc-ax in which the conversion result is stored, is stored in the
  ; following according to the value of the exponent part
  ; <storage location of bc-ax>         b      c      a      x
  ; 9fh <= exponential part <= a6h :  [hl+4] [hl+3] [hl+2] [hl+1]
  ; a7h <= exponential part <= aeh :  [hl+5] [hl+4] [hl+3] [hl+2]
  ; afh <= exponential part <= b6h :  [hl+6] [hl+5] [hl+4] [hl+3]
  ; b7h <= exponential part <= beh :  [hl+7] [hl+6] [hl+5] [hl+4]
  ; -------------------------------------------------------------------
  ; <output result of _REL_ftol (bc-ax)>
  ;   before conversion : seeeeeee exxxxxxx xxxxxxxx xxxxxxxx
  ;   after conversion : 
  ;    adjusted index part    b        c        a       x
  ;             97h  -->  00000001 xxxxxxxx xxxxxxxx xxxxxxx0
  ;             98h  -->  0000001x xxxxxxxx xxxxxxxx xxxxxx00
  ;             99h  -->  000001xx xxxxxxxx xxxxxxxx xxxxx000
  ;             9ah  -->  00001xxx xxxxxxxx xxxxxxxx xxxx0000
  ;             9bh  -->  0001xxxx xxxxxxxx xxxxxxxx xxx00000
  ;             9ch  -->  001xxxxx xxxxxxxx xxxxxxxx xx000000
  ;             9dh  -->  01xxxxxx xxxxxxxx xxxxxxxx x0000000
  ;             9eh  -->  1xxxxxxx xxxxxxxx xxxxxxxx 00000000
  ; -------------------------------------------------------------------
2:
  incw  hl    ; increment the return address
  sub a,#8    ; adjust the index part
  bnc $2b
1:
  ; call the common function _REL_ftol
  add a,#0x9f   ; adjust the index part
  shrw  ax,1
  or  a,d   ; returns the sign
  xchw  ax,bc
  push  hl
  call  !!__REL_ftol
  pop hl
  ; store bc-ax in return address
  ; hl may contain odd addresses by incrementing
  ; since there is, transfer one byte at a time
  mov [hl+1],a
  mov a,x
  mov [hl],a
  mov a,b
  mov [hl+3],a
  mov a,c
  mov [hl+2],a
  ret
0:
  mov d,#0
  ret
.Lfunc_end1:
  .size __REL_ftoll, .Lfunc_end1-__REL_ftoll
