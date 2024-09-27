//===-- REL_d_round.S - Implement _REL_d_round-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_d_round for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_d_round.S"

  .text

  .globl __REL_d_round
  .type  __REL_d_round,@function
__REL_d_round:
  ;-------------------------------------------------------
  ; round the mantissa
  ;-------------------------------------------------------
  ; input value:
  ;  [hl+7]   [hl+6]   [hl+5]   [hl+4] 
  ; 1aaaabbb bbbbbccc cccccddd dddddeee  (*)
  ;  [hl+3]   [hl+2]   [hl+1]    [hl]
  ; eeeeefff fffffggg gggggrxx xxxxxxxx
  ;
  ; * in the case of a subnormal number, msb is 0
  ;
  ; the part where the lower 11 bits (rxx xxxxxxxx part)
  ; of the input value are discarded by rounding
  ; When the "rxx xxxxxxxx" part is 400h (intermediate value),
  ; the least significant bit of the mantissa part is rounded to 0
  ;-------------------------------------------------------
  push  ax    ; sign
  clrw    bc
  movw    ax,[hl]         ; get the lower 2 bytes of the input value
  and     a,#0x07
  cmpw    ax,#0x0400       ; compare the value of the part discarded by
                           ; rounding with # 0x0400 (intermediate value)
  bc      $0f           ; if it is smaller than # 0x0400, it will not be rounded up
  bnz     $1f           ; if it is larger than # 0x0400, it will be rounded up

  ; if it matches # 0x0400, round it to an even number
  mov     a,[hl+1]
  mov1    cy,a.3          ; get the least significant bit of the mantissa
  sknc                    ; if the least significant bit is 0, no rounding is performed
1:
  incw    bc              ; set carry flag
0:
  ;-------------------------------------------------------
  ; adjust the bit position according to the format of ieee754
  ;-------------------------------------------------------
  ; Input value:
  ;  [hl+7]   [hl+6]   [hl+5]   [hl+4] 
  ; 1aaaabbb bbbbbccc cccccddd dddddeee  (*)
  ;  [hl+3]   [hl+2]   [hl+1]    [hl]
  ; eeeeefff fffffggg gggggrxx xxxxxxxx
  ;
  ; * in the case of a subnormal number, msb is 0
  ;
  ; converted value (double format):
  ;  [hl+7]   [hl+6]   [hl+5]   [hl+4] 
  ; seeeeeee eeeeaaaa bbbbbbbb cccccccc
  ;  [hl+3]   [hl+2]   [hl+1]    [hl]
  ; dddddddd eeeeeeee ffffffff gggggggg
  ;-------------------------------------------------------
  push    de              ; index part
  push    hl              ; input value address
  mov     a,#3            ; number of loops
2:
  push    ax              ; number of loops
  movw    ax,[hl+2]       ; 5-bit left shift on the top
  shlw    ax,5
  movw    de,ax
  movw    ax,[hl]         ; 11-bit right shift to the lower
  shrw    ax,11
  addw    ax,de           ; since the bit is not covered, addw is a substitute for or
                          ; carry does not occur here
  addw    ax,bc           ; add carry
  movw    [hl],ax
  clrw    bc              ; initialize the carry flag once
  rolwc   bc,1            ; reset the carry flag
  incw    hl
  incw    hl
  pop     ax              ; number of loops
  dec     a
  bnz     $2b
  ; even after the loop, c is used as a carry flag
  pop     hl              ; input value address
  pop     de              ; index part

  movw    ax,[hl+6]       ; get the value of the most significant 2 bytes from the input value
  shlw    ax,1            ; delete top
  shrw    ax,12           ; get the upper 4 bits (aaaa part) of the mantissa
  addw    ax,bc           ; add rounding up
  cmpw    ax,#0x10        ; when the range that can be expressed by the mantissa is exceeded
  xchw    ax,de           ; increment the value of the exponent part
  bnz     $3f
  incw    ax
  movw    de,#0           ; clear the carry amount 10000 -> 00000, so the value of 0aaaa is not destroyed

  ; if the value that can be expressed by the exponent part is exceeded, it is set to infinity
  movw    bc,#0x07ff
  cmpw    ax,bc           ; compare with the value that can be expressed in the exponent part
  bc      $3f
  skz
  movw    ax,bc           ; store 0x7ff (2047) in the exponent part

3:
  ; reflect the exponent part in the most significant byte
  shlw    ax,4            ; 4-bit left shift of index part
  addw    ax,de           ; instead of or
  movw    [hl+6],ax

  ; reflect the sign in the most significant bit
  pop ax    ; sign
  and a,#0x80   ;
  or  a,[hl+7]
  mov [hl+7],a

  ret
.Lfunc_end1:
  .size __REL_d_round, .Lfunc_end1-__REL_d_round
