//===-- COM_faddsub.S - Implement __subsf3 and __addsf3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __subsf3 and __addsf3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_fadd.S"
  .file   "COM_fsub.S"
  .extern __REL_f_inf
  .extern __REL_f_round

  .text

0:
  ; returns + 0
  clrw  bc
  clrw  ax
  ret
;
1:
  ; since both x and y are subnormal numbers or 0, the operation is performed as it is
  pop ax    ; a.7 is the subtraction flag
  bt  a.7,$3f
2:
  movw  ax,[sp+4] ; lower mantissa of y
  addw  ax,de   ; subordinate to the mantissa of x
  movw  de,ax
  mov a,[sp+6]  ; higher mantissa of y
  addc  c,a   ; higher mantissa of x
  movw  ax,de   ; (when a carry occurs, the least significant bit of the exponent part is set)
  ret     ; no setting is required because b contains the sign and exponent part 0
;
3:
  cmp0  x   ; | x | == | y | flag
  bnz $0b  ; returns + 0 for equivalence subtraction
  movw  ax,[sp+4] ; lower mantissa of y
  xchw  ax,de   ; subordinate to the mantissa of x
  subw  ax,de
  movw  de,ax
  mov a,[sp+6]  ; higher mantissa of y
  subc  c,a   ; higher mantissa of x
  movw  ax,de
  ret
;
4:
  ; x is infinite or infinite
  mov a,x
  or  a,d
  or  a,e
  pop ax    ; flag
  bnz $5f ; x is a non-number
  ; since x >= y, y is not an infinite number if x is infinite
  ; returns x for addition
  ; for subtraction, returns a non-number if y is infinite, x if y is not infinite
  shr a,7   ; a.7 is the subtraction flag
  and a,x   ; if subtraction and x and y are infinite, return a non-number
  bz  $8f ; otherwise it returns x
5:
  ; returns a non-number
  clrw  ax
  decw  ax
  movw  bc,ax
  ret
;
6:
  ; y is 0 or subnormalized, x is 0, subnormalized or normalized
  mov a,h   ; exponent part of x
  cmp0  a
  bz  $1b ; both x and y are 0 or subnormal
  ; x is the subnormal number
  inc l   ; set 1 in the exponent part of y
  ; returns x when y is 0
  cmp0  x   ; higher mantissa of y
  bnz $12f    ; if y is a subnormal number, return to the main process
  movw  ax,[sp+4+2] ; subordinate to y
  or  a,x
  bnz $12f    ; if y is a subnormal number, return to the main process
  skz     ; if y is 0, the next pop instruction is always skipped
7:
  pop bc    ; top of x
  pop ax    ; sign (not used)
8:
  movw  ax,de   ; subordinate to x
  ret
;
9:
  cmp a,#25   ; if the difference in the exponential part is large, y disappears
  bnc $7b ; returns x
  movw  ax,[sp+4+4] ; lower mantissa of y
  xch a,x
  mov l,a
  mov a,[sp+6+4]  ; higher mantissa of y
  movw  [sp+4+4],ax ; lower mantissa of y
  mov [sp+6+4],#0
  mov a,#8
  sub b,a   ; exponent difference
  bz  $14f
  br  $13f
;

  ; this is the entrance to the function
  .globl __COM_fsub
  .type  __COM_fsub,@function
__COM_fsub:
  movw  de,ax
  mov a,[sp+7]  ; "x - y" -> "x + (-y)"
  xor a,#0x80
  mov [sp+7],a
  movw  ax,de

  ; following the processing of _COM_fadd
  ; this is the entrance to the function
  .globl __COM_fadd
  .type  __COM_fadd,@function
__COM_fadd:
  ; [special return value]
  ; (1) if x or y is nan, nan is the return value
  ; (2) if x or y is infinite, infinite is the return value and the code is inherited
  ;     however, if x and y are both infinite and the signs are different, nan is used as the return value
  ; (3) if x or y is 0, the other is the return value
  ;     however, if x and y are both 0 and the signs are different, + 0 is used as the return value

  movw  de,ax   ; subordinate to x
  ; addition processing if the signs match, subtraction processing if they do not match
  mov a,[sp+7]  ; sign of y
  xor a,b   ; the sign of x, a.7 is the subtraction flag
  clrb  x   ; x is the | x | == | y | flag
  push  ax    ; a.7 adds if is 0, subtracts if not 0
  ; the one with the larger absolute value is used as the left operand
  movw  ax,bc   ; top of x
  addw  ax,ax   ; remove sign
  movw  hl,ax   ;
  movw  ax,[sp+6+2] ; higher than y
  addw  ax,ax   ; remove sign
  cmpw  ax,hl
  bnz $10f
  movw  ax,[sp+4+2] ; subordinate to y
  cmpw  ax,de
  sknz
  mov [sp+0],#0x1 ; | x | == | y | flag
10:
  bnh $11f    ; the absolute value of x is large
  ; swap x and y to unify the judgment process and the normalization process of the subnormalized number
  movw  ax,[sp+4+2]
  xchw  ax,de
  movw  [sp+4+2],ax
  movw  ax,[sp+6+2]
  xchw  ax,bc
  movw  [sp+6+2],ax
11:
  ; special value judgment of x
  movw  ax,bc   ; top of x
  addw  ax,ax
  cmp a,#0xff   ; exponent part of x
  bz  $4b ; x is infinite or infinite
  mov h,a   ; exponent part of x
  ; special value judgment of y
  movw  ax,[sp+6+2] ; higher than y
  addw  ax,ax
  cmp0  a
  mov l,a   ; exponent part of y
  bz  $6b  ; the exponent part of y is 0
  ; write back with a stingy expression on the mantissa of y
  oneb  a   ; miser expression
  shlw  ax,7
  mov [sp+6+2],a  ; higher mantissa of y
12:
  ; shift the mantissa of y to the right by the difference in the exponent
  mov a,h   ; exponent part of x
  sub a,l   ; exponent part of x - exponent part of y
  mov l,#0    ; rounding judgment area
  bz  $15f
  push  bc    ; top of x
  mov b,a   ; exponent difference
  cmp a,#8
  bnc $9b  ; when the difference in the exponent part is 8 or more
13:
  mov a,[sp+6+4]  ; higher mantissa of y
  shr a,1
  mov [sp+6+4],a  ; higher mantissa of y
  movw  ax,[sp+4+4] ; lower mantissa of y
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  [sp+4+4],ax ; lower mantissa of y
  mov a,l   ; rounding judgment area
  rorc  a,1
  sknc
  set1  a.0
  mov l,a   ; rounding judgment area
  dec b   ; exponent difference
  bnz $13b
14:
  pop bc    ; top of x
15:
  pop ax    ; a.7 is the subtraction flag, x.0 is the | x | == | y | flag
  addw  ax,ax   ; cy is the subtraction flag, x.1 is the | x | == | y | flag
  mov a,#0x80
  or  c,a   ; miser expression + higher mantissa of x
  and a,b   ; operation result code
  push  ax    ;
  bc  $19f  ; subtraction process
16:
  ; addition processing
  ; h:exponent part of x, cde:mantissa part of x, [sp+6]:the mantissa of y,
  ; l:rounding judgment area, [sp+1]:operation result code
  movw  ax,[sp+4+2] ; lower mantissa of y
  addw  ax,de   ; subordinate to the mantissa of x
  movw  de,ax   ; mantissa part lower level of operation result
  mov a,[sp+6+2]  ; higher mantissa of y
  addc  c,a   ; higher mantissa of x
  bnc $17f  ; no mantissa carry
  ; if there is an overflow, the mantissa part is shifted to the right by 1 bit
  ; and the exponent part is incremented by 1
  mov a,c   ; higher mantissa part of operation result
  shr a,1
  mov c,a   ; higher mantissa part of operation result
  movw  ax,de   ; mantissa part lower level of operation result
  rorc  a,1
  xch a,x
  rorc  a,1
  xch a,x
  movw  de,ax   ; mantissa part lower level of operation result
  mov a,l   ; rounding judgment area
  rorc  a,1
  sknc
  set1  a.0
  mov l,a   ; rounding judgment area
  inc h   ; exponent part
  ; if the exponent part is 0xff, set infinity
  inc h
  sknz
  br  !!__REL_f_inf
  dec h
17:
  ; set to ieee754 format
  ; at this point, the sign is [sp+1], the exponential part is h,
  ; the mantissa part is cde, and the rounding judgment is l
  movw  ax,bc   ; higher mantissa part of operation result
  addw  ax,ax   ;
  mov a,h   ; exponential part of calculation result
  shrw  ax,1
  movw  bc,ax
  movw  ax,hl
  xchw  ax,de
  ; at this point, the sign is [sp+1], the exponent / mantissa part is bcax, and the rounding judgment is e
  br  !!__REL_f_round
;
18:
  ; if they are equivalent, +0 is returned
  pop ax    ; sign (not used)
  clrw  bc
  clrw  ax
  ret
;
19:
  ; subtraction process
  ; h:exponent part of x, cde:mantissa part of x, [sp+6]:the mantissa of y,
  ; l:rounding judgment area, [sp+1]:operation result code, x:| x | == | y | flag
  cmp0  x   ; |x|==|y|flag
  bnz $18b
  clrb  a
  sub a,l   ; rounding judgment area
  mov l,a
  mov a,[sp+4+2]  ; mantissa x_ll - y_ll
  subc  e,a   ;
  mov a,[sp+5+2]  ; mantissa x_lh - y_lh
  subc  d,a   ;
  mov a,[sp+6+2]  ; mantissa x_hl - y_hl
  subc  c,a   ;
  mov a,c
  bt  a.7,$17b  ; no shift required when the most significant bit is set
  ; register move for left shift (cde-l -> axb-c)
  movw  ax,hl
  mov a,e
  xchw  ax,bc
  mov a,d
  xch a,x
  ; shift left until the most significant bit of the mantissa stands
  ; however, if the exponent part becomes 0, it does not shift
20:
  dec h   ; exponent part of x
  bz  $21f  ; do not shift when it becomes a subnormal number
  ; shift the mantissa to the left
  shlw  bc,1
  rolwc ax,1
  bf  a.7,$20b
21:
  ; set to ieee754 format
  ; at this point, the sign is [sp+1], the exponential part is h,
  ; the mantissa part is axb, and the rounding judgment is c
  xch a,x
  mov e,a
  addw  ax,ax
  mov a,h
  shrw  ax,1
  xchw  ax,bc
  xch a,x
  xch a,e
  ; at this point, the sign is [sp+1], the exponent / mantissa part is bcax,
  ; and the rounding judgment is e
  br  !!__REL_f_round
.Lfunc_end1:
  .size __COM_fsub, .Lfunc_end1-__COM_fsub
  .size __COM_fadd, .Lfunc_end1-__COM_fadd

  .weak ___subsf3
  .type ___subsf3,@function
  .set  ___subsf3, __COM_fsub

  .weak ___addsf3
  .type ___addsf3,@function
  .set  ___addsf3, __COM_fadd
