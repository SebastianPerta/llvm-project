//===-- REL_dtoll.S - Implement _REL_dtoll-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_dtoll for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_llshl __COM_llshl_nd
#define __COM_llshr __COM_llshr_nd
#endif

  .file   "REL_dtoll.S"
  .extern __REL_dtol
  .extern __COM_llshl
  .extern __COM_llshr

  .text

  .globl __REL_dtoll
  .type  __REL_dtoll,@function
__REL_dtoll:
  movw  ax,[hl+6]
  addw  ax,ax
  clrb  b
  sknc
  inc b   ; sign
  shrw  ax,5    ; ax = exponential part

  ; index range check
  ; check for underflow with the common function _REL_dtol
  cmpw  ax,#1023+64 ; overflow when the exponent part is (1023 + 64) or more
  bnc $0f
  
  push  bc    ; save sign
  subw  ax,#1023+32 ; judgment of index part <(1023 + 32)
  bnc $1f

  ; when 0 <= exponential part <= (1023 + 31), the conversion result from double type to 32-bit integer type
  ; call the common function _REL_dtol because it will be the same
  push  de
  call  !!__REL_dtol
  pop de
  movw  [de],ax   ; store bc-ax in the last 4 bytes of the return value
  movw  ax,bc
  movw  [de+2],ax
  clrw  ax    ; clear the top 4 bytes
  movw  [de+4],ax
  movw  [de+6],ax
  pop de    ; d = sign
  ret

  ; -------------------------------------------------------------------
  ; when (1023 + 32) <= exponential part <= (1023 + 63), the mantissa part (53 bits)
  ; obtained by adding 1 to msb is shifted according to the value of the exponential part
  ; (call a long long type shift function with 64 bits filled with 0 as the input value)
  ;
  ; when the exponent part = (1023 + 52), the number of shifts becomes 0, and if the
  ; exponent part is smaller than that, it shifts to the right (up to 20 times), and
  ; if it is larger, it shifts to the left (up to 11 times)
  ; -------------------------------------------------------------------
1:
  movw  bc,ax   ; bc = index part
  movw  ax,[hl+6]
  shlw  ax,11
  set1  a.7   ; implicit 1 set
  shrw  ax,11
  
  ; to call a 64-bit shift function, copy the input value and push it onto the stack
  push  ax
  movw  ax,[hl+4]
  push  ax
  movw  ax,[hl+2]
  push  ax
  movw  ax,[hl]
  push  ax
  
  movw  ax,bc
  subw  ax,#20    ; check if the index part is 1023 + 52 (1023 + 32 + 20) or more
        ; (At this point, 1023 + 32 has already been subtracted
        ;  from the index part, so subtract another 20)
  bnc $2f

  ; shift to the right when the exponent part < (1023 + 52)
  clrb  a
  sub a,x
  mov c,a   ; c = number of shifts
  movw  ax,de
  call  !!__COM_llshr
  br  $3f
2:
  ; left shift when exponent > (1023 + 52)
  ; when the exponent part = (1023 + 52), the number of shifts becomes 0
  ; (even when the number of shifts is 0, the shift function is called
  ;  to store the result in the return values [de] to [de + 7])
  movw  bc,ax   ; c = number of shifts
  movw  ax,de
  call  !!__COM_llshl
3:
  addw  sp,#8
  pop de    ; d = sign
  ret
0:
  clrw  ax
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  mov d,a
  ret
.Lfunc_end1:
  .size __REL_dtoll, .Lfunc_end1-__REL_dtoll
