//===-- COM_ftod.S - Implement __extendsfdf2-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __extendsfdf2 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#ifdef __FAR_DATA__
#define __COM_ftod  __COM_ftod_nd
#endif

  .file   "COM_ftod.S"

  .text

  .globl __COM_ftod
  .type  __COM_ftod,@function
__COM_ftod:
  movw  hl,ax   ; store the return address in the hl register
  clrw  ax
  movw  [hl],ax
  xchw  ax,de

  ; get the value and sign of the exponent part
  shlw  bc,1
  rolwc ax,1
  sknc
  mov d,#0x80   ; d = sign

  ; zero check of input value
  addw  ax,bc
  skc
  bz  $0f
  subw  ax,bc

  ; infinity / nan check (is the exponent part ffh?)
  inc a
  bz  $1f
  dec a

  ; checking the number of subnormal numbers
  cmp0  a
  bnz $2f

  ;--------------------------------------------------------------------
  ; processing for subnormal numbers
  ;--------------------------------------------------------------------
  xch a,x   ; store the mantissa in a-bc
4:
  ; shift left until the top 1 goes out of the mantissa (a-bc)
  shlw  bc,1
  rolc  a,1
  bc  $3f
  dec x   ; subtract the exponent
  br  $4b
3:
  xch a,x
  cmp0  a
  skz
  mov e,#0x0f0    ; mask value to make the value of the exponent part negative

  ;--------------------------------------------------------------------
  ; shift right by 4 bits to match the input value (ax-bc)
  ; to the double type format
  ;--------------------------------------------------------------------
  ; before conversion (float) * 1-bit left-shifted
  ;        a        x        b        c
  ;     eeeeeeee xxxxxxxx xxxxxxxx xxxxxxx0
  ; after conversion (double)
  ;      [hl+7]   [hl+6]   [hl+5]   [hl+4]
  ;     seeeeeee eeeexxxx xxxxxxxx xxxxxxxx
  ;      [hl+3]   [hl+2]   [hl+1]    [hl]
  ;     xxx00000 00000000 00000000 00000000
  ;
  ;     s: sign   e: exponent part   x: mantissa part
  ;     e: 1 when the value before conversion is infinity / nan, 0 otherwise
  ;--------------------------------------------------------------------
2:
  push  ax    ; evacuate the upper ranks
  push  bc    ; evacuate the lower level

  xchw  ax,bc
  shlw  ax,12
  movw  [hl+2],ax

  pop ax    ; lower level
  shrw  ax,4
  shlw  bc,12
  addw  ax,bc
  movw  [hl+4],ax

  pop ax    ; top level
  shrw  ax,4
  or  a,e   ; make the exponent part negative (with a shift in the subnormal number)
        ; the most significant sign bit is temporarily set to 1
        ; since the exponent part is at least -24 or more
        ; the sign bit is cleared by adding the bias value
  ; change the bias value of the exponent part from 127 to 1023
  add a,#0x038    ; (1023-127) >> 4 add the sign bit after calculation is 0
  or  a,d   ; reflect the sign
  movw  [hl+6],ax

  ; [hl+0] has been set to 0
  ret

1:
  addw  ax,bc
  skc
  bz  $5f   ; returns infinity if the mantissa is zero

  ; returns nan if the mantissa is nonzero
  clrw  ax
  decw  ax
  movw  [hl],ax
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax
  ret
5:
  movw  ax,#0x7ff0  ; returns infinity
0:
  or  a,d   ; reflect the sign
  movw  [hl+6],ax
  clrw  ax
  movw  [hl+2],ax
  movw  [hl+4],ax
  ret
.Lfunc_end1:
  .size __COM_ftod, .Lfunc_end1-__COM_ftod

#ifdef __FAR_DATA__
#undef __COM_ftod
  .globl __COM_ftod
  .type  __COM_ftod,@function
__COM_ftod:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
  movw  ax, [sp+16]   ; copy arg to DE:BC
  movw  bc, ax
  movw  ax, [sp+18]
  movw  de, ax
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #4
  call  !!__COM_ftod_nd
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
  .size __COM_ftod, .Lfunc_end2-__COM_ftod
#endif

  .weak ___extendsfdf2
  .type ___extendsfdf2,@function
  .set  ___extendsfdf2, __COM_ftod
