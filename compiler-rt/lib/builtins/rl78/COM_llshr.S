//===-- COM_llshr.S - Implement __COM_llshr-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __COM_llshr for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  .file  "COM_llshr.S"

  .text

#ifdef __FAR_DATA__
#define __COM_llshr __COM_llshr_nd
#endif

  .globl  __COM_llshr
  .type  __COM_llshr,@function
__COM_llshr:
  ;logical right shift on 64-bit integer
  ;Vars: P - return value pointer
  ;    : A - 64-bit int to shift
  ;    : B - Nr. of times to shift
  ;input: AX -> P  (or A:DE -> P for far data)
  ;       C  -> B
  ;    [sp+4] -> word #1 of A
  ;    [sp+6] -> word #2 of A
  ;    [sp+8] -> word #3 of A
  ;    [sp+10]-> word #4 of A
  movw hl, ax
  cmp0 c
  bz  $2f

1: ; shift the 64-bit value on the stack, 1 bit per iteration
  movw ax, [sp+10]
  shrw ax, 1
  movw [sp+10], ax
  movw ax, [sp+8]
  rorc a, 1
  xch a, x
  rorc a, 1
  xch a, x
  movw [sp+8], ax
  movw ax, [sp+6]
  rorc a, 1
  xch a, x
  rorc a, 1
  xch a, x
  movw [sp+6], ax
  movw ax, [sp+4]
  rorc a, 1
  xch a, x
  rorc a, 1
  xch a, x
  movw [sp+4], ax

  dec c
  bnz   $1b

2: ; copy the stack value to the return location
  movw ax, [sp+10]
  movw [hl+6], ax
  movw ax, [sp+8]
  movw [hl+4], ax
  movw ax, [sp+6]
  movw [hl+2], ax
  movw ax, [sp+4]
  movw [hl], ax
  ret

.Lfunc_end1:
  .size __COM_llshr, .Lfunc_end1-__COM_llshr

#ifdef __FAR_DATA__
#undef __COM_llshr
  .globl  __COM_llshr
  .type  __COM_llshr,@function
__COM_llshr:
  mov es, a
  push de
  pop hl
  cmp0 c
  bz  $2f

1: ; shift the 64-bit value on the stack, 1 bit per iteration
  movw ax, [sp+10]
  shrw ax, 1
  movw [sp+10], ax
  movw ax, [sp+8]
  rorc a, 1
  xch a, x
  rorc a, 1
  xch a, x
  movw [sp+8], ax
  movw ax, [sp+6]
  rorc a, 1
  xch a, x
  rorc a, 1
  xch a, x
  movw [sp+6], ax
  movw ax, [sp+4]
  rorc a, 1
  xch a, x
  rorc a, 1
  xch a, x
  movw [sp+4], ax

  dec c
  bnz   $1b

2: ; copy the stack value to the return location
  movw ax, [sp+10]
  movw es:[hl+6], ax
  movw ax, [sp+8]
  movw es:[hl+4], ax
  movw ax, [sp+6]
  movw es:[hl+2], ax
  movw ax, [sp+4]
  movw es:[hl], ax
  ret

.Lfunc_end2:
  .size __COM_llshr, .Lfunc_end2-__COM_llshr
#endif

  .weak ___lshrdi3
  .type ___lshrdi3,@function
  .set  ___lshrdi3, __COM_llshr
