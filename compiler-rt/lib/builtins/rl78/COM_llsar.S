//===-- COM_llsar.S - Implement __COM_llsar-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __COM_llsar for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  .file  "COM_llsar.S"

  .text

  .globl  __COM_llsar
  .type  __COM_llsar,@function
__COM_llsar:
  ;arithmetic right shift on 64-bit integer
  ;Vars: P - return value pointer
  ;    : A - 64-bit int to shift
  ;    : B - Nr. of times to shift
  ;input: AX -> P  (or A:DE -> P for far data)
  ;       C  -> B
  ;    [sp+4] -> word #1 of A
  ;    [sp+6] -> word #2 of A
  ;    [sp+8] -> word #3 of A
  ;    [sp+10]-> word #4 of A
#ifdef __FAR_DATA__
  mov es, a
  push de
  pop hl
#define ES_PREFIX es:
#else
  movw hl, ax
#define ES_PREFIX
#endif
  cmp0 c
  bz  $2f

1: ; shift the 64-bit value on the stack, 1 bit per iteration
  movw ax, [sp+10]
  sarw ax, 1
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
  movw ES_PREFIX[hl+6], ax
  movw ax, [sp+8]
  movw ES_PREFIX[hl+4], ax
  movw ax, [sp+6]
  movw ES_PREFIX[hl+2], ax
  movw ax, [sp+4]
  movw ES_PREFIX[hl], ax
  ret

.Lfunc_end1:
  .size __COM_llsar, .Lfunc_end1-__COM_llsar

  .weak ___ashrdi3
  .type ___ashrdi3,@function
  .set  ___ashrdi3, __COM_llsar
