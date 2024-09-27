//===-- COM_llshl.S - Implement __COM_llshl-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __COM_llshl for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  .file  "COM_llshl.S"

  .text

#ifdef __FAR_DATA__
#define __COM_llshl __COM_llshl_nd
#endif

  .globl  __COM_llshl
  .type  __COM_llshl,@function
__COM_llshl:
  ;arithmetic left shift on 64-bit integer
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
  movw ax, [sp+4]
  shlw ax, 1
  movw [sp+4], ax
  movw ax, [sp+6]
  rolwc ax, 1
  movw [sp+6], ax
  movw ax, [sp+8]
  rolwc ax, 1
  movw [sp+8], ax
  movw ax, [sp+10]
  rolwc ax, 1
  movw [sp+10], ax

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
  .size __COM_llshl, .Lfunc_end1-__COM_llshl

#ifdef __FAR_DATA__
#undef __COM_llshl
  .globl  __COM_llshl
  .type  __COM_llshl,@function
__COM_llshl:
  mov es, a
  push de
  pop hl
  cmp0 c
  bz  $2f

1: ; shift the 64-bit value on the stack, 1 bit per iteration
  movw ax, [sp+4]
  shlw ax, 1
  movw [sp+4], ax
  movw ax, [sp+6]
  rolwc ax, 1
  movw [sp+6], ax
  movw ax, [sp+8]
  rolwc ax, 1
  movw [sp+8], ax
  movw ax, [sp+10]
  rolwc ax, 1
  movw [sp+10], ax

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
  .size __COM_llshl, .Lfunc_end2-__COM_llshl
#endif

  .weak ___ashldi3
  .type ___ashldi3,@function
  .set  ___ashldi3, __COM_llshl
