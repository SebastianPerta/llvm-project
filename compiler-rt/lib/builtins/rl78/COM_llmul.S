//===-- COM_llmul.S - Implement __muldi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __muldi3 for the COMpiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_llmul.S"
  .extern __REL_llmul_addh
  .extern __COM_mulul
  .extern __COM_lmul

  .text

#ifdef __FAR_DATA__
#define __COM_llmul __COM_llmul_nd
#endif

  .globl __COM_llmul
  .type  __COM_llmul,@function
__COM_llmul:
  push  ax      ; return address
  movw  ax,[sp+14+2]    ; y_lh
  push  ax
  movw  ax,[sp+12+4]    ; y_ll
  push  ax
  movw  ax,[sp+6+6]   ; x_lh
  movw  de,ax
  movw  ax,[sp+4+6]   ; x_ll
  movw  bc,ax
  movw  ax,[sp+4]   ; return address
  call  !!__COM_mulul   ; ret = x_l * y_l
;
  ; since _COM_mulul does not destroy the argument, y_l is used as it is
  movw  ax,[sp+10+6]    ; x_hh
  movw  bc,ax
  movw  ax,[sp+8+6]   ; x_hl
  call  !!__COM_lmul
  call  !!__REL_llmul_addh  ; ret_h += (x_h * y_l)
  movw  ax,[sp+18+6]    ; y_hh
  movw  [sp+2],ax
  movw  ax,[sp+16+6]    ; y_hl
  movw  [sp+0],ax
  movw  ax,[sp+6+6]   ; x_lh
  movw  bc,ax
  movw  ax,[sp+4+6]   ; x_ll
  call  !!__COM_lmul
  call  !!__REL_llmul_addh  ; ret_h += (x_l * y_h)
  addw  sp,#6
  ret
.Lfunc_end1:
  .size __COM_llmul, .Lfunc_end1-__COM_llmul

#ifdef __FAR_DATA__
#undef __COM_llmul
  .globl __COM_llmul
  .type  __COM_llmul,@function
__COM_llmul:
  subw  sp, #8        ; space for the tmp retval
  push  ax            ; save the addr of the org retval (far ptr)
  push  de
#ifdef __OPTIMIZE_SIZE__
  mov   e, #8         ; copy args using a loop
1:
  movw  ax,[sp+30]
  push  ax
  dec   e
  bnz   $1b
#else
  movw  ax,[sp+30]    ; copy arg 2
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]    ; copy arg 1
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
  movw  ax,[sp+30]
  push  ax
#endif
  movw  ax, sp        ; set AX to the addr of the tmp retval
  addw  ax, #20
  call  !!__COM_llmul_nd
  addw  sp, #16       ; get rid of the arg copies from the stack
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
  .size __COM_llmul, .Lfunc_end2-__COM_llmul
#endif

  .weak ___muldi3
  .type ___muldi3,@function
  .set  ___muldi3, __COM_llmul
