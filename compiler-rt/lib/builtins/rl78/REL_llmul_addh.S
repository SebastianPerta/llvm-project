//===-- REL_llmul_addh.S - Implement _REL_llmul_addh-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_llmul_addh for the COMpiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_llmul_addh.S"

  .text

  .globl __REL_llmul_addh
  .type  __REL_llmul_addh,@function
__REL_llmul_addh:
  ; add bc-ax to the upper 4 bytes of long long type data pointed to by [sp+8]
  movw  de,ax
  movw  ax,[sp+8]
  movw  hl,ax
  movw  ax,[hl+4]
  addw  ax,de
  movw  [hl+4],ax
  movw  ax,[hl+6]
  sknc
  incw  ax
  addw  ax,bc
  movw  [hl+6],ax
  ret
.Lfunc_end1:
  .size __REL_llmul_addh, .Lfunc_end1-__REL_llmul_addh
