//===-- REL_llrev.S - Implement REL_llrev-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements REL_llrev for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file "REL_llrev.S"

  .text

  .globl __REL_llrev
  .type  __REL_llrev,@function
__REL_llrev:
  clrw  ax
  subw  ax,[hl+0] ; *xp_ll = -(*xp_ll)
  movw  [hl],ax
  clrb  a
  subc  a,[hl+2]  ; *xp_lh = -(*xp_lh)
  mov x,a
  clrb  a
  subc  a,[hl+3]
  movw  [hl+2],ax
  clrb  a
  subc  a,[hl+4]  ; *xp_hl = -(*xp_hl)
  mov x,a
  clrb  a
  subc  a,[hl+5]
  movw  [hl+4],ax
  subc  a,a
  mov x,a
  subw  ax,[hl+6] ; *xp_hh = -(*xp_hh)
  movw  [hl+6],ax
  ret
.Lfunc_end1:
  .size __REL_llrev, .Lfunc_end1-__REL_llrev
