//===-- REL_llrem.S - Implement _REL_llrem-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_llrem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "def.S"

  .file   "REL_llrem.S"

#if defined(__RL78_S3__) || defined(__MDA_ENABLED__)
  .equ xpoff, 6
  .equ ypoff, 8
#else
;
#endif

  .text

#if defined(__RL78_S3__) || defined(__MDA_ENABLED__)
#ifdef __RL78_S3__
0:     ; *retp_h = 0, *retp_l = 32bit % 32bit
  movw  ax,[de+2] ; bcax = *xp_l
  movw  bc,ax
  movw  ax,[de]
  push  ax
  movw  ax,[hl]   ; hlde = *yp_l
  movw  de,ax
  movw  ax,[hl+2]
  movw  hl,ax
  pop ax
  divwu
  movw  ax,hl   ; *retp_l = 32bit % 32bit
  pop hl    ; retp
  movw  [hl+2],ax
  movw  ax,de
  movw  [hl],ax
  clrw  ax    ; *retp_h = 0
  movw  [hl+4],ax
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret
#else       // __MDA_ENABLED__
0:     ; *retp_h = 0, *retp_l = 32bit % 32bit
  movw  ax,[de]   ; mda <- *xp_l
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax
  movw  ax,[de+2]
  movw  MDAH,ax
  movw  ax,[hl]   ; mdb <- *yp_l
  movw  MDBL,ax
  movw  ax,[hl+2]
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
1:
  mov a,!LOWW(MDUC) ; if (divst == 1) then wait
  bt  a.0,$1b
;
  movw  bc,!LOWW(MDCH)
  movw  ax,!LOWW(MDCL)
  pop psw
  pop hl    ; retp
  movw  [hl],ax   ; *retp_l = 32bit % 32bit
  movw  ax,bc
  movw  [hl+2],ax
  clrw  ax    ; *retp_h = 0
  movw  [hl+4],ax
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret
#endif
;
  ; this is the entrance to the function
  .globl __REL_llrem
  .type  __REL_llrem,@function
__REL_llrem:
  push  hl    ; yp
  push  de    ; xp
  subw  sp,#4   ; tmp
  push  ax    ; retp
;
  mov a,[hl+7]  ; if (*yp_h != 0) then 16f
  or  a,[hl+6]
  or  a,[hl+5]
  or  a,[hl+4]
  skz
  br  $!16f
  movw  ax,[de+4] ; if (*xp_h == 0) then 0b
  movw  bc,ax
  movw  ax,[de+6]
  or  a,x
  or  a,c
  or  a,b
  bz  $0b

#ifdef __RL78_S3__
  ; *xp_h % *yp_l -> rem1
  movw  ax,[de+6] ; bcax = *xp_h
  movw  bc,ax
  movw  ax,[de+4]
  push  ax
  movw  ax,[hl]   ; hlde = *yp_l
  movw  de,ax
  movw  ax,[hl+2]
  movw  hl,ax
  pop ax
  divwu     ; hlde:rem1
;
  movw  ax,hl   ; bc = rem1_h (not use if 2f)
  movw  bc,ax
  movw  ax,[sp+ypoff] ; if (*yp_lh == 0) then 2f
  movw  hl,ax
  movw  ax,[hl+2]
  or  x,a
  bz  $2f
  cmp0  a   ; if (*yp_lhh == 0) then 3f else 11f
  bz  $3f
  br  $!11f

2:     ; *retp = 64bit % 16bit
  ; rem1_l,*xp_lh % *yp_ll -> rem2(16bit)
  movw  ax,de   ; bc = rem1_l
  movw  bc,ax
  movw  ax,[sp+xpoff] ; ax = *xp_lh
  movw  de,ax
  movw  ax,[de+2]
  push  ax
  movw  ax,[sp+ypoff+2] ; de = *yp_ll
  movw  hl,ax
  movw  ax,[hl]
  movw  de,ax
  clrw  ax    ; hl = 0
  movw  hl,ax
  pop ax
  divwu     ; de:rem2
  ; rem2,*xp_ll % *yp_ll -> rem3(16bit)
  movw  ax,de   ; bc = rem2
  movw  bc,ax
  movw  ax,[sp+xpoff] ; ax = *xp_ll
  movw  de,ax
  movw  ax,[de]
  push  ax
  movw  ax,[sp+ypoff+2] ; de = *yp_ll
  movw  hl,ax
  movw  ax,[hl]
  movw  de,ax
  clrw  ax    ; hl = 0
  movw  hl,ax
  pop ax
  divwu     ; de:rem3
  pop hl    ; retp
  movw  ax,de   ; *retp_ll = rem3
  movw  [hl],ax
  clrw  ax    ; *retp_hh = *retp_hl = *retp_lh = 0
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret

3:     ; *retp = 64bit % 24bit
  ; rem1(24bit),*xp_lhh % *yp(24bit) -> rem2(24bit)
  shlw  bc,8    ; b = rem1_hl
  mov a,d   ; c = rem1_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_lhh
  movw  hl,ax
  mov a,[hl+3]
  mov x,a
  mov a,e   ; a = rem1_ll
  push  ax
  movw  ax,[sp+ypoff+2] ; hlde = *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  de,ax
  movw  ax,[hl+2]
  movw  hl,ax
  pop ax
  divwu     ; lde:rem2
  ; rem2(24bit),*xp_lhl % *yp(24bit) -> rem3(24bit)
  mov a,l   ; b = rem2_hl
  mov b,a
  mov a,d   ; c = rem2_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_lhl
  movw  hl,ax
  movw  ax,[hl+2] ; mov x,[hl+2]
  mov a,e   ; a = rem2_ll
  push  ax
  movw  ax,[sp+ypoff+2] ; hlde = *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  de,ax
  movw  ax,[hl+2]
  movw  hl,ax
  pop ax
  divwu     ; lde:rem3
  ; rem3(24bit),*xp_llh % *yp(24bit) -> rem4(24bit)
  mov a,l   ; b = rem3_hl
  mov b,a
  mov a,d   ; c = rem3_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_llh
  movw  hl,ax
  movw  ax,[hl]   ; mov x,[hl+1]
  mov x,a
  mov a,e   ; a = rem3_ll
  push  ax
  movw  ax,[sp+ypoff+2] ; hlde = *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  de,ax
  movw  ax,[hl+2]
  movw  hl,ax
  pop ax
  divwu     ; lde:rem4
  ; rem4_*xp_lll % *yp -> rem5(24bit)
  mov a,l   ; b = rem4_hl
  mov b,a
  mov a,d   ; c = rem4_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_lll
  movw  hl,ax
  movw  ax,[hl]   ; mov x,[hl]
  mov a,e   ; a = rem4_ll
  push  ax
  movw  ax,[sp+ypoff+2] ; hlde = *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  de,ax
  movw  ax,[hl+2]
  movw  hl,ax
  pop ax
  divwu     ; lde:rem5
  movw  ax,hl   ; *retp_l = rem5
  pop hl    ; retp
  movw  [hl+2],ax
  movw  ax,de
  movw  [hl],ax
  clrw  ax    ; *retp_h = 0
  movw  [hl+4],ax
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret
#else       // __MDA_ENABLED__
  ; *xp_h % *yp_l -> rem1
  movw  ax,[de+4] ; mda <- *xp_h
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax
  movw  ax,[de+6]
  movw  MDAH,ax
  movw  ax,[hl]   ; mdb <- *yp_l
  movw  MDBL,ax
  movw  ax,[hl+2]
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
4:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$4b
;
  movw  bc,!LOWW(MDCH)  ; bcde = rem1
  movw  de,!LOWW(MDCL)
  pop psw
;
  movw  ax,[sp+ypoff] ; if (*yp_lh == 0) then 2f
  movw  hl,ax
  movw  ax,[hl+2]
  or  x,a
  bz  $2f
  cmp0  a   ; if (*yp_lhh == 0) then 3f else 11f
  bz  $3f
  br  $!11f

2:     ; *retp = 64bit % 16bit
  ; rem1_l,*xp_lh % *yp_ll -> rem2(16bit)
  movw  ax,[sp+xpoff] ; MDAL <- *xp_lh
  movw  hl,ax
  movw  ax,[hl+2]
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax
  movw  ax,de   ; MDAH <- rem1_l
  movw  MDAH,ax
  movw  ax,[sp+ypoff+2] ; MDBL <- *yp_ll
  movw  hl,ax
  movw  ax,[hl]
  movw  MDBL,ax
  clrw  ax    ; MDBH <- 0
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
5:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$5b
;
  movw  de,!LOWW(MDCL)  ; de = rem2
  pop psw
  ; rem2,*xp_ll % *yp_ll -> rem3(16bit)
  movw  ax,[sp+xpoff] ; MDAL <- *xp_ll
  movw  hl,ax
  movw  ax,[hl]
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax
  movw  ax,de   ; MDAH <- rem2
  movw  MDAH,ax
  movw  ax,[sp+ypoff+2] ; MDBL <- *yp_ll
  movw  hl,ax
  movw  ax,[hl]
  movw  MDBL,ax
  clrw  ax    ; MDBH <- 0
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
6:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$6b
;
  movw  ax,!LOWW(MDCL)  ; ax = rem3
  pop psw
  pop hl    ; retp
  movw  [hl],ax   ; *retp_ll = rem3
  clrw  ax    ; *retp_hh = *retp_hl = *retp_lh = 0
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret

3:     ; *retp = 64bit % 24bit
  ; rem1(24bit),*xp_lhh % *yp(24bit) -> rem2(24bit)
  shlw  bc,8    ; b = rem1_hl
  mov a,d   ; c = rem1_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_lhh
  movw  hl,ax
  mov a,[hl+3]
  mov x,a
  mov a,e   ; a = rem1_ll
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDAL <- rem1_ll,*xp_lhh
  movw  ax,bc   ; MDAH <- rem1_hl,rem1_lh
  movw  MDAH,ax
  movw  ax,[sp+ypoff+2] ; mdb <- *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  MDBL,ax
  movw  ax,[hl+2]
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
7:
  mov a,!LOWW(MDUC) ; if (divst == 1) then wait
  bt  a.0,$7b
;
  movw  bc,!LOWW(MDCH)  ; cde = rem2
  movw  de,!LOWW(MDCL)
  pop psw
  ; rem2(24bit),*xp_lhl % *yp(24bit) -> rem3(24bit)
  shlw  bc,8    ; b = rem2_hl
  mov a,d   ; c = rem2_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_lhl
  movw  hl,ax
  movw  ax,[hl+2] ; mov x,[hl+2]
  mov a,e   ; a = rem2_ll
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDAL <- rem2_ll,*xp_lhl
  movw  ax,bc   ; MDAH <- rem2_hl,rem2_lh
  movw  MDAH,ax
  movw  ax,[sp+ypoff+2] ; mdb <- *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  MDBL,ax
  movw  ax,[hl+2]
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
8:
  mov a,!LOWW(MDUC) ; if (divst == 1) then wait
  bt  a.0,$8b
;
  movw  bc,!LOWW(MDCH)  ; cde = rem3
  movw  de,!LOWW(MDCL)
  pop psw
  ; rem3(24bit),*xp_llh % *yp(24bit) -> rem4(24bit)
  shlw  bc,8    ; b = rem3_hl
  mov a,d   ; c = rem3_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_llh
  movw  hl,ax
  movw  ax,[hl]   ; mov x,[hl+1]
  mov x,a
  mov a,e   ; a = rem3_ll
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDAL <- rem3_ll,*xp_llh
  movw  ax,bc   ; MDAH <- rem3_hl,rem3_lh
  movw  MDAH,ax
  movw  ax,[sp+ypoff+2] ; mdb <- *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  MDBL,ax
  movw  ax,[hl+2]
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
9:
  mov a,!LOWW(MDUC) ; if (divst == 1) then wait
  bt  a.0,$9b
;
  movw  bc,!LOWW(MDCH)  ; cde = rem4
  movw  de,!LOWW(MDCL)
  pop psw
  ; rem4_*xp_lll % *yp -> rem5(24bit)
  shlw  bc,8    ; b = rem4_hl
  mov a,d   ; c = rem4_lh
  mov c,a
  movw  ax,[sp+xpoff] ; x = *xp_lll
  movw  hl,ax
  movw  ax,[hl]   ; mov x,[hl]
  mov a,e   ; a = rem4_ll
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDAL <- rem4_ll,*xp_lll
  movw  ax,bc   ; MDAH <- rem4_hl,rem4_lh
  movw  MDAH,ax
  movw  ax,[sp+ypoff+2] ; mdb <- *yp
  movw  hl,ax
  movw  ax,[hl]
  movw  MDBL,ax
  movw  ax,[hl+2]
  movw  MDBH,ax
;
  mov !LOWW(MDUC),#0x081  ; divmode = 1, divst = 1
10:
  mov a,!LOWW(MDUC) ; if (divst == 1) then wait
  bt  a.0,$10b
;
  movw  bc,!LOWW(MDCH)  ; cax = rem5
  movw  ax,!LOWW(MDCL)
  pop psw
  pop hl    ; retp
  movw  [hl],ax   ; *retp_l = rem5
  movw  ax,bc
  movw  [hl+2],ax
  clrw  ax    ; *retp_h = 0
  movw  [hl+4],ax
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret
#endif

11:
  movw  ax,[sp+xpoff] ; xp
  xchw  ax,de   ; *xp_h(ret_l) = rem1
  movw  [de+4],ax
  movw  ax,bc
  movw  [de+6],ax
  movw  ax,[sp+ypoff] ; yp
  movw  hl,ax
  mov c,#32   ; loop_count = 32
12:
  movw  ax,[de]   ; *xp_l = *xp_l << 1
  addw  ax,ax
  movw  [de],ax
  movw  ax,[de+2]
  rolwc ax,1
  movw  [de+2],ax
  movw  ax,[de+4] ; *xp_h(ret_l) = *xp_h(ret_l) << 1
  rolwc ax,1
  movw  [de+4],ax
  movw  ax,[de+6]
  rolwc ax,1
  movw  [de+6],ax
  bc  $14f  ; if (*xp_h(ret_l) >= *yp_l) then 14f
  cmpw  ax,[hl+2] ; (33bit compair)
  bnz $13f
  movw  ax,[de+4]
  cmpw  ax,[hl+0]
13:
  bc  $15f
14:
  movw  ax,[de+4] ; *xp_h(ret_l) = *xp_h(ret_l) - *yp_l
  subw  ax,[hl+0]
  movw  [de+4],ax
  movw  ax,[de+6]
  sknc
  decw  ax
  subw  ax,[hl+2]
  movw  [de+6],ax
15:
  dec c   ; --loop_count
  bnz $12b
;
  pop hl    ; retp
  movw  ax,[de+4] ; *retp_l = *xp_h
  movw  [hl],ax
  movw  ax,[de+6]
  movw  [hl+2],ax
  clrw  ax    ; *retp_h = 0
  movw  [hl+4],ax
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret

16:
  movw  ax,[de+6] ; if (*xp < *yp) then *retp = *xp
  cmpw  ax,[hl+6] ; else if (*xp == *yp) then *retp = 0
  bnz $17f
  movw  ax,[de+4]
  cmpw  ax,[hl+4]
  bnz $17f
  movw  ax,[de+2]
  cmpw  ax,[hl+2]
  bnz $17f
  movw  ax,[de]
  cmpw  ax,[hl+0]
  bz  $18f
17:
  bnc $19f
;
  pop hl
  movw  ax,[de]
  movw  [hl],ax
  movw  ax,[de+2]
  movw  [hl+2],ax
  movw  ax,[de+4]
  movw  [hl+4],ax
  movw  ax,[de+6]
  movw  [hl+6],ax
  addw  sp,#8   ; tmp,xp,yp
  ret
18:
  pop hl
  clrw  ax
  movw  [hl+6],ax
  movw  [hl+4],ax
  movw  [hl+2],ax
  movw  [hl],ax
  addw  sp,#8   ; tmp,xp,yp
  ret

19:
  clrw  ax    ; tmp(rem_h) = 0
  movw  [sp+2],ax
  movw  [sp+4],ax
  mov c,#32   ; loop_count = 32
20:
  movw  ax,[de]   ; *xp_l = *xp_l << 1
  addw  ax,ax
  movw  [de],ax
  movw  ax,[de+2]
  rolwc ax,1
  movw  [de+2],ax
  movw  ax,[de+4] ; *xp_h(rem_l) = *xp_h(rem_l) << 1
  rolwc ax,1
  movw  [de+4],ax
  movw  ax,[de+6]
  rolwc ax,1
  movw  [de+6],ax
  movw  ax,[sp+2] ; tmp(rem_h) = tmp(rem_h) << 1
  rolwc ax,1
  movw  [sp+2],ax
  movw  ax,[sp+4]
  rolwc ax,1
  movw  [sp+4],ax
  cmpw  ax,[hl+6] ; if (rem >= *yp) then 22f
  bnz $21f
  movw  ax,[sp+2]
  cmpw  ax,[hl+4]
  bnz $21f
  movw  ax,[de+6]
  cmpw  ax,[hl+2]
  bnz $21f
  movw  ax,[de+4]
  cmpw  ax,[hl+0]
21:
  bc  $23f
22:
  movw  ax,[de+4] ; *xp_h(rem_l) = *xp_h(rem_l) - *yp_l
  subw  ax,[hl+0]
  movw  [de+4],ax
  movw  ax,[de+6]
  xch a,x
  subc  a,[hl+2]
  xch a,x
  subc  a,[hl+3]
  movw  [de+6],ax
  movw  ax,[sp+2] ; tmp(rem_h) = tmp(rem_h) - *yp_h
  xch a,x
  subc  a,[hl+4]
  xch a,x
  subc  a,[hl+5]
  movw  [sp+2],ax
  movw  ax,[sp+4]
  sknc
  decw  ax
  subw  ax,[hl+6]
  movw  [sp+4],ax
23:
  dec c   ; --loop_count
  bnz $20b
;
  pop hl    ; retp
  movw  ax,[de+4] ; *retp_l = *xp_h
  movw  [hl],ax
  movw  ax,[de+6]
  movw  [hl+2],ax
  pop ax    ; *retp_h = tmp
  movw  [hl+4],ax
  pop ax
  movw  [hl+6],ax
  addw  sp,#4   ; xp,yp
  ret
#else       // S1/S2
;
  ; this is the entrance to the function
  .globl __REL_llrem
  .type  __REL_llrem,@function
__REL_llrem:
  push  hl    ; yp
  push  de    ; xp
  subw  sp,#8   ; tmp
  push  ax    ; retp
;
  clrw  ax    ; tmp(rem) = 0
  movw  [sp+2],ax
  movw  [sp+4],ax
  movw  [sp+6],ax
  movw  [sp+8],ax
  mov c,#64   ; loop_count = 64
20:
  movw  ax,[de]   ; *xp = *xp << 1
  addw  ax,ax
  movw  [de],ax
  movw  ax,[de+2]
  rolwc ax,1
  movw  [de+2],ax
  movw  ax,[de+4]
  rolwc ax,1
  movw  [de+4],ax
  movw  ax,[de+6]
  rolwc ax,1
  movw  [de+6],ax
  movw  ax,[sp+2] ; tmp(rem) = tmp(rem) << 1
  rolwc ax,1
  movw  [sp+2],ax
  movw  ax,[sp+4]
  rolwc ax,1
  movw  [sp+4],ax
  movw  ax,[sp+6]
  rolwc ax,1
  movw  [sp+6],ax
  movw  ax,[sp+8]
  rolwc ax,1
  movw  [sp+8],ax
  cmpw  ax,[hl+6] ; if (tmp(rem) >= *yp) then 22f
  bnz $21f
  movw  ax,[sp+6]
  cmpw  ax,[hl+4]
  bnz $21f
  movw  ax,[sp+4]
  cmpw  ax,[hl+2]
  bnz $21f
  movw  ax,[sp+2]
  cmpw  ax,[hl+0]
21:
  bc  $23f
22:
  movw  ax,[sp+2] ; tmp(rem) = tmp(rem) - *yp
  subw  ax,[hl+0]
  movw  [sp+2],ax
  movw  ax,[sp+4]
  xch a,x
  subc  a,[hl+2]
  xch a,x
  subc  a,[hl+3]
  movw  [sp+4],ax
  movw  ax,[sp+6]
  xch a,x
  subc  a,[hl+4]
  xch a,x
  subc  a,[hl+5]
  movw  [sp+6],ax
  movw  ax,[sp+8]
  sknc
  decw  ax
  subw  ax,[hl+6]
  movw  [sp+8],ax
23:
  dec c   ; --loop_count
  bnz $20b
;
  pop hl    ; retp
  pop ax    ; *retp = tmp
  movw  [hl],ax
  pop ax
  movw  [hl+2],ax
  pop ax
  movw  [hl+4],ax
  pop ax
  movw  [hl+6],ax
  addw  sp,#4   ; xp,yp
  ret
#endif
.Lfunc_end1:
  .size __REL_llrem, .Lfunc_end1-__REL_llrem
