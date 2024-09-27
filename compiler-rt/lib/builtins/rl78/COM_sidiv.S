//===-- COM_sidiv.s - Implement _COM_sidiv --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_sidiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_sidiv
//
//	int _COM_sidiv(int x, int y);
//
//	input:
//		x = AX
//		y = BC
//	output:
//		AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_sidiv
  $IFN(_RL78_S3)
  .EXTERN __COM_uidiv
  $ENDIF
  
  .text

.L_ZERODIV:
  DECW AX
  RET
__COM_sidiv:
  $IF(_RL78_S3)
  MOVW DE, AX
  CLRW AX
  CMPW AX, BC
#ifdef __OPTIMIZE_SIZE__
  BZ $.L_ZERODIV
#else  
  SKNZ
  BR $.L_ZERODIV
#endif
  MOVW HL, AX
  MOVW AX, BC
  BF A.7, $.L1
  INC L
  CLRW AX
  SUBW AX, BC
.L1:
  XCHW AX, DE
  BF A.7, $.L2
  INC L
  MOVW BC, AX
  CLRW AX
  SUBW AX, BC
.L2:
  DIVHU
  DEC L
  BNZ $.L_END
  MOVW BC, AX
  CLRW AX
  SUBW AX, BC
.L_END:
  RET
  $ELSE
  MOVW DE, AX
  CLRW AX
  CMPW AX, BC
  BZ $.L_ZERODIV
  MOVW HL, AX
  MOVW AX, BC
  BF A.7, $.L1
  INC L
  CLRW AX
  SUBW AX, BC
  MOVW BC, AX
.L1:
  MOVW AX, DE
  BF A.7, $.L2
  INC L
  CLRW AX
  SUBW AX, DE
.L2:
  $IF(_XMULDIV)
  CALL !!__COM_uidiv
  $ELSE
  PUSH HL
  CALL !!__COM_uidiv
  POP HL
  $ENDIF
  DEC L
  BNZ $.L_END
  MOVW BC, AX
  CLRW AX
  SUBW AX, BC
.L_END:
  RET
  $ENDIF
.Lfunc_end1:
  .size __COM_sidiv, .Lfunc_end1-__COM_sidiv

  .weak  ___divhi3
  .type  ___divhi3,@function
  .set  ___divhi3, __COM_sidiv
