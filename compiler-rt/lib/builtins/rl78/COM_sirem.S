//===-- COM_sirem.s - Implement _COM_sirem --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_sirem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
//	_COM_sirem
//
//	int _COM_sirem(int x, int y);
//
//	input:
//		x = AX
//		y = BC
//	output:
//		AX
//===----------------------------------------------------------------------===//
  #include "def.S"
  
  .PUBLIC __COM_sirem
  $IFN(_RL78_S3)
  .EXTERN __COM_uirem
  $ENDIF
  
  .text

__COM_sirem:
  $IF(_RL78_S3)
  MOVW DE, AX
  CLRW AX
  CMPW AX, BC
#ifdef __OPTIMIZE_SIZE__
  BZ $.L_END
#else  
  SKNZ
  BR $.L_END
#endif
  MOVW HL, AX
  MOVW AX, BC
  BF A.7, $.L1
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
  CLRW AX
  SUBW AX, DE
  RET
.L_END:
  MOVW AX, DE
  RET
  $ELSE
  MOVW HL, AX
  CLRW AX
  CMPW AX, BC
  XCHW AX, HL
#ifdef __OPTIMIZE_SIZE__
  BZ $.L_END
#else  
  SKNZ
  BR $.L_END
#endif
  BF A.7, $.L1
  INC L
  MOVW DE, AX
  CLRW AX
  SUBW AX, DE
.L1:
  XCHW AX, BC
  BF A.7, $.L2
  MOVW DE, AX
  CLRW AX
  SUBW AX, DE
.L2:
  XCHW AX, BC
  $IF(_XMULDIV)
  CALL !!__COM_uirem
  $ELSE
  PUSH HL
  CALL !!__COM_uirem
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
  .size __COM_sirem, .Lfunc_end1-__COM_sirem

  .weak ___modhi3
  .type ___modhi3,@function
  .set  ___modhi3, __COM_sirem
