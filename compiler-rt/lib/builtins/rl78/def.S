//===-- def.S - Define common values --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifdef __RL78_S3__
    _RL78_S3	.EQU	1
    _XMAC		.EQU	0
    _XMULDIV	.EQU	0
    _XMUL		.EQU	0
    MACRH		.EQU	0xFFFF2
    MACRL		.EQU	0xFFFF0
#else
    _RL78_S3	.EQU	0
    #ifdef  __MDA_ENABLED__
        _XMAC		.EQU	1
        _XMULDIV	.EQU	1
        _XMUL		.EQU	1
        MDAL		.EQU	0xFFFF0
        MDAH		.EQU	0xFFFF2
        MDBL		.EQU	0xFFFF6
        MDBH		.EQU	0xFFFF4
        MDCL		.EQU	0xF00E0
        MDCH		.EQU	0xF00E2
        MDUC		.EQU	0xF00E8
    #else
        _XMAC		.EQU	0
        #ifdef  XMULDIV
            _XMULDIV	.EQU	1
            _XMUL		.EQU	1
        #else
            _XMULDIV	.EQU	0
            #ifdef  XMUL
                _XMUL		.EQU	1
            #else
                _XMUL		.EQU	0
            #endif
        #endif
    #endif
#endif

#ifdef DBL4
    _DBL4		.EQU	1
#else
    _DBL4		.EQU	0
#endif