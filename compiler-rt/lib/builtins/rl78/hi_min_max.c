//===-- hi_min_max.c - Implement hi (u/s)min/(u/s)max -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements hi (u/s)min/(u/s)max for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#include "../int_lib.h"

COMPILER_RT_ABI signed int __smax(signed int a, signed int b) {
  return a >= b ? a : b;
}

COMPILER_RT_ABI signed int __smin(signed int a, signed int b) {
  return a <= b ? a : b;
}

COMPILER_RT_ABI unsigned int __umax(unsigned int a, unsigned int b) {
  return a >= b ? a : b;
}

COMPILER_RT_ABI unsigned int __umin(unsigned int a, unsigned int b) {
  return a <= b ? a : b;
}
