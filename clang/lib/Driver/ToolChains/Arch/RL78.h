//===--- RISCV.h - RISCV-specific Tool Helpers ------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_ARCH_RL78_H
#define LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_ARCH_RL78_H

#include "clang/Driver/Driver.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Option/Option.h"
#include <string>
#include <vector>

namespace clang {
namespace driver {
namespace tools {
namespace rl78 {
void getRL78TargetFeatures(const Driver &D, const llvm::Triple &Triple,
                            const llvm::opt::ArgList &Args,
                            std::vector<llvm::StringRef> &Features);
StringRef getRL78Cpu(const llvm::opt::ArgList &Args,
                              const llvm::Triple &Triple);
bool getRL78OptSize(const llvm::opt::ArgList &Args,
                              const llvm::Triple &Triple);
StringRef getRL78CodeModel(const llvm::opt::ArgList &Args,
                              const llvm::Triple &Triple);
StringRef getRL78DataModel(const llvm::opt::ArgList &Args,
                           const llvm::Triple &Triple);
StringRef getRL78DoubleSize(const llvm::opt::ArgList &Args,
                              const llvm::Triple &Triple);
StringRef getRL78DisableMDA(const llvm::opt::ArgList &Args,
                              const llvm::Triple &Triple);

//TODO: do we need this for calling convention
//StringRef getRL78ABI(const llvm::opt::ArgList &Args,
//                      const llvm::Triple &Triple);
} // end namespace rl78
} // namespace tools
} // end namespace driver
} // end namespace clang

#endif // LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_ARCH_RL78_H
