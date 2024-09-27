//===--- RL78.cpp - RL78 Helpers for Tools --------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RL78.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/Driver/Options.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Support/raw_ostream.h"
#include "ToolChains/CommonArgs.h"

using namespace clang::driver;
using namespace clang::driver::tools;
using namespace clang;
using namespace llvm::opt;


void rl78::getRL78TargetFeatures(const Driver &D, const llvm::Triple &Triple,
                            const llvm::opt::ArgList &Args,
                            std::vector<llvm::StringRef> &Features) {

  StringRef cpu = getRL78Cpu(Args, Triple);
  const Arg *disableMDA = Args.getLastArg(options::OPT_mdisable_mda);
  const Arg *mCode = Args.getLastArg(options::OPT_mnear_code, options::OPT_mfar_code);

  bool isS2 = cpu.equals_insensitive("s2");
  
  bool mdaDisabled = disableMDA;

  if (!isS2 && mdaDisabled) {
    D.Diag(diag::err_drv_cannot_mix_options) << cpu << "-mdisable-mda";
    return;
  }

  // Add any that the user explicitly requested on the command line,
  // which may override the defaults.
  handleTargetFeaturesGroup(D, Triple, Args, Features, options::OPT_m_rl78_Features_Group);

  //if(!D.CCCIsCXX() && !mCode && !coreName.equals_lower("s1")) {
  //    Features.push_back("+far-code");
  //}

  if(mCode && mCode->getOption().getID() == options::OPT_mnear_code) {
    Features.push_back("-far-code");
    Features.erase(std::remove(Features.begin(), Features.end(), "+near-code"), Features.end());
  }
  const Arg *mData = Args.getLastArg(options::OPT_mnear_data, options::OPT_mfar_data);
  if(mData && mData->getOption().getID() == options::OPT_mnear_data) {
      Features.push_back("-far-data");
      Features.erase(std::remove(Features.begin(), Features.end(), "+near-data"), Features.end());
    }
}

StringRef rl78::getRL78Cpu(const llvm::opt::ArgList &Args,
                              const llvm::Triple &Triple) {
    assert(Triple.isRL78() && "Unexpected triple");

    if (const Arg *A = Args.getLastArg(options::OPT_mcpu_EQ))
        return A->getValue();
    // Default cpu is S3.
    return "s3";
}

bool rl78::getRL78OptSize(const llvm::opt::ArgList &Args,
                          const llvm::Triple &Triple) {
    assert(Triple.isRL78() && "Unexpected triple");
    if (const Arg *optimizeOpt = Args.getLastArg(options::OPT_O)) {
        StringRef Opt = optimizeOpt->getValue();
        return Opt == "s" || Opt == "z";
    }
    // Default is not optimize for size.
    return false;
}

StringRef rl78::getRL78CodeModel(const llvm::opt::ArgList &Args,
                                 const llvm::Triple &Triple) {
    assert(Triple.isRL78() && "Unexpected triple");

    const Arg *mCode =
        Args.getLastArg(options::OPT_mnear_code, options::OPT_mfar_code);
    if (mCode && mCode->getOption().getID() == options::OPT_mfar_code)
        return "mfar-code";
    // Default is near-code.
    return "mnear-code";
}

StringRef rl78::getRL78DataModel(const llvm::opt::ArgList &Args,
                                 const llvm::Triple &Triple) {
  assert(Triple.isRL78() && "Unexpected triple");

  const Arg *mData =
      Args.getLastArg(options::OPT_mnear_data, options::OPT_mfar_data);
  if (mData && mData->getOption().getID() == options::OPT_mfar_data)
    return "mfar-data";
  // Default is near-data.
  return "mnear-data";
}

StringRef rl78::getRL78DoubleSize(const llvm::opt::ArgList &Args,
                                  const llvm::Triple &Triple) {
    assert(Triple.isRL78() && "Unexpected triple");

    if (const Arg *BitDoubles = Args.getLastArg(options::OPT_m64bit_doubles))
        return "m64bit-doubles";
    // Default is 32 bit.
    return "m32bit-doubles";
}


StringRef rl78::getRL78DisableMDA(const llvm::opt::ArgList &Args,
                              const llvm::Triple &Triple) {
    assert(Triple.isRL78() && "Unexpected triple");

    if (const Arg *BitDoubles = Args.getLastArg(options::OPT_mdisable_mda))
        return "mdisable-mda";
    // Default is enabled, but we don't have a flag for it.
    return "";
}