//===-- RL78FixupKinds.h - RL78 Specific Fixup Entries --------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78FIXUPKINDS_H
#define LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78FIXUPKINDS_H

#include "llvm/MC/MCFixup.h"

namespace llvm {
namespace RL78 {
enum Fixups {
  fixup_RL78_DIR8S_PCREL = FirstTargetFixupKind,
  fixup_RL78_DIR16S_PCREL,
  fixup_RL78_DIR3U,
  fixup_RL78_DIR8U,
  fixup_RL78_DIR8U_SAD,
  fixup_RL78_DIR8UW_SAD,
  fixup_RL78_DIR16U,
  fixup_RL78_DIR16U_RAM,
  fixup_RL78_DIR16UW_RAM,
  fixup_RL78_DIR20U,
  fixup_RL78_DIR20U_16,
  fixup_RL78_DIR20UW_16,
  fixup_RL78_DIR32U,
  fixup_RL78_DIR_CALLT,
  fixup_RL78_SYM,
  fixup_RL78_OPsctsize,
  fixup_RL78_OPscttop,
  fixup_RL78_OPsub,
  fixup_RL78_OPadd,
  fixup_RL78_OPlowH,
  fixup_RL78_OPlowL,
  fixup_RL78_OPhighW,
  fixup_RL78_OPlowW,
  fixup_RL78_OPhighW_MIR,
  fixup_RL78_OPlowW_MIR,
  fixup_RL78_OPlowW_SMIR,
  fixup_RL78_OPABSlowH,
  fixup_RL78_OPABSlowL,
  fixup_RL78_OPABShighW,
  fixup_RL78_OPABSlowW,
  fixup_RL78_ABS3U,
  fixup_RL78_ABS8U,
  fixup_RL78_ABS16U,
  fixup_RL78_ABS16UW,
  fixup_RL78_ABS20U,
  fixup_RL78_ABS32U,

  // Marker
  LastTargetFixupKind,
  NumTargetFixupKinds = LastTargetFixupKind - FirstTargetFixupKind
};
}
} // end namespace llvm

#endif
