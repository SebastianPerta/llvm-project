//===-- RL78TargetStreamer.h - RL78 Target Streamer ----------*- C++ -*--===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78TARGETSTREAMER_H
#define LLVM_LIB_TARGET_RL78_RL78TARGETSTREAMER_H

#include "llvm/MC/MCELFStreamer.h"
#include "llvm/Support/FormattedStream.h"

namespace llvm {

class RL78ELFStreamer : public MCELFStreamer {

public:
  RL78ELFStreamer(MCContext &Context, std::unique_ptr<MCAsmBackend> TAB,
                  std::unique_ptr<MCObjectWriter> OW,
                  std::unique_ptr<MCCodeEmitter> Emitter);
  ~RL78ELFStreamer() override = default;

  // We override this to align text to 1 bytes
  void initSections(bool NoExecStack, const MCSubtargetInfo &STI) override;

  // We override this to be able to emit multiple fixups for a data directive
  void emitValueImpl(const MCExpr *Value, unsigned Size,
                     SMLoc Loc = SMLoc()) override;
};

class RL78TargetStreamer : public MCTargetStreamer {
  virtual void anchor();

public:
  RL78TargetStreamer(MCStreamer &S);
  /// Emit register name.
  virtual void emitRL78RegisterName(unsigned reg) = 0;
};

// This part is for ascii assembly output
class RL78TargetAsmStreamer : public RL78TargetStreamer {
  formatted_raw_ostream &OS;

public:
  RL78TargetAsmStreamer(MCStreamer &S, formatted_raw_ostream &OS);
  void emitRL78RegisterName(unsigned reg) override;
};

// This part is for ELF object output
class RL78TargetELFStreamer : public RL78TargetStreamer {
public:
  RL78TargetELFStreamer(MCStreamer &S, const MCSubtargetInfo &STI);
  MCELFStreamer &getStreamer();
  void emitRL78RegisterName(unsigned reg) override {}
};
} // end namespace llvm

#endif
