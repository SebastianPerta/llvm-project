//====- RL78MCExpr.h - RL78 specific MC expression classes --*- C++ -*-=====//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file describes RL78-specific MCExprs, used for modifiers like
// "%hi" or "%lo" etc.,
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78MCEXPR_H
#define LLVM_LIB_TARGET_RL78_MCTARGETDESC_RL78MCEXPR_H

#include "RL78FixupKinds.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/MC/MCExpr.h"

namespace llvm {

class StringRef;
class RL78MCExpr : public MCTargetExpr {
public:
  enum VariantKind {
    VK_RL78_None,
    VK_RL78_SADW,
    VK_RL78_HIGH,
    VK_RL78_LOW,
    VK_RL78_HIGHW,
    VK_RL78_LOWW,
    VK_RL78_MIRHW,
    VK_RL78_MIRLW,
    VK_RL78_SMRLW,
    VK_RL78_STARTOF,
    VK_RL78_SIZEOF,
    VK_RL78_BITPOSITIONAL,
    VK_RL78_IMM_SYM,
    VK_RL78_REL_DIFF,
    VK_RL78_FUNCTION,

    VK_RL78_LAST
  };

private:
  const VariantKind VKind;
  const MCExpr *Expr;
  const MCExpr *BitPositionExpr;


  explicit RL78MCExpr(VariantKind Kind, const MCExpr *Expr)
      : VKind(Kind), Expr(Expr) {}

  explicit RL78MCExpr(VariantKind Kind, const MCExpr *AddressExpr,
                      const MCExpr *BitPositionExpr)
      : VKind(Kind), Expr(AddressExpr), BitPositionExpr(BitPositionExpr) {}

  struct ConversionStatus {
    bool Success = false;
    const MCExpr *SymWithPossibleOffset = nullptr;
    int64_t Constant = 0;
    bool IsAbsolute = false;
    bool AllowOnlyAbsPlusMinus = false;
    RL78MCExpr::VariantKind VariantKind = RL78MCExpr::VK_RL78_None;
    bool WasSizeOfPlusStartOf = false;
  };
  static ConversionStatus
  ConvertExpressionToFixups(const MCExpr *Expression,
                            SmallVectorImpl<MCFixup> &fixups, bool &NeedsPop,
                            unsigned FixupFromOp, MCContext &Ctx, SMLoc Loc,
                            int64_t offset, RL78::Fixups &DirectFixup);
  static ConversionStatus
  HandleBinaryRelAbsOp(const MCExpr *SymWithPossibleOffset, int64_t Abs,
                       RL78MCExpr::ConversionStatus &CurrentStatus,
                       bool &NeedsPop, SmallVectorImpl<MCFixup> &fixups,
                       MCContext &Ctx, SMLoc Loc, int64_t offset, bool IsAdd);

public:
  /// @name Construction
  /// @{

  static const RL78MCExpr *create(VariantKind Kind, const MCExpr *Expr,
                                  MCContext &Ctx);
  /// @}
  /// @name Accessors
  /// @{

  /// getOpcode - Get the kind of this expression.
  VariantKind getVariantKind() const { return VKind; }

  /// getSubExpr - Get the child of this expression.
  const MCExpr *getSubExpr() const { return Expr; }
 
  const MCExpr *getBitPositionalAddressSubExpr() const { return Expr; }
  const MCExpr *getBitPositionalBitPostionSubExpr() const { return BitPositionExpr; }

  /// getFixupKind - Get the fixup kind of this expression.
  bool getFixupForKind(RL78::Fixups &Fixup, bool IsPopPush,
                       unsigned FixupFromOp) const {
    return getFixupForKind(VKind, Fixup, IsPopPush, FixupFromOp);
  }

  /// @}
  void printImpl(raw_ostream &OS, const MCAsmInfo *MAI) const override;
  bool evaluateAsRelocatableImpl(MCValue &Res, const MCAsmLayout *Layout,
                                 const MCFixup *Fixup) const override;
  void visitUsedExpr(MCStreamer &Streamer) const override;
  MCFragment *findAssociatedFragment() const override {
    return getSubExpr()->findAssociatedFragment();
  }

  void fixELFSymbolsInTLSFixups(MCAssembler &Asm) const override {};

  static bool classof(const MCExpr *E) {
    return E->getKind() == MCExpr::Target;
  }

  static bool classof(const RL78MCExpr *) { return true; }

  static bool printVariantKind(raw_ostream &OS, VariantKind Kind);
  static bool getFixupForKind(VariantKind Kind, RL78::Fixups &Fixup, bool IsPopPush, unsigned FixupFromOp);
  static bool isTargetExpr(const MCExpr *Value);
  static bool FoldBitPositionalExpression(const MCExpr *Value,
                                          MCValue &AddressValue,
                                          int64_t &BitPosition, MCContext &Ctx);
  static void createFixupsForExpression(const MCExpr *expression,
                                        int64_t offset,
                                        unsigned resultSize,
                                        SmallVectorImpl<MCFixup> &fixups,
                                        bool IsTopLevelExpression,
                                        unsigned FixupFromOp,
                                        MCContext &Ctx,
                                        SMLoc Loc);
};

} // end namespace llvm.

#endif
