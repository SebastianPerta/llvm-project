//===-- RL78MCExpr.cpp - RL78 specific MC expression classes --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of the assembly expression modifiers
// accepted by the RL78 architecture (e.g. "%hi", "%lo", ...).
//
//===----------------------------------------------------------------------===//

#include "RL78MCExpr.h"
#include "RL78.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCObjectStreamer.h"
#include "llvm/MC/MCSymbolELF.h"
#include "llvm/MC/MCValue.h"
#include "llvm/ADT/StringExtras.h"
#include <set>

using namespace llvm;

#define DEBUG_TYPE "RL78mcexpr"

const RL78MCExpr *RL78MCExpr::create(VariantKind Kind, const MCExpr *Expr,
                                     MCContext &Ctx) {
  if (Kind == VK_RL78_BITPOSITIONAL) {
    if (Expr->getKind() != MCExpr::ExprKind::Binary)
      llvm_unreachable("Bad VK_RL78_BITPOSITIONAL expression");
    const MCBinaryExpr *BinExpr = cast<MCBinaryExpr>(Expr);
    return new (Ctx) RL78MCExpr(Kind, BinExpr->getLHS(), BinExpr->getRHS());
  }
  return new (Ctx) RL78MCExpr(Kind, Expr);
}

void RL78MCExpr::printImpl(raw_ostream &OS, const MCAsmInfo *MAI) const {
  bool closeParen = printVariantKind(OS, VKind);

  const MCExpr *Expr = getSubExpr();
  Expr->print(OS, MAI);

  if (closeParen)
    OS << ')';
}

bool RL78MCExpr::printVariantKind(raw_ostream &OS, VariantKind Kind) {
  bool closeParen = true;
  switch (Kind) {
  default:
    closeParen = false;
    break;
  case VK_RL78_HIGH:
    OS << "HIGH(";
    break;
  case VK_RL78_LOW:
    OS << "LOW(";
    break;
  case VK_RL78_HIGHW:
    OS << "HIGHW(";
    break;
  case VK_RL78_LOWW:
    OS << "LOWW(";
    break;
  case VK_RL78_MIRHW:
    OS << "MIRHW(";
    break;
  case VK_RL78_MIRLW:
    OS << "MIRLW(";
    break;
  case VK_RL78_SMRLW:
    OS << "SMRLW(";
    break;
  case VK_RL78_STARTOF:
    OS << "STARTOF(";
    break;
  case VK_RL78_SIZEOF:
    OS << "SIZEOF(";
    break;
  }
  return closeParen;
}

bool RL78MCExpr::getFixupForKind(RL78MCExpr::VariantKind Kind, RL78::Fixups &Fixup,
                                         bool IsPopPush, unsigned FixupFromOp) {
  switch (Kind) {
  default:
    return false;
  case VK_RL78_SADW:
    if (IsPopPush)
      // Can't be PopPush, since we are generating it in a single place
      return false;
    else {
      // Allow the op to decide between fixup_RL78_DIR8UW_SAD
      //  and fixup_RL78_DIR8U_SAD
      Fixup = (RL78::Fixups)FixupFromOp;
      return true;
    }
  case VK_RL78_HIGH:
    if (IsPopPush)
      Fixup = RL78::fixup_RL78_OPABSlowH;
    else
      Fixup = RL78::fixup_RL78_OPlowH;
    return true;
  case VK_RL78_LOW:
    if (IsPopPush)
      Fixup = RL78::fixup_RL78_OPABSlowL;
    else
      Fixup = RL78::fixup_RL78_OPlowL;
    return true;
  case VK_RL78_HIGHW:
    if (IsPopPush)
      Fixup = RL78::fixup_RL78_OPABShighW;
    else
      Fixup = RL78::fixup_RL78_OPhighW;
    return true;
  case VK_RL78_LOWW:
    if (IsPopPush)
      Fixup = RL78::fixup_RL78_OPABSlowW;
    else
      Fixup = RL78::fixup_RL78_OPlowW;
    return true;
  case VK_RL78_MIRHW:
    if (IsPopPush) // TODO detect this at parsing stage?
      return false;
    else
      Fixup = RL78::fixup_RL78_OPhighW_MIR;
    return true;
  case VK_RL78_MIRLW:
    if (IsPopPush) // TODO detect this at parsing stage?
      return false;
    else
      Fixup = RL78::fixup_RL78_OPlowW_MIR;
    return true;
  case VK_RL78_SMRLW:
    if (IsPopPush) // TODO detect this at parsing stage?
      return false;
    Fixup = RL78::fixup_RL78_OPlowW_SMIR;
    return true;
  case VK_RL78_STARTOF:
    if (IsPopPush) // TODO detect this at parsing stage?
      return false;
    else
      Fixup = RL78::fixup_RL78_OPscttop;
    return true;
  case VK_RL78_SIZEOF:
    if (IsPopPush)
      return false;
    else
      Fixup = RL78::fixup_RL78_OPsctsize;
    return true;
  case VK_RL78_FUNCTION:
    if (IsPopPush)
      return false;
    else
      Fixup = RL78::fixup_RL78_DIR16U;
    return true;
  }
}

bool GetAbsValueForVariant(RL78MCExpr::VariantKind Kind, int64_t &AbsVal) {
  switch (Kind) {
  default:
    llvm_unreachable("Unhandled RL78MCExpr::VariantKind");
  case RL78MCExpr::VK_RL78_None:
    llvm_unreachable("VK_RL78_None is invalid");
  case RL78MCExpr::VK_RL78_HIGH:
    AbsVal = (AbsVal >> 8) & 0xFF;
    break;
  case RL78MCExpr::VK_RL78_LOW:
    AbsVal = AbsVal & 0xFF;
    break;
  case RL78MCExpr::VK_RL78_HIGHW:
  // TODO: for now we emit a warning and treat it like HIGHW
  case RL78MCExpr::VK_RL78_MIRHW:
    AbsVal = (AbsVal >> 16) & 0xFFFF;
    break;
  case RL78MCExpr::VK_RL78_LOWW:
  case RL78MCExpr::VK_RL78_SMRLW:
  // TODO: for VK_RL78_MIRLW we emit a warning and treat it like LOWW
  // CC-RL uses the device file to know the mirror start address and to
  // correctly transform this.
  case RL78MCExpr::VK_RL78_MIRLW:
    AbsVal = AbsVal & 0xFFFF;
    break;
  case RL78MCExpr::VK_RL78_STARTOF:
  case RL78MCExpr::VK_RL78_SIZEOF:
  case RL78MCExpr::VK_RL78_BITPOSITIONAL:
    return false;
  }
  return true;
}


bool RL78MCExpr::evaluateAsRelocatableImpl(MCValue &Res,
                                           const MCAsmLayout *Layout,
                                           const MCFixup *Fixup) const {

  bool subExprRelocatable =
      getSubExpr()->evaluateAsRelocatable(Res, Layout, Fixup);
  if (!subExprRelocatable)
    return false;

  // evaluateAsAbsolute() and evaluateAsValue() require that we evaluate the
  // %hi/%lo/etc. here. Fixup is a null pointer when either of these is the
  // caller.
  if (Res.isAbsolute() && Fixup == nullptr) {
    int64_t AbsVal = Res.getConstant();
   if(!GetAbsValueForVariant(VKind, AbsVal))
       return false;
    Res = MCValue::get(AbsVal);
    return true;
  }

  if (VKind == VariantKind::VK_RL78_IMM_SYM) {
    Res = MCValue::get(cast<MCSymbolRefExpr>(getSubExpr()), nullptr, 0, VKind);
    return true;
  }

  // We want to defer it for relocatable expressions since the constant is
  // applied to the whole symbol value.
  //
  // The value of getKind() that is given to MCValue is only intended to aid
  // debugging when inspecting MCValue objects. It shouldn't be relied upon
  // for decision making.
  Res =
      MCValue::get(Res.getSymA(), Res.getSymB(), Res.getConstant(), VKind);

  return true;
}

void RL78MCExpr::visitUsedExpr(MCStreamer &Streamer) const {
  Streamer.visitUsedExpr(*getSubExpr());
}

bool RL78MCExpr::isTargetExpr(const MCExpr *expression) {
  switch (expression->getKind())
  {
  case MCExpr::Target:
          return true;
  case MCExpr::Binary: {
      const MCBinaryExpr *BinaryExpr = static_cast<const MCBinaryExpr *>(expression);
      return isTargetExpr(BinaryExpr->getLHS()) || 
             isTargetExpr(BinaryExpr->getRHS());
  }
  case MCExpr::Unary: {
      const MCUnaryExpr *UnaryExpr = static_cast<const MCUnaryExpr *>(expression);
      return isTargetExpr(UnaryExpr->getSubExpr());
  }
  default:
    return false;   
  }
}

bool ExecuteOperation(int64_t &Result, int64_t LHS, int64_t RHS,
                      MCBinaryExpr::Opcode Op) {
  switch (Op) {
  case MCBinaryExpr::AShr:
    Result = LHS >> RHS;
    break;
  case MCBinaryExpr::Add:
    Result = LHS + RHS;
    break;
  case MCBinaryExpr::And:
    Result = LHS & RHS;
    break;
  case MCBinaryExpr::Div:
    if (RHS == 0)
      return false;
    Result = LHS / RHS;
    break;
  case MCBinaryExpr::Mod:
    if (RHS == 0)
      return false;
    Result = LHS % RHS;
    break;
  case MCBinaryExpr::EQ:
    Result = LHS == RHS;
    break;
  case MCBinaryExpr::GT:
    Result = LHS > RHS;
    break;
  case MCBinaryExpr::GTE:
    Result = LHS >= RHS;
    break;
  case MCBinaryExpr::LAnd:
    Result = LHS && RHS;
    break;
  case MCBinaryExpr::LOr:
    Result = LHS || RHS;
    break;
  case MCBinaryExpr::LShr:
    Result = uint64_t(LHS) >> uint64_t(RHS);
    break;
  case MCBinaryExpr::LT:
    Result = LHS < RHS;
    break;
  case MCBinaryExpr::LTE:
    Result = LHS <= RHS;
    break;
  case MCBinaryExpr::Mul:
    Result = LHS * RHS;
    break;
  case MCBinaryExpr::NE:
    Result = LHS != RHS;
    break;
  case MCBinaryExpr::Or:
    Result = LHS | RHS;
    break;
  case MCBinaryExpr::Shl:
    Result = uint64_t(LHS) << uint64_t(RHS);
    break;
  case MCBinaryExpr::Sub:
    Result = LHS - RHS;
    break;
  case MCBinaryExpr::Xor:
    Result = LHS ^ RHS;
    break;
  default:
    return false;
  }
  return true;
}

bool RL78MCExpr::FoldBitPositionalExpression(const MCExpr *Value,
                                             MCValue &AddressValue,
                                             int64_t &BitPosition,
                                             MCContext &Ctx) {
  // At this point we assume that somewhere in the expression there is a bit
  // positional.
  switch (Value->getKind()) {
  case MCExpr::Target: {
    const RL78MCExpr *TargetExpr = static_cast<const RL78MCExpr *>(Value);
    if (TargetExpr->getVariantKind() == VK_RL78_BITPOSITIONAL) {
      return TargetExpr->getBitPositionalAddressSubExpr()
                 ->evaluateAsRelocatable(AddressValue, nullptr, nullptr) &&
             TargetExpr->getBitPositionalBitPostionSubExpr()
                 ->evaluateAsAbsolute(BitPosition);
    }
    break;
  }
  case MCExpr::Binary: {
    const MCBinaryExpr *BinaryExpr = static_cast<const MCBinaryExpr *>(Value);
    MCBinaryExpr::Opcode Op = BinaryExpr->getOpcode();
    // The order counts:
    // Const + Addr.Bitpos -> (Const + Addr).Bitpos
    // Addr.Bitpos + Const  -> Addr.(Bitpos + Const)

    MCValue RHSAddressValue, LHSAddressValue;
    int64_t RHSBitPosition = -1, LHSBitPosition = -1;
    int64_t AbsAddress;

    if (FoldBitPositionalExpression(BinaryExpr->getRHS(), RHSAddressValue,
                                    RHSBitPosition, Ctx) &&
        FoldBitPositionalExpression(BinaryExpr->getLHS(), LHSAddressValue,
                                    LHSBitPosition, Ctx)) {

      // Forbidden combinations:
      // A1.X OpCode A2.X
      // A1.X OpCode Sym
      // Sym AnyOpExceptSub Sym.B
      // If we have a bit position, but RHS/LHS finds another
      if (LHSBitPosition != -1 && RHSBitPosition != -1 ||
          LHSBitPosition != -1 && !RHSAddressValue.isAbsolute() ||
          !LHSAddressValue.isAbsolute() && !RHSAddressValue.isAbsolute() &&
              Op != MCBinaryExpr::Sub ||
          BitPosition != -1 && (LHSBitPosition != -1 || RHSBitPosition != -1))
        return false;

      BitPosition = RHSBitPosition != -1 ? RHSBitPosition : LHSBitPosition;

      if (LHSBitPosition == -1) {
        if (LHSAddressValue.isAbsolute() && RHSAddressValue.isAbsolute() &&
            ExecuteOperation(AbsAddress, LHSAddressValue.getConstant(),
                             RHSAddressValue.getConstant(), Op)) {
          // Const AnyOp Const(.B)
          AddressValue = MCValue::get(AbsAddress);
          return true;
        } else if (LHSAddressValue.isAbsolute() &&
                   !RHSAddressValue.isAbsolute() && Op == MCBinaryExpr::Add) {
          // Const + Sym(.B)
          AddressValue = MCValue::get(
              RHSAddressValue.getSymA(), RHSAddressValue.getSymB(),
              RHSAddressValue.getConstant() + LHSAddressValue.getConstant());
          return true;
        } else if (!LHSAddressValue.isAbsolute() &&
                   RHSAddressValue.isAbsolute() && Op == MCBinaryExpr::Sub) {
          // Sym - Const(.B)
          AddressValue = MCValue::get(
              LHSAddressValue.getSymA(), LHSAddressValue.getSymB(),
              LHSAddressValue.getConstant() - RHSAddressValue.getConstant());
          return true;
        }
      }

      if (!LHSAddressValue.isAbsolute() && !RHSAddressValue.isAbsolute() &&
          Op == MCBinaryExpr::Sub && !LHSAddressValue.getSymB() &&
          !RHSAddressValue.getSymB() && LHSBitPosition == -1) {
        // Sym - Sym(.B)
        AddressValue = MCValue::get(
            LHSAddressValue.getSymA(), RHSAddressValue.getSymA(),
            LHSAddressValue.getConstant() - RHSAddressValue.getConstant());
        BitPosition = RHSBitPosition;
        return true;
      }

      // SYM.B OpCode Const
      if (LHSBitPosition != -1 &&
          ExecuteOperation(BitPosition, LHSBitPosition,
                           RHSAddressValue.getConstant(), Op)) {
        AddressValue = LHSAddressValue;
        return true;
      }

      // Const + Const.B
      if (RHSBitPosition != -1 && LHSAddressValue.isAbsolute() &&
          RHSAddressValue.isAbsolute() &&
          ExecuteOperation(AbsAddress, LHSAddressValue.getConstant(),
                           RHSAddressValue.getConstant(), Op)) {
        AddressValue = MCValue::get(AbsAddress);
        return true;
      }
    }
    return false;
  }
  case MCExpr::Unary: {
    const MCUnaryExpr *UnaryExpr = static_cast<const MCUnaryExpr *>(Value);
    // we ignore the +, but error out on any other
    if (UnaryExpr->getOpcode() == MCUnaryExpr::Plus) {
      return FoldBitPositionalExpression(UnaryExpr->getSubExpr(), AddressValue,
                                         BitPosition, Ctx);
    } else {
      return false;
    }
  }
  default:
    break;
  }
  return Value->evaluateAsRelocatable(AddressValue, nullptr, nullptr);
}

RL78MCExpr::ConversionStatus RL78MCExpr::HandleBinaryRelAbsOp(
    const MCExpr *SymWithPossibleOffset, int64_t Abs,
    RL78MCExpr::ConversionStatus &CurrentStatus, bool &NeedsPop,
    SmallVectorImpl<MCFixup> &fixups, MCContext &Ctx, SMLoc Loc, int64_t offset,
    bool IsAdd) {
  if (Abs == 0) {
    // If offset modification is 0, do nothing.
    CurrentStatus.SymWithPossibleOffset = SymWithPossibleOffset;

  } else if (SymWithPossibleOffset) {
    // If it's not yet a nullptr, we can simply add/sub the offset
    if (IsAdd)
      CurrentStatus.SymWithPossibleOffset = MCBinaryExpr::createAdd(
          SymWithPossibleOffset, MCConstantExpr::create(Abs, Ctx), Ctx);
    else
      CurrentStatus.SymWithPossibleOffset = MCBinaryExpr::createSub(
          SymWithPossibleOffset, MCConstantExpr::create(Abs, Ctx), Ctx);
  } else {
    // Otherwise The symbol's value should be on the op stack already, we need
    // to create a symbol for the ABS, a fixup for it and the fixup for the
    // operation
    MCSymbol *AbsSymbol = Ctx.lookupSymbol("@$IMM_" + utostr(Abs));
    if (!AbsSymbol)
      return ConversionStatus();
    AbsSymbol->setUsedInReloc();
    NeedsPop = true;
    CurrentStatus.VariantKind = RL78MCExpr::VK_RL78_IMM_SYM;
    fixups.push_back(MCFixup::create(
        offset,
        RL78MCExpr::create(RL78MCExpr::VK_RL78_IMM_SYM,
                           MCSymbolRefExpr::create(AbsSymbol, Ctx), Ctx),
        (MCFixupKind)RL78::Fixups::fixup_RL78_SYM, Loc));
    fixups.push_back(
        MCFixup::create(offset, MCConstantExpr::create(0, Ctx),
                        (MCFixupKind)(IsAdd ? RL78::Fixups::fixup_RL78_OPadd
                                            : RL78::Fixups::fixup_RL78_OPsub),
                        Loc));
  }
  return CurrentStatus;
}

RL78MCExpr::ConversionStatus RL78MCExpr::ConvertExpressionToFixups(
    const MCExpr *Expression, SmallVectorImpl<MCFixup> &fixups, bool &NeedsPop,
    unsigned FixupFromOp, MCContext &Ctx, SMLoc Loc, int64_t offset,
    RL78::Fixups &DirectFixup) {
  ConversionStatus CurrentStatus;

  std::set<RL78MCExpr::VariantKind> VariantSet1 = {};
  std::set<RL78MCExpr::VariantKind> VariantSet2 = {};

  switch (Expression->getKind()) {
  case MCExpr::Constant: {
    const MCConstantExpr *ConstExpr = cast<MCConstantExpr>(Expression);
    return {/*Success*/ true, /*SymWithPossibleOffset*/ nullptr,
            /*Constant*/ ConstExpr->getValue(), /*IsAbsolute*/ true};
  }

  case MCExpr::SymbolRef: {
    const MCSymbolRefExpr *SymExpr = cast<MCSymbolRefExpr>(Expression);
    return {/*Success*/ true, /*SymWithPossibleOffset*/ SymExpr, /*Constant*/ 0,
            /*IsAbsolute*/ false};
  }

  case MCExpr::Target: {
    const RL78MCExpr *TargetExpr = cast<RL78MCExpr>(Expression);
    const MCExpr *SubExpr = TargetExpr->getSubExpr();
    RL78::Fixups Fixup;
    ConversionStatus SubStatus = ConvertExpressionToFixups(
        SubExpr, fixups, NeedsPop, FixupFromOp, Ctx, Loc, offset, DirectFixup);
    CurrentStatus.VariantKind = TargetExpr->getVariantKind();
    CurrentStatus.WasSizeOfPlusStartOf = SubStatus.WasSizeOfPlusStartOf;

    if (!SubStatus.Success ||
        !TargetExpr->getFixupForKind(
            Fixup, SubStatus.VariantKind != RL78MCExpr::VK_RL78_None,
            FixupFromOp))
      return ConversionStatus();

    // FXIME: hack which needs to be deleted when we get rid of the plt.
    // Remove DirectFixup from param list.
    if (CurrentStatus.VariantKind == VK_RL78_FUNCTION) {
      DirectFixup = Fixup;
      const MCSymbolRefExpr *SymExpr = cast<MCSymbolRefExpr>(SubExpr);
      return {/*Success*/ true,
              /*SymWithPossibleOffset*/ SymExpr,
              /*Constant*/ 0,
              /*IsAbsolute*/ false};
    }

    if (SubStatus.IsAbsolute) {
      CurrentStatus.Success = GetAbsValueForVariant(CurrentStatus.VariantKind,
                                                    CurrentStatus.Constant);
      CurrentStatus.IsAbsolute = true;
    } else {

      // TODO: uncomment datapos when we allow it to be relocateable
      const std::set<RL78MCExpr::VariantKind> CurrentExprSet1 = {
          VK_RL78_HIGH, VK_RL78_LOW, VK_RL78_HIGHW, VK_RL78_LOWW};
      const std::set<RL78MCExpr::VariantKind> SubExprSet1 = {
          VK_RL78_MIRHW, VK_RL78_MIRLW, VK_RL78_SMRLW /*, VK_RL78_DATAPOS*/};
      const std::set<RL78MCExpr::VariantKind> CurrentExprSet2 = {
          VK_RL78_MIRHW, VK_RL78_MIRLW, VK_RL78_SMRLW};
      const std::set<RL78MCExpr::VariantKind> SubExprSet2 = {
          VK_RL78_HIGH,  VK_RL78_LOW,   VK_RL78_HIGHW, VK_RL78_LOWW,
          VK_RL78_MIRHW, VK_RL78_MIRLW, VK_RL78_SMRLW /*,  VK_RL78_DATAPOS*/};
      // Note 1. Operation is possible when X is not relocatable terms operated
      // on by MIRHW, MIRLW, SMRLW, or DATAPOS. Note 2. Operation is possible
      // when X is not relocatable terms operated on by HIGH, LOW, HIGHW, LOWW,
      // MIRHW, MIRLW, SMRLW, or DATAPOS.

      if (CurrentExprSet1.find(CurrentStatus.VariantKind) !=
                  CurrentExprSet1.end() &&
              SubExprSet1.find(SubStatus.VariantKind) != SubExprSet1.end() ||
          CurrentExprSet2.find(CurrentStatus.VariantKind) !=
                  CurrentExprSet2.end() &&
              SubExprSet2.find(SubStatus.VariantKind) != SubExprSet2.end())
        return ConversionStatus();

      CurrentStatus.Success = true;
      CurrentStatus.IsAbsolute = false;
      CurrentStatus.AllowOnlyAbsPlusMinus = true;
      if (TargetExpr->getVariantKind() != RL78MCExpr::VK_RL78_SADW) {
        NeedsPop = (CurrentStatus.VariantKind != VK_RL78_FUNCTION);
        fixups.push_back(
            MCFixup::create(offset,
                            SubStatus.VariantKind == RL78MCExpr::VK_RL78_None
                                ? (SubStatus.SymWithPossibleOffset
                                       ? SubStatus.SymWithPossibleOffset
                                       : MCConstantExpr::create(0, Ctx))
                                : MCConstantExpr::create(0, Ctx),
                            (MCFixupKind)Fixup, Loc));
      } else {
        CurrentStatus.SymWithPossibleOffset = SubExpr;
      }
    }
    return CurrentStatus;
  }

  case MCExpr::Binary: {
    const MCBinaryExpr *BinaryExpr =
        static_cast<const MCBinaryExpr *>(Expression);
    MCBinaryExpr::Opcode Op = BinaryExpr->getOpcode();
    ConversionStatus LHS = ConvertExpressionToFixups(
        BinaryExpr->getLHS(), fixups, NeedsPop, FixupFromOp, Ctx, Loc, offset, DirectFixup);
    ConversionStatus RHS = ConvertExpressionToFixups(
        BinaryExpr->getRHS(), fixups, NeedsPop, FixupFromOp, Ctx, Loc, offset, DirectFixup);

    if (!LHS.Success || !RHS.Success || LHS.WasSizeOfPlusStartOf ||
        RHS.WasSizeOfPlusStartOf)
      return ConversionStatus();

    // Based on the CC-RL manual 5.1.14 (Table 5.8)
    // If both are absolute, all operations are permitted.
    if (LHS.IsAbsolute && RHS.IsAbsolute) {
      CurrentStatus.Success = ExecuteOperation(CurrentStatus.Constant,
                                               LHS.Constant, RHS.Constant, Op);
      CurrentStatus.IsAbsolute = true;
      return CurrentStatus;
    } else {
      const MCExpr *SymWithPossibleOffset = LHS.IsAbsolute
                                                ? RHS.SymWithPossibleOffset
                                                : LHS.SymWithPossibleOffset;
      int64_t Abs = LHS.IsAbsolute ? LHS.Constant : RHS.Constant;
      switch (Op) {
      case llvm::MCBinaryExpr::Add:
        if (!LHS.IsAbsolute && !RHS.IsAbsolute) {
          // STARTOF + SIZEOF is permitted as an exception
          if (LHS.VariantKind == RL78MCExpr::VK_RL78_STARTOF &&
                  RHS.VariantKind == RL78MCExpr::VK_RL78_SIZEOF ||
              RHS.VariantKind == RL78MCExpr::VK_RL78_STARTOF &&
                  LHS.VariantKind == RL78MCExpr::VK_RL78_SIZEOF) {
            NeedsPop = true;
            fixups.push_back(MCFixup::create(
                offset, MCConstantExpr::create(0, Ctx),
                (MCFixupKind)RL78::Fixups::fixup_RL78_OPadd, Loc));
            CurrentStatus.Success = true;
            CurrentStatus.WasSizeOfPlusStartOf = true;
            CurrentStatus.VariantKind = RL78MCExpr::VK_RL78_STARTOF;
            return CurrentStatus;
          }
          return ConversionStatus();
        } else {
          // ABS + REL
          // REL + ABS
          CurrentStatus.Success = true;
          return HandleBinaryRelAbsOp(SymWithPossibleOffset, Abs, CurrentStatus,
                                      NeedsPop, fixups, Ctx, Loc, offset, true);
        }
        break;
      case llvm::MCBinaryExpr::Sub:
        if (LHS.IsAbsolute) {
          // ABS - REL
          return ConversionStatus();
        } else if (RHS.IsAbsolute) {
          // REL - ABS
          CurrentStatus.Success = true;
          return HandleBinaryRelAbsOp(SymWithPossibleOffset, Abs, CurrentStatus,
                                      NeedsPop, fixups, Ctx, Loc, offset,
                                      false);
        } else if (LHS.AllowOnlyAbsPlusMinus || RHS.AllowOnlyAbsPlusMinus ||
                   !LHS.SymWithPossibleOffset || !RHS.SymWithPossibleOffset) {
          return ConversionStatus();
        } else {
          // REL - REL
          NeedsPop = true;
          CurrentStatus.Success = true;
          CurrentStatus.VariantKind = VK_RL78_REL_DIFF;
          fixups.push_back(
              MCFixup::create(offset, LHS.SymWithPossibleOffset,
                              (MCFixupKind)RL78::Fixups::fixup_RL78_SYM, Loc));
          fixups.push_back(
              MCFixup::create(offset, RHS.SymWithPossibleOffset,
                              (MCFixupKind)RL78::Fixups::fixup_RL78_SYM, Loc));
          fixups.push_back(MCFixup::create(
              offset, MCConstantExpr::create(0, Ctx),
              (MCFixupKind)RL78::Fixups::fixup_RL78_OPsub, Loc));
          return CurrentStatus;
        }

        break;
      default:
        return ConversionStatus();
        break;
      }
    }

    return ConversionStatus();
  }
  case MCExpr::Unary: {
    const MCUnaryExpr *UnaryExpr = static_cast<const MCUnaryExpr *>(Expression);
    int64_t Res;
    if (UnaryExpr->getOpcode() == MCUnaryExpr::Plus)
      return ConvertExpressionToFixups(UnaryExpr->getSubExpr(), fixups,
                                       NeedsPop, FixupFromOp, Ctx, Loc, offset,
                                       DirectFixup);
    if (UnaryExpr->getSubExpr()->evaluateAsAbsolute(Res)) {
      if (UnaryExpr->getOpcode() == MCUnaryExpr::Minus)
        Res = -Res;
      else if (UnaryExpr->getOpcode() == MCUnaryExpr::Not)
        Res = ~Res;
      else
        return ConversionStatus();
      CurrentStatus.Success = true;
      CurrentStatus.IsAbsolute = true;
      CurrentStatus.Constant = Res;
      return CurrentStatus;
    } else
      return ConversionStatus();
  }
  default:
    break;
  }
  return ConversionStatus();
}


void RL78MCExpr::createFixupsForExpression(const MCExpr *expression,
                                           int64_t offset,
                                           unsigned resultSizeInBits,
                                           SmallVectorImpl<MCFixup> &fixups,
                                           bool IsTopLevelExpression,
                                           unsigned FixupFromOp,
                                           MCContext &Ctx,
                                           SMLoc Loc) {
      RL78::Fixups PopFixup, DirectFixup;
      switch (resultSizeInBits) {
      case 3:
        PopFixup = RL78::fixup_RL78_ABS3U;
        DirectFixup = RL78::fixup_RL78_DIR3U;
        break;
      case 8:
        PopFixup = RL78::fixup_RL78_ABS8U;
        DirectFixup = RL78::fixup_RL78_DIR8U;
        break;
      case 16:
        PopFixup = RL78::fixup_RL78_ABS16U;
        DirectFixup = RL78::fixup_RL78_DIR16U;
        break;
      case 24:
        PopFixup = RL78::fixup_RL78_ABS20U;
        DirectFixup = RL78::fixup_RL78_DIR20U;
        break;
      case 32:
        PopFixup = RL78::fixup_RL78_ABS32U;
        DirectFixup = RL78::fixup_RL78_DIR32U;
        break;
      default:
        llvm_unreachable("Unhandled RL78MCExpr ResultSize");
        break;
      }

      if (FixupFromOp != 0)
        DirectFixup = (RL78::Fixups)FixupFromOp;

      // SymbolRefs can use the DirectFixups, no need for the queue based ones.
      bool NeedsPop = false;

      ConversionStatus Status = ConvertExpressionToFixups(expression, fixups, NeedsPop, FixupFromOp,
                                    Ctx, Loc, offset, DirectFixup);

      // TODO: Loc might be null, leading to an unhelpful error message.
      if (!Status.Success) {
        LLVM_DEBUG(expression->dump());
        Ctx.reportError(Loc, "invalid expression");
        return;
      }

      if (NeedsPop) {
        // ConvertExpressionToFixups takes care of the push fixups.
        fixups.push_back(MCFixup::create(offset, MCConstantExpr::create(0, Ctx),
                                         (MCFixupKind)PopFixup, Loc));
      } else {
        if (!Status.SymWithPossibleOffset) {
          Ctx.reportError(Loc, "error during expression evaluation");
          return;
        }
        fixups.push_back(MCFixup::create(offset, Status.SymWithPossibleOffset,
                                         (MCFixupKind)DirectFixup, Loc));
      }
}