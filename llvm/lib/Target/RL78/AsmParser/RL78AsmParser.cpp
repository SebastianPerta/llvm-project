//===-- RL78AsmParser.cpp - Parse RL78 assembly to MCInst instructions --===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#include "MCTargetDesc/RL78MCExpr.h"
#include "MCTargetDesc/RL78MCTargetDesc.h"
#include "RL78.h"
#include "TargetInfo/RL78TargetInfo.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCParser/MCAsmLexer.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCValue.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/SMLoc.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <regex>

using namespace llvm;
#define DEBUG_TYPE "rl78-asm-parser"

namespace llvm {
    extern cl::opt<bool> EnableRL78CCRLAsmSyntax;
}

namespace {

class RL78Operand;

class RL78AsmParser : public MCTargetAsmParser {
  MCAsmParser &Parser;

  /// @name Auto-generated Match Functions
  /// {

#define GET_ASSEMBLER_HEADER
#include "RL78GenAsmMatcher.inc"

  /// }

  // Public interface of the MCTargetAsmParser.
  bool MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                               OperandVector &Operands, MCStreamer &Out,
                               uint64_t &ErrorInfo,
                               bool MatchingInlineAsm) override;
  OperandMatchResultTy tryParseRegister(MCRegister &RegNo, SMLoc &StartLoc,
                                        SMLoc &EndLoc) override;
  bool parseRegister(MCRegister &Reg, SMLoc &StartLoc, SMLoc &EndLoc) override;

  bool ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
                        SMLoc NameLoc, OperandVector &Operands) override;

  bool ParseDirective(AsmToken DirectiveID) override;

  unsigned validateTargetOperandClass(MCParsedAsmOperand &Op,
                                      unsigned Kind) override;

  const MCExpr *createTargetUnaryExpr(const MCExpr *E,
                                      AsmToken::TokenKind OperatorToken,
                                      MCContext &Ctx) override;

  int64_t getSymbolAliasValue(StringRef name);

  // Custom parse functions for RL78 specific operands.

  OperandMatchResultTy parseMEMOperand(OperandVector &Operands);
  OperandMatchResultTy parseStackSlotOperand(OperandVector &Operands);

  OperandMatchResultTy parseRegOffsetAddrOperand(OperandVector &Operands,
                                                 StringRef Mnemonic);
  OperandMatchResultTy parseRegOffsetAddrOperand(OperandVector &Operands);
  OperandMatchResultTy parseRegRegAddrOperand(OperandVector &Operands);

  OperandMatchResultTy parseEsRegRegRegOperand(OperandVector &Operands);
  OperandMatchResultTy RegBrackets(OperandVector &Operands, StringRef Mnemonic);
  OperandMatchResultTy parseEsRegRegAddrOperand(OperandVector &Operands);
  OperandMatchResultTy parseEsRegRegAddrAndDotOperand(OperandVector &Operands,
                                                      StringRef Mnemonic);
  OperandMatchResultTy parseOperand(OperandVector &Operands, StringRef Name);

  bool tryParseBCCorSCC(OperandVector &Operands, StringRef Name, SMLoc NameLoc);

  OperandMatchResultTy ParseOpeandRBx(OperandVector &Operands);

  OperandMatchResultTy ParseRegister(OperandVector &Operands,
                                     StringRef Mnemonic);
   
  OperandMatchResultTy parseDotIncludingOperand(OperandVector &Operands,
                                                StringRef Mnemonic);

  OperandMatchResultTy ParseShiftIntegerOperand(OperandVector &Operands,
                                                StringRef Mnemonic);

  bool searchSymbolAlias(StringRef name, MCRegister &Register, unsigned &RegKind);

  /// Returns true if Tok is matched to a register and returns register in
  /// RegNo.
  bool matchRegisterName(const AsmToken &Tok, MCRegister &Register,
                         unsigned &RegKind);
  bool matchRegisterNameByName(StringRef name, MCRegister &Register,
                               unsigned &RegKind);

  bool is64Bit() const { return false; }

private:
  struct RelocationAttributeDefault {
    StringRef DefaultSectionName;
    unsigned Type = ELF::SHT_PROGBITS;
    unsigned Flags = ELF::SHF_ALLOC | ELF::SHF_EXECINSTR;
    unsigned DefaultAlign;
    bool AllowAlignAttribute;
    StringRef ShortDirective;
  };

  struct MacroLocalDefinitionRange {
    size_t Start;
    size_t End;
  };

  StringMap<RelocationAttributeDefault> RelocationAttributeMap;
  StringMap<std::string> MacroBodies;
  
  void InitializeRelocationAttributeMap();
  bool parseDirectiveSymbolAttribute(MCSymbolAttr Attr);
  bool parseIdentifier(StringRef &Res);
  void eatToEndOfStatement();
  bool eatSpacesTillEndOfLine();
  bool ParseSectionName(StringRef &SectionName);
  void SwitchToSection(StringRef NewSectionName, unsigned Type, unsigned Flags);
  bool LookupRelocationAttribute(
      StringRef SectionName, StringRef Attribute,
      RelocationAttributeDefault **RelocationAttributeDesc);
  bool ParseSectionArguments(SMLoc loc);
  bool parseDirectiveSeg(StringRef Name, StringRef Type);
  bool ParseDirectiveOrg();
  bool ParseDirectiveOffset();
  bool EmitSectionDirective(
      StringRef SectionName, StringRef RelocationAttribute,
      const RelocationAttributeDefault* RelocationAttributeDesc);
  bool ParseSectionAddress(std::string SectionName,
                           std::string &NewSectionName);
  bool checkForValidSection();
  bool parseDirectiveValue(StringRef IDVal, unsigned Size);
  bool parseDSDirective();
  bool parseDirectiveAlign();
  bool parseDirectiveMacro(StringRef Name);
  bool parseMacroLocalSymbols(StringMap<std::string> &MacroLocalSymbols);
  std::string ReplaceMacroLocalSymbols(
      std::string MacroBody, StringMap<std::string> &MacroLocalSymbols,
      SmallVector<MacroLocalDefinitionRange, 10> &MacroLocalSymbolRanges);
  bool SplitBitPosition(std::string *AddressSymbol, int64_t *AddressValue,
                        int64_t *BitPosition, bool *IsSymAddress,
                        std::string *ErrorMsg);
  bool parseDirectiveSet(StringRef Name);
  bool parseDirectiveEqu(StringRef Name);
  bool parseDirectiveVector(StringRef Name);
  bool HasTargetSubExpressionKind(const MCExpr *Expr,
                                  unsigned TargetExpressionKind);

  // Parsed, but ignored directives
  bool parseDirectiveLine();
  bool parseDirectiveLineTopEnd();
  bool parseDirectiveStack();
  bool parseDirectiveType();

public:
  RL78AsmParser(const MCSubtargetInfo &sti, MCAsmParser &parser,
                const MCInstrInfo &MII, const MCTargetOptions &Options)
      : MCTargetAsmParser(Options, sti, MII), Parser(parser) {
    // Initialize the set of available features.
    setAvailableFeatures(ComputeAvailableFeatures(getSTI().getFeatureBits()));
	InitializeRelocationAttributeMap();
  }

  ~RL78AsmParser() override;
};

} // end anonymous namespace

static constexpr const char *BitPositionSymbolPrefix = ".$$$";

static const MCPhysReg IntRegs[8] = {
    RL78::R0,  RL78::R1,  RL78::R2,  RL78::R3,  RL78::R4,  RL78::R5,  RL78::R6,
    RL78::R7};

namespace {

/// RL78Operand - Instances of this class represent a parsed RL78 machine
/// instruction.
class RL78Operand : public MCParsedAsmOperand {
public:
  enum RegisterKind {
    rk_None,
    rk_Reg,
    rk_RegPair,
  };

private:
  enum KindTy {
    k_Token,
    k_Register,
    k_Immediate,
    k_cc,
    k_Imm07,
    k_Imm17,
    k_Imm115,
    k_selrbx,
    k_Abs16,
    k_Abs8,
    k_Abs5,
    k_Abs20,
    k_MemoryReg,
    k_MemoryImm,
    k_STACKSlot,
    k_RegOffsetAddr,
    k_RegBorCOffsetAddr,
    k_RegRegAddr,
    k_EsRegRegReg,
    k_HLAddr,
    k_EsRegRegAddr,
    k_EsRegBorCRegAddr,
    k_EsHlRegAddr,
    k_brtargetRel8,
    k_brtargetRel16,
    k_brtargetAbs16,
    k_sfr,
    k_sfrp,
    k_EsAddr16
  } Kind;

  SMLoc StartLoc, EndLoc;

  struct Token {
    const char *Data;
    unsigned Length;
  };

  struct RegOp {
    unsigned RegNum;
    RegisterKind Kind;
  };

  struct RegRegAddrOp {
    RegOp RPReg;
    RegOp Reg;
  };

  struct EsRegRegRegOp {
    RegOp ESReg;
    RegOp RPReg;
    RegOp Reg;
  };

  struct STACKSlotNoOp {
    RegOp SPreg;
    const MCExpr *Val;
  };

  struct RegOffsetAddrOp {
    RegOp RPReg;
    const MCExpr *Val;
  };

  struct RegBorCOffsetAddrOp {
    RegOp Reg;
    const MCExpr *Val;
  };

  struct HLAddrOp {
    RegOp HlReg;
  };

  struct EsRegRegAddrOp {
    RegOp ESReg;
    RegOp RPReg;
    const MCExpr *Val;
  };
  struct EsRegBorCRegAddrOp {
    RegOp ESReg;
    RegOp Reg;
    const MCExpr *Val;
  };
  struct EsHlRegAddrOp {
    RegOp RL78RegES;
    RegOp RL78HL;
  };

  struct ImmOp {
    const MCExpr *Val;
  };

  struct Abs16Op {
    const MCExpr *Val;
  };
  struct Abs8Op {
    const MCExpr *Val;
  };

  struct Abs5Op {
    const MCExpr *Val;
  };

  struct Abs20Op {
    const MCExpr *Val;
  };

  struct Rel8Op {
    const MCExpr *Val;
  };

  struct Rel16Op {
    const MCExpr *Val;
  };

  struct brtargetAbs16Op {
    const MCExpr *Val;
  };

  struct brtargetRel8Op {
    const MCExpr *Val;
  };
  struct brtargetRel16Op {
    const MCExpr *Val;
  };

  struct sfrOp {
    const MCExpr *Val;
  };
  struct sfrpOp {
    const MCExpr *Val;
  };

  struct CCOp {
    const MCExpr *Val;
  };
  struct Imm07Op {
    const MCExpr *Val;
  };
  struct Imm17Op {
    const MCExpr *Val;
  };
  struct Imm115Op {
    const MCExpr *Val;
  };
  struct SELRBxOp {
    const MCExpr *Val;
  };

  struct EsAddr16Op {
    RegOp ESReg;
    const MCExpr *Val;
  };

  struct MemOp {
    unsigned Base;
    unsigned OffsetReg;
    const MCExpr *Off;
  };

  union {
    struct Token Tok;
    struct RegOp Reg;
    struct ImmOp Imm;
    struct MemOp Mem;
    struct Abs5Op Abs5;
    struct Abs8Op Abs8;
    struct Abs16Op Abs16;
    struct Abs20Op Abs20;
    struct brtargetRel8Op brtargetRel8;
    struct brtargetRel16Op brtargetRel16;
    struct brtargetAbs16Op brtargetAbs16;
    struct STACKSlotNoOp STACKSlotNo;
    struct RegRegAddrOp RegRegAddr;
    struct RegOffsetAddrOp RegOffsetAddr;
    struct RegBorCOffsetAddrOp RegBorCOffsetAddr;
    struct EsRegRegAddrOp EsRegRegAddr;
    struct EsHlRegAddrOp EsHlRegAddr;
    struct HLAddrOp HLAddr;
    struct sfrOp sfr;
    struct sfrpOp sfrp;
    struct EsAddr16Op EsAddr16;
    struct EsRegRegRegOp EsRegRegReg;
    struct EsRegBorCRegAddrOp EsRegBorCRegAddr;
    struct SELRBxOp SELRBx;
    struct Imm07Op Imm07;
    struct Imm17Op Imm17;
    struct Imm115Op Imm115;
    struct CCOp CC;
  };

public:
  RL78Operand(KindTy K) : MCParsedAsmOperand(), Kind(K) {}
  bool isABS5() { return Kind == k_Abs5; }
  bool isABS8() { return Kind == k_Abs8; }
  bool isCCOp() { return Kind == k_cc; }
  bool isSELRBx() { return Kind == k_selrbx; }
  bool isABS16() { return Kind == k_Abs16; }
  bool isABS20() { return Kind == k_Abs20; }
  bool isbrtargetRel8() { return Kind == k_brtargetRel8; }
  bool isbrtargetRel16() { return Kind == k_brtargetRel16; }
  bool isbrtargetAbs16() { return Kind == k_brtargetAbs16; }
  bool isToken() const override { return Kind == k_Token; }
  bool isReg() const override { return Kind == k_Register; }
  bool isImm() const override { return Kind == k_Immediate; }
  bool isImm07() const { return Kind == k_Imm07; }
  bool isImm17() const { return Kind == k_Imm17; }
  bool isImm115() const { return Kind == k_Imm115; }

  bool isMem() const override { return isMEMrr() || isMEMri(); }
  bool isMEMrr() const { return Kind == k_MemoryReg; }
  bool isMEMri() const { return Kind == k_MemoryImm; }

  bool isSTACKSlotNo() const { return Kind == k_STACKSlot; }
  bool isRegOffsetAddr() const { return Kind == k_RegOffsetAddr; }
  bool isRegBorCOffsetAddr() const { return Kind == k_RegBorCOffsetAddr; }
  bool isRegRegAddr() const { return Kind == k_RegRegAddr; }
  bool isEsRegRegReg() const { return Kind == k_EsRegRegReg; }
  bool isEsRegBorCRegAddr() const { return Kind == k_EsRegBorCRegAddr; }

  bool isEsRegRegAddr() const { return Kind == k_EsRegRegAddr; }
  bool isEsHlRegAddr() const { return Kind == k_EsHlRegAddr; }
  bool isHLAddr() const {
    return Kind == k_HLAddr && HLAddr.HlReg.RegNum == RL78::RP6;
  }
  bool is8BitReg() const { return (Kind == k_Register && Reg.Kind == rk_Reg); }
  bool is16BitReg() const {
    return (Kind == k_Register && Reg.Kind == rk_RegPair);
  }
  bool isSfr() const { return Kind == k_sfr; }
  bool isSfrp() const { return Kind == k_sfrp; }
  bool isEsAddr16() const { return Kind == k_EsAddr16; }

  StringRef getToken() const {
    assert(Kind == k_Token && "Invalid access!");
    return StringRef(Tok.Data, Tok.Length);
  }

  template <int N, int M> bool isImmInRange() const {
    const MCConstantExpr *MCE;

    if (isImm())
      MCE = dyn_cast<MCConstantExpr>(getImm());
    else if (isImm17())
      MCE = dyn_cast<MCConstantExpr>(getImm17());
    else if (isImm07())
      MCE = dyn_cast<MCConstantExpr>(getImm07());
    else if (isImm115())
      MCE = dyn_cast<MCConstantExpr>(getImm115());
    else
      return false;
    if (!MCE)
      return false;
    int64_t Val = MCE->getValue();
    return (Val >= N && Val <= M);
  }
  unsigned getStackSlotNoReg() const {
    assert((Kind == k_STACKSlot) && "Invalid access!");
    assert((STACKSlotNo.SPreg.RegNum == RL78::SPreg) && "Invalid Register!");
    return STACKSlotNo.SPreg.RegNum;
  }

  const MCExpr *getStackSlotNoImm() const {
    assert((Kind == k_STACKSlot) && "Invalid access!");
    return STACKSlotNo.Val;
  }

  unsigned getRegBorCOffsetAddrReg() const {
    assert((Kind == k_RegBorCOffsetAddr) && "Invalid access!");
    return RegBorCOffsetAddr.Reg.RegNum;
  }

  const MCExpr *gettRegBorCOffsetAddrImm() const {
    assert((Kind == k_RegBorCOffsetAddr) && "Invalid access!");
    return RegBorCOffsetAddr.Val;
  }

  unsigned getRegOffsetAddrReg() const {
    assert((Kind == k_RegOffsetAddr) && "Invalid access!");
    return RegOffsetAddr.RPReg.RegNum;
  }

  unsigned getHLAddrReg() const {
    assert((Kind == k_HLAddr) && "Invalid access!");
    return HLAddr.HlReg.RegNum;
  }

  const MCExpr *gettRegOffsetAddrImm() const {
    assert((Kind == k_RegOffsetAddr) && "Invalid access!");
    return RegOffsetAddr.Val;
  }

  unsigned getRegRegAddrRpReg() const {
    assert((Kind == k_RegRegAddr) && "Invalid access!");
    return RegRegAddr.RPReg.RegNum;
  }
  unsigned getRegRegAddrRReg() const {
    assert((Kind == k_RegRegAddr) && "Invalid access!");
    return RegRegAddr.Reg.RegNum;
  }

  unsigned getEsRegRegRegEsReg() const {
    assert((Kind == k_EsRegRegReg) && "Invalid access!");
    return EsRegRegReg.ESReg.RegNum;
  }
  unsigned getEsRegRegRegRpReg() const {
    assert((Kind == k_EsRegRegReg) && "Invalid access!");
    return EsRegRegReg.RPReg.RegNum;
  }
  unsigned getEsRegRegRegRReg() const {
    assert((Kind == k_EsRegRegReg) && "Invalid access!");
    return EsRegRegReg.Reg.RegNum;
  }

  unsigned getEsRegRegAddrEsReg() const {
    assert((Kind == k_EsRegRegAddr) && "Invalid access!");
    return EsRegRegAddr.ESReg.RegNum;
  }
  unsigned getEsRegRegAddrRpReg() const {
    assert((Kind == k_EsRegRegAddr) && "Invalid access!");
    return EsRegRegAddr.RPReg.RegNum;
  }

  const MCExpr *gettEsRegRegAddrImm() const {
    assert((Kind == k_EsRegRegAddr) && "Invalid access!");
    return EsRegRegAddr.Val;
  }

  unsigned getEsRegBorCRegAddrEsReg() const {
    assert((Kind == k_EsRegBorCRegAddr) && "Invalid access!");
    return EsRegBorCRegAddr.ESReg.RegNum;
  }
  unsigned getEsRegBorCRegAddrReg() const {
    assert((Kind == k_EsRegBorCRegAddr) && "Invalid access!");
    return EsRegBorCRegAddr.Reg.RegNum;
  }

  const MCExpr *gettEsRegBorCRegAddrImm() const {
    assert((Kind == k_EsRegBorCRegAddr) && "Invalid access!");
    return EsRegBorCRegAddr.Val;
  }

  unsigned getEsHlRegAddrEsReg() const {
    assert((Kind == k_EsHlRegAddr) && "Invalid access!");
    return EsHlRegAddr.RL78RegES.RegNum;
  }
  unsigned getEsHlRegAddrHlReg() const {
    assert((Kind == k_EsHlRegAddr) && "Invalid access!");
    return EsHlRegAddr.RL78HL.RegNum;
  }

  unsigned getReg() const override {
    assert((Kind == k_Register) && "Invalid access!");
    return Reg.RegNum;
  }

  const MCExpr *getImm() const {
    assert((Kind == k_Immediate) && "Invalid access!");
    return Imm.Val;
  }
  const MCExpr *getAbs5() const {
    assert((Kind == k_Abs5) && "Invalid access!");
    return Abs5.Val;
  }
  const MCExpr *getCC() const {
    assert((Kind == k_cc) && "Invalid access!");
    return CC.Val;
  }
  const MCExpr *getImm07() const {
    assert((Kind == k_Imm07) && "Invalid access!");
    return Imm07.Val;
  }
  const MCExpr *getImm17() const {
    assert((Kind == k_Imm17) && "Invalid access!");
    return Imm17.Val;
  }
  const MCExpr *getImm115() const {
    assert((Kind == k_Imm115) && "Invalid access!");
    return Imm115.Val;
  }
  const MCExpr *getSELRBx() const {
    assert((Kind == k_selrbx) && "Invalid access!");
    return SELRBx.Val;
  }

  const MCExpr *getAbs16() const {
    assert((Kind == k_Abs16) && "Invalid access!");
    return Abs16.Val;
  }
  const MCExpr *getAbs8() const {
    assert((Kind == k_Abs8) && "Invalid access!");
    return Abs8.Val;
  }
  const MCExpr *getAbs20() const {
    assert((Kind == k_Abs20) && "Invalid access!");
    return Abs20.Val;
  }

  const MCExpr *getSfr() const {
    assert((Kind == k_sfr) && "Invalid access!");
    return sfr.Val;
  }

  const MCExpr *getSfrp() const {
    assert((Kind == k_sfrp) && "Invalid access!");
    return sfrp.Val;
  }

  unsigned getEsAddr16EsReg() const {
    assert((Kind == k_EsAddr16) && "Invalid access!");
    return EsAddr16.ESReg.RegNum;
  }
  const MCExpr *getEsAddr16Addr() const {
    assert((Kind == k_EsAddr16) && "Invalid access!");
    return EsAddr16.Val;
  }

  const MCExpr *getbrtargetAbs16() const {
    assert((Kind == k_brtargetAbs16) && "Invalid access!");
    return brtargetAbs16.Val;
  }

  const MCExpr *getbrtargetRel8() const {
    assert((Kind == k_brtargetRel8) && "Invalid access!");
    return brtargetRel8.Val;
  }

  const MCExpr *getbrtargetRel16() const {
    assert((Kind == k_brtargetRel16) && "Invalid access!");
    return brtargetRel16.Val;
  }

  unsigned getMemBase() const {
    assert((Kind == k_MemoryReg || Kind == k_MemoryImm) && "Invalid access!");
    return Mem.Base;
  }

  unsigned getMemOffsetReg() const {
    assert((Kind == k_MemoryReg) && "Invalid access!");
    return Mem.OffsetReg;
  }

  const MCExpr *getMemOff() const {
    assert((Kind == k_MemoryImm) && "Invalid access!");
    return Mem.Off;
  }

  /// getStartLoc - Get the location of the first token of this operand.
  SMLoc getStartLoc() const override { return StartLoc; }
  /// getEndLoc - Get the location of the last token of this operand.
  SMLoc getEndLoc() const override { return EndLoc; }

  void print(raw_ostream &OS) const override {
    switch (Kind) {
    case k_Token:
      OS << "Token: " << getToken() << "\n";
      break;
    case k_Register:
      OS << "Reg: #" << getReg() << "\n";
      break;
    case k_Immediate:
      OS << "Imm: " << getImm() << "\n";
      break;
    case k_MemoryReg:
      OS << "Mem: " << getMemBase() << "+" << getMemOffsetReg() << "\n";
      break;
    case k_MemoryImm:
      assert(getMemOff() != nullptr);
      OS << "Mem: " << getMemBase() << "+" << *getMemOff() << "\n";
      break;
    default:
      break;
    }
  }

  void addRegOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getReg()));
  }

  void addImmOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getImm();
    addExpr(Inst, Expr);
  }

  void addCCOpOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getCC();
    addExpr(Inst, Expr);
  }

  void addImm07Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getImm07();
    addExpr(Inst, Expr);
  }

  void addImm17Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getImm17();
    addExpr(Inst, Expr);
  }

  void addImm115Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getImm115();
    addExpr(Inst, Expr);
  }

  void addSELRBxOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getSELRBx();
    addExpr(Inst, Expr);
  }

  void addABS8Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getAbs8();
    addExpr(Inst, Expr);
  }

  void addABS5Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getAbs5();
    addExpr(Inst, Expr);
  }

  void addABS16Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getAbs16();
    addExpr(Inst, Expr);
  }

  void addABS20Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getAbs20();
    addExpr(Inst, Expr);
  }

  void addSfrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getSfr();
    addExpr(Inst, Expr);
  }

  void addSfrpOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getSfrp();
    addExpr(Inst, Expr);
  }

  void addEsAddr16Operands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getEsAddr16EsReg()));
    const MCExpr *Expr = getEsAddr16Addr();
    addExpr(Inst, Expr);
  }

  void addbrtargetAbs16Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getbrtargetAbs16();
    addExpr(Inst, Expr);
  }

  void addbrtargetRel8Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getbrtargetRel8();
    addExpr(Inst, Expr);
  }

  void addbrtargetRel16Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    const MCExpr *Expr = getbrtargetRel16();
    addExpr(Inst, Expr);
  }

  void addSTACKSlotNoOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getStackSlotNoReg()));
    const MCExpr *Expr = getStackSlotNoImm();
    addExpr(Inst, Expr);
  }

  void addHLAddrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getHLAddrReg()));
  }

  void addRegBorCOffsetAddrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getRegBorCOffsetAddrReg()));
    const MCExpr *Expr = gettRegBorCOffsetAddrImm();
    addExpr(Inst, Expr);
  }
  void addRegOffsetAddrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getRegOffsetAddrReg()));
    const MCExpr *Expr = gettRegOffsetAddrImm();
    addExpr(Inst, Expr);
  }

  void addRegRegAddrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getRegRegAddrRpReg()));
    Inst.addOperand(MCOperand::createReg(getRegRegAddrRReg()));
  }

  void addEsRegRegRegOperands(MCInst &Inst, unsigned N) const {
    assert(N == 3 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getEsRegRegRegEsReg()));
    Inst.addOperand(MCOperand::createReg(getEsRegRegRegRpReg()));
    Inst.addOperand(MCOperand::createReg(getEsRegRegRegRReg()));
  }

  void addEsRegRegAddrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 3 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getEsRegRegAddrEsReg()));
    Inst.addOperand(MCOperand::createReg(getEsRegRegAddrRpReg()));
    const MCExpr *Expr = gettEsRegRegAddrImm();
    addExpr(Inst, Expr);
  }

  void addEsRegBorCRegAddrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 3 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getEsRegBorCRegAddrEsReg()));
    Inst.addOperand(MCOperand::createReg(getEsRegBorCRegAddrReg()));
    const MCExpr *Expr = gettEsRegBorCRegAddrImm();
    addExpr(Inst, Expr);
  }

  void addEsHlRegAddrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getEsHlRegAddrEsReg()));
    Inst.addOperand(MCOperand::createReg(getEsHlRegAddrHlReg()));
  }

  void addHLAddressOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getReg()));
  }

  void addExpr(MCInst &Inst, const MCExpr *Expr) const {
    // Add as immediate when possible.  Null MCExpr = 0.
    if (!Expr)
      Inst.addOperand(MCOperand::createImm(0));
    else if (const MCConstantExpr *CE = dyn_cast<MCConstantExpr>(Expr))
      Inst.addOperand(MCOperand::createImm(CE->getValue()));
    else
      Inst.addOperand(MCOperand::createExpr(Expr));
  }

  void addMemOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getMemBase()));
    const MCExpr *Expr = getMemOff();
    addExpr(Inst, Expr);
  }

  void addMEMrrOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getMemBase()));
    assert(getMemOffsetReg() != 0 && "Invalid offset");
    Inst.addOperand(MCOperand::createReg(getMemOffsetReg()));
  }

  void addMEMriOperands(MCInst &Inst, unsigned N) const {
    assert(N == 2 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(getMemBase()));
    const MCExpr *Expr = getMemOff();
    addExpr(Inst, Expr);
  }

  static std::unique_ptr<RL78Operand> CreateToken(StringRef Str, SMLoc S) {
    auto Op = std::make_unique<RL78Operand>(k_Token);
    Op->Tok.Data = Str.data();
    Op->Tok.Length = Str.size();
    Op->StartLoc = S;
    Op->EndLoc = S;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateReg(unsigned RegNum, unsigned Kind,
                                                SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Register);
    Op->Reg.RegNum = RegNum;
    Op->Reg.Kind = (RL78Operand::RegisterKind)Kind;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateSTACKSlotNo(unsigned RegNum,
                                                        unsigned Kind,
                                                        const MCExpr *Val,
                                                        SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_STACKSlot);
    Op->STACKSlotNo.SPreg.RegNum = RegNum;
    Op->STACKSlotNo.SPreg.Kind = (RL78Operand::RegisterKind)Kind;
    Op->STACKSlotNo.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateRegOffsetAddr(unsigned RPRegNum,
                                                          unsigned RPRegKind,
                                                          const MCExpr *Val,
                                                          SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_RegOffsetAddr);
    Op->RegOffsetAddr.RPReg.RegNum = RPRegNum;
    Op->RegOffsetAddr.RPReg.Kind = (RL78Operand::RegisterKind)RPRegKind;
    Op->RegOffsetAddr.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand>
  CreateRegBorCOffsetAddr(unsigned RegNum, unsigned RegKind, const MCExpr *Val,
                          SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_RegBorCOffsetAddr);
    Op->RegBorCOffsetAddr.Reg.RegNum = RegNum;
    Op->RegBorCOffsetAddr.Reg.Kind = (RL78Operand::RegisterKind)RegKind;
    Op->RegBorCOffsetAddr.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand>
  CreateHLAddr(unsigned RPRegNum, unsigned RPRegKind, SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_HLAddr);
    Op->HLAddr.HlReg.RegNum = RPRegNum;
    Op->HLAddr.HlReg.Kind = (RL78Operand::RegisterKind)RPRegKind;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand>
  CreateRegRegAddr(unsigned RPRegNum, unsigned RPRegKind, unsigned RegNum,
                   unsigned RegKind, SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_RegRegAddr);
    Op->RegRegAddr.RPReg.RegNum = RPRegNum;
    Op->RegRegAddr.RPReg.Kind = (RL78Operand::RegisterKind)RPRegKind;
    Op->RegRegAddr.Reg.RegNum = RegNum;
    Op->RegRegAddr.Reg.Kind = (RL78Operand::RegisterKind)RegKind;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand>
  CreateEsRegRegAddr(unsigned ESRegNum, unsigned ESKind, unsigned RPRegNum,
                     unsigned RPKind, const MCExpr *Val, SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_EsRegRegAddr);
    Op->EsRegRegAddr.ESReg.RegNum = ESRegNum;
    Op->EsRegRegAddr.ESReg.Kind = (RL78Operand::RegisterKind)ESKind;
    Op->EsRegRegAddr.RPReg.RegNum = RPRegNum;
    Op->EsRegRegAddr.RPReg.Kind = (RL78Operand::RegisterKind)RPKind;
    Op->EsRegRegAddr.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }
  static std::unique_ptr<RL78Operand>
  CreateEsRegBorCRegAddr(unsigned ESRegNum, unsigned ESKind, unsigned RegNum,
                         unsigned Kind, const MCExpr *Val, SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_EsRegBorCRegAddr);
    Op->EsRegBorCRegAddr.ESReg.RegNum = ESRegNum;
    Op->EsRegBorCRegAddr.ESReg.Kind = (RL78Operand::RegisterKind)ESKind;
    Op->EsRegBorCRegAddr.Reg.RegNum = RegNum;
    Op->EsRegBorCRegAddr.Reg.Kind = (RL78Operand::RegisterKind)Kind;
    Op->EsRegBorCRegAddr.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }
  static std::unique_ptr<RL78Operand>
  CreateEsRegRegReg(unsigned ESRegNum, unsigned ESKind, unsigned RPRegNum,
                    unsigned RPKind, unsigned RegNum, unsigned Kind, SMLoc S,
                    SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_EsRegRegReg);
    Op->EsRegRegReg.ESReg.RegNum = ESRegNum;
    Op->EsRegRegReg.ESReg.Kind = (RL78Operand::RegisterKind)ESKind;
    Op->EsRegRegReg.RPReg.RegNum = RPRegNum;
    Op->EsRegRegReg.RPReg.Kind = (RL78Operand::RegisterKind)RPKind;
    Op->EsRegRegReg.Reg.RegNum = RegNum;
    Op->EsRegRegReg.Reg.Kind = (RL78Operand::RegisterKind)Kind;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand>
  CreateEsHlRegAddr(unsigned ESRegNum, unsigned ESKind, unsigned RPRegNum,
                    unsigned RPKind, SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_EsHlRegAddr);
    Op->EsHlRegAddr.RL78RegES.RegNum = ESRegNum;
    Op->EsHlRegAddr.RL78RegES.Kind = (RL78Operand::RegisterKind)ESKind;
    Op->EsHlRegAddr.RL78HL.RegNum = RPRegNum;
    Op->EsHlRegAddr.RL78HL.Kind = (RL78Operand::RegisterKind)RPKind;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateImm(const MCExpr *Val, SMLoc S,
                                                SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Immediate);
    Op->Imm.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateAbs5(const MCExpr *Val, SMLoc S,
                                                 SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Abs5);
    Op->Abs5.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateAbs8(const MCExpr *Val, SMLoc S,
                                                 SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Abs8);
    Op->Abs8.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateAbs16(const MCExpr *Val, SMLoc S,
                                                  SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Abs16);
    Op->Abs16.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateSfr(const MCExpr *Val, SMLoc S,
                                                SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_sfr);
    Op->sfr.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateSfrp(const MCExpr *Val, SMLoc S,
                                                 SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_sfrp);
    Op->sfrp.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateEsAddr16(unsigned RegNum,
                                                     unsigned RegKind,
                                                     const MCExpr *Val, SMLoc S,
                                                     SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_EsAddr16);
    Op->EsAddr16.ESReg.RegNum = RegNum;
    Op->EsAddr16.ESReg.Kind = (RL78Operand::RegisterKind)RegKind;
    Op->EsAddr16.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateAbs20(const MCExpr *Val, SMLoc S,
                                                  SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Abs20);
    Op->Abs20.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreatebrtargetRel8(const MCExpr *Val,
                                                         SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_brtargetRel8);
    Op->brtargetRel8.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreatebrtargetRel16(const MCExpr *Val,
                                                          SMLoc S, SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_brtargetRel16);
    Op->brtargetRel16.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateMEMr(unsigned Base, SMLoc S,
                                                 SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_MemoryReg);
    Op->Mem.Base = Base;
    Op->Mem.OffsetReg = RL78::R0; // always 0
    Op->Mem.Off = nullptr;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }

  static std::unique_ptr<RL78Operand> CreateSELRBx(const MCExpr *Val, SMLoc S,
                                                   SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_selrbx);
    Op->SELRBx.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }
  static std::unique_ptr<RL78Operand> CreateImm07(const MCExpr *Val, SMLoc S,
                                                  SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Imm07);
    Op->Imm07.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }
  static std::unique_ptr<RL78Operand> CreateImm17(const MCExpr *Val, SMLoc S,
                                                  SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Imm17);
    Op->Imm17.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }
  static std::unique_ptr<RL78Operand> CreateImm115(const MCExpr *Val, SMLoc S,
                                                   SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_Imm115);
    Op->Imm115.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }
  static std::unique_ptr<RL78Operand> CreateCC(const MCExpr *Val, SMLoc S,
                                               SMLoc E) {
    auto Op = std::make_unique<RL78Operand>(k_cc);
    Op->CC.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    return Op;
  }
};
} // end anonymous namespace

static std::map<std::string, int> ccTono{

    // C/NC/Z/NZ/H/NH.
    {"c", RL78CC::RL78CC_C},  {"nc", RL78CC::RL78CC_NC},
    {"z", RL78CC::RL78CC_Z},  {"nz", RL78CC::RL78CC_NZ},
    {"h", RL78CC::RL78CC_H},  {"nh", RL78CC::RL78CC_NH},
    {"f", RL78CC::RL78CC_NZ}, {"t", RL78CC::RL78CC_Z}};

RL78AsmParser::~RL78AsmParser() = default;

bool RL78AsmParser::MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                                            OperandVector &Operands,
                                            MCStreamer &Out,
                                            uint64_t &ErrorInfo,
                                            bool MatchingInlineAsm) {

  MCInst Inst;
  SmallVector<MCInst, 8> Instructions;
  unsigned MatchResult =
      MatchInstructionImpl(Operands, Inst, ErrorInfo, MatchingInlineAsm);
  switch (MatchResult) {
  case Match_Success: {
    Inst.setLoc(IDLoc);
    Instructions.push_back(Inst);

    for (const MCInst &I : Instructions) {
      Out.emitInstruction(I, getSTI());
    }
    return false;
  }

  case Match_MissingFeature:
    return Error(IDLoc,
                 "instruction requires a CPU feature not currently enabled");

  case Match_InvalidOperand: {
    SMLoc ErrorLoc = IDLoc;
    if (ErrorInfo != ~0ULL) {
      if (ErrorInfo >= Operands.size())
        return Error(IDLoc, "too few operands for instruction");

      ErrorLoc = ((RL78Operand &)*Operands[ErrorInfo]).getStartLoc();
      if (ErrorLoc == SMLoc())
        ErrorLoc = IDLoc;
    }

    return Error(ErrorLoc, "invalid operand for instruction");
  }
  case Match_MnemonicFail:
    return Error(IDLoc, "invalid instruction mnemonic");
  }
  llvm_unreachable("Implement any new match types added!");
}

bool RL78AsmParser::tryParseBCCorSCC(OperandVector &Operands, StringRef Name,
                                     SMLoc NameLoc) {

  // BC / BNC / BZ / BNZ / BH / BNH.
  // SC / SNC / SZ / SNZ / SH / SNH.
  // SK_cc.
  // BT/BF.
  StringRef mnemonic;
  StringRef operand;

  if (Name.substr(0, 1).compare("b") == 0 &&
      ccTono.find(Name.substr(1, Name.size()).str()) != ccTono.end()) {

    mnemonic = Name.substr(0, 1);
    operand = Name.substr(1, Name.size());

  } else if (Name.substr(0, 2).compare("sk") == 0 &&
             ccTono.find(Name.substr(2, Name.size()).str()) != ccTono.end()) {

    mnemonic = Name.substr(0, 2);
    operand = Name.substr(2, Name.size());

  } else
    return false;

  if (!mnemonic.empty() && !operand.empty()) {

    Operands.push_back(RL78Operand::CreateToken(mnemonic, NameLoc));
    SMLoc S = Parser.getTok().getLoc();
    SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
    const MCExpr *EVal;
    EVal = MCConstantExpr::create(ccTono[operand.str()], getContext());
    Operands.push_back(RL78Operand::CreateCC(EVal, S, E));
    return true;
  }

  return false;
}

/// parseIdentifier:
///   ::= identifier
///   ::= string
bool RL78AsmParser::parseIdentifier(StringRef &Res) {
  auto& Lexer = getLexer();
  // The assembler has relaxed rules for accepting identifiers, in particular we
  // allow things like '.globl $foo' and '.def @feat.00', which would normally be
  // separate tokens. At this level, we have already lexed so we cannot (currently)
  // handle this as a context dependent token, instead we detect adjacent tokens
  // and return the combined identifier.
  if (Lexer.is(AsmToken::Dollar) || Lexer.is(AsmToken::At)) {
    SMLoc PrefixLoc = Lexer.getLoc();

    // Consume the prefix character, and check for a following identifier.

    AsmToken Buf[1];
    Lexer.peekTokens(Buf, false);

    if (Buf[0].isNot(AsmToken::Identifier))
      return true;

    // We have a '$' or '@' followed by an identifier, make sure they are adjacent.
    if (PrefixLoc.getPointer() + 1 != Buf[0].getLoc().getPointer())
      return true;

    // eat $ or @
    Lexer.Lex(); // Lexer's Lex guarantees consecutive token.
    // Construct the joined identifier and consume the token.
    Res =
        StringRef(PrefixLoc.getPointer(), getTok().getIdentifier().size() + 1);
    Lex(); // Parser Lex to maintain invariants.
    return false;
  }

  if (getLexer().isNot(AsmToken::Identifier) && getLexer().isNot(AsmToken::String))
    return true;

  Res = getTok().getIdentifier();

  Lex(); // Consume the identifier token.

  return false;
}

/// parseDirectiveSymbolAttribute
///  ::= { ".globl", ".weak", ... } [ identifier ( , identifier )* ]
bool RL78AsmParser::parseDirectiveSymbolAttribute(MCSymbolAttr Attr) {
  auto parseOp = [&]() -> bool {
    StringRef Name;
    SMLoc Loc = getTok().getLoc();
    if (parseIdentifier(Name))
      return Error(Loc, "expected identifier");
    MCSymbol *Sym = getContext().getOrCreateSymbol(Name);

    // Assembler local symbols don't make any sense here. Complain loudly.
    if (Sym->isTemporary())
      return Error(Loc, "non-local symbol required");

    if (!getStreamer().emitSymbolAttribute(Sym, Attr))
      return Error(Loc, "unable to emit symbol attribute");
    return false;
  };

  if (parseMany(parseOp))
    return addErrorSuffix(" in directive");
  return false;
}

void RL78AsmParser::eatToEndOfStatement() {
  auto& Lexer = getLexer();
  while (Lexer.isNot(AsmToken::EndOfStatement) && Lexer.isNot(AsmToken::Eof))
    Lexer.Lex();

  // Eat EOL.
  if (Lexer.is(AsmToken::EndOfStatement))
    Lexer.Lex();
}

bool RL78AsmParser::eatSpacesTillEndOfLine() {
  auto &Lexer = getLexer();
  while (Lexer.is(AsmToken::Space) || Lexer.is(AsmToken::Comment)) {
    Lexer.Lex();
  }
  if (Lexer.isNot(AsmToken::EndOfStatement))
    return true;
  return false;
}

bool RL78AsmParser::ParseSectionName(StringRef &SectionName) {
  // A section name can contain -, so we cannot just use
  // parseIdentifier.
  SMLoc FirstLoc = getLexer().getLoc();
  unsigned Size = 0;

  if (getLexer().is(AsmToken::String)) {
    SectionName = getTok().getIdentifier();
    Lex();
    return false;
  }

  while (!getParser().hasPendingError()) {
    SMLoc PrevLoc = getLexer().getLoc();
    if (getLexer().is(AsmToken::Comma) ||
      getLexer().is(AsmToken::EndOfStatement))
      break;

    unsigned CurSize;
    if (getLexer().is(AsmToken::String)) {
      CurSize = getTok().getIdentifier().size() + 2;
      Lex();
    } else if (getLexer().is(AsmToken::Identifier)) {
      CurSize = getTok().getIdentifier().size();
      Lex();
    } else {
      CurSize = getTok().getString().size();
      Lex();
    }
    Size += CurSize;
    SectionName = StringRef(FirstLoc.getPointer(), Size);

    // Make sure the following token is adjacent.
    if (PrevLoc.getPointer() + CurSize != getTok().getLoc().getPointer())
      break;
  }
  if (Size == 0)
    return true;

  return false;
}

void RL78AsmParser::InitializeRelocationAttributeMap() {
  // clang-format off
  RelocationAttributeMap["CALLT0"] =         {".callt0", ELF::SHT_PROGBITS, ELF::SHF_ALLOC, 2, true, ".CSEG"};
  RelocationAttributeMap["TEXT"] =           {".text", ELF::SHT_PROGBITS, ELF::SHF_ALLOC | ELF::SHF_EXECINSTR, 1, true, ".CSEG"};
  RelocationAttributeMap["TEXTF"] =          {".textf", ELF::SHT_PROGBITS, ELF::SHF_ALLOC | ELF::SHF_EXECINSTR, 1, true, ".CSEG"};
  RelocationAttributeMap["TEXTF_UNIT64KP"] = {".textf_unit64kp", ELF::SHT_PROGBITS, ELF::SHF_ALLOC | ELF::SHF_EXECINSTR, 2, true, ".CSEG"};
  RelocationAttributeMap["CONST"] =          {".const", ELF::SHT_PROGBITS, ELF::SHF_ALLOC, 2, true, ".CSEG"};
  RelocationAttributeMap["CONSTF"] =         {".constf", ELF::SHT_PROGBITS, ELF::SHF_ALLOC, 2, true, ".CSEG"};
  RelocationAttributeMap["SDATA"] =          {".sdata", ELF::SHT_PROGBITS, ELF::SHF_ALLOC, 2, true, ".DSEG"};
  RelocationAttributeMap["SBSS"] =           {".sbss", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_WRITE, 2, true, ".DSEG"};
  RelocationAttributeMap["SBSS_BIT"] =       {".sbss_bit", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_WRITE, 2, true, ".BSEG"};
  RelocationAttributeMap["DATA"] =           {".data", ELF::SHT_PROGBITS, ELF::SHF_ALLOC,2, true, ".DSEG"};
  RelocationAttributeMap["BSS"] =            {".bss", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_WRITE, 2, true, ".DSEG"};
  RelocationAttributeMap["BSS_BIT"] =        {".bss_bit", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_WRITE, 2, true, ".BSEG"};
  RelocationAttributeMap["DATAF"] =          {".dataf", ELF::SHT_PROGBITS, ELF::SHF_ALLOC, 2, true, ".DSEG"};
  RelocationAttributeMap["BSSF"] =           {".bssf", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_WRITE, 2, true, ".DSEG"};
  RelocationAttributeMap["AT"] =             {".text_AT", ELF::SHT_PROGBITS, ELF::SHF_ALLOC | ELF::SHF_EXECINSTR | ELF::SHF_RENESAS_ABS, 1, false, ".CSEG"};
  RelocationAttributeMap["DATA_AT"] =        {".data_AT", ELF::SHT_PROGBITS, ELF::SHF_ALLOC | ELF::SHF_RENESAS_ABS, 1, false, ".DSEG"};
  RelocationAttributeMap["BSS_AT"] =         {".bss_AT", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_WRITE | ELF::SHF_RENESAS_ABS, 1, false, ".DSEG"};
  RelocationAttributeMap["BIT_AT"] =         {"", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_WRITE | ELF::SHF_RENESAS_ABS, 1, false, ".BSEG"};
  RelocationAttributeMap["OPT_BYTE"] =       {".option_byte", ELF::SHT_PROGBITS, ELF::SHF_ALLOC, 1, false, ".CSEG"};// TODO error check for rename
  RelocationAttributeMap["SECUR_ID"] =       {".security_id", ELF::SHT_PROGBITS, ELF::SHF_ALLOC, 1, false, ".CSEG"};// TODO error check for rename
  // clang-format on
}

bool RL78AsmParser::ParseSectionAddress(std::string SectionName,
                                        std::string &NewSectionName) {
  const MCExpr *Value;
  uint64_t SectionAddress;
  SMLoc ExprLoc = getLexer().getLoc();
  if (getParser().parseExpression(Value))
    return true;
  if (const MCConstantExpr *MCE = dyn_cast<MCConstantExpr>(Value)) {
    SectionAddress = MCE->getValue();
    if (!isUIntN(20, SectionAddress))
      return Error(ExprLoc, "out of range literal value");
  } else
    return Error(ExprLoc, "out of range literal value");

  std::ostringstream ss;
  ss << "_AT" << std::uppercase << std::hex << SectionAddress;
  NewSectionName = SectionName + ss.str();
  return false;
}

void RL78AsmParser::SwitchToSection(StringRef NewSectionName, unsigned Type,
                                    unsigned Flags) {
  int64_t Size = 0;
  StringRef GroupName;
  const MCExpr *Subsection = nullptr;
  MCSection *ELFSection = getParser().getContext().getELFSection(
      NewSectionName, Type, Flags, Size);

  getStreamer().switchSection(ELFSection, Subsection);
}

bool RL78AsmParser::EmitSectionDirective(
    StringRef SectionName, StringRef RelocationAttribute,
    const RelocationAttributeDefault* RelocationAttributeDesc) {
  // Parse and handle absolute section address.
  std::string NewSectionName = SectionName.str();
  if (RelocationAttribute.compare_insensitive("AT") == 0 ||
      RelocationAttribute.compare_insensitive("DATA_AT") == 0 ||
      RelocationAttribute.compare_insensitive("BSS_AT") == 0 ||
      RelocationAttribute.compare_insensitive("BIT_AT") == 0) {

    // TODO check for overlaps at compile time already?
    if (ParseSectionAddress(SectionName.str(), NewSectionName))
      return true;
  }

  // We expect spaces, comments, EOF/EOL only after this on this line.
  if (eatSpacesTillEndOfLine())
    return TokError("unexpected token in directive");

  unsigned Flags = RelocationAttributeDesc->Flags;
  // If .ORG is written immediately after a section definition directive, the
  // section is only generated from the absolute address.
  AsmToken NextToken = getLexer().peekTok();
  if (NextToken.is(AsmToken::Identifier) &&
      (NextToken.getString().compare_insensitive(".ORG") == 0)) {
    // Eat EndOfStatement.
    Lex();
    // Eat .ORG.
    Lex();
    if (ParseSectionAddress(SectionName.str(), NewSectionName))
      return true;
    Flags = Flags | ELF::SHF_RENESAS_ABS;
  }

  SwitchToSection(NewSectionName, RelocationAttributeDesc->Type, Flags);

  // Apply the default section align
  if (RelocationAttribute.compare_insensitive("TEXT") == 0 ||
      RelocationAttribute.compare_insensitive("TEXT") == 0 ||
      RelocationAttribute.compare_insensitive("TEXTF") == 0 ||
      RelocationAttribute.compare_insensitive("TEXTF_UNIT64KP") == 0) {
    getStreamer().emitCodeAlignment(
        Align(RelocationAttributeDesc->DefaultAlign), STI);
  } else {
    getStreamer().emitValueToAlignment(
        Align(RelocationAttributeDesc->DefaultAlign), 0, 1);
  }

  return false;
}

bool RL78AsmParser::LookupRelocationAttribute(
    StringRef SectionName, StringRef Attribute,
    RelocationAttributeDefault **RelocationAttributeDesc) {
  auto RelocationAttributeMatch = RelocationAttributeMap.find(Attribute);

  if (RelocationAttributeMatch == RelocationAttributeMap.end())
    return TokError("unexpected relocation-attribute in directive");

  if (Attribute.compare_insensitive("OPT_BYTE") == 0 && SectionName.compare("") != 0 && SectionName.compare(".option_byte") != 0 ||
      Attribute.compare_insensitive("SECUR_ID") == 0 && SectionName.compare("") != 0 && SectionName.compare(".security_id") != 0)
	return TokError("special section name cannot be changed");

  // Not exactly an appropriate place, but check for section name correctness
  // too.
  if (SectionName.compare("") != 0 &&
      !std::regex_match(SectionName.str(), std::regex("[A-Za-z0-9\\._@]+")))
    return TokError("invalid characters in section name");

  *RelocationAttributeDesc = &RelocationAttributeMatch->second;
  return false;
}

bool RL78AsmParser::ParseSectionArguments(SMLoc loc) {
  StringRef SectionName;

  if (ParseSectionName(SectionName))
    return TokError("expected identifier in directive");

  if (getLexer().is(AsmToken::Comma)) {
    Lex();
    if (getLexer().isNot(AsmToken::Identifier)) {
      return TokError("expected relocation-attribute in directive");
    } else {
      StringRef RelocationAttribute = getTok().getIdentifier();
      Lex();
      RelocationAttributeDefault *RelocationAttributeDesc;
      if (LookupRelocationAttribute(SectionName, RelocationAttribute, &RelocationAttributeDesc))
        return true;

      return EmitSectionDirective(SectionName, RelocationAttribute,
                                  RelocationAttributeDesc);
    }
  } else {
    return TokError("unexpected relocation-attribute in directive");
  }
}

bool RL78AsmParser::parseDirectiveSeg(StringRef Name, StringRef Type) {

  StringRef RelocationAttribute;
  if (Type.compare_insensitive(".CSEG") == 0)
    RelocationAttribute = "TEXT";
  else if (Type.compare_insensitive(".DSEG") == 0)
    RelocationAttribute = "DATA";
  else if (Type.compare_insensitive(".BSEG") == 0)
    RelocationAttribute = "SBSS_BIT";
  else
    return TokError("unexpected directive kind");

  // See if a relocation attribute is present
  if (getLexer().is(AsmToken::Identifier)) {
    RelocationAttribute = getLexer().getTok().getIdentifier();
    Lex();
  }
  RelocationAttributeDefault *RelocationAttributeDesc;
  if (LookupRelocationAttribute(Name, RelocationAttribute, &RelocationAttributeDesc))
    return true;
  return EmitSectionDirective(Name.compare("") == 0
                                  ? RelocationAttributeDesc->DefaultSectionName
                                  : Name,
                              RelocationAttribute, RelocationAttributeDesc);
}

bool RL78AsmParser::ParseDirectiveOrg() {
  std::string NewSectionName;
  MCSectionELF *CurrentSection =
      dyn_cast<MCSectionELF>(getStreamer().getCurrentSectionOnly());
  std::string SectionNamePrefix = CurrentSection->getName().str();

  // If the section name already has the _AT<address> suffix, drop it
  SectionNamePrefix =
      std::regex_replace(SectionNamePrefix, std::regex("_AT[0-9a-fA-F]*$"), "");

  if (ParseSectionAddress(SectionNamePrefix, NewSectionName))
    return true;

  SwitchToSection(NewSectionName, CurrentSection->getType(),
                  CurrentSection->getFlags() | ELF::SHF_RENESAS_ABS);

  return false;
}

bool RL78AsmParser::ParseDirectiveOffset() {
  const MCExpr *Offset;
  SMLoc OffsetLoc = getLexer().getLoc();
  if (checkForValidSection() || getParser().parseExpression(Offset))
    return true;
  int64_t FillExpr = 0;
  if (parseToken(AsmToken::EndOfStatement))
    return addErrorSuffix(" in '.OFFSET' directive");

  getStreamer().emitValueToOffset(Offset, FillExpr, OffsetLoc);
  return false;
}

bool RL78AsmParser::checkForValidSection() {
  if (!isParsingMSInlineAsm() && !getStreamer().getCurrentSectionOnly()) {
    getStreamer().initSections(false, *STI);
    return Error(getTok().getLoc(),
                 "expected section directive before assembly directive");
  }
  return false;
}

bool RL78AsmParser::parseDirectiveValue(StringRef IDVal, unsigned Size) {
  auto parseOp = [&]() -> bool {
    const MCExpr *Value;
    SMLoc ExprLoc = getLexer().getLoc();

    if (getLexer().getTok().is(AsmToken::String)) {
      if (Size != 1)
        return Error(ExprLoc, "Illegal string.");
      getStreamer().emitBytes(getLexer().getTok().getStringContents());
      Lex();
      return false;
    }

    if (checkForValidSection() || getParser().parseExpression(Value))
      return true;

    if (const MCConstantExpr *MCE = dyn_cast<MCConstantExpr>(Value)) {
      assert(Size <= 8 && "Invalid size");
      uint64_t IntValue = MCE->getValue();
      if (!isUIntN(8 * Size, IntValue) && !isIntN(8 * Size, IntValue))
        return Error(ExprLoc, "out of range literal value");
      getStreamer().emitIntValue(IntValue, Size);
    } else {
      getStreamer().emitValue(Value, Size, ExprLoc);
    }
    return false;
  };

  if (parseMany(parseOp))
    return addErrorSuffix(" in '" + Twine(IDVal) + "' directive");
  return false;
}

bool RL78AsmParser::parseDSDirective() {
  const MCExpr *Value;
  SMLoc ExprLoc = getLexer().getLoc();
  if (checkForValidSection() || getParser().parseExpression(Value))
    return true;
  // Special case constant expressions to match code generator.
  if (const MCConstantExpr *MCE = dyn_cast<MCConstantExpr>(Value)) {
    uint64_t AllocationSize = MCE->getValue();
    if (AllocationSize > 0xFFFFF)
      return Error(ExprLoc, "out of range literal value");
    for (uint32_t i = 1; i <= AllocationSize / 8; i++)
      getStreamer().emitIntValue(0, 8);
    if(AllocationSize % 8 > 0)
        getStreamer().emitIntValue(0, AllocationSize % 8);
  } else
    return Error(ExprLoc, "invalid absolute-expression");
  return false;
}

bool RL78AsmParser::parseDirectiveAlign() {
  SMLoc AlignmentLoc = getLexer().getLoc();
  int64_t Alignment;
  SMLoc MaxBytesLoc;
  bool HasFillExpr = false;
  int64_t FillExpr = 0;
  int64_t MaxBytesToFill = 0;

  if (checkForValidSection())
    return addErrorSuffix(" in directive");

  const MCExpr *Value;
  SMLoc ExprLoc = getLexer().getLoc();
  if (checkForValidSection() || getParser().parseExpression(Value))
    return true;

  if (const MCConstantExpr *MCE = dyn_cast<MCConstantExpr>(Value)) {
    uint64_t IntValue = MCE->getValue();
    // TODO: since the standard specifies powers of two, we do the same.
    // Revisit if we really need to allow any even alignment.
    if (IntValue < 2 || !llvm::isPowerOf2_64(IntValue))
      return Error(ExprLoc, "out of range literal value");
    Alignment = IntValue;
  } else {
    return Error(ExprLoc, "expected constant expression");
  }
  // Always emit an alignment here even if we thrown an error.
  bool ReturnVal = false;

  // Diagnose non-sensical max bytes to align.
  if (MaxBytesLoc.isValid()) {
    if (MaxBytesToFill < 1) {
      ReturnVal |= Error(MaxBytesLoc,
                         "alignment directive can never be satisfied in this "
                         "many bytes, ignoring maximum bytes expression");
      MaxBytesToFill = 0;
    }

    if (MaxBytesToFill >= Alignment) {
      Warning(MaxBytesLoc, "maximum bytes expression exceeds alignment and "
                           "has no effect");
      MaxBytesToFill = 0;
    }
  }

  // Check whether we should use optimal code alignment for this .align
  // directive.
  const MCSection *Section = getStreamer().getCurrentSectionOnly();
  assert(Section && "must have section to emit alignment");
  bool UseCodeAlign = Section->useCodeAlign();
  if (!HasFillExpr && UseCodeAlign) {
    getStreamer().emitCodeAlignment(Align(Alignment), STI, MaxBytesToFill);
  } else {
    // FIXME: Target specific behavior about how the "extra" bytes are filled.
    getStreamer().emitValueToAlignment(Align(Alignment), FillExpr, 1, MaxBytesToFill);
  }
  return ReturnVal;
}

std::string RL78AsmParser::ReplaceMacroLocalSymbols(
    std::string MacroBody, StringMap<std::string> &MacroLocalSymbols,
    SmallVector<MacroLocalDefinitionRange, 10> &MacroLocalSymbolRanges) {

  // Delete .LOCAL definitions from the macro body
  size_t Offset = 0;
  for (const MacroLocalDefinitionRange &Range : MacroLocalSymbolRanges) {
    size_t Length = Range.End - Range.Start;
    MacroBody.erase(Range.Start - Offset, Length);
    Offset += Length;
  }

  // Replace .LOCAL symbols from the macro definition
  // with unique local file level symbols
  for (const StringMapEntry<std::string> &LocalSymbol : MacroLocalSymbols)
    MacroBody =
        std::regex_replace(MacroBody, std::regex(LocalSymbol.getKey().str()),
                           LocalSymbol.getValue());

  return MacroBody;
}

bool RL78AsmParser::parseMacroLocalSymbols(
    StringMap<std::string> &MacroLocalSymbols) {
  auto parseOp = [&]() -> bool {
    StringRef Name;
    SMLoc Loc = getTok().getLoc();
    if (parseIdentifier(Name))
      return Error(Loc, "expected identifier");
    std::string LocalSymbolName = ".LL_" + Name.str() + "_\\@";
    MacroLocalSymbols[Name] = LocalSymbolName;
    /*MCSymbol *Sym = getContext().getOrCreateSymbol(LocalSymbolName);

    if (!getStreamer().emitSymbolAttribute(Sym, MCSA_Local))
      return Error(Loc, "unable to emit symbol attribute");*/
    return false;
  };

  if (parseMany(parseOp))
    return addErrorSuffix(" in directive");
  return false;
}

bool RL78AsmParser::parseDirectiveMacro(StringRef Name) {

  SMLoc DirectiveLoc = getLexer().getLoc();

  // Eat the .MACRO
  Lex();

  MCAsmMacroParameters Parameters;
  while (getLexer().isNot(AsmToken::EndOfStatement)) {

    MCAsmMacroParameter Parameter;
    if (parseIdentifier(Parameter.Name))
      return TokError("expected identifier in '.macro' directive");

    // Emit an error if two (or more) named parameters share the same name
    for (const MCAsmMacroParameter &CurrParam : Parameters)
      if (CurrParam.Name.equals(Parameter.Name))
        return TokError("macro '" + Name +
                        "' has multiple parameters"
                        " named '" +
                        Parameter.Name + "'");
    // CC-RL has only required parameters
    Parameter.Required = true;
    Parameters.push_back(std::move(Parameter));

    if (getLexer().is(AsmToken::Comma))
      Lex();
  }

  // Eat just the end of statement.
  getLexer().Lex();

  // Consuming deferred text, so use Lexer.Lex to ignore Lexing Errors
  AsmToken EndToken, StartToken = getTok();
  StringMap<std::string> MacroLocalSymbolMap;
  SmallVector<MacroLocalDefinitionRange, 10> MacroLocalSymbolRanges;
  // Lex the macro definition.
  while (true) {
    // Ignore Lexing errors in macros.
    while (getLexer().is(AsmToken::Error)) {
      getLexer().Lex();
    }

    // Check whether we have reached the end of the file.
    if (getLexer().is(AsmToken::Eof))
      return Error(DirectiveLoc, "no matching '.ENDM' in definition");

    if (getLexer().is(AsmToken::Identifier)) {
      if (getTok().getIdentifier() == ".LOCAL") {
        // Parse macro local symbol declarations and save
        // the declaration start/end position.
        size_t Start =
            getTok().getLoc().getPointer() - StartToken.getLoc().getPointer();
        getLexer().Lex();
        parseMacroLocalSymbols(MacroLocalSymbolMap);
        size_t End =
            getTok().getLoc().getPointer() - StartToken.getLoc().getPointer();
        MacroLocalSymbolRanges.push_back({Start, End});
      } else if (getTok().getIdentifier() == ".ENDM") {
        EndToken = getTok();
        getLexer().Lex();
        if (getLexer().isNot(AsmToken::EndOfStatement))
          return TokError("unexpected token in '" + EndToken.getIdentifier() +
                          "' directive");
        break;
      }
    }

    // Otherwise, scan til the end of the statement.
    eatToEndOfStatement();
  }

  if (getContext().lookupMacro(Name)) {
    return Error(DirectiveLoc, "macro '" + Name + "' is already defined");
  }

  const char *BodyStart = StartToken.getLoc().getPointer();
  const char *BodyEnd = EndToken.getLoc().getPointer();
  std::string Body = StringRef(BodyStart, BodyEnd - BodyStart).str();

  // Prepend "\" to parameters, as expected by the gcc syntax
  // The other option would be to reimplement handleMacroEntry and all the
  // related functions.
  for (const MCAsmMacroParameter &CurrParam : Parameters)
    Body = std::regex_replace(Body, std::regex(CurrParam.Name.str()),
                              ("\\" + CurrParam.Name).str());

  // Save new body
  MacroBodies[Name] = ReplaceMacroLocalSymbols(Body, MacroLocalSymbolMap,
                                               MacroLocalSymbolRanges);

  // checkForBadMacro(DirectiveLoc, Name, Body, Parameters);
  MCAsmMacro Macro(Name, StringRef(MacroBodies[Name]), std::move(Parameters));
  DEBUG_WITH_TYPE("asm-macros", dbgs() << "Defining new macro:\n";
                  Macro.dump());
  getContext().defineMacro(Name, std::move(Macro));
  return false;
}


/// Returns whether the given symbol is used anywhere in the given expression,
/// or subexpressions.
static bool isSymbolUsedInExpression(const MCSymbol *Sym, const MCExpr *Value) {
  switch (Value->getKind()) {
  case MCExpr::Binary: {
    const MCBinaryExpr *BE = static_cast<const MCBinaryExpr *>(Value);
    return isSymbolUsedInExpression(Sym, BE->getLHS()) ||
           isSymbolUsedInExpression(Sym, BE->getRHS());
  }
  case MCExpr::Target:
  case MCExpr::Constant:
    return false;
  case MCExpr::SymbolRef: {
    const MCSymbol &S =
        static_cast<const MCSymbolRefExpr *>(Value)->getSymbol();
    if (S.isVariable())
      return isSymbolUsedInExpression(Sym, S.getVariableValue());
    return &S == Sym;
  }
  case MCExpr::Unary:
    return isSymbolUsedInExpression(
        Sym, static_cast<const MCUnaryExpr *>(Value)->getSubExpr());
  }

  llvm_unreachable("Unknown expr kind!");
}

static bool checkSymbolDefinitionExpression(StringRef Name, bool allow_redef,
                               MCAsmParser &Parser, MCSymbol *&Sym,
                               const MCExpr *Value, SMLoc EqualLoc) {

  if (Parser.parseToken(AsmToken::EndOfStatement))
    return true;

  // Validate that the LHS is allowed to be a variable (either it has not been
  // used as a symbol, or it is an absolute symbol).
  Sym = Parser.getContext().lookupSymbol(Name);
  if (Sym) {
    // Diagnose assignment to a label.
    //
    // FIXME: Diagnostics. Note the location of the definition as a label.
    // FIXME: Diagnose assignment to protected identifier (e.g., register name).
    if (Value && isSymbolUsedInExpression(Sym, Value))
      return Parser.Error(EqualLoc, "Recursive use of '" + Name + "'");
    else if (Sym->isUndefined(/*SetUsed*/ false) && !Sym->isUsed() &&
             !Sym->isVariable())
      ; // Allow redefinitions of undefined symbols only used in directives.
    else if (Sym->isVariable() && !Sym->isUsed() && allow_redef)
      ; // Allow redefinitions of variables that haven't yet been used.
    else if (!Sym->isUndefined() && (!Sym->isVariable() || !allow_redef))
      return Parser.Error(EqualLoc, "redefinition of '" + Name + "'");
    else if (!Sym->isVariable())
      return Parser.Error(EqualLoc, "invalid assignment to '" + Name + "'");
    else if (!isa<MCConstantExpr>(Sym->getVariableValue()))
      return Parser.Error(EqualLoc,
                          "invalid reassignment of non-absolute variable '" +
                              Name + "'");
  }   
  return false;
}

bool RL78AsmParser::HasTargetSubExpressionKind(const MCExpr *Expr,
                                               unsigned TargetExpressionKind) {

  switch (Expr->getKind()) {
  case MCExpr::Binary: {
    const MCBinaryExpr *BExpr = cast<MCBinaryExpr>(Expr);
    return HasTargetSubExpressionKind(BExpr->getLHS(), TargetExpressionKind) ||
           HasTargetSubExpressionKind(BExpr->getRHS(), TargetExpressionKind);
  }
  case MCExpr::Constant:
  case MCExpr::SymbolRef:
    return false;
  case MCExpr::Unary:
    return HasTargetSubExpressionKind(cast<MCUnaryExpr>(Expr)->getSubExpr(),
                                      TargetExpressionKind);

  case MCExpr::Target: {
    const RL78MCExpr *TExpr = cast<RL78MCExpr>(Expr);
    return TExpr->getVariantKind() == TargetExpressionKind;
  }
  default:
    return false;
  }
}

static bool isGlobalElfSymbol(MCSymbol *symbol) {
    return symbol->isELF() && ((MCSymbolELF *)symbol)->getBinding() == ELF::STB_GLOBAL;
}

bool RL78AsmParser::parseDirectiveSet(StringRef Name) {
  // Each name is a redefinable name.
  // A bit position specification cannot be defined.
  // The name generated by the .SET directive cannot be externally defined by
  // the .PUBLIC directive.
  MCSymbol *Sym = nullptr;
  const MCExpr *Value = nullptr;
  SMLoc EqualLoc = Parser.getTok().getLoc();
  // Eat the .SET
  Lex();

  if (Parser.parseExpression(Value))
    return Parser.TokError("missing expression");

  if (HasTargetSubExpressionKind(Value, RL78MCExpr::VK_RL78_BITPOSITIONAL))
    return Error(EqualLoc, "invalid expression");

  int64_t Res;
  if (!Value->evaluateAsAbsolute(Res))
    return Parser.TokError("not an absolute expression");

  if (checkSymbolDefinitionExpression(Name, true, getParser(), Sym, Value,
                                      EqualLoc))
    return true;
  if (!Sym)
    Sym = Parser.getContext().getOrCreateSymbol(Name);
  else if (isGlobalElfSymbol(Sym))
    return Error(EqualLoc, "symbol already defined as public/extern");

  Sym->setRedefinable(true);
  getStreamer().emitAssignment(Sym, MCConstantExpr::create(Res, getContext()));
  return false;
}

bool RL78AsmParser::SplitBitPosition(std::string *AddressSymbol,
                                     int64_t *AddressValue,
                                     int64_t *BitPosition, bool *IsSymAddress,
                                     std::string *ErrorMsg) {
  // TODO: check in case of symbols that they are not in turn bit positionals

  auto Parts = Parser.getTok().getString().split('.');
  // For absolute values, address and bit position, the AsmLexer already
  // validated the ranges Handle the address part
  if (Parts.first.startswith("0x")) {
    *IsSymAddress = false;
    std::stringstream ss;
    ss << std::hex << Parts.first.str();
    ss >> *AddressValue;
  } else {
    *IsSymAddress = true;
    *AddressSymbol = Parts.first;
  }

  // Handle the bit part
  if (Parts.second[0] >= '0' && Parts.second[0] <= '7') {
    *BitPosition = Parts.second[0] - '0';
  } else {
    // Bit symbol should be a locally resolved symbol.
    const MCSymbol *BitSym = Parser.getContext().lookupSymbol(Parts.second);
    if (!BitSym) {
      *ErrorMsg = "unresolved bit position symbol";
      return true;
    }

    int64_t Position = -1;
    if (BitSym->isVariable() &&
        BitSym->getVariableValue()->evaluateAsAbsolute(Position)) {
      if (Position >= 0 && Position <= 7) {
        *BitPosition = Position;
      } else {
        *ErrorMsg = "bit position not in [0, 7] range";
        return true;
      }
    } else {
      *ErrorMsg = "invalid bit position symbol";
      return true;
    }
  }
  return false;
}

bool RL78AsmParser::parseDirectiveEqu(StringRef Name) {
  // Symbols that have already been defined by using .EQU cannot be redefined.
  // The name generated by the .EQU directive can be externally defined by the
  // .PUBLIC directive. A bit position specification can be defined.
  // Relocatable terms cannot be specified in the operand field.
  MCSymbol *Sym;
  MCSymbol *BitPosSym =
      Parser.getContext().lookupSymbol(BitPositionSymbolPrefix + Name);

  SMLoc EqualLoc = Parser.getTok().getLoc();
  // Eat the .EQU
  Lex();

  int64_t AbsoluteValue = 0;
  bool CreateBitposSym = false;
  int64_t BitPosition = -1;
  // .EQU will treat dots as bit positional specifiers.
  const MCExpr *Value = nullptr;

  if (Parser.parseExpression(Value))
    return Parser.TokError("missing expression");

  // Parse expression already tried to constant fold it
  if (Value->getKind() == MCExpr::Constant) {
    AbsoluteValue = cast<MCConstantExpr>(Value)->getValue();
  } else {
    // The expression contains a target expression somewhere or it's couldn't
    // constant fold it.
    MCValue AbsVal;
    if (!HasTargetSubExpressionKind(Value, RL78MCExpr::VK_RL78_BITPOSITIONAL) ||
        !RL78MCExpr::FoldBitPositionalExpression(Value, AbsVal, BitPosition,
                                                 getContext()) ||
        !AbsVal.isAbsolute() || BitPosition == -1)
      return Error(EqualLoc, "invalid expression");
    AbsoluteValue = AbsVal.getConstant();
    CreateBitposSym = true;
  }

  if (checkSymbolDefinitionExpression(Name, false, getParser(), Sym, Value,
                                      EqualLoc))
    return true;

  if (CreateBitposSym && BitPosSym)
    return Parser.TokError("bit position symbol already defined");

  // At this point we should have an absolute value and possibly a bit position
  // value. Create the symbol(s) and assign values.
  bool ShouldBePublic = false;
  if (!Sym)
    Sym = Parser.getContext().getOrCreateSymbol(Name);
  else
    ShouldBePublic = isGlobalElfSymbol(Sym);
  Sym->setRedefinable(false);

  if (CreateBitposSym) {
    BitPosSym =
        Parser.getContext().getOrCreateSymbol(BitPositionSymbolPrefix + Name);
    BitPosSym->setRedefinable(false);
    MCSymbolELF *ELFBitPosSymbol = cast<MCSymbolELF>(BitPosSym);
    ELFBitPosSymbol->setType(ELF::STT_HIPROC);

    if (ShouldBePublic &&
        !getStreamer().emitSymbolAttribute(BitPosSym, MCSA_Global))
      return Error(Parser.getTok().getLoc(), "unable to emit symbol attribute");

    getStreamer().emitAssignment(
        BitPosSym, MCConstantExpr::create(BitPosition, getContext()));
  }
  getStreamer().emitAssignment(
      Sym, MCConstantExpr::create(AbsoluteValue, getContext()));

  return false;
}

// symbol-name .VECTOR Vector-table-allocation-address
bool RL78AsmParser::parseDirectiveVector(StringRef Name) {

  MCSymbol *Sym = Parser.getContext().lookupSymbol(Name);

  SMLoc EqualLoc = Parser.getTok().getLoc();
  // Eat the .VECTOR
  Lex();

  // Parse vector table allocation address
  if (getLexer().getTok().isNot(AsmToken::Integer))
    return TokError("unexpected token in directive");

  // An even address between 0x00000 and 0x0007E can be specified as the vector
  // table allocation address.
  int64_t VectorAddress = getLexer().getTok().getIntVal();
  if (0 > VectorAddress || VectorAddress > 0x7e || VectorAddress % 2 != 0)
    return TokError("invalid vector allocation address value");

  std::string VectorSymbolName =
      ("___vector_" + Twine::utohexstr(VectorAddress) + "_").str();

  MCSymbol *VectorSym = Parser.getContext().lookupSymbol(VectorSymbolName);
  if (VectorSym)
    return TokError("Redefinition of the 0x" +
                    Twine::utohexstr(VectorAddress & 0xFE).str() +
                    " entry in the interrupt table!");

  // Eat the address value.
  Lex();
  if (!Sym)
    Sym = Parser.getContext().getOrCreateSymbol(Name);
   VectorSym = Parser.getContext().getOrCreateSymbol(VectorSymbolName);

  VectorSym->setRedefinable(false);
  getStreamer().emitAssignment(VectorSym,
                               MCSymbolRefExpr::create(Sym, getContext()));
  getStreamer().emitSymbolAttribute(VectorSym, MCSA_Global);

  return false;
}

// .LINE ["file-name",] line-number [; comment]
bool RL78AsmParser::parseDirectiveLine() {
  AsmToken Token = getLexer().getTok();

  StringRef FileName;
  int64_t LineNo;

  // Parse optional filename
  if (Token.is(AsmToken::String)) {
    FileName = Token.getString();
    Lex();
    if (getParser().check(getLexer().getTok().isNot(AsmToken::Comma),
                          getLexer().getTok().getLoc(),
                          "expected ',' after filename"))
      return true;
    Lex();
  }

  // Parse line number
  if (getLexer().getTok().isNot(AsmToken::Integer))
    return TokError("unexpected token in directive");

  LineNo = getLexer().getTok().getIntVal();
  Lex();

  // TODO: It appears that the CC-RL assembler ignores this directive, contrary
  // to LLVM's .loc. Let's also ignore it for now.

  return false;
}

// ._LINE_TOP inline_asm [; comment]
// ._LINE_END inline_asm [; comment]
bool RL78AsmParser::parseDirectiveLineTopEnd() {
  AsmToken Token = getLexer().getTok();
  // After syntax checking we ignore this directive
  // Note that we don't check for matching TOP/END pairs.
  if (Token.isNot(AsmToken::Identifier) ||
      Token.getString().compare("inline_asm") != 0)
    return TokError("unexpected token in directive");
  Lex();
  return false;
}

// .STACK symbol-name=absolute-expression [; comment]
bool RL78AsmParser::parseDirectiveStack() {

  // After syntax checking we ignore this directive
  if (getLexer().getTok().isNot(AsmToken::Identifier))
    return TokError("unexpected token in directive");
  Lex();

  if (getLexer().getTok().isNot(AsmToken::Equal))
    return TokError("unexpected token in directive");
  Lex();

  int64_t Value;
  if (getParser().parseAbsoluteExpression(Value))
    return true;

  return false;
}

bool RL78AsmParser::parseDirectiveType() {

  // No syntax checking because the CC-RL manual does not describe the
  // directive. Just eat everything till the end of the line.
  while (getLexer().getTok().isNot(AsmToken::EndOfStatement) &&
         getLexer().getTok().isNot(AsmToken::Eof))
    Lex();

  return false;
}

bool RL78AsmParser::ParseDirective(AsmToken DirectiveID) {

  if (!EnableRL78CCRLAsmSyntax)
    return true;

  SMLoc Loc = getLexer().getLoc();

  if (DirectiveID.getString().compare_insensitive(".PUBLIC") == 0 ||
      DirectiveID.getString().compare_insensitive(".EXTERN") == 0) {
    // TODO: add error handling
    return parseDirectiveSymbolAttribute(MCSA_Global);
  }
  if (DirectiveID.getString().compare_insensitive(".SECTION") == 0)
    return ParseSectionArguments(Loc);
  if (DirectiveID.getString().compare_insensitive(".ORG") == 0)
    return ParseDirectiveOrg();
  if (DirectiveID.getString().compare_insensitive(".OFFSET") == 0)
    return ParseDirectiveOffset();
  if (DirectiveID.getString().compare_insensitive(".DB") == 0)
    return parseDirectiveValue(".DB", 1);
  if (DirectiveID.getString().compare_insensitive(".DB2") == 0)
    return parseDirectiveValue(".DB2", 2);
  if (DirectiveID.getString().compare_insensitive(".DB4") == 0)
    return parseDirectiveValue(".DB4", 4);
  if (DirectiveID.getString().compare_insensitive(".DB8") == 0)
    return parseDirectiveValue(".DB8", 8);
  if (DirectiveID.getString().compare_insensitive(".DS") == 0)
    return parseDSDirective();
  if (DirectiveID.getString().compare_insensitive(".ALIGN") == 0)
    return parseDirectiveAlign();

  /*if (DirectiveID.getString().compare(".DBIT") == 0) {
        //TODO error check for current section = bit section
        getStreamer().emitIntValue(0, 1);
    return false;
  }*/
  if (DirectiveID.getString().compare_insensitive(".LINE") == 0)
    return parseDirectiveLine();
  if (DirectiveID.getString().compare_insensitive("._LINE_TOP") == 0 ||
      DirectiveID.getString().compare_insensitive("._LINE_END") == 0)
    return parseDirectiveLineTopEnd();
  if (DirectiveID.getString().compare_insensitive(".STACK") == 0)
    return parseDirectiveStack();
  if (DirectiveID.getString().compare_insensitive(".TYPE") == 0)
    return parseDirectiveType();

  if (DirectiveID.getKind() == AsmToken::Identifier) {
    StringRef Tok = getLexer().getTok().getString();
    if (Tok.compare_insensitive(".MACRO") == 0)
      return parseDirectiveMacro(DirectiveID.getString());
	if (Tok.compare_insensitive(".SET") == 0)
      return parseDirectiveSet(DirectiveID.getString());
	if (Tok.compare_insensitive(".EQU") == 0)
      return parseDirectiveEqu(DirectiveID.getString());

    if (Tok.compare_insensitive(".CSEG") == 0 || Tok.compare_insensitive(".BSEG") == 0 ||
        Tok.compare_insensitive(".DSEG") == 0) {
      Lex();
      return parseDirectiveSeg(DirectiveID.getString(), Tok);
    }

    // section name is optional
    if (DirectiveID.getString().compare_insensitive(".CSEG") == 0 ||
        DirectiveID.getString().compare_insensitive(".DSEG") == 0 ||
        DirectiveID.getString().compare_insensitive(".BSEG") == 0)
      return parseDirectiveSeg("", DirectiveID.getString());

    if (Tok.compare_insensitive(".VECTOR") == 0)
      return parseDirectiveVector(DirectiveID.getString());
  }
  return true;
}

bool RL78AsmParser::ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
                                     SMLoc NameLoc, OperandVector &Operands) {

  // First verify if b_cc or s_cc.
  // If not, single mnemonic - push operand.
  if (Name.compare("sel") == 0 && getSTI().getCPU() == "RL78_S1") {

    SMLoc Loc = getLexer().getLoc();
    return Error(Loc, "Instruction not defined for S1 core type");
  }
  if ((Name.compare("mulhu") == 0 || Name.compare("mulh") == 0 ||
       Name.compare("divhu") == 0 || Name.compare("divwu") == 0 ||
       Name.compare("machu") == 0 || Name.compare("mach") == 0) &&
      (getSTI().getCPU() == "RL78_S1" || getSTI().getCPU() == "RL78_S2")) {

    SMLoc Loc = getLexer().getLoc();
    return Error(Loc, "Instruction defined only for S3 core type.");
  }
  if (!tryParseBCCorSCC(Operands, Name, NameLoc)) {
    // First operand in MCInst is instruction mnemonic.
    Operands.push_back(RL78Operand::CreateToken(Name, NameLoc));
  }

  // Read the remaining operands.
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    // Read the first operand.
    if (parseOperand(Operands, Name)) {
      SMLoc Loc = getLexer().getLoc();
      Parser.eatToEndOfStatement();
      return Error(Loc, "unexpected token in argument list");
    }

    while (getLexer().is(AsmToken::Comma)) {
      Parser.Lex(); // Eat the comma.

      // Parse and remember the operand.
      if (parseOperand(Operands, Name)) {
        SMLoc Loc = getLexer().getLoc();
        Parser.eatToEndOfStatement();
        return Error(Loc, "unexpected token in argument list");
      }
    }
  }

  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    SMLoc Loc = getLexer().getLoc();
    Parser.eatToEndOfStatement();
    return Error(Loc, "unexpected token in argument list");
  }
  // Consume the EndOfStatement.
  Parser.Lex();
  return false;
}



static OperandMatchResultTy CheckAddressValueRange(StringRef Mnemonic,
                                                   OperandVector &Operands,
                                                   int64_t AddressValue,
                                                   MCContext &Context, SMLoc S,
                                                   SMLoc E) {
  const MCExpr *EVal = MCConstantExpr::create(AddressValue, Context);
  if (Mnemonic.compare("movw") != 0 && AddressValue > 0xfff1f &&
      AddressValue <= 0xfffff)
    Operands.push_back(RL78Operand::CreateSfr(EVal, S, E));
  else if (AddressValue > 0xfff1f && AddressValue <= 0xfffff &&
           AddressValue % 2 == 0)
    Operands.push_back(RL78Operand::CreateSfrp(EVal, S, E));
  else if (AddressValue >= 0xffe20 && AddressValue <= 0xfff1f)
    Operands.push_back(RL78Operand::CreateAbs8(EVal, S, E));
  else
    return MatchOperand_NoMatch;
  return MatchOperand_Success;
}

StringRef StripTempSymbolPrefix(StringRef Symbol) {
  // We are expecting names in the form of:
  // .L__$__{Symbol or RegName}__$__{Nr}
  StringRef Guard = "__$__";
  size_t Start = Symbol.find(Guard) + Guard.size();
  size_t End = Symbol.rfind(Guard);
  if (Start != StringRef::npos && End != StringRef::npos && Start != End) {
    StringRef Temp = Symbol.substr(Start, End - Start);
    return Symbol.substr(Start, End - Start);
  }

  return Symbol;
}

OperandMatchResultTy
RL78AsmParser::parseDotIncludingOperand(OperandVector &Operands,
                                        StringRef Mnemonic) {

  if (Mnemonic.compare("mov1") != 0 && Mnemonic.compare("and1") != 0 &&
      Mnemonic.compare("or1") != 0 && Mnemonic.compare("xor1") != 0 &&
      Mnemonic.compare("set1") != 0 && Mnemonic.compare("clr1") != 0 &&
      Mnemonic.compare("bt") != 0 && Mnemonic.compare("bf") != 0 &&
      Mnemonic.compare("btclr") != 0)
    return MatchOperand_NoMatch;

  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const AsmToken &Token = getLexer().getTok();

  if (Token.is(AsmToken::Identifier) &&
          (Token.getString().compare_insensitive("cy") == 0 ||
           Token.getString().compare_insensitive("es") == 0) ||
      Token.is(AsmToken::LBrac))
    return MatchOperand_NoMatch;

  const MCExpr *Value;
  if (getParser().parseExpression(Value)) {
    Error(Token.getLoc(), "missing expression");
    return MatchOperand_NoMatch;
  }

  int64_t AddressValue = 0;
  MCValue AddressMCValue;
  int64_t BitPosition = -1;
  // Check if it's a symbolref to a bitpositional symbol
  if (Value->getKind() == MCExpr::SymbolRef) {
    const MCSymbol *AddressSymbol =
        Parser.getContext().lookupSymbol(Token.getString());
    MCSymbol *PositionSymbol = Parser.getContext().lookupSymbol(
        BitPositionSymbolPrefix + Token.getString());
    if (!AddressSymbol || !AddressSymbol->isVariable() ||
        !AddressSymbol->getVariableValue()->evaluateAsAbsolute(AddressValue))
      return MatchOperand_NoMatch;
    if (!PositionSymbol || !PositionSymbol->isVariable() ||
        !PositionSymbol->getVariableValue()->evaluateAsAbsolute(BitPosition))
      return MatchOperand_NoMatch;
    if (CheckAddressValueRange(Mnemonic, Operands, AddressValue, getContext(),
                               S, E) != MatchOperand_Success)
      return MatchOperand_NoMatch;
  } else {

    if (/*!HasTargetSubExpressionKind(Value, RL78MCExpr::VK_RL78_BITPOSITIONAL)
           ||*/
        !RL78MCExpr::FoldBitPositionalExpression(Value, AddressMCValue,
                                                 BitPosition, getContext()) ||
        BitPosition == -1) {
      LLVM_DEBUG(Value->dump());
      Error(Token.getLoc(), "invalid expression");
      return MatchOperand_NoMatch;
    }

    if (AddressMCValue.isAbsolute() &&
        CheckAddressValueRange(Mnemonic, Operands, AddressMCValue.getConstant(),
                               getContext(), S, E) != MatchOperand_Success) {
      LLVM_DEBUG(Value->dump());
      Error(Token.getLoc(), "invalid expression");
      return MatchOperand_NoMatch;
    } else if (!AddressMCValue.isAbsolute()) {
      unsigned RegAKind, RegBKind;
      MCRegister RegA, RegB;
      bool IsSymARegister = false;
      bool IsSymBRegister = false;
      StringRef SymAName, SymBName;
      MCSymbol *SymA, *SymB;

      if (AddressMCValue.getSymA()) {
        SymAName = StripTempSymbolPrefix(
            AddressMCValue.getSymA()->getSymbol().getName());
        IsSymARegister = matchRegisterNameByName(SymAName, RegA, RegAKind);
        SymA = getContext().lookupSymbol(SymAName);
      }

      if (AddressMCValue.getSymB()) {
        SymBName = StripTempSymbolPrefix(
            AddressMCValue.getSymB()->getSymbol().getName());
        IsSymBRegister = matchRegisterNameByName(SymBName, RegB, RegBKind);
      }

      // Registers can't be used in binary expressions and can't have constant
      // adds.
      if ((IsSymARegister || IsSymBRegister) &&
          AddressMCValue.getConstant() != 0) {
        Error(Token.getLoc(), "invalid expression");
        return MatchOperand_NoMatch;
      }
      const MCExpr *SymEVal;
      if (IsSymARegister || IsSymBRegister) {
        Operands.push_back(
            RL78Operand::CreateReg(IsSymARegister ? RegA : RegB,
                                   IsSymARegister ? RegAKind : RegBKind, S, E));
      } else if (AddressMCValue.getSymA() && AddressMCValue.getSymB()) {
        SymA = getContext().getOrCreateSymbol(SymAName);
        SymB = getContext().getOrCreateSymbol(SymBName);
        SymEVal = MCBinaryExpr::createAdd(
            MCSymbolRefExpr::create(SymA, getContext()),
            MCConstantExpr::create(AddressMCValue.getConstant(), getContext()),
            getContext());
        SymEVal = MCBinaryExpr::createSub(
            SymEVal, MCSymbolRefExpr::create(SymB, getContext()), getContext());

        Operands.push_back(RL78Operand::CreateAbs8(SymEVal, S, E));
      } else if (AddressMCValue.getSymA()) {
        SymA = getContext().getOrCreateSymbol(SymAName);
        SymEVal = MCBinaryExpr::createAdd(
            MCSymbolRefExpr::create(SymA, getContext()),
            MCConstantExpr::create(AddressMCValue.getConstant(), getContext()),
            getContext());
        Operands.push_back(RL78Operand::CreateAbs8(SymEVal, S, E));
      } else {
        llvm_unreachable("Unexpected MCValue");
      }
    }
  }

  const MCExpr *EVal = MCConstantExpr::create(BitPosition, getContext());
  Operands.push_back(RL78Operand::CreateImm07(EVal, S, E));
  return MatchOperand_Success;
}

OperandMatchResultTy RL78AsmParser::ParseRegister(OperandVector &Operands,
                                                  StringRef Mnemonic) {

  OperandMatchResultTy ResTy = MatchOperand_NoMatch;
  unsigned RegKind;
  MCRegister Reg;
  if (matchRegisterName(Parser.getTok(), Reg, RegKind) &&
      !getLexer().peekTok().is(AsmToken::Colon)) {

    SMLoc S = Parser.getTok().getLoc();
    Parser.Lex(); // Eat the identifier token.
    SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
    Operands.push_back(RL78Operand::CreateReg(Reg, RegKind, S, E));

    ResTy = MatchOperand_Success;
  }

  return ResTy;
}

OperandMatchResultTy RL78AsmParser::ParseOpeandRBx(OperandVector &Operands) {

  OperandMatchResultTy ResTy = MatchOperand_NoMatch;

  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const MCExpr *EVal;

  StringRef name = Parser.getTok().getString();
  if (name.compare_insensitive("rb0") == 0) {
    EVal = MCConstantExpr::create(0, getContext());
    Operands.push_back(RL78Operand::CreateSELRBx(EVal, S, E));
    ResTy = MatchOperand_Success;
    Parser.Lex();
  } else if (name.compare_insensitive("rb1") == 0) {
    EVal = MCConstantExpr::create(1, getContext());
    Operands.push_back(RL78Operand::CreateSELRBx(EVal, S, E));
    ResTy = MatchOperand_Success;
    Parser.Lex();
  } else if (name.compare_insensitive("rb2") == 0) {
    EVal = MCConstantExpr::create(2, getContext());
    Operands.push_back(RL78Operand::CreateSELRBx(EVal, S, E));
    ResTy = MatchOperand_Success;
    Parser.Lex();
  } else if (name.compare_insensitive("rb3") == 0) {
    EVal = MCConstantExpr::create(3, getContext());
    Operands.push_back(RL78Operand::CreateSELRBx(EVal, S, E));
    ResTy = MatchOperand_Success;
    Parser.Lex();
  }
  return ResTy;
}

OperandMatchResultTy
RL78AsmParser::ParseShiftIntegerOperand(OperandVector &Operands,
                                        StringRef Mnemonic) {

  OperandMatchResultTy ResTy = MatchOperand_NoMatch;

  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const MCExpr *EVal;
  if (Mnemonic.compare("shr") == 0 || Mnemonic.compare("shl") == 0 ||
      Mnemonic.compare("sar") == 0) {
    std::unique_ptr<RL78Operand> Op;
    if (!getParser().parseExpression(EVal, E)) {
      Op = RL78Operand::CreateImm17(EVal, S, E);

      Operands.push_back(std::move(Op));
      ResTy = MatchOperand_Success;
    }
  } else if (Mnemonic.compare("shrw") == 0 || Mnemonic.compare("shlw") == 0 ||
             Mnemonic.compare("sarw") == 0 || Mnemonic.compare("shrw") == 0) {

    std::unique_ptr<RL78Operand> Op;
    if (!getParser().parseExpression(EVal, E)) {
      Op = RL78Operand::CreateImm115(EVal, S, E);

      Operands.push_back(std::move(Op));
      ResTy = MatchOperand_Success;
    }
  } else if (Mnemonic.compare("ror") == 0 || Mnemonic.compare("rol") == 0 ||
             Mnemonic.compare("rorc") == 0 || Mnemonic.compare("rolc") == 0 ||
             Mnemonic.compare("rolwc") == 0 || Mnemonic.compare("rorc") == 0) {

    Operands.push_back(RL78Operand::CreateToken(Parser.getTok().getString(),
                                                Parser.getTok().getLoc()));
    Parser.Lex();
    ResTy = MatchOperand_Success;
  }
  return ResTy;
}

OperandMatchResultTy RL78AsmParser::parseOperand(OperandVector &Operands,
                                                 StringRef Mnemonic) {
  // TODO: cleanup/code duplication reduction
  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const MCExpr *Res;

  // SEL RB0 ;TODO: add s1 not check.
  if (ParseOpeandRBx(Operands) == MatchOperand_Success)
    return MatchOperand_Success;
  // Register ax, special, or r8.
  if (ParseRegister(Operands, Mnemonic) == MatchOperand_Success)
    return MatchOperand_Success;

  // Byte or word.
  if (getLexer().is(AsmToken::Hash)) {

    Parser.Lex(); // Eat the Hash token.
    SMLoc S = Parser.getTok().getLoc();
    SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
    const MCExpr *EVal;
    Parser.parseExpression(EVal, E);
    Operands.push_back(RL78Operand::CreateImm(EVal, S, E));
    return MatchOperand_Success;
  }
  if (getLexer().is(AsmToken::Dollar)) {

    AsmToken Excl = Parser.Lex();
    if (getLexer().is(AsmToken::Exclaim)) {
      Parser.Lex();
      SMLoc S = Parser.getTok().getLoc();
      SMLoc E =
          SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
      const MCExpr *EVal;
      Parser.parseExpression(EVal, E);
      if (Mnemonic.compare("call") == 0)
        Operands.push_back(RL78Operand::CreatebrtargetRel16(EVal, S, E));
      else
        Operands.push_back(RL78Operand::CreatebrtargetRel16(EVal, S, E));
      return MatchOperand_Success;

    } else {
      SMLoc S = Parser.getTok().getLoc();
      SMLoc E =
          SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
      const MCExpr *EVal;
      Parser.parseExpression(EVal, E);
      Operands.push_back(RL78Operand::CreatebrtargetRel8(EVal, S, E));
      return MatchOperand_Success;
    }
  }
  if (getLexer().is(AsmToken::Exclaim)) {
    AsmToken ExclFirst = Parser.getTok();
    AsmToken ExclSecond = Parser.Lex();
    if (getLexer().is(AsmToken::Exclaim)) {
      Parser.Lex();
      SMLoc S = Parser.getTok().getLoc();
      SMLoc E =
          SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
      const MCExpr *EVal;
      Parser.parseExpression(EVal, E);
      if (Mnemonic.compare("br") == 0) {
        Operands.push_back(RL78Operand::CreateToken(ExclFirst.getString(),
                                                    ExclFirst.getLoc()));
        Operands.push_back(RL78Operand::CreateToken(ExclSecond.getString(),
                                                    ExclSecond.getLoc()));

        Operands.push_back(RL78Operand::CreateAbs20(EVal, S, E));
      } else {
        Operands.push_back(RL78Operand::CreateToken(ExclFirst.getString(),
                                                    ExclFirst.getLoc()));
        Operands.push_back(RL78Operand::CreateToken(ExclSecond.getString(),
                                                    ExclSecond.getLoc()));

        Operands.push_back(RL78Operand::CreateAbs20(EVal, S, E));
      }
      return MatchOperand_Success;
    } else {

      SMLoc S = Parser.getTok().getLoc();
      SMLoc E =
          SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
      const MCExpr *EVal;
      StringRef checkDot = getLexer().getTok().getString();

      size_t dot = checkDot.find(".");
      if (dot != std::string::npos &&
          checkDot.substr(dot + 1, checkDot.size())
                  .find_first_not_of("0123456789") == std::string::npos &&
          (Mnemonic.compare("set1") == 0 || Mnemonic.compare("clr1") == 0)) {
        std::string before_dot = checkDot.substr(0, dot).str();

        int64_t value = getSymbolAliasValue(before_dot);

        if (value == 0) {
          std::stringstream ss;
          if (before_dot.find("F") != std::string::npos ||
              before_dot.find("f") != std::string::npos) {
            ss << std::hex << before_dot;
          } else {
            ss << before_dot;
          }
          ss >> value;
        }

        if (value != 0)
          EVal = MCConstantExpr::create(value, getContext());
        else {
          MCSymbol *Sym = getContext().getOrCreateSymbol(before_dot);
          MCSymbolRefExpr::VariantKind Variant = MCSymbolRefExpr::VK_None;
          EVal =
              MCSymbolRefExpr::create(Sym, Variant, getParser().getContext());
        }

        Operands.push_back(RL78Operand::CreateAbs16(EVal, S, E));

        std::string imm = checkDot.substr(dot + 1, checkDot.size()).str();
        const MCExpr *EVal;
        EVal = MCConstantExpr::create(std::stoi(imm), getContext());
        SMLoc S = Parser.getTok().getLoc();
        SMLoc E =
            SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
        Operands.push_back(RL78Operand::CreateImm07(EVal, S, E));
        Parser.Lex();
        return MatchOperand_Success;
      } else {
        StringRef checkDot = getLexer().getTok().getString();
        size_t dot = checkDot.find(".");
        if (dot == std::string::npos) {
          if (!Parser.parseExpression(EVal, E)) {
            MCValue AddressValue;
            int64_t BitPosition = -1;
            if (!RL78MCExpr::FoldBitPositionalExpression(
                    EVal, AddressValue, BitPosition, getContext()) ||
                BitPosition == -1) {
              Operands.push_back(RL78Operand::CreateAbs16(EVal, S, E));
            } else {
              const MCExpr *AddressExpr;
              if (AddressValue.isAbsolute()) {
                AddressExpr = MCConstantExpr::create(AddressValue.getConstant(),
                                                     getContext());
              } else if (!AddressValue.getSymB()) {
                AddressExpr = AddressValue.getSymA();
              } else {
                AddressExpr = MCBinaryExpr::createSub(AddressValue.getSymA(),
                                                      AddressValue.getSymB(),
                                                      getContext());
              }
              Operands.push_back(RL78Operand::CreateAbs16(AddressExpr, S, E));
              Operands.push_back(RL78Operand::CreateImm07(
                  MCConstantExpr::create(BitPosition, getContext()), S, E));
            }

            return MatchOperand_Success;
          }
        } else {
          // We expect set1 !addr16.imm.
          const MCExpr *EVal;

          SMLoc S = Parser.getTok().getLoc();
          SMLoc E =
              SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
          std::string before_dot = checkDot.substr(0, dot).str();

          int64_t value = getSymbolAliasValue(before_dot);

          if (value == 0) {
            std::stringstream ss;
            if (before_dot.find("F") != std::string::npos ||
                before_dot.find("f") != std::string::npos) {
              ss << std::hex << before_dot;
            } else
              ss << before_dot;
            ss >> value;
          }
          if (value != 0) {
            EVal = MCConstantExpr::create(value, getContext());
          } else {
            MCSymbol *Sym = getContext().getOrCreateSymbol(before_dot);
            MCSymbolRefExpr::VariantKind Variant = MCSymbolRefExpr::VK_None;
            EVal =
                MCSymbolRefExpr::create(Sym, Variant, getParser().getContext());
          }

          Operands.push_back(RL78Operand::CreateAbs16(EVal, S, E));

          std::string imm = checkDot.substr(dot + 1, checkDot.size()).str();
          EVal = MCConstantExpr::create(std::stoi(imm), getContext());
          S = Parser.getTok().getLoc();
          E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
          Operands.push_back(RL78Operand::CreateImm07(EVal, S, E));
          Parser.Lex();

          return MatchOperand_Success;
        }
      }
    }
  }

  if (parseDotIncludingOperand(Operands, Mnemonic) == MatchOperand_Success)
    return MatchOperand_Success;

  // ES:!addr16.
  // ES : [DE].
  // ES : [DE + byte].
  // ES : [HL] ES : word[B].
  // ES : word[BC].
  if (parseEsRegRegAddrAndDotOperand(Operands, Mnemonic) ==
          MatchOperand_Success &&
      (getLexer().getTok().getString().find(".") == std::string::npos ||
       getLexer().getTok().getString().find(";") != std::string::npos))
    return MatchOperand_Success;

  if (ParseShiftIntegerOperand(Operands, Mnemonic) == MatchOperand_Success)
    return MatchOperand_Success;

  // word[bc].
  // word[c].
  // word[b].
  if (parseRegOffsetAddrOperand(Operands, Mnemonic) == MatchOperand_Success &&
      (getLexer().getTok().getString().find(".") == std::string::npos ||
       getLexer().getTok().getString().find(";") != std::string::npos))
    return MatchOperand_Success;

  if (RegBrackets(Operands, Mnemonic) == MatchOperand_Success &&
      (getLexer().getTok().getString().find(".") == std::string::npos ||
       getLexer().getTok().getString().find(";") != std::string::npos))
    return MatchOperand_Success;

  StringRef checkDot = getLexer().getTok().getString();
  size_t dot = checkDot.find(".");
  if (dot == std::string::npos) {
    Parser.parseExpression(Res, E);
    if (Res) {
      int64_t value = 0;
      if (Res->getKind() == Res->Constant)
        value = ((dyn_cast<MCConstantExpr>(Res))->getValue());

      LLVM_DEBUG(dbgs() << "Value is :" << value);
      if (Mnemonic.compare("movw") != 0 && value >= 0xfff1f && value <= 0xfffff)
        Operands.push_back(RL78Operand::CreateSfr(Res, S, E));
      else if (value >= 0xfff1f && value <= 0xfffff && value % 2 == 0)
        Operands.push_back(RL78Operand::CreateSfrp(Res, S, E));
      else if (value >= 0xffe20 && value <= 0xfff1f)
        Operands.push_back(RL78Operand::CreateAbs8(Res, S, E));
      else
        Operands.push_back(RL78Operand::CreateAbs8(Res, S, E));
    }
  }

  // Handle bit position part of [HL].5 or ES:[HL].6 for example
  AsmToken Token = getLexer().getTok();
  StringRef TokenString = Token.getString();
  dot = TokenString.find('.');
  int64_t BitPositionValue;
  if (dot == 0) {
    // TODO: eliminate code duplication
    if (Token.is(AsmToken::Real)) {
      // See if we have (0xf230+4).[0-7]
      if (TokenString.size() != 2 || TokenString[1] < '0' ||
          TokenString[1] > '7')
        return MatchOperand_NoMatch;
      BitPositionValue = TokenString[1] - '0';

    } else if (Token.is(AsmToken::Identifier)) {
      // Or (0xf230+4).SYM
      const MCSymbol *BitSym = getContext().lookupSymbol(
          TokenString.substr(1, TokenString.size() - 2));
      if (!BitSym || !BitSym->isVariable() ||
          !BitSym->getVariableValue()->evaluateAsAbsolute(BitPositionValue))
        return MatchOperand_NoMatch;
    } else {
      return MatchOperand_NoMatch;
    }
    const MCExpr *BitPosExpr =
        MCConstantExpr::create(BitPositionValue, getContext());
    Parser.Lex();
    SMLoc S = Parser.getTok().getLoc();
    SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
    Operands.push_back(RL78Operand::CreateImm07(BitPosExpr, S, E));
    return MatchOperand_Success;
  }

  return MatchOperand_Success;
}

// Unused.
OperandMatchResultTy RL78AsmParser::parseMEMOperand(OperandVector &Operands) {
  return MatchOperand_NoMatch;
}

// Unused.
OperandMatchResultTy
RL78AsmParser::parseStackSlotOperand(OperandVector &Operands) {
  return MatchOperand_NoMatch;
}

OperandMatchResultTy
RL78AsmParser::parseRegOffsetAddrOperand(OperandVector &Operands,
                                         StringRef Mnemonic) {

  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const MCExpr *Res = nullptr;
  unsigned RegKind;
  MCRegister Reg;
  // Due to the fact that we can actually have an expression here and we might
  // parse it and lose it we need to check for dot.
  StringRef checkDot = getLexer().getTok().getString();
  size_t dot = checkDot.find(".");
  // In case we have a dot we stop as we will parse this later.
  if (getLexer().is(AsmToken::LBrac) || dot != std::string::npos)
    return MatchOperand_NoMatch;

  // Needed for word[bc].
  if (!getParser().parseExpression(Res, E)) {
    // A LBrac is what we actually want, but because we already parsed the
    // expression we also need to take care of the else case.
    if (getLexer().is(AsmToken::LBrac)) {

      Parser.Lex(); // Eat the '['.

      StringRef name = Parser.getTok().getString();
      if ((name.compare_insensitive("bc") == 0 || name.compare_insensitive("b") == 0 ||
           name.compare_insensitive("c") == 0) &&
          Res != nullptr) {
        if (!matchRegisterName(Parser.getTok(), Reg, RegKind))
          return MatchOperand_NoMatch;
        Parser.Lex(); // Eat the identifier token.

        if (getLexer().is(AsmToken::RBrac)) {
          if (name.compare_insensitive("bc") == 0)
            Operands.push_back(
                RL78Operand::CreateRegOffsetAddr(Reg, RegKind, Res, S, E));
          else
            Operands.push_back(RL78Operand::CreateRegBorCOffsetAddr(
                Reg, RegKind, Res, S, E));

          Parser.Lex(); // Eat the ']'.
          return MatchOperand_Success;
        }
      }
      return MatchOperand_NoMatch;
    } else {
      // We need this here because we already parsed the expression.
      if (Res) {
        int64_t value = 0;
        if (Res->getKind() == Res->Constant)
          value = ((dyn_cast<MCConstantExpr>(Res))->getValue());

        LLVM_DEBUG(dbgs() << "Value is :" << value);
        if (Mnemonic.compare("movw") != 0 && value >= 0xfff1f &&
            value <= 0xfffff)
          Operands.push_back(RL78Operand::CreateSfr(Res, S, E));
        else if (value >= 0xfff1f && value <= 0xfffff && value % 2 == 0)
          Operands.push_back(RL78Operand::CreateSfrp(Res, S, E));
        else if (value >= 0xffe20 && value <= 0xfff1f)
          Operands.push_back(RL78Operand::CreateAbs8(Res, S, E));
        else
          Operands.push_back(RL78Operand::CreateAbs8(Res, S, E));
        return MatchOperand_Success;
      }
    }
    return MatchOperand_NoMatch;
  }
  return MatchOperand_NoMatch;
}

OperandMatchResultTy
RL78AsmParser::parseRegOffsetAddrOperand(OperandVector &Operands) {
  return MatchOperand_NoMatch;
}
OperandMatchResultTy
RL78AsmParser::parseRegRegAddrOperand(OperandVector &Operands) {
  return MatchOperand_NoMatch;
}
OperandMatchResultTy
RL78AsmParser::parseEsRegRegRegOperand(OperandVector &Operands) {
  return MatchOperand_NoMatch;
}
OperandMatchResultTy
RL78AsmParser::parseEsRegRegAddrOperand(OperandVector &Operands) {
  return MatchOperand_NoMatch;
}
// ES:!addr16.
// ES : [DE].
// ES : [DE + byte].
// ES : [HL] ES : word[B].
// ES : word[BC].
OperandMatchResultTy
RL78AsmParser::parseEsRegRegAddrAndDotOperand(OperandVector &Operands,
                                              StringRef Mnemonic) {

  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const MCExpr *Res = nullptr;
  unsigned RegESKind, RegKind;
  MCRegister RegES, Reg;

  if ((getLexer().getTok().getString() == "es" ||
       getLexer().getTok().getString() == "ES") &&
      getLexer().peekTok().is(AsmToken::Colon)) {

    if (!matchRegisterName(Parser.getTok(), RegES, RegESKind))
      return MatchOperand_NoMatch;

    Parser.Lex();

    if (getLexer().is(AsmToken::Colon))
      Parser.Lex(); // Eat the ':'.
    else
      return MatchOperand_NoMatch;

    if (getLexer().is(AsmToken::Exclaim)) {
      Parser.Lex(); // Eat the '!'.

      StringRef name = Parser.getTok().getString();
      size_t dot = name.find(".");
      if (dot != std::string::npos &&
          name.substr(dot + 1, name.size()).find_first_not_of("0123456789") ==
              std::string::npos &&
          (Mnemonic.compare("set1") == 0 || Mnemonic.compare("clr1") == 0)) {

        std::string before_dot = name.substr(0, dot).str();
        StringRef sfrx = before_dot;
        int64_t value = getSymbolAliasValue(before_dot);

        if (value == 0) {
          std::stringstream ss;
          if (before_dot.find("F") != std::string::npos ||
              before_dot.find("f") != std::string::npos) {
            ss << std::hex << before_dot;
          } else {
            ss << before_dot;
          }
          ss >> value;
        }

        if (value != 0)
          Res = MCConstantExpr::create(value, getContext());
        else {
          MCSymbol *Sym = getContext().getOrCreateSymbol(before_dot);
          MCSymbolRefExpr::VariantKind Variant = MCSymbolRefExpr::VK_None;
          Res = MCSymbolRefExpr::create(Sym, Variant, getParser().getContext());
        }

        Operands.push_back(
            RL78Operand::CreateEsAddr16(RegES, RegESKind, Res, S, E));

        std::string imm = name.substr(dot + 1, name.size()).str();
        const MCExpr *EVal;
        EVal = MCConstantExpr::create(std::stoi(imm), getContext());
        SMLoc S = Parser.getTok().getLoc();
        SMLoc E =
            SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
        Operands.push_back(RL78Operand::CreateImm07(EVal, S, E));
        Parser.Lex(); // Eat the '!'.
        return MatchOperand_Success;

      }

      else {

        if (!getParser().parseExpression(Res, E)) {
          MCValue AddressValue;
          int64_t BitPosition = -1;
          if (!RL78MCExpr::FoldBitPositionalExpression(
                  Res, AddressValue, BitPosition, getContext()) ||
              BitPosition == -1) {
            Operands.push_back(
                RL78Operand::CreateEsAddr16(RegES, RegESKind, Res, S, E));
          } else {
            const MCExpr *AddressExpr;
            if (AddressValue.isAbsolute()) {
              AddressExpr = MCConstantExpr::create(AddressValue.getConstant(),
                                                   getContext());
            } else if (!AddressValue.getSymB()) {
              AddressExpr = AddressValue.getSymA();
            } else {
              AddressExpr = MCBinaryExpr::createSub(
                  AddressValue.getSymA(), AddressValue.getSymB(), getContext());
            }
            Operands.push_back(RL78Operand::CreateEsAddr16(RegES, RegESKind,
                                                           AddressExpr, S, E));
            Operands.push_back(RL78Operand::CreateImm07(
                MCConstantExpr::create(BitPosition, getContext()), S, E));
          }
          return MatchOperand_Success;
        }
      }

    } else if (getLexer().is(AsmToken::LBrac)) {
      Parser.Lex();

      if (!matchRegisterName(Parser.getTok(), Reg, RegKind))
        return MatchOperand_NoMatch;
      Parser.Lex();

      if (getLexer().is(AsmToken::RBrac)) {
        AsmToken a = getLexer().peekTok();
        size_t dot = a.getString().find(".");
        if (dot == std::string::npos) {

          Res = MCConstantExpr::create(0, getContext());

          Operands.push_back(RL78Operand::CreateEsRegRegAddr(
              RegES, RegESKind, Reg, RegKind, Res, S, E));

          Parser.Lex(); // Eat the ']'.
          return MatchOperand_Success;
        } else {
          Parser.Lex(); // Eat the ']'.

          Operands.push_back(RL78Operand::CreateEsHlRegAddr(
              RegES, RegESKind, Reg, RegKind, S, E));
          return MatchOperand_Success;
        }
      } else if (getLexer().is(AsmToken::Plus)) {
        Parser.Lex(); // Eat the '+'
        unsigned Kind;
        MCRegister Reg2;
        if (matchRegisterName(Parser.getTok(), Reg2, Kind)) {

          Operands.push_back(RL78Operand::CreateEsRegRegReg(
              RegES, RegESKind, Reg, RegKind, Reg2, Kind, S, E));

          Parser.Lex();
          if (getLexer().is(AsmToken::RBrac)) {
            Parser.Lex(); // Eat the ']'.
            return MatchOperand_Success;
          }
        } else if (!getParser().parseExpression(Res, E)) {

          Operands.push_back(RL78Operand::CreateEsRegRegAddr(
              RegES, RegESKind, Reg, RegKind, Res, S, E));

          if (getLexer().is(AsmToken::RBrac)) {
            Parser.Lex(); // Eat the ']'.
            return MatchOperand_Success;
          }
        }
      }
    } else {
      if (!getParser().parseExpression(Res, E)) {
        if (getLexer().is(AsmToken::LBrac)) {
          Parser.Lex();
          if (!matchRegisterName(Parser.getTok(), Reg, RegKind))
            return MatchOperand_NoMatch;
          Parser.Lex();
          if (getLexer().is(AsmToken::RBrac)) {
            if (Reg == RL78::RP2)
              Operands.push_back(RL78Operand::CreateEsRegRegAddr(
                  RegES, RegESKind, Reg, RegKind, Res, S, E));
            else
              Operands.push_back(RL78Operand::CreateEsRegBorCRegAddr(
                  RegES, RegESKind, Reg, RegKind, Res, S, E));

            Parser.Lex(); // Eat the ']'.
            return MatchOperand_Success;

          } else
            return MatchOperand_Success;
        }
      }
    }
  }
  return MatchOperand_NoMatch;
}

OperandMatchResultTy RL78AsmParser::RegBrackets(OperandVector &Operands,
                                                StringRef Mnemonic) {

  OperandMatchResultTy ResTy = MatchOperand_NoMatch;

  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const MCExpr *Res;
  if (Mnemonic.compare("callt") == 0) {

    if (getLexer().is(AsmToken::LBrac)) {
      Parser.Lex(); // Eat the '[' token.

      if (!getParser().parseExpression(Res, E)) {
        Operands.push_back(RL78Operand::CreateAbs5(Res, S, E));
        ResTy = MatchOperand_Success;
      }
      if (getLexer().is(AsmToken::RBrac)) {
        Parser.Lex();
        return ResTy;
      }
    }
  }
  if (getLexer().is(AsmToken::LBrac)) {
    unsigned Reg1Kind;
    MCRegister Reg1;

    Parser.Lex(); // Eat the '[' token.

    if (!matchRegisterName(Parser.getTok(), Reg1, Reg1Kind))
      return MatchOperand_NoMatch;

    Parser.Lex();

    if (getLexer().is(AsmToken::RBrac) &&
        getLexer().peekTok(true).getString().find(".") != std::string::npos &&
        Reg1 == RL78::RP6) {

      Operands.push_back(RL78Operand::CreateHLAddr(Reg1, Reg1Kind, S, E));
      Parser.Lex(); // Eat the ']' token.

      ResTy = MatchOperand_Success;
    } else if (getLexer().is(AsmToken::RBrac)) {

      Res = MCConstantExpr::create(0, getContext());

      if (Reg1 == RL78::SPreg)
        Operands.push_back(
            RL78Operand::CreateSTACKSlotNo(Reg1, Reg1Kind, Res, S, E));
      else
        Operands.push_back(
            RL78Operand::CreateRegOffsetAddr(Reg1, Reg1Kind, Res, S, E));

      Parser.Lex(); // Eat the ']'.
      return MatchOperand_Success;

    } else if (getLexer().is(AsmToken::Plus)) {
      Parser.Lex(); // Eat the '+'.

      unsigned Reg2Kind;
      MCRegister Reg2;
      if (matchRegisterName(Parser.getTok(), Reg2, Reg2Kind)) {

        Operands.push_back(RL78Operand::CreateRegRegAddr(
            Reg1, Reg1Kind, Reg2, Reg2Kind, S, E));
        Parser.Lex();
        ResTy = MatchOperand_Success;
      } else if (!getParser().parseExpression(Res, E)) {

        if (Reg1 == RL78::SPreg) {

          Operands.push_back(
              RL78Operand::CreateSTACKSlotNo(Reg1, Reg1Kind, Res, S, E));
        } else {
          Operands.push_back(
              RL78Operand::CreateRegOffsetAddr(Reg1, Reg1Kind, Res, S, E));
        }

        Parser.Lex();
        ResTy = MatchOperand_Success;
      }
    }

    if (getLexer().is(AsmToken::RBrac)) {

      Parser.Lex();
      return ResTy;
    }
  }

  return ResTy;
}

bool RL78AsmParser::matchRegisterName(const AsmToken &Tok, MCRegister &Register,
                                      unsigned &RegKind) {
  RegKind = RL78Operand::rk_None;
  StringRef name = Tok.getString();

  return matchRegisterNameByName(name, Register, RegKind);
}

bool RL78AsmParser::matchRegisterNameByName(StringRef name, MCRegister &Register,
                                            unsigned &RegKind) {
  RegKind = RL78Operand::rk_None;
  // Bank 0 registers:
  // X, A, C, B, E, D, L, H.

  if (name.compare_insensitive("x") == 0) {
    Register = RL78::R0;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("a") == 0) {
    Register = RL78::R1;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("c") == 0) {
    Register = RL78::R2;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("b") == 0) {
    Register = RL78::R3;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("e") == 0) {
    Register = RL78::R4;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("d") == 0) {
    Register = RL78::R5;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("l") == 0) {
    Register = RL78::R6;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("h") == 0) {
    Register = RL78::R7;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("ax") == 0) {
    Register = RL78::RP0;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("bc") == 0) {
    Register = RL78::RP2;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("de") == 0) {
    Register = RL78::RP4;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("hl") == 0) {
    Register = RL78::RP6;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("es") == 0) {
    Register = RL78::ES;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("cs") == 0) {
    Register = RL78::CS;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("sp") == 0) {
    Register = RL78::SPreg;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("cy") == 0) {
    Register = RL78::CY;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("psw") == 0) {
    Register = RL78::PSW;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("pmc") == 0) {
    Register = RL78::PMC;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("mem") == 0) {
    Register = RL78::MEM;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("spl") == 0) {
    Register = RL78::SPL;
    RegKind = RL78Operand::rk_Reg;
    return true;
  } else if (name.compare_insensitive("sph") == 0) {
    Register = RL78::SPH;
    RegKind = RL78Operand::rk_Reg;
    return true;
  }

  return searchSymbolAlias(name, Register, RegKind);
}

// Determine if an expression contains a reference to the symbol
// "_GLOBAL_OFFSET_TABLE_".
static bool hasGOTReference(const MCExpr *Expr) {
  switch (Expr->getKind()) {
  case MCExpr::Target:
    if (const RL78MCExpr *SE = dyn_cast<RL78MCExpr>(Expr))
      return hasGOTReference(SE->getSubExpr());
    break;

  case MCExpr::Constant:
    break;

  case MCExpr::Binary: {
    const MCBinaryExpr *BE = cast<MCBinaryExpr>(Expr);
    return hasGOTReference(BE->getLHS()) || hasGOTReference(BE->getRHS());
  }

  case MCExpr::SymbolRef: {
    const MCSymbolRefExpr &SymRef = *cast<MCSymbolRefExpr>(Expr);
    return (SymRef.getSymbol().getName() == "_GLOBAL_OFFSET_TABLE_");
  }

  case MCExpr::Unary:
    return hasGOTReference(cast<MCUnaryExpr>(Expr)->getSubExpr());
  }
  return false;
}

OperandMatchResultTy RL78AsmParser::tryParseRegister(MCRegister &Register, SMLoc &StartLoc,
                                  SMLoc &EndLoc) {
  const AsmToken &Tok = Parser.getTok();
  StartLoc = Tok.getLoc();
  EndLoc = Tok.getEndLoc();
  Register = 0;
  unsigned regKind = RL78Operand::rk_None;
  if (matchRegisterName(Tok, Register, regKind)) {
    Parser.Lex();
    return MatchOperand_Success;
  }

  return MatchOperand_NoMatch;
}

bool RL78AsmParser::parseRegister(MCRegister &RegNo, SMLoc &StartLoc,
                                   SMLoc &EndLoc) {
  if (tryParseRegister(RegNo, StartLoc, EndLoc) != MatchOperand_Success)
    return Error(StartLoc, "invalid register name");
  return false;
}

extern "C" void LLVMInitializeRL78AsmParser() {
  RegisterMCAsmParser<RL78AsmParser> A(getTheRL78Target());
}

#define GET_REGISTER_MATCHER
#define GET_MATCHER_IMPLEMENTATION
#include "RL78GenAsmMatcher.inc"

unsigned RL78AsmParser::validateTargetOperandClass(MCParsedAsmOperand &GOp,
                                                   unsigned Kind) {
  return Match_InvalidOperand;
}
bool RL78AsmParser::searchSymbolAlias(StringRef name, MCRegister &Register,
                                      unsigned &RegKind) {
    MCSymbol *Sym = getContext().lookupSymbol(name);
    if (!Sym)
      return false;
    if (Sym->isVariable()) {
      const MCExpr *Expr = Sym->getVariableValue();
      if (Expr->getKind() == MCExpr::SymbolRef) {
        const MCSymbolRefExpr *Ref = static_cast<const MCSymbolRefExpr *>(Expr);
        StringRef DefSymbol = Ref->getSymbol().getName();

        LLVM_DEBUG(dbgs() << "Alias for register\n");
        if (matchRegisterNameByName(DefSymbol, Register, RegKind))
          return true;
      }
    } else if (Sym->isUnset())
      return false; 
  return false;
}

int64_t RL78AsmParser::getSymbolAliasValue(StringRef name) {
  int64_t DefSymbol = 0;

  MCSymbol *Sym = getContext().lookupSymbol(name);
  if (!Sym)
    return DefSymbol;
  if (Sym->isVariable()) {
    const MCExpr *Expr = Sym->getVariableValue();
    if (Expr->getKind() == MCExpr::Constant) {
      const MCConstantExpr *Ref = static_cast<const MCConstantExpr *>(Expr);
      DefSymbol = Ref->getValue();
    }
  }
  return DefSymbol;
}

const MCExpr *RL78AsmParser::createTargetUnaryExpr(
    const MCExpr *E, AsmToken::TokenKind OperatorToken, MCContext &Ctx) {
  switch (OperatorToken) {
  default:
    llvm_unreachable("Unknown token");
    return nullptr;
  case AsmToken::High:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_HIGH, E, Ctx);
  case AsmToken::Low:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_LOW, E, Ctx);
  case AsmToken::HighW:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_HIGHW, E, Ctx);
  case AsmToken::LowW:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_LOWW, E, Ctx);
  case AsmToken::MirHW:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_MIRHW, E, Ctx);
  case AsmToken::MirLW:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_MIRLW, E, Ctx);
  case AsmToken::SMRLW:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_SMRLW, E, Ctx);
  case AsmToken::StartOf:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_STARTOF, E, Ctx);
  case AsmToken::SizeOf:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_SIZEOF, E, Ctx);
  case AsmToken::BitPosition:
    return RL78MCExpr::create(RL78MCExpr::VK_RL78_BITPOSITIONAL, E, Ctx);
  }
}
