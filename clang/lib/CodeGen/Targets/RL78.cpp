//===- RL78.cpp ----------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ABIInfoImpl.h"
#include "TargetInfo.h"

using namespace clang;
using namespace clang::CodeGen;

//===----------------------------------------------------------------------===//
// RL78 ABI Implementation.
//===----------------------------------------------------------------------===//

namespace {
class RL78ABIInfo : public DefaultABIInfo {
public:
  RL78ABIInfo(CodeGenTypes &CGT) : DefaultABIInfo(CGT) {}

private:
  ABIArgInfo classifyReturnType(QualType RetTy) const;
  ABIArgInfo classifyArgumentType(QualType ArgTy, bool IsVarArg) const;
  void computeInfo(CGFunctionInfo &FI) const override;
  Address EmitVAArg(CodeGenFunction &CGF, Address VAListAddr, QualType Ty) const override;
};
} // end anonymous namespace


static ABIArgInfo coerceStructToIntArray(QualType Ty,
                                          ASTContext &Context,
                                          llvm::LLVMContext &LLVMContext, bool IsVarArg = false) {
  // Alignment and Size are measured in bits.
  const uint64_t Size = Context.getTypeSize(Ty);
  const uint64_t Alignment = IsVarArg ? 16 : Context.getTypeAlign(Ty);
  llvm::Type *IntType = llvm::Type::getIntNTy(LLVMContext, Alignment);
  const uint64_t NumElements = (Size + Alignment - 1) / Alignment;
  return ABIArgInfo::getDirect(llvm::ArrayType::get(IntType, NumElements));
}

ABIArgInfo RL78ABIInfo::classifyReturnType(QualType Ty) const {
  //if its void, ignore  
  if (Ty->isVoidType())
    return ABIArgInfo::getIgnore();

  // Get size in Bits.
  uint64_t Size = getContext().getTypeSize(Ty);
  // If it doesn't fit in 4 bytes place it on the stack.
  if (Size > 32) {
    return getNaturalAlignIndirect(Ty, true);
  } else {
     if (isAggregateTypeForABI(Ty)) {
      return coerceStructToIntArray(Ty,getContext(), getVMContext());
     } else {
      return ABIArgInfo::getDirect();
     }
  }  
}

ABIArgInfo RL78ABIInfo::classifyArgumentType(QualType ArgTy, bool IsVarArg) const {
  //const RecordType *RT = ArgTy->getAs<RecordType>();
  //TODO 
  //promote near pointers to far pointer
  //handle void*?

  if (isAggregateTypeForABI(ArgTy)) {
    // Records with non-trivial destructors/copy-constructors should not be
    // passed by value.
    if (CGCXXABI::RecordArgABI RAA = getRecordArgABI(ArgTy, getCXXABI()))
      return getNaturalAlignIndirect(ArgTy,
                                     RAA == CGCXXABI::RAA_DirectInMemory);
    return coerceStructToIntArray(ArgTy, getContext(), getVMContext(), IsVarArg);
  } else {
    return ABIArgInfo::getDirect();
  }
}

void RL78ABIInfo::computeInfo(CGFunctionInfo &FI) const {
  if (!getCXXABI().classifyReturnType(FI))
    FI.getReturnInfo() = classifyReturnType(FI.getReturnType());

 size_t ArgIndex = 0;
 for (auto &Arg : FI.arguments()) {
    Arg.info = classifyArgumentType(Arg.type, FI.getNumRequiredArgs() <= ArgIndex);
	ArgIndex++;
 }
}

Address RL78ABIInfo::EmitVAArg(CodeGenFunction &CGF, Address VAListAddr,
                               QualType Ty) const {

  // Emit va_arg using the common void* representation,
  // where arguments are simply emitted in an array of slots on the stack.
  // All arguments are passed directly, using 2 byte slots.
  // We don't allow greater than 2 byte alignment.

  auto TypeInfo = getContext().getTypeInfoInChars(Ty);

  return emitVoidPtrVAArg(CGF, VAListAddr, Ty, /*Indirect*/ false, TypeInfo,
                          CharUnits::fromQuantity(2),
                          /*AllowHigherAlign*/ false);
}

#include "llvm/IR/Constants.h"

namespace {
class RL78TargetCodeGenInfo : public TargetCodeGenInfo {
 
  enum AddressSpaces { Default = 0, Near = 1, Far = 2 };

  bool isNullOrUndef(const llvm::Constant *C) const {
  // Check that the constant isn't all zeros or undefs.
  if (C->isNullValue() || isa<llvm::UndefValue>(C))
    return true;
  if (!isa<llvm::ConstantAggregate>(C))
    return false;
  for (auto Operand : C->operand_values()) {
    if (!isNullOrUndef(cast<llvm::Constant>(Operand)))
      return false;
  }
  return true;
}

  std::string getAddressSection(const llvm::GlobalVariable *GV,
                              const VarDecl *VD) const {
  std::string sectionPrefix;
  bool isFar = GV->getAddressSpace() == Far;
  if (GV->isConstant())
    sectionPrefix = isFar ? ".constf_AT" : ".const_AT";
  else
    sectionPrefix = isFar ? ".bssf_AT" : ".bss_AT";
  std::string buf;
  llvm::raw_string_ostream stream(buf);
  stream << (llvm::format_hex_no_prefix(
      VD->getAttr<RL78AddressAttr>()->getAddress(), 5));
  return sectionPrefix + stream.str();
}

  std::string replaceSectionNamePlaceholder(std::string sectionName,
                                          std::string sectionPrefix) const {
  std::vector<std::string> placeholders = {
      "...t...",
      "...d...",
      "...r...",
      "...b...",
  };
  for (std::string &placeholder : placeholders)
    if (sectionName.find(placeholder) != std::string::npos) {
      sectionName.replace(0, placeholder.length(), sectionPrefix);
      return sectionName;
    }
    return sectionName;
  return sectionName;
  }

  bool isBss(const VarDecl *VD, const llvm::GlobalVariable *GV) const {
    return !VD->hasInit() && !GV->isConstant();
  }

  bool isData(const VarDecl *VD, const llvm::GlobalVariable *GV) const {
    return VD->hasInit() && !GV->isConstant();
  }

public:
  RL78TargetCodeGenInfo(CodeGen::CodeGenTypes &CGT)
      : TargetCodeGenInfo(std::make_unique<RL78ABIInfo>(CGT)) {}

  void setTargetAttributes(const Decl *D, llvm::GlobalValue *GV,
                           CodeGen::CodeGenModule &CGM) const override {
    bool isFar = GV->getAddressSpace() == Far;

    if (const auto *FD = dyn_cast_or_null<FunctionDecl>(D)) {
      auto *Fn = cast<llvm::Function>(GV);
      if (const auto *Attr = FD->getAttr<RL78InterruptAttr>()) {
        std::string Specs = std::to_string(Attr->getSpecs());
        for (unsigned Vect : Attr->vects()) {
          Specs.append("Vect_");
          Specs.append(std::to_string(Vect));
        }
        Fn->addFnAttr("interrupt", Specs);
        Fn->addFnAttr("disable-tail-calls", "true");
        // marking the interrupt handlers as used ensures that they aren't discarded by LTO
        if (!D->hasAttr<UsedAttr>())
          const_cast<Decl *>(D)->addAttr(UsedAttr::CreateImplicit(CGM.getContext()));
      }

      if (const auto *Attr = FD->getAttr<RL78BRKInterruptAttr>()) {
        std::string Specs = std::to_string(Attr->getSpecs());
        Fn->addFnAttr("brk_interrupt", Specs);
        Fn->addFnAttr("disable-tail-calls", "true");
      }

      if (const auto *Attr = FD->getAttr<RL78CalltAttr>()) {
        Fn->addFnAttr("callt");
      }

      if (const auto *Attr = FD->getAttr<RL78InlineASMAttr>()) {
        Fn->addFnAttr("inline_asm");
      }
      if (CGM.getLangOpts().RenesasExt &&
          Fn->hasFnAttribute("implicit-section-name") &&
          FD->hasAttr<PragmaClangTextSectionAttr>()) {
        std::string section =
            Fn->getFnAttribute("implicit-section-name").getValueAsString().str();
        Fn->removeFnAttr("implicit-section-name");
        // TODO: getAddressSpace doesn't seem to work yet for far functions
        section =
            replaceSectionNamePlaceholder(section, isFar ? ".textf" : ".text");
        Fn->addFnAttr("implicit-section-name", section + (isFar ? "_f" : "_n"));
      } /*else if (!FD->hasAttr<SectionAttr>() &&
                 !FD->hasAttr<PragmaClangTextSectionAttr>() &&
                 !Fn->hasFnAttribute("implicit-section-name") &&
                 !CGM.getCodeGenOpts().FunctionSections) {
        Fn->addFnAttr("implicit-section-name", isFar ? ".textf" : ".text");
      }*/
    }

    if (const auto *VD = dyn_cast_or_null<VarDecl>(D)) {
      auto *Var = cast<llvm::GlobalVariable>(GV);

      // With -mfar-data, the default address space is far
      if (GV->getAddressSpace() == Default && CGM.getLangOpts().RenesasRL78DataModel)
        isFar = true;
      
      // Generate section name/prefix based on kind and attributes
      std::string prefix;
      if (isData(VD, Var))
        prefix = VD->hasAttr<RL78SaddrAttr>() ? ".sdata"
                                              : isFar ? ".dataf" : ".data";
      else if (isBss(VD, Var))
        prefix =
            VD->hasAttr<RL78SaddrAttr>() ? ".sbss" : isFar ? ".bssf" : ".bss";
      else {
        if (CGM.getLangOpts().RenesasExt)
          prefix = isFar ? ".constf" : ".const";
        else
          prefix = isFar ? ".frodata" : ".rodata";
      }

      // Add the _n, _f suffix to sections in case of custom section names or
      // allocate the variable to the correct section based on the far
      // attribute.
      std::string suffix;
      if (VD->hasAttr<RL78SaddrAttr>()) {
        suffix = "_s";
      } else {
        suffix = isFar ? "_f" : "_n";
      }

      if (VD->hasAttr<RL78AddressAttr>()) {
        SectionAttr *attr = VD->getAttr<SectionAttr>();
        std::string section = attr->getName().str();
        attr->setName(CGM.getContext(), prefix + section);
		Var->addAttribute("abs_addr");
        Var->setSection(attr->getName());
        return;
      }

      if (Var->isConstant() && CGM.getLangOpts().RenesasExt) {
        // signal that we need to emit const/constf prefix instead of
        // rodata/frodata
        Var->addAttribute("use-renesas-naming");
      }

      llvm::AttributeSet AS = Var->getAttributes();
      if (CGM.getLangOpts().RenesasExt && AS.hasAttribute("bss-section") &&
          VD->hasAttr<PragmaClangBSSSectionAttr>()) {
        std::string section = AS.getAttribute("bss-section").getValueAsString().str();
        section = replaceSectionNamePlaceholder(section, prefix);
        AS = AS.removeAttribute(CGM.getLLVMContext(), "bss-section");
        AS = AS.addAttribute(CGM.getLLVMContext(), "bss-section",
                             section + suffix);
      } /*else if (isBss(VD, Var) && !VD->hasAttr<SectionAttr>() &&
                 !VD->hasAttr<PragmaClangBSSSectionAttr>() &&
                 !AS.hasAttribute("bss-section") &&
                 !CGM.getCodeGenOpts().DataSections) {
        AS = AS.addAttribute(CGM.getLLVMContext(), "bss-section", prefix);
      }*/

      if (CGM.getLangOpts().RenesasExt && AS.hasAttribute("data-section") &&
          VD->hasAttr<PragmaClangDataSectionAttr>()) {
        std::string section =
            AS.getAttribute("data-section").getValueAsString().str();
        section = replaceSectionNamePlaceholder(section, prefix);
        AS = AS.removeAttribute(CGM.getLLVMContext(), "data-section");
        AS = AS.addAttribute(CGM.getLLVMContext(), "data-section",
                             section + suffix);
      } /*else if (isData(VD, Var) &&
                 !VD->hasAttr<PragmaClangDataSectionAttr>() &&
                 !VD->hasAttr<SectionAttr>() &&
                 !AS.hasAttribute("data-section") &&
                 !CGM.getCodeGenOpts().DataSections) {
        AS = AS.addAttribute(CGM.getLLVMContext(), "data-section", prefix);
      }*/

      if (CGM.getLangOpts().RenesasExt && AS.hasAttribute("rodata-section") &&
          VD->hasAttr<PragmaClangRodataSectionAttr>()) {
        std::string section =
            AS.getAttribute("rodata-section").getValueAsString().str();
        section = replaceSectionNamePlaceholder(section, prefix);
        AS = AS.removeAttribute(CGM.getLLVMContext(), "rodata-section");
        AS = AS.addAttribute(CGM.getLLVMContext(), "rodata-section",
                             section + suffix);
      }/* else if (Var->isConstant() &&
                 !VD->hasAttr<PragmaClangRodataSectionAttr>() &&
                 !VD->hasAttr<SectionAttr>() &&
                 !AS.hasAttribute("rodata-section") &&
                 !CGM.getCodeGenOpts().DataSections) {
        AS = AS.addAttribute(CGM.getLLVMContext(), "bss-section", prefix);
      }*/

      Var->setAttributes(AS);

      if (VD->hasAttr<RL78SaddrAttr>()) {
        if(GV->getLinkage() == llvm::GlobalVariable::CommonLinkage)
          GV->setLinkage(llvm::GlobalVariable::ExternalLinkage);
        Var->addAttribute("saddr");
      }
    }
  }
};
} // namespace

std::unique_ptr<TargetCodeGenInfo>
CodeGen::createRL78TargetCodeGenInfo(CodeGenModule &CGM) {
    return std::make_unique<RL78TargetCodeGenInfo>(CGM.getTypes());
}
