//===- RL78.cpp
//------------------------------------------------------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "InputFiles.h"
#include "OutputSections.h"
#include "SymbolTable.h"
#include "Symbols.h"
#include "Target.h"
#include "lld/Common/ErrorHandler.h"
#include "llvm/Object/ELF.h"
#include "llvm/Support/Endian.h"
#include <stack>

using namespace llvm;
using namespace llvm::ELF;
using namespace llvm::object;
using namespace llvm::support::endian;
using namespace lld;
using namespace lld::elf;

namespace {
class RL78 final : public TargetInfo {
public:
  RL78();
  void relocate(uint8_t *loc, const Relocation &rel,
                uint64_t val) const override;
  void relocateAlloc(InputSectionBase &sec, uint8_t *buf) const override;
  uint32_t calcEFlags() const override;
  RelExpr getRelExpr(RelType Type, const Symbol &S,
                     const uint8_t *loc) const override;
  void writePlt(uint8_t *buf, const Symbol &sym,
                uint64_t pltEntryAddr) const override;

private:
  std::stack<uint64_t> relocationStack;
  uint64_t checkAndPop(uint8_t *loc, const Relocation &rel, char bitSize = 0,
                       bool isSigned = false, uint64_t adj = 0) const;
  void push(uint8_t *loc, uint64_t Value) const;
  uint16_t checkAndConvertRAM(uint8_t *loc, const Relocation &rel,
                              uint64_t val) const;
};
} // namespace

RL78::RL78() { pltEntrySize = 4; }

static uint32_t getEFlags(InputFile *file) {
  return cast<ObjFile<ELF32LE>>(file)->getObj().getHeader().e_flags;
}

static bool mergeFlags(uint32_t &mergedFlags, uint32_t newFlags, unsigned flag,
                       const Twine &msg, InputFile *f) {
  if ((mergedFlags & flag) == 0) { // if the merged flag is set to common
    mergedFlags |= (newFlags & flag);
    return true;
  } else if ((newFlags & flag) == 0) { // if the new flag is set to common
    return true;
  } else if ((mergedFlags & flag) !=
             (newFlags & flag)) { // if both are non-common and non-matching
    error(msg + toString(f));
    return false;
  } else {

    return true;
  }
}

uint32_t RL78::calcEFlags() const {
  assert(!ctx.objectFiles.empty());
  uint32_t mergedFlags = getEFlags(ctx.objectFiles[0]);
  bool mergeSucceeded = true;
  // Verify that all input files have compatible flags
  for (InputFile *f : makeArrayRef(ctx.objectFiles).slice(1)) {
    uint32_t newFlags = getEFlags(f);
    if (mergedFlags == newFlags)
      continue;

    mergedFlags |= (newFlags & ELF::EF_RL78_FU_EXIST);
    mergedFlags |= (newFlags & ELF::EF_RL78_EI_EXIST);

    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_MAA_1,
                                 "incompatible MAA flags: ", f);

    if ((mergedFlags & ELF::EF_RL78_CPU_16BIT) == 0) {
      if ((newFlags & ELF::EF_RL78_CPU_16BIT) == 0) {
        error("CPU flag can't be set to common for both input files: " +
              toString(f));
        mergeSucceeded = false;
      } else {
        mergedFlags |= (newFlags & ELF::EF_RL78_CPU_16BIT);
      }
    } else if ((newFlags & ELF::EF_RL78_CPU_16BIT) != 0 &&
               (mergedFlags & ELF::EF_RL78_CPU_16BIT) !=
                   (newFlags & ELF::EF_RL78_CPU_16BIT)) {
      error("incompatible CPU flags: " + toString(f));
      mergeSucceeded = false;
    }

    // TODO change to size 8 if force option is specified
    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_DOUBLE_8,
                                 "incompatible double type size flags: ", f);

    // TODO change to far if force option is specified
    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_TEXT_FAR,
                                 "incompatible text area flags: ", f);

    // TODO change to far if force option is specified
    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_DATA_FAR,
                                 "incompatible data area flags: ", f);

    if ((mergedFlags & ELF::EF_RL78_RODATA_FAR) == 0) {
      mergedFlags |= (newFlags & ELF::EF_RL78_RODATA_FAR);
    } else if ((newFlags & ELF::EF_RL78_RODATA_FAR) != 0 &&
               (mergedFlags & ELF::EF_RL78_RODATA_FAR) !=
                   (newFlags & ELF::EF_RL78_RODATA_FAR)) {
      warn("incompatible rodata area flags, changed to far:  " + toString(f));
      mergedFlags |= (newFlags & ELF::EF_RL78_RODATA_FAR);
    }
  }
  return mergeSucceeded ? mergedFlags : 0;
}

RelExpr RL78::getRelExpr(RelType Type, const Symbol &S,
                         const uint8_t *loc) const {
  switch (Type) {
  case R_RL78_DIR8S_PCREL:
  case R_RL78_DIR16S_PCREL:
  case R_RL78_ABS8S_PCREL:
  case R_RL78_ABS16S_PCREL:
    return R_PC;
  default:
    return R_ABS;
  }
}

void RL78::writePlt(uint8_t *buf, const Symbol &sym,
                    uint64_t pltEntryAddr) const {
  write32le(buf, 0x000000EC | ((sym.getVA() & 0xFFFFF) << 8));
}

inline void write3le(void *P, uint8_t V) {
  write<uint8_t, llvm::support::little>(
      P, (read<uint8_t, llvm::support::little>(P) & 0x8f) | ((V & 0x7) << 4));
}

inline void write8le(void *P, uint8_t V) {
  write<uint8_t, llvm::support::little>(P, V);
}

inline void write24le(void *P, uint64_t V) {
  write32le(P, (read32le(P) & 0xff00'0000) | (V & ~0xff00'0000));
}

static uint64_t checkAndConvertMirrorAddr(uint8_t *loc, const Relocation &rel,
                                          uint64_t val,
                                          bool AllowOutOfRange = false) {
  // clang-format off
  /*
  RL78-S1 core
    MAA = 0: Mirror data in addresses 00000H to 05EFFH to addresses F8000H to FDEFFH.
    MAA = 1: Setting prohibited. 
  RL78-S2 core 
    MAA = 0: Mirror data in addresses 00000H to 0FFFFH to addresses F0000H to FFFFFH. 
    MAA = 1: Mirror data in addresses 10000H to 1FFFFH to addresses F0000H to FFFFFH. 
  RL78-S3 core 
    MAA = 0: Mirror data in addresses 00000H to 0FFFFH to addresses F0000H to FFFFFH.
    MAA = 1: Mirror data in addresses 10000H to 1FFFFH to addresses F0000H to FFFFFH.
  */
  // clang-format on

  ErrorPlace errPlace = getErrorPlace(loc);
  uint32_t maaFlag = config->eflags & ELF::EF_RL78_MAA_1;
  uint32_t cpuType = config->eflags & ELF::EF_RL78_CPU_16BIT;

  uint32_t max;
  uint32_t min;
  uint32_t correction;

  if (maaFlag == 0) {
    // code should not depend on MAA mode, yet it does
    error(errPlace.loc + "relocation " + lld::toString(rel.type) +
          " is invalid when MAA mode flag in ELF is set to common!");
    return 0;
  }
  if (cpuType == 0) {
    // need to know CPU bitness, cause there are different mirror regions for S1
    // and S2/S3
    error(errPlace.loc + "relocation " + lld::toString(rel.type) +
          " is invalid when CPU bit flag in ELF is set to common!");
    return 0;
  }
  if (cpuType == ELF::EF_RL78_CPU_8BIT && maaFlag == ELF::EF_RL78_MAA_1) {
    // RL78-S1 core   MAA = 1: Setting prohibited.
    error(errPlace.loc + "relocation " + lld::toString(rel.type) +
          "error: S1 cores can't have MAA set to 1!");
    return 0;
  }

  switch (maaFlag) {
  case EF_RL78_MAA_0: // MAA = 0
    min = 0;
    max = cpuType == ELF::EF_RL78_CPU_8BIT ? 0x5EFF : 0xFFFF;
    correction = cpuType == 1 ? 0xF8000 : 0xF0000;
    break;
  case EF_RL78_MAA_1: // MAA = 1
    min = 0x10000;
    max = 0x1FFFF;
    correction = 0xE0000;
    break;
  default:
    error(errPlace.loc + "relocation " + lld::toString(rel.type) +
          " invalid MAA flag value!");
    return 0;
    break;
  }

  if (val >= min && val <= max) {
    return val + correction;
  } else if (AllowOutOfRange) {
    // return it unchanged, used for R_RL78_OPmir
    return val;
  } else {
    errorOrWarn(errPlace.loc + "relocation " + lld::toString(rel.type) +
                " out of MIRROR range: " + Twine::utohexstr(val).str() +
                " is not in [" + Twine::utohexstr(min).str() + ", " +
                Twine::utohexstr(max).str() + "]");
    return 0;
  }
}

static uint8_t checkAndConvertSAddr(uint8_t *loc, const Relocation &rel,
                                    uint64_t val) {
  ErrorPlace errPlace = getErrorPlace(loc);
  uint32_t max1 = 0xff1f;
  uint32_t min1 = 0xfe20;
  uint32_t max2 = 0xfff1f;
  uint32_t min2 = 0xffe20;
  if (val >= min1 && val <= max1 || val >= min2 && val <= max2) {
    return val;
  } else {
    error(errPlace.loc + "relocation " + lld::toString(rel.type) +
          " out of SADDR(P) range: " + Twine(val).str() + " is not in [" +
          Twine::utohexstr(min1).str() + ", " + Twine::utohexstr(max1).str() +
          "] or [" + Twine::utohexstr(min2).str() + ", " +
          Twine::utohexstr(max2).str() + "]");
    return 0;
  }
}

uint16_t RL78::checkAndConvertRAM(uint8_t *loc, const Relocation &rel,
                                  uint64_t val) const {
  ErrorPlace errPlace = getErrorPlace(loc);
  uint32_t max = 0xffeff;
  uint32_t min = 0xfef00;

  Symbol *minRamAddrSym = symtab.find("__data");
  if (minRamAddrSym != nullptr) {
    min = minRamAddrSym->getVA(0);
  }

  if (val >= min && val <= max) {
    return val;
  } else {
    error(errPlace.loc + "relocation " + lld::toString(rel.type) +
          " out of RAM range: " + Twine::utohexstr(val).str() + " is not in [" +
          Twine::utohexstr(min).str() + ", " + Twine::utohexstr(max).str() +
          "]");
    return 0;
  }
}

uint64_t RL78::checkAndPop(uint8_t *loc, const Relocation &rel, char bitSize,
                           bool isSigned, uint64_t adj) const {
  if (relocationStack.empty()) {
    error(getErrorPlace(loc).loc + "relocation " + lld::toString(rel.type) +
          " is invalid: linker relocation stack is empty, nothing to pop!");
    return 0;
  } else {
    uint64_t t = relocationStack.top() - adj;

    if (bitSize > 0) {
      if (isSigned) {
        checkInt(loc, t, bitSize, rel);
      } else {
        checkUInt(loc, t, bitSize, rel);
      }
    }

    const_cast<RL78 *>(this)->relocationStack.pop();
    return t;
  }
}

void RL78::push(uint8_t *loc, uint64_t Value) const {
  const_cast<RL78 *>(this)->relocationStack.push(Value);
}

void RL78::relocate(uint8_t *loc, const Relocation &rel, uint64_t val) const {
  // TODO Not sure if zero refers to boot cluster 0?
  // also if these addresses are target specific?
  uint32_t zeroCALLTST = 0x00080;
  uint32_t CALLTST = 0x01080;

  switch (rel.type) {
  case R_RL78_DIR3U:
    checkUInt(loc, val, 3, rel);
    write3le(loc, val);
    break;
  case R_RL78_DIR8U:
    checkUInt(loc, val, 8, rel);
    write8le(loc, val);
    break;
  case R_RL78_DIR16U:
    // checkUInt(loc, val, 16, Type); - temporary revert
    write16le(loc, val);
    break;
  case R_RL78_DIR20U:
    checkUInt(loc, val, 20, rel);
    write24le(loc, val);
    break;
  case R_RL78_DIR20U_16:
    checkUInt(loc, val, 20, rel);
    write16le(loc, val);
    break;
  case R_RL78_DIR20UW_16:
    checkUInt(loc, val, 20, rel);
    write16le(loc, val & 0xfffe);
    break;
  case R_RL78_DIR32U:
    checkUInt(loc, val, 32, rel);
    write32le(loc, val);
    break;
  case R_RL78_DIR8U_MIR:
    write8le(loc, checkAndConvertMirrorAddr(loc, rel, val));
    break;
  case R_RL78_DIR16U_MIR:
    write16le(loc, checkAndConvertMirrorAddr(loc, rel, val));
    break;
  case R_RL78_DIR16UW_MIR:
    write16le(loc, checkAndConvertMirrorAddr(loc, rel, val) & 0xfffe);
    break;
  case R_RL78_DIR8U_SAD:
    write8le(loc, checkAndConvertSAddr(loc, rel, val) & 0xff);
    break;
  case R_RL78_DIR8UW_SAD:
    write8le(loc, checkAndConvertSAddr(loc, rel, val) & 0xfe);
    break;
  case R_RL78_DIR16U_RAM:
    write16le(loc, checkAndConvertRAM(loc, rel, val) & 0xffff);
    break;
  case R_RL78_DIR16UW_RAM:
    write16le(loc, checkAndConvertRAM(loc, rel, val) & 0xfffe);
    break;
  case R_RL78_DIR8S_PCREL:
    checkIntUInt(loc, val - 1, 8, rel);
    write8le(loc, val - 1);
    break;
  case R_RL78_DIR16S_PCREL:
    checkIntUInt(loc, val - 2, 16, rel);
    write16le(loc, val - 2);
    break;
  case R_RL78_DIR_CALLT:
    write8le(loc, ((((val - zeroCALLTST) & 0x30) >> 4) +
                   (((val - CALLTST) & 0x0e) << 3)) |
                      0x84);
    break;
  case R_RL78_ABS3U:
    write3le(loc, checkAndPop(loc, rel, 3));
    break;
  case R_RL78_ABS8U:
    write8le(loc, checkAndPop(loc, rel, 8));
    break;
  case R_RL78_ABS8UW:
    write8le(loc, checkAndPop(loc, rel, 8) & 0xfe);
    break;
  case R_RL78_ABS16U:
    write16le(loc, checkAndPop(loc, rel, 16));
    break;
  case R_RL78_ABS16UW:
    write16le(loc, checkAndPop(loc, rel, 16) & 0xfffe);
    break;
  case R_RL78_ABS20U:
    write24le(loc, checkAndPop(loc, rel, 20));
    break;
  case R_RL78_ABS20U_16:
    write16le(loc, checkAndPop(loc, rel, 20));
    break;
  case R_RL78_ABS20UW_16:
    write16le(loc, checkAndPop(loc, rel, 20) & 0xfffe);
    break;
  case R_RL78_ABS32U:
    write32le(loc, checkAndPop(loc, rel, 32));
    break;
  case R_RL78_ABS8S_PCREL:
    write8le(loc, (checkAndPop(loc, rel, 8, true, val) - 1) & 0xff);
    break;
  case R_RL78_ABS16S_PCREL:
    write16le(loc, (checkAndPop(loc, rel, 16, true, val) - 2) & 0xffff);
    break;
  case R_RL78_ABS_CALLT: {
    uint64_t savedVal = checkAndPop(loc, rel);
    write8le(loc, ((((savedVal - zeroCALLTST) & 0x30) >> 4) +
                   (((savedVal - CALLTST) & 0x0e) << 3)) |
                      0x84);
  } break;
  case R_RL78_REF:
    break;
  case R_RL78_SYM:
    push(loc, val);
    break;
  case R_RL78_SYM_MIR:
    push(loc, checkAndConvertMirrorAddr(loc, rel, val));
    break;
  case R_RL78_OPadd: {
    uint64_t a = checkAndPop(loc, rel);
    uint64_t b = checkAndPop(loc, rel);
    push(loc, a + b);
  } break;
  case R_RL78_OPsub: {
    uint64_t a = checkAndPop(loc, rel);
    uint64_t b = checkAndPop(loc, rel);
    push(loc, b - a);
  } break;
  case R_RL78_OPsctsize:
  case R_RL78_OPscttop:
    push(loc, val);
    break;
  case R_RL78_OPlowH:
    push(loc, (val & 0xFF00) >> 8);
    break;
  case R_RL78_OPlowL:
    push(loc, val & 0xff);
    break;
  case R_RL78_OPhighW:
    push(loc, (val & 0xFFFF0000) >> 16);
    break;
  case R_RL78_OPlowW:
    // TODO currently we incorrectly use this for constant references too, it
    // should be R_RL78_OPlowW_MIR one possible solution to this might be at
    // ISelLowering::makeaddress, where we would insert a different node to
    // signal that it should be a constant access from the rom/mirror area
    push(loc, val & 0xFFFF);
    break;
  case R_RL78_OPhighW_MIR:
    push(loc, (checkAndConvertMirrorAddr(loc, rel, val) & 0xFFFF0000) >> 16);
    break;
  case R_RL78_OPlowW_MIR:
  case R_RL78_OPlowW_SMIR: // TODO this might be wrong PUSH (MIR(S)+ A) & 0xFFFF
    push(loc, checkAndConvertMirrorAddr(loc, rel, val) & 0xFFFF);
    break;
  case R_RL78_OPmir: {
    uint64_t T = checkAndPop(loc, rel);
    push(loc, checkAndConvertMirrorAddr(loc, rel, T, true));
  } break;
  case R_RL78_OPABSlowH:
    push(loc, (checkAndPop(loc, rel) & 0xFF00) >> 8);
    break;
  case R_RL78_OPABSlowL:
    push(loc, checkAndPop(loc, rel) & 0xFF);
    break;
  case R_RL78_OPABShighW:
    push(loc, (checkAndPop(loc, rel) & 0xFFFF0000) >> 16);
    break;
  case R_RL78_OPABSlowW:
    push(loc, checkAndPop(loc, rel) & 0xFFFF);
    break;
  default:
    error(getErrorLocation(loc) + "unrecognized relocation " + Twine(rel.type));
  }
}

void RL78::relocateAlloc(InputSectionBase &sec, uint8_t *buf) const {
  const unsigned bits = config->is64 ? 64 : 32;
  uint64_t secAddr = sec.getOutputSection()->addr;
  if (auto *s = dyn_cast<InputSection>(&sec))
    secAddr += s->outSecOff;
  for (const Relocation &rel : sec.relocs()) {
    uint8_t *loc = buf + rel.offset;
    const uint64_t val = SignExtend64(
        sec.getRelocTargetVA(sec.file, rel.type, rel.addend,
                             secAddr + rel.offset, *rel.sym, rel.expr),
        bits);
    if (rel.sym->isInPlt()) {
      target->relocate(loc, rel, rel.sym->getPltVA());
    } else {
      switch (rel.type) {
      case R_RL78_ABS8S_PCREL:
      case R_RL78_ABS16S_PCREL:
        target->relocate(loc, rel, secAddr + rel.offset);
        break;
      case R_RL78_OPsctsize: {
        auto symbol = lld::toString(*rel.sym);
        if (Defined *d = dyn_cast<Defined>(rel.sym)) {
          if (InputSection *isec = cast_or_null<InputSection>(d->section)) {
            target->relocate(loc, rel, isec->getOutputSection()->size);
          } else {
            errorOrWarn(getErrorLocation(loc) + " symbol " + symbol +
                        " is not a section symbol!");
          }
        } else {
          errorOrWarn(getErrorLocation(loc) + " symbol " + symbol +
                      " is not defined!");
        }
      } break;
      default:
        target->relocate(loc, rel, val);
      }
    }
  }
}

/*TargetInfo *TargetInfo::getRL78TargetInfo() {
  static RL78 Target;
  return &Target;
}*/

TargetInfo *elf::getRL78TargetInfo() {
  static RL78 target;
  return &target;
}