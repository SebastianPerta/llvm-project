//===-- RL78TargetMachine.cpp - Define TargetMachine for RL78 -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//
//===----------------------------------------------------------------------===//

#include "RL78TargetMachine.h"
#include "RL78TargetObjectFile.h"
#include "RL78MachineFunctionInfo.h"
#include "RL78TargetTransformInfo.h"
#include "TargetInfo/RL78TargetInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Transforms/Scalar.h"

// FIXME: convert 2 x 8 bit load + 2 x 8 bit store to 1 x bit load + 1 xchg with
// mem + 1 x store (check MEM Alias for this).

using namespace llvm;

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeRL78Target() {
  // Register the target.
  RegisterTargetMachine<RL78TargetMachine> X(getTheRL78Target());
  auto *PR = PassRegistry::getPassRegistry();
  initializeRL78DAGToDAGISelPass(*PR);
}

static std::string computeDataLayout(const Triple &T, StringRef FS) {

  size_t FarFlagPos = FS.rfind("+far-code");
  size_t NearFlagPos = FS.rfind("+near-code");

  const auto farCodeModel =
      FarFlagPos != StringRef::npos &&
      (NearFlagPos == StringRef::npos || NearFlagPos < FarFlagPos);
  const auto farDataModel = FS.rfind("+far-data") != StringRef::npos;

  std::string DL;
  llvm::raw_string_ostream SS(DL);

  // NOTE: keep in sync with def from clang/lib/Basic/Targets/RL78.cpp
  SS << "e"               // little endian
        "-m:o";           // Mach-O mangling: Private symbols get L prefix.
                          // Other symbols get a _ prefix.
  if (farDataModel) {
    SS << "-p0:32:16:16"  // default: 32 bit width, 16 bit aligned
          "-A1";          // near allocas
  } else {
    SS << "-p0:16:16:16"; // default: 16 bit width, 16 bit aligned
  }

  SS << "-p1:16:16:16" // Near pointers: 16 bit width, 16 bit aligned.
        "-p2:32:16:16" // Far data pointers: 32 bit width, 16 bit aligned.
        "-p3:32:16:16" // Far code pointers: 32 bit width, 16 bit aligned.
        "-i32:16-i64:16-f32:16-f64:16-a:8" // TODO: explain
        "-n8:8"                            // 8 bit native integer width
        "-n16:16"                          // 16 bit native integer width
        "-S16";                            // 16 bit natural stack alignment

  if (farCodeModel)
    SS << "-P3"; // Use far pointers for functions.

  SS.flush();

  return DL;
}

static Reloc::Model getEffectiveRelocModel(std::optional<Reloc::Model> RM) {
  if (!RM.has_value())
    return Reloc::Static;
  return *RM;
}

/// Create an RL78 architecture model
RL78TargetMachine::RL78TargetMachine(const Target &T, const Triple &TT,
                                     StringRef CPU, StringRef FS,
                                     const TargetOptions &Options,
                                     std::optional<Reloc::Model> RM,
                                     std::optional<CodeModel::Model> CM,
                                     CodeGenOpt::Level OL, bool JIT)
    : LLVMTargetMachine(T, computeDataLayout(TT, FS), TT, CPU, FS, Options,
                        getEffectiveRelocModel(RM),
                        getEffectiveCodeModel(CM, CodeModel::Tiny), OL),
      TLOF(std::make_unique<RL78ELFTargetObjectFile>()) {

  // Bcause the optimizer is getting smarter in figuring out undefined behavior/poison
  // cases, we have trap unreachable = true as default (can be overriden by the user).
  // We don't want to trap after the __attribute__((noreturn)) though.
  this->Options.NoTrapAfterNoreturn = true;

  initAsmInfo();

  // RL78 supports the MachineOutliner.
  setMachineOutliner(true);

  // RL78 supports default outlining behaviour.
  setSupportsDefaultOutlining(true);

}

RL78TargetMachine::~RL78TargetMachine() {}

const RL78Subtarget *
RL78TargetMachine::getSubtargetImpl(const Function &F) const {
  Attribute CPUAttr = F.getFnAttribute("target-cpu");
  Attribute FSAttr = F.getFnAttribute("target-features");

  std::string CPU = !CPUAttr.hasAttribute(Attribute::None)
                        ? CPUAttr.getValueAsString().str()
                        : TargetCPU;
  std::string FS = !FSAttr.hasAttribute(Attribute::None)
                       ? FSAttr.getValueAsString().str()
                       : TargetFS;

  auto &I = SubtargetMap[CPU + FS];
  if (!I) {
    // This needs to be done before we create a new subtarget since any
    // creation will depend on the TM and the code generation flags on the
    // function that reside in TargetOptions.
    resetTargetOptions(F);
    Attribute TuneAttr = F.getFnAttribute("tune-cpu");
    std::string TuneCPU =
      TuneAttr.isValid() ? TuneAttr.getValueAsString().str() : CPU;
    auto ABIName = Options.MCOptions.getABIName();
    I = std::make_unique<RL78Subtarget>(TargetTriple, CPU, TuneCPU, FS, ABIName, *this);
  }
  return I.get();
}

TargetTransformInfo
RL78TargetMachine::getTargetTransformInfo(const Function &F) const {
  return TargetTransformInfo(RL78TTIImpl(this, F));
}

MachineFunctionInfo *RL78TargetMachine::createMachineFunctionInfo(
    BumpPtrAllocator &Allocator, const Function &F,
    const TargetSubtargetInfo *STI) const {
  return RL78MachineFunctionInfo::create<RL78MachineFunctionInfo>(Allocator,
                                                                    F, STI);
}

namespace {
/// RL78 Code Generator Pass Configuration Options.
class RL78PassConfig : public TargetPassConfig {
public:
  RL78PassConfig(RL78TargetMachine &TM, PassManagerBase &PM)
      : TargetPassConfig(TM, PM) {}

  RL78TargetMachine &getRL78TargetMachine() const {
    return getTM<RL78TargetMachine>();
  }

  bool addPreISel() override;
  void addIRPasses() override;
  bool addInstSelector() override;
  void addPreEmitPass() override;
  void addPreRegAlloc() override;
  void addPostRegAlloc() override;
};
} // end anonymous namespace

TargetPassConfig *RL78TargetMachine::createPassConfig(PassManagerBase &PM) {
  return new RL78PassConfig(*this, PM);
}

bool RL78PassConfig::addPreISel() {
  // TODO: very little benefit, check values.
  addPass(createGlobalMergePass(TM, 255, true));
  return false;
}

void RL78PassConfig::addIRPasses() {
  //FIXME: consider this or a similar algorithm.
  //addPass(createSeparateConstOffsetFromGEPPass());
  addPass(createNaryReassociatePass());
  addPass(createSinkingPass());
  TargetPassConfig::addIRPasses();
}

bool RL78PassConfig::addInstSelector() {
  addPass(createRL78ISelDag(getRL78TargetMachine(), getOptLevel()));
  return false;
}

void RL78PassConfig::addPreEmitPass() {
  addPass(createRL78InsertExchangeInstructionsPass());
  addPass(&MachineCopyPropagationID);
  addPass(createRL78CMPWithZeroElimPass());
  addPass(createRL78InstructionSpecializationPass());
  addPass(createRL78BranchExpandPass());
  addPass(createRL78SelectBTCLRPass());
}

void RL78PassConfig::addPreRegAlloc() {
  if (getOptLevel() != CodeGenOpt::None) {
    // TODO: looked at a test case where this is worse it's because of the
    // machine outliner misses an opprtunity, there's might be many other cases
    // where because we do things differently (for optimization reasons we
    // remove oportunities for the outliner. the upcomming IR outliner can solve
    // this.
    // addPass(createRL78AdjustMemRefsPass());
    addPass(createRL78ConstPropAndOpSwap());

    addPass(&ProcessImplicitDefsID);

    // LiveVariables currently requires pure SSA form.
    //
    // FIXME: Once TwoAddressInstruction pass no longer uses kill flags,
    // LiveVariables can be removed completely, and LiveIntervals can be
    // directly computed. (We still either need to regenerate kill flags after
    // regalloc, or preferably fix the scavenger to not depend on them).
    addPass(&LiveVariablesID);
    addPass(&ProcessImplicitDefsID);
    addPass(&UnreachableMachineBlockElimID);
    addPass(&DeadMachineInstructionElimID);
  }
}

void RL78PassConfig::addPostRegAlloc() {
  addPass(createRL78CMPWithZeroElimPass());
}

// Assertion failed : MO->isDead() && "Cannot fold physreg def", file F :
// \SVN\LLVM_5.0\llvm - 5.0.0.src\lib\CodeGen\InlineSpiller.cpp, line 805
// Assertion failed : !MIS.empty() && "Unexpected empty span of instructions!",
// file F : \SVN\LLVM_5.0\llvm - 5.0.0.src\lib\CodeGen\InlineSpiller.cpp, line
// 818 fatal error : error in backend : ran out of registers during register
// allocation

//////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO: move to separate file

// This a simple pass to improve register allocation in case of indirect
// addressing: During lowering we only use RP6 this is what most instructions
// can accept however a few instructions accept BC and DE as well.
// FIXME: calc_func gets 29 bytes bigger so need to look further into this
// FIXME: Handle here also ADD/SUB/AND/OR/XOR/CMP r, A:
//%1:rl78reg = COPY $r1
//$r1 = COPY %0 : rl78reg
//$r1 = ADD_r_r $r1, %1 : rl78rexcepta, implicit - def dead $ccreg
//%2 : rl78reg = COPY killed $r1
// We need to split ADD_r_r into: ADD_A_r ADD_r_A (and the rest of them)
// FIXME: handle also [HL+C] usage [HL+B]

namespace {
class RL78AdjustMemRefsPass : public MachineFunctionPass {
public:
  RL78AdjustMemRefsPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "RL78 Adjust Indirect Memory Refs";
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  static char ID;
};

char RL78AdjustMemRefsPass::ID = 0;
} // end anonymous namespace

FunctionPass *llvm::createRL78AdjustMemRefsPass() {
  return new RL78AdjustMemRefsPass();
}

static bool isLoadWhichAllowBCDE(unsigned int opcode) {
  return (opcode == RL78::LOAD8_r_ri) || (opcode == RL78::LOAD16_rp_rpi);
}

static bool isStoreWhichAllowBCDE(unsigned int opcode) {
  return (opcode == RL78::STORE8_ri_r) || (opcode == RL78::STORE16_rpi_rp);
}

// Return the next registers to be used for indirect addressing.
static unsigned switchToNextReg(unsigned current) {
  switch (current) {
  case RL78::RP6:
    return RL78::RP4;
  //////////////////////////
  case RL78::RP4:
    return RL78::RP6;
  //////////////////////////
  // alternative:
  // TODO: bemchmark this
  // case RL78::RP4:
  //    return RL78::RP2;
  // case RL78::RP2:
  //    return RL78::RP6;
  default:
    llvm_unreachable("Invalid Register used for indirect addressing!");
  }
}

bool RL78AdjustMemRefsPass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;
  std::map<unsigned, unsigned> vRegsMap;
  unsigned NextRegToUse = RL78::RP6;

  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty())
      continue;
    //
    // MBB.dump();
    for (MachineBasicBlock::iterator Next = MBB.begin(), E = MBB.end();
         Next != E;) {
      MachineInstr &MI = *Next;
      // MI.dump();
      ++Next;

      // We are looking for a sequence similar to:
      // $rp6 = COPY %0:rl78rpregs
      // $rp0 = LOAD16_rp_rpi $rp6, ....
      // OR:
      // $rp6 = COPY %0:rl78rpregs
      // STORE16_rpi_rp $rp6, ....
      if ((MI.getOpcode() != RL78::COPY) ||
          (MI.getOperand(0).getReg() != RL78::RP6))
        continue;
      // Make sure we haven't reached the end of the BB.
      if (Next == MBB.end())
        break;
      // Now locate the load/store instruction.
      MachineInstr *MI2 = &*Next;
      bool RP6Used = false;
      while ((!isLoadWhichAllowBCDE(MI2->getOpcode())) &&
             (!isStoreWhichAllowBCDE(MI2->getOpcode()))) {
        // If there any other uses of RP6 start from the top (this might by a
        // new $rp6 = COPY ... if not we will continue with the next
        // instruction).
        for (unsigned op = 0, e = MI2->getNumOperands(); op != e; ++op)
          if (MI2->getOperand(op).isReg() &&
              MI2->getOperand(op).getReg() == RL78::RP6) {
            RP6Used = true;
            break;
          }
        // Exit the loop before the ++Next.
        if (RP6Used)
          break;
        ++Next;
        if (Next == MBB.end())
          break;
        MI2 = &*Next;
      }
      //
      if (RP6Used)
        continue;
      if (Next == MBB.end())
        break;
      // MI2->dump();
      unsigned opIndex = isLoadWhichAllowBCDE(MI2->getOpcode()) ? 1 : 0;

      assert(MI2->getOperand(opIndex).isReg() &&
             (MI2->getOperand(opIndex).getReg() == RL78::RP6));
      // This is a load/store instruction no need to look at it as COPY at the
      // next iteration.
      ++Next;
      // Check if this virtual register was used before in a load/store pattern.
      auto it = vRegsMap.find(MI.getOperand(1).getReg());
      if (it != vRegsMap.end()) {
        // Use the hard registers which we used before
        // (don't need to change if it's already RP6).
        if (it->second != RL78::RP6) {
          MI.getOperand(0).ChangeToRegister(it->second, true);
          MI2->getOperand(opIndex).ChangeToRegister(it->second, false);
          Changed = true;
        }
      } else {
        // Add a new entry for this virtual reg.
        vRegsMap.insert(std::pair<unsigned, unsigned>(MI.getOperand(1).getReg(),
                                                      NextRegToUse));
        // Use 'NextRegToUse' (don't need to change if it's already RP6).
        if (NextRegToUse != RL78::RP6) {
          MI.getOperand(0).ChangeToRegister(NextRegToUse, true);
          MI2->getOperand(opIndex).ChangeToRegister(NextRegToUse, false);
          Changed = true;
        }
        // Update NextRegToUse.
        NextRegToUse = switchToNextReg(NextRegToUse);
      }
    }
  }

  return Changed;
}
