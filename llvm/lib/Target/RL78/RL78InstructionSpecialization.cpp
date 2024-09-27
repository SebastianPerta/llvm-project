//===-- RL78InstructionSpecialization.cpp - Define TargetMachine for RL78
//--------------===//
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

using namespace llvm;

#define DEBUG_TYPE "instr-specialization"

struct Specialization {
  const unsigned int NewOpCode = 0;
  const char OperandOffset = 0;
  const bool ZeroImm = false;
  const bool UCharImm = true;
  const unsigned int EnumImmValue = 0;
  const char *DebugName;
  const std::set<unsigned int> AllowedOp1Regs;
  const std::set<unsigned int> AllowedOp2Regs;

  Specialization() {}

  Specialization(unsigned int newOpCode, unsigned int enumImmValue,
                 const char *debugName)
      : NewOpCode(newOpCode), DebugName(debugName), EnumImmValue(enumImmValue) {
  }

  Specialization(unsigned int newOpCode, const char *debugName)
      : NewOpCode(newOpCode), DebugName(debugName) {}

  Specialization(unsigned int newOpCode, std::set<unsigned int> allowedOp1Regs,
                 std::set<unsigned int> allowedOp2Regs, const char *debugName,
                 char operandOffset = 0, bool zeroImm = false,
                 bool ucharImm = true)
      : NewOpCode(newOpCode), OperandOffset(operandOffset), ZeroImm(zeroImm),
        UCharImm(ucharImm), AllowedOp1Regs(allowedOp1Regs),
        AllowedOp2Regs(allowedOp2Regs), DebugName(debugName) {}
};

namespace {
class RL78InstructionSpecializationPass : public MachineFunctionPass {
public:
  RL78InstructionSpecializationPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "RL78 instruction specialization";
  }

  bool runOnMachineFunction(MachineFunction &MF) override {
    bool changed = false;
    LLVM_DEBUG(dbgs() << "Starting instruction specialization pass on: "
                      << MF.getName() << '\n');
    // MF.dump();
    const TargetInstrInfo *TII =
        MF.getSubtarget<RL78Subtarget>().getInstrInfo();
    for (MachineBasicBlock &MBB : MF) {
      std::vector<MachineInstr *> removedMIs;
      if (MBB.empty())
        continue;
      MachineBasicBlock::iterator I = MBB.getLastNonDebugInstr();
      if (I == MBB.end())
        continue;

      for (MachineBasicBlock::iterator nextI = MBB.begin(), E = MBB.end();
           nextI != E; ++nextI) {
        bool miReplaced = processInstruction(*nextI, MBB, TII);
        if (miReplaced)
          removedMIs.push_back(&*nextI);

        changed |= miReplaced;
      }

      for (MachineInstr *mi : removedMIs)
        mi->removeFromParent();
    }
    LLVM_DEBUG(dbgs() << "End of instruction specialization pass \n");
    // MF.dump();
    return changed;
  }

private:
  static char ID;
  bool processInstruction(MachineInstr &MI, MachineBasicBlock &MBB,
                          const TargetInstrInfo *TII);

  typedef bool (*isOpCallback)(MachineInstr &MI, Specialization &newOp);
  bool iterateMatches(MachineInstr &MI, MachineBasicBlock &MBB,
                      const TargetInstrInfo *TII,
                      std::multimap<unsigned int, Specialization> &list,
                      isOpCallback callback);
  bool replaceInstruction(MachineInstr &MI, MachineBasicBlock &MBB,
                          const TargetInstrInfo *TII, Specialization &newOp);
};
char RL78InstructionSpecializationPass::ID = 0;
} // end of anonymous namespace

FunctionPass *llvm::createRL78InstructionSpecializationPass() {
  return new RL78InstructionSpecializationPass();
}

std::set<unsigned int> bank0ExceptARegs = {
    RL78::R0, RL78::R2, RL78::R3, RL78::R4, RL78::R5, RL78::R6, RL78::R7};

std::set<unsigned int> bank0Regs = {RL78::R0, RL78::R1, RL78::R2, RL78::R3,
                                    RL78::R4, RL78::R5, RL78::R6, RL78::R7};

std::set<unsigned int> bank0RPRegs = {RL78::RP0, RL78::RP2, RL78::RP4,
                                      RL78::RP6};

std::set<unsigned int> XACB = {RL78::R0, RL78::R1, RL78::R2, RL78::R3};

std::multimap<unsigned int, Specialization> A_memDEHL_spec = {
    {RL78::ADD_r_memri,
     {RL78::ADD_r_memHL, {}, {RL78::RP6}, "ADD_r_memHL", 0, true}},
    {RL78::ADDC_r_memri,
     {RL78::ADDC_r_memHL, {}, {RL78::RP6}, "ADDC_r_memHL", 0, true}},
    {RL78::SUB_r_memri,
     {RL78::SUB_r_memHL, {}, {RL78::RP6}, "SUB_r_memHL", 0, true}},
    {RL78::SUBC_r_memri,
     {RL78::SUBC_r_memHL, {}, {RL78::RP6}, "SUBC_r_memHL", 0, true}},
    {RL78::AND_r_memri,
     {RL78::AND_r_memHL, {}, {RL78::RP6}, "AND_r_memHL", 0, true}},
    {RL78::OR_r_memri,
     {RL78::OR_r_memHL, {}, {RL78::RP6}, "OR_r_memHL", 0, true}},
    {RL78::XOR_r_memri,
     {RL78::XOR_r_memHL, {}, {RL78::RP6}, "XOR_r_memHL", 0, true}},
    {RL78::CMP_r_memri,
     {RL78::CMP_r_memHL, {}, {RL78::RP6}, "CMP_r_memHL", 0, true}},
    {RL78::LOAD16_rp_esrpi,
     {RL78::LOAD16_rp_esmemDE, {RL78::RP4}, {}, "LOAD16_rp_esmemDE", 0, true}},
    {RL78::LOAD16_rp_esrpi,
     {RL78::LOAD16_rp_esmemHL, {RL78::RP6}, {}, "LOAD16_rp_esmemHL", 0, true}},
    {RL78::LOAD16_rp_esrpi,
     {RL78::LOAD16_rp_esmemDEi,
      {RL78::RP4},
      {},
      "LOAD16_rp_esmemDEi",
      0,
      false}},
    {RL78::LOAD16_rp_esrpi,
     {RL78::LOAD16_rp_esmemHLi,
      {RL78::RP6},
      {},
      "LOAD16_rp_esmemHLi",
      0,
      false}},
    {RL78::LOAD16_rp_rpi,
     {RL78::LOAD16_rp_memDE, {RL78::RP4}, {}, "LOAD16_rp_memDE", 0, true}},
    {RL78::LOAD16_rp_rpi,
     {RL78::LOAD16_rp_memHL, {RL78::RP6}, {}, "LOAD16_rp_memHL", 0, true}},
    {RL78::LOAD16_rp_rpi,
     {RL78::LOAD16_rp_memDEi, {RL78::RP4}, {}, "LOAD16_rp_memDEi", 0, false}},
    {RL78::LOAD16_rp_rpi,
     {RL78::LOAD16_rp_memHLi, {RL78::RP6}, {}, "LOAD16_rp_memHLi", 0, false}},
    {RL78::LOAD8_r_ri,
     {RL78::LOAD8_r_memDE, {RL78::RP4}, {}, "LOAD8_r_memDE", 0, true}},
    {RL78::LOAD8_r_ri,
     {RL78::LOAD8_r_memHL, {RL78::RP6}, {}, "LOAD8_r_memHL", 0, true}},
    {RL78::LOAD8_r_ri,
     {RL78::LOAD8_r_memDEi, {RL78::RP4}, {}, "LOAD8_r_memDEi", 0, false}},
    {RL78::LOAD8_r_ri,
     {RL78::LOAD8_r_memHLi, {RL78::RP6}, {}, "LOAD8_r_memHLi", 0, false}},
    {RL78::STORE16_esrpi_rp,
     {RL78::STORE16_esmemDE_rp,
      {RL78::RP4},
      {},
      "STORE16_esmemDE_rp",
      0,
      true}},
    {RL78::STORE16_esrpi_rp,
     {RL78::STORE16_esmemHL_rp,
      {RL78::RP6},
      {},
      "STORE16_esmemHL_rp",
      0,
      true}},
    {RL78::STORE16_esrpi_rp,
     {RL78::STORE16_esmemDEi_rp,
      {RL78::RP4},
      {},
      "STORE16_esmemDEi_rp",
      0,
      false}},
    {RL78::STORE16_esrpi_rp,
     {RL78::STORE16_esmemHLi_rp,
      {RL78::RP6},
      {},
      "STORE16_esmemHLi_rp",
      0,
      false}},
    {RL78::STORE16_rpi_rp,
     {RL78::STORE16_memDE_rp, {RL78::RP4}, {}, "STORE16_memDE_rp", 0, true}},
    {RL78::STORE16_rpi_rp,
     {RL78::STORE16_memHL_rp, {RL78::RP6}, {}, "STORE16_memHL_rp", 0, true}},
    {RL78::STORE16_rpi_rp,
     {RL78::STORE16_memDEi_rp, {RL78::RP4}, {}, "STORE16_memDEi_rp", 0, false}},
    {RL78::STORE16_rpi_rp,
     {RL78::STORE16_memHLi_rp, {RL78::RP6}, {}, "STORE16_memHLi_rp", 0, false}},
    {RL78::STORE8_ri_imm,
     {RL78::STORE8_memDEi_imm, {RL78::RP4}, {}, "STORE8_memDEi_imm", 0, false}},
    {RL78::STORE8_ri_imm,
     {RL78::STORE8_memHLi_imm, {RL78::RP6}, {}, "STORE8_memHLi_imm", 0, false}},
    {RL78::STORE8_ri_r,
     {RL78::STORE8_memDE_r, {RL78::RP4}, {}, "STORE8_memDE_r", 0, true}},
    {RL78::STORE8_ri_r,
     {RL78::STORE8_memHL_r, {RL78::RP6}, {}, "STORE8_memHL_r", 0, true}},
    {RL78::STORE8_ri_r,
     {RL78::STORE8_memDEi_r, {RL78::RP4}, {}, "STORE8_memDEi_r", 0, false}},
    {RL78::STORE8_ri_r,
     {RL78::STORE8_memHLi_r, {RL78::RP6}, {}, "STORE8_memHLi_r", 0, false}},
    {RL78::LOAD16_rp_stack_slot,
     {RL78::LOAD16_rp_memHL, {RL78::RP6}, {}, "LOAD16_rp_memHL", 0, true}},
    {RL78::LOAD16_rp_stack_slot,
     {RL78::LOAD16_rp_memHLi, {RL78::RP6}, {}, "LOAD16_rp_memHLi", 0, false}},
    {RL78::LOAD8_r_stack_slot,
     {RL78::LOAD8_r_memHL, {RL78::RP6}, {}, "LOAD8_r_memHL", 0, true}},
    {RL78::LOAD8_r_stack_slot,
     {RL78::LOAD8_r_memHLi, {RL78::RP6}, {}, "LOAD8_r_memHLi", 0, false}},
    {RL78::STORE16_stack_slot_rp,
     {RL78::STORE16_memHL_rp, {RL78::RP6}, {}, "STORE16_memHL_rp", 0, true}},
    {RL78::STORE16_stack_slot_rp,
     {RL78::STORE16_memHLi_rp, {RL78::RP6}, {}, "STORE16_memHLi_rp", 0, false}},
    {RL78::STORE8_stack_slot_r,
     {RL78::STORE8_memHL_r, {RL78::RP6}, {}, "STORE8_memHL_r", 0, true}},
    {RL78::STORE8_stack_slot_r,
     {RL78::STORE8_memHLi_r, {RL78::RP6}, {}, "STORE8_memHLi_r", 0, false}},
};

std::multimap<unsigned int, Specialization> limitedRegOp_spec = {
    {RL78::XCH_A_r, {RL78::XCH_A_X, {RL78::R1}, {RL78::R0}, "XCH_A_X"}},
    {RL78::AND1_cy_r, {RL78::AND1_cy_A, {RL78::R1}, {}, "AND1_cy_A"}},
    {RL78::OR1_cy_r, {RL78::OR1_cy_A, {RL78::R1}, {}, "OR1_cy_A"}},
    {RL78::XOR1_cy_r, {RL78::XOR1_cy_A, {RL78::R1}, {}, "XOR1_cy_A"}},
    {RL78::MOVW_rp_sp, {RL78::MOVW_AX_sp, {RL78::RP0}, {}, "MOVW_AX_sp", -1}}};

std::multimap<unsigned int, Specialization> enumImmOp_spec = {
    {RL78::B_cc, {RL78::B_BNH, RL78CC::RL78CC_NH, "B_BNH"}},
    {RL78::B_cc, {RL78::B_BC, RL78CC::RL78CC_C, "B_BC"}},
    {RL78::B_cc, {RL78::B_BNC, RL78CC::RL78CC_NC, "B_BNC"}},
    {RL78::B_cc, {RL78::B_BZ, RL78CC::RL78CC_Z, "B_BZ"}},
    {RL78::B_cc, {RL78::B_BNZ, RL78CC::RL78CC_NZ, "B_BNZ"}}};

bool isAMemDEHLOp(MachineInstr &MI, Specialization &newOp);
bool isLimitedOp(MachineInstr &MI, Specialization &newOp);
bool isMatchingEnumImmOp(MachineInstr &MI, Specialization &newOp);
bool replaceMACRMoves(MachineInstr &MI, MachineBasicBlock &MBB, const TargetInstrInfo *TII);


bool RL78InstructionSpecializationPass::processInstruction(
    MachineInstr &MI, MachineBasicBlock &MBB, const TargetInstrInfo *TII) {
  return iterateMatches(MI, MBB, TII, A_memDEHL_spec, isAMemDEHLOp) ||
         iterateMatches(MI, MBB, TII, limitedRegOp_spec, isLimitedOp) ||
         iterateMatches(MI, MBB, TII, enumImmOp_spec, isMatchingEnumImmOp) ||
         replaceMACRMoves(MI, MBB, TII);
}

bool RL78InstructionSpecializationPass::iterateMatches(
    MachineInstr &MI, MachineBasicBlock &MBB, const TargetInstrInfo *TII,
    std::multimap<unsigned int, Specialization> &list, isOpCallback callback) {

  if (list.count(MI.getOpcode())) {
    LLVM_DEBUG(dbgs() << "Found instruction: ");
    LLVM_DEBUG(MI.dump());
    std::pair<std::multimap<unsigned int, Specialization>::iterator,
              std::multimap<unsigned int, Specialization>::iterator>
        ret = list.equal_range(MI.getOpcode());
    for (auto newOp = ret.first; newOp != ret.second; ++newOp) {
      if (callback(MI, newOp->second)) {
        return replaceInstruction(MI, MBB, TII, newOp->second);
      }
    }
    LLVM_DEBUG(dbgs() << "MI present in map, but not matched\n");
  }
  return false;
}

bool isAMemDEHLOp(MachineInstr &MI, Specialization &newOp) {
  char memRegIndex =
      newOp.AllowedOp1Regs.size() > 0 && newOp.AllowedOp2Regs.size() == 0
          ? MI.getNumExplicitDefs()      // op [reg] offset a.
          : MI.getNumExplicitDefs() + 1; // op a [reg] offset.
  char offsetIndex = memRegIndex + 1;

  unsigned int memRegId = MI.getOperand(memRegIndex).isReg()
                              ? MI.getOperand(memRegIndex).getReg().id()
                              : 0;

  return (MI.getOperand(memRegIndex).isReg() &&
          (newOp.AllowedOp1Regs.count(memRegId) > 0 ||
           newOp.AllowedOp2Regs.count(memRegId) > 0) &&
          MI.getOperand(offsetIndex).isImm() &&
          (newOp.ZeroImm && MI.getOperand(offsetIndex).getImm() == 0 ||
           !newOp.ZeroImm &&
               (newOp.UCharImm && MI.getOperand(offsetIndex).getImm() < 255 ||
                !newOp.UCharImm)));
}

bool isLimitedOp(MachineInstr &MI, Specialization &newOp) {
  char op1Index = MI.getNumExplicitDefs() + newOp.OperandOffset;
  char op2Index = MI.getNumExplicitDefs() + newOp.OperandOffset + 1;
  bool firstOpOk =
      newOp.AllowedOp1Regs.size() == 0 ||
      MI.getOperand(op1Index).isReg() &&
          newOp.AllowedOp1Regs.count(MI.getOperand(op1Index).getReg().id()) > 0;
  bool secondOpOk =
      newOp.AllowedOp2Regs.size() == 0 ||
      MI.getOperand(op2Index).isReg() &&
          newOp.AllowedOp2Regs.count(MI.getOperand(op2Index).getReg().id()) > 0;

  return firstOpOk && secondOpOk;
}

bool isMatchingEnumImmOp(MachineInstr &MI, Specialization &newOp) {
  return MI.getOperand(1).getImm() == newOp.EnumImmValue;
}

bool RL78InstructionSpecializationPass::replaceInstruction(
    MachineInstr &MI, MachineBasicBlock &MBB, const TargetInstrInfo *TII,
    Specialization &newOp) {

  MachineInstrBuilder newMI =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(newOp.NewOpCode));
  for (auto op : MI.operands())
    newMI = newMI.add(op);

  LLVM_DEBUG(dbgs() << "replaced with: " << newOp.DebugName << "\n");
  return true;
}

bool replaceMACRMoves(MachineInstr &MI, MachineBasicBlock &MBB, const TargetInstrInfo *TII) {
#define MACRHigh 0xFFF2
#define MACRLow 0xFFF0
  if (MI.getOpcode() == RL78::MOVW_rp_AX &&
      (MI.getOperand(0).getReg() == RL78::MACRH ||
       MI.getOperand(0).getReg() == RL78::MACRL)) {
    unsigned DestAddr =
        MI.getOperand(0).getReg() == RL78::MACRH ? MACRHigh : MACRLow;
    BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::STORE16_abs16_rp))
        .addImm(DestAddr)
        .add(MI.getOperand(1));
    return true;
  } else if (MI.getOpcode() == RL78::MOVW_AX_rp &&
             (MI.getOperand(1).getReg() == RL78::MACRH ||
              MI.getOperand(1).getReg() == RL78::MACRL)) {
    unsigned SrcAddr =
        MI.getOperand(1).getReg() == RL78::MACRH ? MACRHigh : MACRLow;
    BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(RL78::LOAD16_rp_abs16))
        .add(MI.getOperand(0))
        .addImm(SrcAddr);
    return true;
  }
  return false;
}
