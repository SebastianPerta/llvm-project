add_llvm_component_group(RL78)

set(LLVM_TARGET_DEFINITIONS RL78.td)

tablegen(LLVM RL78GenAsmMatcher.inc -gen-asm-matcher)
tablegen(LLVM RL78GenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM RL78GenDAGISel.inc -gen-dag-isel)
tablegen(LLVM RL78GenDisassemblerTables.inc -gen-disassembler)
tablegen(LLVM RL78GenInstrInfo.inc -gen-instr-info)
tablegen(LLVM RL78GenMCCodeEmitter.inc -gen-emitter)
tablegen(LLVM RL78GenRegisterInfo.inc -gen-register-info)
tablegen(LLVM RL78GenCallingConv.inc -gen-callingconv)
tablegen(LLVM RL78GenSubtargetInfo.inc -gen-subtarget)

add_public_tablegen_target(RL78CommonTableGen)

add_llvm_target(RL78CodeGen
  RL78AsmPrinter.cpp
  RL78InstrInfo.cpp
  RL78ISelDAGToDAG.cpp
  RL78ISelLowering.cpp
  RL78FrameLowering.cpp
  RL78MachineFunctionInfo.cpp
  RL78RegisterInfo.cpp
  RL78Subtarget.cpp
  RL78TargetMachine.cpp
  RL78MCInstLower.cpp
  RL78TargetObjectFile.cpp
  RL78CMPWithZeroElimination.cpp
  RL78SelectBTCLR.cpp
  RL78InsertExchangeInstructions.cpp
  RL78BranchExpand.cpp
  RL78InstructionSpecialization.cpp
  RL78ConstPropAndOpSwap.cpp
  RL78SelectionDAGTargetInfo.cpp
  RL78TargetTransformInfo.cpp

  LINK_COMPONENTS
  Analysis
  AsmPrinter
  Core
  IPO
  CodeGen
  MC
  RL78Desc
  RL78Info
  SelectionDAG
  Support
  Target
  TargetParser
  TransformUtils
  GlobalISel

  ADD_TO_COMPONENT
  RL78
  )

add_subdirectory(AsmParser)
add_subdirectory(Disassembler)
add_subdirectory(MCTargetDesc)
add_subdirectory(TargetInfo)
