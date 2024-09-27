add_llvm_component_library(LLVMRL78AsmParser
  RL78AsmParser.cpp

  LINK_COMPONENTS
  MC
  MCParser
  RL78Desc
  RL78Info
  Support
  TargetParser

  ADD_TO_COMPONENT
  RL78
  )
