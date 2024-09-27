add_llvm_component_library(LLVMRL78Info
  RL78TargetInfo.cpp
  
  LINK_COMPONENTS
  MC
  Support

  ADD_TO_COMPONENT
  RL78
  )
