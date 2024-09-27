add_llvm_component_library(LLVMRL78Desc
  RL78AsmBackend.cpp
  RL78InstPrinter.cpp
  RL78ELFObjectWriter.cpp
  RL78MCAsmInfo.cpp
  RL78MCCodeEmitter.cpp
  RL78MCTargetDesc.cpp
  RL78MCExpr.cpp
  RL78TargetStreamer.cpp

  LINK_COMPONENTS
  MC
  RL78Info
  Support
  TargetParser

  ADD_TO_COMPONENT
  RL78
  )
