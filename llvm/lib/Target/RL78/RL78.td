//===-- RL78.td - Describe the RL78 Target Machine -------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Target-independent interfaces which we are implementing
//===----------------------------------------------------------------------===//

include "llvm/Target/Target.td"


//===----------------------------------------------------------------------===//
// Register File, Calling Conv, Instruction Descriptions
//===----------------------------------------------------------------------===//

include "RL78Schedule.td"
include "RL78InstrInfo.td"
include "RL78CallingConv.td"

def RL78InstrInfo : InstrInfo {
  // this will be the default behavior in the future, so better to be prepared
  let guessInstructionProperties = 0;
}

def RL78AsmParser : AsmParser {
  bit ShouldEmitMatchRegisterName = 0;
}

//===----------------------------------------------------------------------===//
// RL78 Subtarget features.
//===----------------------------------------------------------------------===//

def Feature64bitDoubles : SubtargetFeature<"64bit-doubles", "has64BitDoubles", "true",
                                      "Use 64-bit Doubles">;
// TODO actually set the MAA to 1
def FeatureMirrorSourceOne : SubtargetFeature<"mirror-source-1", "mirrorSource", "1",
                                      "MAA is set to 1">;
def FeatureMirrorSourceZero : SubtargetFeature<"mirror-source-0", "mirrorSource", "0",
                                      "MAA is set to 0">;
def FeatureMirrorSourceCommon : SubtargetFeature<"mirror-source-common", "mirrorSource", "2",
                                      "Mirror source is set to common">;

def FeatureFarCode : SubtargetFeature<"far-code", "hasFarCodeModel", "true",
                                      "Default function pointers are far.">;

def FeatureFarData : SubtargetFeature<"far-data", "hasFarDataModel", "true",
                                      "Default data pointers are far.">;

def FeatureNearRom : SubtargetFeature<"near-rom", "romModel", "0",
                                      "Default constant data pointers are near.">;

def FeatureFarRom : SubtargetFeature<"far-rom", "romModel", "1",
                                      "Default constant data pointers are far.">;

def FeatureCommonRom : SubtargetFeature<"common-rom", "romModel", "2",
                                      "Common constant mode.">;

def FeatureDisableMDA : SubtargetFeature<"disable-mda", "disableMDA", "true",
                                      "Disable usage of Mul/Div/Mac accelerator (S2 only).">;

//def FeatureCallingConvention : CCRL, LLVM, IAR?



//===----------------------------------------------------------------------===//
// RL78 processors supported.
//===----------------------------------------------------------------------===//

class Proc<string Name, list<SubtargetFeature> Features>
 : Processor<Name, NoItineraries, Features>;

def : ProcessorModel<"RL78_S1", NoSchedModel, []>;
def : ProcessorModel<"RL78_S2", NoSchedModel, []>;
def : ProcessorModel<"RL78_S3", NoSchedModel, []>;

//===----------------------------------------------------------------------===//
// Declare the target which we are implementing
//===----------------------------------------------------------------------===//

def RL78AsmWriter : AsmWriter {
  string AsmWriterClassName  = "InstPrinter";
  int PassSubtarget = 1;
  int Variant = 0;
}

def RL78 : Target {
  // Pull in Instruction Info:
  let InstructionSet = RL78InstrInfo;
  let AssemblyParsers  = [RL78AsmParser];
  let AssemblyWriters = [RL78AsmWriter];
}
