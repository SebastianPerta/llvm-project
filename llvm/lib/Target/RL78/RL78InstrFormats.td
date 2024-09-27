//===-- RL78InstrFormats.td - RL78 Instruction Formats ---*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

class InstRL78<dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary>
   : Instruction 
{
  let Namespace = "RL78";

  dag OutOperandList = outs;
  dag InOperandList = ins;
  let AsmString   = asmstr;
  let Pattern = pattern;

  // SoftFail is a field the disassembler can use to provide a way for
  // instructions to not match without killing the whole decode process. It is
  // mainly used for ARM, but Tablegen expects this field to exist or it fails
  // to build the decode table.
  field bits<40> SoftFail = 0;

  // OBS: this changes the conservative default (of 1) as most of the RL78 instructions don't have side effects,
  // meaning that the instructions that do have side effects have to be marked with hasSideEffects = 1 explicitly
  let hasSideEffects = 0;

  //let DecoderNamespace = "RL78";
  //pipeline see chapter 7 in software manual
  //let Itinerary = itin;
}

class InstRL78_8bit<field bits<8> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<8> Inst = inst;
  let Size = 1;
}

class InstRL78_16bit<field bits<16> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<16> Inst = inst;
  let Size = 2;
}

class InstRL78_24bit<field bits<24> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<24> Inst = inst;
  let Size = 3;
}

class InstRL78_32bit<field bits<32> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<32> Inst = inst;
  let Size = 4;
}

class InstRL78_40bit<field bits<40> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<40> Inst = inst;
  let Size = 5;
}

class InstRL78_48bit<field bits<48> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<48> Inst = inst;
  let Size = 6;
}

class InstRL78_56bit<field bits<56> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<56> Inst = inst;
  let Size = 7;
}

class InstRL78_64bit<field bits<64> inst, dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin = NoItinerary> 
  : InstRL78<outs, ins, asmstr, pattern, itin>
{
  field bits<64> Inst = inst;
  let Size = 8;
}

// Pseudo instructions.
class Pseudo<dag outs, dag ins, string asmstr, list<dag> pattern>
   : InstRL78<outs, ins, asmstr, pattern> {
  let isCodeGenOnly = 1;
  let isPseudo = 1;
}
