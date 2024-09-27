//===-- RL78RegisterInfo.td - RL78 Register defs ---------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  Declarations that describe the RL78 register file
//===----------------------------------------------------------------------===//

class RL78Register<string n, bits<6> num, list<string> altNames = []> : Register<n, altNames> {
  field bits<6> Num = num;
  let Namespace = "RL78";
}

let Namespace = "RL78" in {
  def BankRegAltName : RegAltNameIndex;
}

def R0 : RL78Register<"X", 0, []>, DwarfRegNum<[46]>;
def R1 : RL78Register<"A", 1, []>, DwarfRegNum<[47]>;
def R2 : RL78Register<"C", 2, []>, DwarfRegNum<[48]>;
def R3 : RL78Register<"B", 3, []>, DwarfRegNum<[49]>;
def R4 : RL78Register<"E", 4, []>, DwarfRegNum<[50]>;
def R5 : RL78Register<"D", 5, []>, DwarfRegNum<[51]>;
def R6 : RL78Register<"L", 6, []>, DwarfRegNum<[52]>;
def R7 : RL78Register<"H", 7, []>, DwarfRegNum<[53]>;

let Namespace = "RL78" in {
def ES : Register<"es">;
def CS : Register<"cs">;
def CY : Register<"cy">;
def PSW : Register<"psw">;
def PMC : Register<"pmc">;
def MEM : Register<"mem">;
def SPL : Register<"spl">;
def SPH : Register<"sph">;
def MACRL : Register<"macrl">;
def MACRH : Register<"macrh">;
}

def RL78RegES : RegisterClass<"RL78", [i8], 8, (add ES)>;
def RL78RegCS : RegisterClass<"RL78", [i8], 8, (add CS)>;
def RL78RegCY : RegisterClass<"RL78", [i8], 8, (add CY)>; 

def RL78RegPSW : RegisterClass<"RL78", [i8], 8, (add PSW)>; 
def RL78RegPMC : RegisterClass<"RL78", [i8], 8, (add PMC)>; 
def RL78RegMEM : RegisterClass<"RL78", [i8], 8, (add MEM)>; 
def RL78RegSPL : RegisterClass<"RL78", [i8], 8, (add SPL)>; 
def RL78RegSPH : RegisterClass<"RL78", [i8], 8, (add SPH)>; 

def RL78RegMACRL : RegisterClass<"RL78", [i16], 16, (add MACRL)>; 
def RL78RegMACRH : RegisterClass<"RL78", [i16], 16, (add MACRH)>; 


def RL78SfrReg : RegisterClass<"RL78", [i8], 16, (add SPL, SPH, PSW, CS, ES, PMC, MEM)>;

def RL78Reg : RegisterClass<"RL78", [i8], 8, (add R1, R0, R2, R3, R4, R5, R6, R7)>;


def RL78OddReg : RegisterClass<"RL78", [i8], 8, (add R1, R3, R5, R7)>;

def RL78AReg : RegisterClass<"RL78", [i8], 8, (add R1)>;
//used for MULU
def RL78XReg : RegisterClass<"RL78", [i8], 8, (add R0)>;

//used of SHL
def RL78ABCReg : RegisterClass<"RL78", [i8], 8, (add R1, R2, R3)>;

def RL78BCEDHLReg : RegisterClass<"RL78", [i8], 8, (add R2, R3, R4, R5, R6, R7)>;

def RL78XBCEDHLReg : RegisterClass<"RL78", [i8], 8, (add R0, R2, R3, R4, R5, R6, R7)>;

//this is for ADDrr
def RL78BCReg : RegisterClass<"RL78", [i8], 8, (add R2, R3)>;

def RL78BCXReg : RegisterClass<"RL78", [i8], 8, (add R0, R2, R3)>;


def RL78Bank0Reg : RegisterClass<"RL78", [i8], 8, (add R0, R1, R2, R3, R4, R5, R6, R7)>;

def RL78Bank0Lo : RegisterClass<"RL78", [i8], 8, (add R1, R0, R2, R3)>;

def RL78Bank0Hi : RegisterClass<"RL78", [i8], 8, (add R4, R5, R6, R7)>;

let Namespace = "RL78" in
{
  def sub_lo : SubRegIndex<8>;
  def sub_hi : SubRegIndex<8, 8>;
}

class RL78RPReg<string n, bits<6> num, list<Register> subregs, list<string> altNames = []> : RL78Register<n, num, altNames> {
  let SubRegs = subregs;
  let SubRegIndices = [sub_lo, sub_hi];
}

def RP0 : RL78RPReg<"AX", 0, [R0, R1], []>, DwarfRegNum<[38]>;
def RP2 : RL78RPReg<"BC", 2, [R2, R3], []>, DwarfRegNum<[39]>;
def RP4 : RL78RPReg<"DE", 4, [R4, R5], []>, DwarfRegNum<[40]>;
def RP6 : RL78RPReg<"HL", 6, [R6, R7], []>, DwarfRegNum<[41]>;

def RL78RPRegs : RegisterClass<"RL78", [i16], 16, (add RP0, RP2, RP4, RP6)>;

def RL78AXRP : RegisterClass<"RL78", [i16], 16, (add RP0)>;

def RL78AXBCRP : RegisterClass<"RL78", [i16], 16, (add RP0, RP2)>;

//this is for ADDRri and ADDrr
def RL78BCDEHL : RegisterClass<"RL78", [i16], 16, (add RP6, RP4, RP2)>;
def RL78HL : RegisterClass<"RL78", [i16], 16, (add RP6)>;

def SPreg : RL78Register<"SP", 32>, DwarfRegNum<[32]>;
def CCreg : RL78Register<"CC", 34>;
def Zflag : RL78Register<"Z", 35>;

def RL78SPReg : RegisterClass<"RL78", [i16], 16, (add SPreg)>;
def RL78CCReg : RegisterClass<"RL78", [i8], 8, (add CCreg)>;

def PCreg : RL78Register<"PC", 37>, DwarfRegNum<[37]>;
