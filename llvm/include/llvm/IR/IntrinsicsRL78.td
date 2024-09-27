let TargetPrefix = "rl78" in { // All intrinsics start with "llvm.rl78."

// CPU control.
def int_rl78_ei : Intrinsic<[], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_di : Intrinsic<[], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_halt : Intrinsic<[], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_stop : Intrinsic<[], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_nop  : Intrinsic<[], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_brk  : Intrinsic<[], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_pswie : Intrinsic<[llvm_i8_ty], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_getpswisp : Intrinsic<[llvm_i8_ty], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_setpswisp : Intrinsic<[], [llvm_i8_ty], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_getpsw : Intrinsic<[llvm_i8_ty], [], [IntrNoMem, IntrHasSideEffects]>;
def int_rl78_setpsw : Intrinsic<[], [llvm_i8_ty], [IntrNoMem, IntrHasSideEffects]>;

// Bit manipulation.
def int_rl78_mov1 : Intrinsic<[], [llvm_ptr_ty, llvm_i8_ty, llvm_i8_ty, llvm_i8_ty]>;
def int_rl78_and1 : Intrinsic<[], [llvm_ptr_ty, llvm_i8_ty, llvm_i8_ty, llvm_i8_ty]>;
def int_rl78_or1  : Intrinsic<[], [llvm_ptr_ty, llvm_i8_ty, llvm_i8_ty, llvm_i8_ty]>;
def int_rl78_xor1 : Intrinsic<[], [llvm_ptr_ty, llvm_i8_ty, llvm_i8_ty, llvm_i8_ty]>;
def int_rl78_set1 : Intrinsic<[], [llvm_ptr_ty, llvm_i8_ty]>;
def int_rl78_clr1 : Intrinsic<[], [llvm_ptr_ty, llvm_i8_ty]>;
def int_rl78_not1 : Intrinsic<[], [llvm_ptr_ty, llvm_i8_ty]>;
def int_rl78_ror1 : Intrinsic<[llvm_i8_ty], [llvm_i8_ty], [IntrNoMem]>;
def int_rl78_rol1 : Intrinsic<[llvm_i8_ty], [llvm_i8_ty], [IntrNoMem]>;
def int_rl78_rolb : Intrinsic<[llvm_i8_ty], [llvm_i8_ty, llvm_i8_ty], [IntrNoMem]>;
def int_rl78_rorb : Intrinsic<[llvm_i8_ty], [llvm_i8_ty, llvm_i8_ty], [IntrNoMem]>;
def int_rl78_rolw : Intrinsic<[llvm_i16_ty], [llvm_i16_ty, llvm_i8_ty], [IntrNoMem]>;
def int_rl78_rorw : Intrinsic<[llvm_i16_ty], [llvm_i16_ty, llvm_i8_ty], [IntrNoMem]>;

// Arithmetic operations.
def int_rl78_mulu : Intrinsic<[llvm_i16_ty], [llvm_i8_ty, llvm_i8_ty], [IntrNoMem]>;
def int_rl78_mului : Intrinsic<[llvm_i32_ty], [llvm_i16_ty, llvm_i16_ty], [IntrNoMem]>;
def int_rl78_mulsi : Intrinsic<[llvm_i32_ty], [llvm_i16_ty, llvm_i16_ty], [IntrNoMem]>;
def int_rl78_mulul : Intrinsic<[llvm_i64_ty], [llvm_i32_ty, llvm_i32_ty], [IntrNoMem]>;
def int_rl78_mulsl : Intrinsic<[llvm_i64_ty], [llvm_i32_ty, llvm_i32_ty], [IntrNoMem]>;
def int_rl78_divui : Intrinsic<[llvm_i16_ty], [llvm_i16_ty, llvm_i8_ty], [IntrNoMem]>;
def int_rl78_divul : Intrinsic<[llvm_i32_ty], [llvm_i32_ty, llvm_i16_ty], [IntrNoMem]>;
def int_rl78_remui : Intrinsic<[llvm_i8_ty], [llvm_i16_ty, llvm_i8_ty], [IntrNoMem]>;
def int_rl78_remul : Intrinsic<[llvm_i16_ty], [llvm_i32_ty, llvm_i16_ty], [IntrNoMem]>;
def int_rl78_macui : Intrinsic<[llvm_i32_ty], [llvm_i16_ty, llvm_i16_ty, llvm_i32_ty], [IntrNoMem]>;
def int_rl78_macsi : Intrinsic<[llvm_i32_ty], [llvm_i16_ty, llvm_i16_ty, llvm_i32_ty], [IntrNoMem]>;

}
