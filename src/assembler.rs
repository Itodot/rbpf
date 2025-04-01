// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2017 Rich Lane <lanerl@gmail.com>

//! This module translates eBPF assembly language to binary.

use self::InstructionType::{
    AluBinary, AluUnary, Call, Endian, JumpConditional, JumpUnconditional, LoadAbs, LoadImm,
    LoadInd, LoadReg, NoOperand, StoreImm, StoreReg,
};
use crate::asm_parser::Operand::{Integer, Memory, Nil, Register};
use crate::asm_parser::{parse, Instruction, Operand};
use crate::ebpf;
use crate::ebpf::Insn;
use crate::lib::*;

/// 指令类型的枚举，用于表示不同类型的 eBPF 指令。
#[derive(Clone, Copy, Debug, PartialEq)]
enum InstructionType {
    /// 算术和逻辑二元操作指令，例如加法、减法等。
    AluBinary,
    /// 算术和逻辑一元操作指令，例如取反等。
    AluUnary,
    /// 加载立即数指令。
    LoadImm,
    /// 加载绝对地址的指令。
    LoadAbs,
    /// 加载间接地址的指令。
    LoadInd,
    /// 从内存加载到寄存器的指令。
    LoadReg,
    /// 将立即数存储到内存的指令。
    StoreImm,
    /// 将寄存器值存储到内存的指令。
    StoreReg,
    /// 无条件跳转指令。
    JumpUnconditional,
    /// 条件跳转指令。
    JumpConditional,
    /// 调用指令。
    Call,
    /// 大小端转换指令，包含转换的位数。
    Endian(i64),
    /// 无操作数的指令。
    NoOperand,
}

/// 创建一个指令映射表，将指令名称映射到其对应的类型和操作码。
///
/// # 返回
/// 一个 `HashMap`，键为指令名称（字符串），值为指令类型和操作码的元组。
fn make_instruction_map() -> HashMap<String, (InstructionType, u8)> {
    let mut result = HashMap::new();

    // 算术和逻辑二元操作符及其对应的操作码。
    let alu_binary_ops = [
        ("add", ebpf::BPF_ADD),
        ("sub", ebpf::BPF_SUB),
        ("mul", ebpf::BPF_MUL),
        ("div", ebpf::BPF_DIV),
        ("or", ebpf::BPF_OR),
        ("and", ebpf::BPF_AND),
        ("lsh", ebpf::BPF_LSH),
        ("rsh", ebpf::BPF_RSH),
        ("mod", ebpf::BPF_MOD),
        ("xor", ebpf::BPF_XOR),
        ("mov", ebpf::BPF_MOV),
        ("arsh", ebpf::BPF_ARSH),
    ];

    // 内存操作的大小后缀及其对应的操作码。
    let mem_sizes = [
        ("w", ebpf::BPF_W),   // 32位
        ("h", ebpf::BPF_H),   // 16位
        ("b", ebpf::BPF_B),   // 8位
        ("dw", ebpf::BPF_DW), // 64位
    ];

    // 条件跳转指令及其对应的操作码。
    let jump_conditions = [
        ("jeq", ebpf::BPF_JEQ),   // 等于
        ("jgt", ebpf::BPF_JGT),   // 大于
        ("jge", ebpf::BPF_JGE),   // 大于等于
        ("jlt", ebpf::BPF_JLT),   // 小于
        ("jle", ebpf::BPF_JLE),   // 小于等于
        ("jset", ebpf::BPF_JSET), // 位设置
        ("jne", ebpf::BPF_JNE),   // 不等于
        ("jsgt", ebpf::BPF_JSGT), // 有符号大于
        ("jsge", ebpf::BPF_JSGE), // 有符号大于等于
        ("jslt", ebpf::BPF_JSLT), // 有符号小于
        ("jsle", ebpf::BPF_JSLE), // 有符号小于等于
    ];

    {
        // 辅助函数，用于向映射表中添加条目。
        let mut entry = |name: &str, inst_type: InstructionType, opc: u8| {
            result.insert(name.to_string(), (inst_type, opc))
        };

        // 杂项指令。
        entry("exit", NoOperand, ebpf::EXIT); // 退出指令
        entry("ja", JumpUnconditional, ebpf::JA); // 无条件跳转
        entry("call", Call, ebpf::CALL); // 调用指令
        entry("lddw", LoadImm, ebpf::LD_DW_IMM); // 加载双字立即数

        // 一元算术操作指令。
        entry("neg", AluUnary, ebpf::NEG64); // 取反
        entry("neg32", AluUnary, ebpf::NEG32); // 32位取反
        entry("neg64", AluUnary, ebpf::NEG64); // 64位取反

        // 二元算术和逻辑操作指令。
        for &(name, opc) in &alu_binary_ops {
            //这里
            entry(name, AluBinary, ebpf::BPF_ALU64 | opc); // 64位操作
            entry(&format!("{name}32"), AluBinary, ebpf::BPF_ALU | opc); // 32位操作
            entry(&format!("{name}64"), AluBinary, ebpf::BPF_ALU64 | opc); // 显式64位操作
        }

        // 加载和存储指令。
        for &(suffix, size) in &mem_sizes {
            entry(
                &format!("ldabs{suffix}"),
                LoadAbs,
                ebpf::BPF_ABS | ebpf::BPF_LD | size,
            ); // 绝对加载
            entry(
                &format!("ldind{suffix}"),
                LoadInd,
                ebpf::BPF_IND | ebpf::BPF_LD | size,
            ); // 间接加载
            entry(
                &format!("ldx{suffix}"),
                LoadReg,
                ebpf::BPF_MEM | ebpf::BPF_LDX | size,
            ); // 从内存加载到寄存器
            entry(
                &format!("st{suffix}"),
                StoreImm,
                ebpf::BPF_MEM | ebpf::BPF_ST | size,
            ); // 存储立即数到内存
            entry(
                &format!("stx{suffix}"),
                StoreReg,
                ebpf::BPF_MEM | ebpf::BPF_STX | size,
            ); // 存储寄存器值到内存
        }

        // 条件跳转指令。
        for &(name, condition) in &jump_conditions {
            entry(name, JumpConditional, ebpf::BPF_JMP | condition); // 条件跳转
            entry(
                &format!("{name}32"),
                JumpConditional,
                ebpf::BPF_JMP32 | condition,
            ); // 32位条件跳转
        }

        // 大小端转换指令。
        for &size in &[16, 32, 64] {
            entry(&format!("be{size}"), Endian(size), ebpf::BE); // 转换为大端
            entry(&format!("le{size}"), Endian(size), ebpf::LE); // 转换为小端
        }
    }

    result
}

/// 构造一个 eBPF 指令（Insn）
///
/// # 参数
/// - `opc`: 操作码（opcode）
/// - `dst`: 目标寄存器编号
/// - `src`: 源寄存器编号
/// - `off`: 偏移量
/// - `imm`: 立即数
///
/// # 返回
/// 如果参数有效，返回一个 `Insn` 对象；否则返回错误信息。
fn insn(opc: u8, dst: i64, src: i64, off: i64, imm: i64) -> Result<Insn, String> {
    // 检查目标寄存器编号是否在有效范围内（0 到 15）
    if !(0..16).contains(&dst) {
        return Err(format!("无效的目标寄存器编号 {dst}"));
    }
    // 检查源寄存器编号是否在有效范围内（0 到 15）
    if dst < 0 || src >= 16 {
        return Err(format!("无效的源寄存器编号 {src}"));
    }
    // 检查偏移量是否在有效范围内（-32768 到 32767）
    if !(-32768..32768).contains(&off) {
        return Err(format!("无效的偏移量 {off}"));
    }
    // 检查立即数是否在有效范围内（-2147483648 到 2147483647）
    if !(-2147483648..2147483648).contains(&imm) {
        return Err(format!("无效的立即数 {imm}"));
    }
    // 构造并返回指令
    Ok(Insn {
        opc,
        dst: dst as u8,
        src: src as u8,
        off: off as i16,
        imm: imm as i32,
    })
}

// TODO Use slice patterns when available and remove this function.
/// 将操作数切分为一个三元组（最多三个操作数）
///
/// # 参数
/// - `operands`: 操作数的切片
///
/// # 返回
/// 如果操作数数量在 0 到 3 之间，返回一个包含操作数的三元组；
/// 如果操作数数量超过 3，返回错误信息。
fn operands_tuple(operands: &[Operand]) -> Result<(Operand, Operand, Operand), String> {
    match operands.len() {
        0 => Ok((Nil, Nil, Nil)),         // 没有操作数，返回全为 Nil 的三元组
        1 => Ok((operands[0], Nil, Nil)), // 一个操作数，后两个为 Nil
        2 => Ok((operands[0], operands[1], Nil)), // 两个操作数，最后一个为 Nil
        3 => Ok((operands[0], operands[1], operands[2])), // 三个操作数，直接返回
        _ => Err("操作数过多".to_string()), // 超过三个操作数，返回错误
    }
}

/// 根据指令类型、操作码和操作数生成 eBPF 指令（Insn）
///
/// # 参数
/// - `inst_type`: 指令类型
/// - `opc`: 操作码
/// - `operands`: 操作数列表
///
/// # 返回
/// 如果操作数匹配成功，返回一个 `Insn` 对象；否则返回错误信息。
fn encode(inst_type: InstructionType, opc: u8, operands: &[Operand]) -> Result<Insn, String> {
    // 将操作数切分为三元组（最多三个操作数）
    let (a, b, c) = (operands_tuple(operands))?;
    // 根据指令类型和操作数模式匹配生成指令
    match (inst_type, a, b, c) {
        // 二元算术和逻辑操作，两个寄存器作为操作数
        (AluBinary, Register(dst), Register(src), Nil) => insn(opc | ebpf::BPF_X, dst, src, 0, 0),
        // 二元算术和逻辑操作，一个寄存器和一个立即数作为操作数
        (AluBinary, Register(dst), Integer(imm), Nil) => insn(opc | ebpf::BPF_K, dst, 0, 0, imm),
        // 一元算术操作，一个寄存器作为操作数
        (AluUnary, Register(dst), Nil, Nil) => insn(opc, dst, 0, 0, 0),
        // 绝对加载操作，一个立即数作为操作数
        (LoadAbs, Integer(imm), Nil, Nil) => insn(opc, 0, 0, 0, imm),
        // 间接加载操作，一个寄存器和一个立即数作为操作数
        (LoadInd, Register(src), Integer(imm), Nil) => insn(opc, 0, src, 0, imm),
        // 从内存加载到寄存器或将寄存器值存储到内存
        (LoadReg, Register(dst), Memory(src, off), Nil)
        | (StoreReg, Memory(dst, off), Register(src), Nil) => insn(opc, dst, src, off, 0),
        // 将立即数存储到内存
        (StoreImm, Memory(dst, off), Integer(imm), Nil) => insn(opc, dst, 0, off, imm),
        // 无操作数的指令
        (NoOperand, Nil, Nil, Nil) => insn(opc, 0, 0, 0, 0),
        // 无条件跳转指令，一个立即数作为偏移量
        (JumpUnconditional, Integer(off), Nil, Nil) => insn(opc, 0, 0, off, 0),
        // 条件跳转指令，两个寄存器和一个立即数作为偏移量
        (JumpConditional, Register(dst), Register(src), Integer(off)) => {
            insn(opc | ebpf::BPF_X, dst, src, off, 0)
        }
        // 条件跳转指令，一个寄存器、一个立即数和一个偏移量
        (JumpConditional, Register(dst), Integer(imm), Integer(off)) => {
            insn(opc | ebpf::BPF_K, dst, 0, off, imm)
        }
        // 调用指令，一个立即数作为操作数
        (Call, Integer(imm), Nil, Nil) => insn(opc, 0, 0, 0, imm),
        // 大小端转换指令，一个寄存器和转换的位数
        (Endian(size), Register(dst), Nil, Nil) => insn(opc, dst, 0, 0, size),
        // 加载立即数指令，一个寄存器和一个立即数
        (LoadImm, Register(dst), Integer(imm), Nil) => insn(opc, dst, 0, 0, (imm << 32) >> 32),
        // 其他未匹配的操作数模式
        _ => Err(format!("Unexpected operands: {operands:?}")),
    }
}

fn assemble_internal(parsed: &[Instruction]) -> Result<Vec<Insn>, String> {
    let instruction_map = make_instruction_map();
    let mut result: Vec<Insn> = vec![];

    //循环parsed列表 (parsed来自parse方法返回值)
    for instruction in parsed {
        //获取命令名称
        let name = instruction.name.as_str();
        //匹配类型和opcode
        match instruction_map.get(name) {
            Some(&(inst_type, opc)) => {
                match encode(inst_type, opc, &instruction.operands) {
                    //匹配成功后返在结果内添加命令
                    Ok(insn) => result.push(insn),
                    //发生错误时,返回错误
                    Err(msg) => return Err(format!("Failed to encode {name}: {msg}")),
                }
                // Special case for lddw.
                // 当类型是imm类型时,对命令取高32位进行拼接
                if let LoadImm = inst_type {
                    if let Integer(imm) = instruction.operands[1] {
                        result.push(insn(0, 0, 0, 0, imm >> 32).unwrap());
                    }
                }
            }
            None => return Err(format!("Invalid instruction {name:?}")),
        }
    }
    Ok(result)
}

/// Parse assembly source and translate to binary.
///
/// # Examples
///
/// ```
/// use rbpf::assembler::assemble;
/// let prog = assemble("
///                      add64 r1, 0x605
///                      mov64 r2, 0x32
///                      mov64 r1, r0
///                      be16 r0
///                      neg64 r2
///                      exit");
/// println!("{:?}", prog);
/// # assert_eq!(prog,
/// #            Ok(vec![0x07, 0x01, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00,
/// #                    0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
/// #                    0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// #                    0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
/// #                    0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// #                    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
/// ```
///
/// This will produce the following output:
///
/// ```test
/// Ok([0x07, 0x01, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00,
///     0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
///     0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///     0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
/// ```
/// `insns` 是通过调用 `assemble_internal` 函数并传入 `parsed` 参数生成的结果。
/// 该变量通常表示汇编指令的集合，可能用于进一步处理或执行。
///
/// 注意：`assemble_internal` 函数返回一个 `Result`，因此需要使用 `?` 操作符
/// 来处理可能的错误。
pub fn assemble(src: &str) -> Result<Vec<u8>, String> {
    let parsed = (parse(src))?;
    //Ok([Instruction { name: "mov", operands: [Register(0), Integer(0)] }, Instruction { name: "add", operands: [Register(1), Integer(2)] }])
    let insns = (assemble_internal(&parsed))?;

    let mut result: Vec<u8> = vec![];
    for insn in insns {
        result.extend_from_slice(&insn.to_array());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::asm_parser::parse;
    use crate::assembler::assemble_internal;
    #[test]
    fn test_assemble_internal() {
        let src = "
        mov r1,0
        add r1,2
        ja +1
        lsh r3, 0x8
        call 1
        ldxb r2, [r1+12]
        ";
        let parsed = parse(&src).unwrap();
        eprint!("{:?}\n", parsed);
        let insns = assemble_internal(&parsed).unwrap();
        eprint!("{:?}", insns);
    }
}
