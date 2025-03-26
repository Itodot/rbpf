// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: safety checks, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust)

// This “verifier” performs simple checks when the eBPF program is loaded into the VM (before it is
// interpreted or JIT-compiled). It has nothing to do with the much more elaborated verifier inside
// Linux kernel. There is no verification regarding the program flow control (should be a Direct
// Acyclic Graph) or the consistency for registers usage (the verifier of the kernel assigns types
// to the registers and is much stricter).
//
// On the other hand, rbpf is not expected to run in kernel space.
//
// Improving the verifier would be nice, but this is not trivial (and Linux kernel is under GPL
// license, so we cannot copy it).
//
// Contrary to the verifier of the Linux kernel, this one does not modify the bytecode at all.

use crate::ebpf;
use crate::lib::*;

fn reject<S: AsRef<str>>(msg: S) -> Result<(), Error> {
    //当前文件通用报错方法
    let full_msg = format!("[Verifier] Error: {}", msg.as_ref());
    Err(Error::new(ErrorKind::Other, full_msg))
}
//检查程序长度
fn check_prog_len(prog: &[u8]) -> Result<(), Error> {
    //这里指定必须以字节为单位,即取余8为0
    if prog.len() % ebpf::INSN_SIZE != 0 {
        reject(format!(
            "eBPF program length must be a multiple of {:?} octets",
            ebpf::INSN_SIZE
        ))?;
    }
    //这里规定了最大的指令数为1000000字节
    if prog.len() > ebpf::PROG_MAX_SIZE {
        reject(format!(
            "eBPF program length limited to {:?}, here {:?}",
            ebpf::PROG_MAX_INSNS,
            prog.len() / ebpf::INSN_SIZE
        ))?;
    }
    //这里过滤指令不能为空
    if prog.is_empty() {
        reject("no program set, call set_program() to load one")?;
    }
    //这里获取最后一位
    let last_opc = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1).opc;
    //last_opc & ebpf::BPF_CLS_MASK  按位与或获取类型
    //这里取后三位,0x95 0x01010101 后三位为101 即为5
    if last_opc & ebpf::BPF_CLS_MASK != ebpf::BPF_JMP {
        reject("program does not end with “EXIT” instruction")?;
    }

    Ok(())
}
//检查imm是否为16 32 64位
//imm为:eBPF 指令（Insn）中的一个字段，表示“立即数”（immediate value），通常用于存储常量或操作数。
fn check_imm_endian(insn: &ebpf::Insn, insn_ptr: usize) -> Result<(), Error> {
    match insn.imm {
        16 | 32 | 64 => Ok(()),
        _ => reject(format!(
            "unsupported argument for LE/BE (insn #{insn_ptr:?})"
        )),
    }
}
//check_load_dw 的作用是检查 eBPF 程序中的 LD_DW（64 位双字加载）指令是否完整。
//由于 LD_DW 在 eBPF 中由 两条连续的 32 位指令 组成，因此需要确保：
//insn #0: LD_DW 低32位数据 (opc = LD_DW)
//insn #1: 高32位数据      (opc = 0)  <- 合法
//insn #2: EXIT

//insn #0: LD_DW 低32位数据 (opc = LD_DW)
//insn #1: ADD             (opc = ADD)  <- 非法！
fn check_load_dw(prog: &[u8], insn_ptr: usize) -> Result<(), Error> {
    // We know we can reach next insn since we enforce an EXIT insn at the end of program, while
    // this function should be called only for LD_DW insn, that cannot be last in program.
    let next_insn = ebpf::get_insn(prog, insn_ptr + 1);
    if next_insn.opc != 0 {
        reject(format!("incomplete LD_DW instruction (insn #{insn_ptr:?})"))?;
    }

    Ok(())
}
//判断是否会发生死循环
//是否跳出指令范围
//检查是否跳到LD_DW的中间,因为LD_DW为64位数据,需要两个32位指令,跳到第二个指令会导致失败
fn check_jmp_offset(prog: &[u8], insn_ptr: usize) -> Result<(), Error> {
    let insn = ebpf::get_insn(prog, insn_ptr);
    //判断是否会发生死循环
    if insn.off == -1 {
        reject(format!("infinite loop (insn #{insn_ptr:?})"))?;
    }
    //是否跳出指令范围
    let dst_insn_ptr = insn_ptr as isize + 1 + insn.off as isize;
    if dst_insn_ptr < 0 || dst_insn_ptr as usize >= (prog.len() / ebpf::INSN_SIZE) {
        reject(format!(
            "jump out of code to #{dst_insn_ptr:?} (insn #{insn_ptr:?})"
        ))?;
    }
    //检查是否跳到LD_DW的后32位,因为LD_DW为64位数据,需要两个32位指令,跳到第二个指令会导致失败
    let dst_insn = ebpf::get_insn(prog, dst_insn_ptr as usize);
    if dst_insn.opc == 0 {
        reject(format!(
            "jump to middle of LD_DW at #{dst_insn_ptr:?} (insn #{insn_ptr:?})"
        ))?;
    }

    Ok(())
}
//检查是否被注册
fn check_registers(insn: &ebpf::Insn, store: bool, insn_ptr: usize) -> Result<(), Error> {
    //确保源寄存器编号不超过 10,因为只有R0到R10 11个寄存器
    if insn.src > 10 {
        reject(format!("invalid source register (insn #{insn_ptr:?})"))?;
    }
    //当store为true时允许写入R10寄存器,为false时不允许写入
    //任何情况下都可以写入R0-R9寄存器
    //其它任何情况都为报错
    match (insn.dst, store) {
        (0..=9, _) | (10, true) => Ok(()),
        (10, false) => reject(format!(
            "cannot write into register r10 (insn #{insn_ptr:?})"
        )),
        (_, _) => reject(format!("invalid destination register (insn #{insn_ptr:?})")),
    }
}

pub fn check(prog: &[u8]) -> Result<(), Error> {
    //检查程序指令长度
    check_prog_len(prog)?; //1.指令长度

    //定义当前读取大小
    let mut insn_ptr: usize = 0;
    while insn_ptr * ebpf::INSN_SIZE < prog.len() {
        //获取指令
        let insn = ebpf::get_insn(prog, insn_ptr);
        //不允许存储到R10寄存器
        let mut store = false;

        match insn.opc {
            //根据opc码选择类型

            // BPF_LD class
            // LD_ABS 固定偏移
            //ABS 直接访问固定偏移，适合静态场景，效率更高。
            ebpf::LD_ABS_B => {}  //8位
            ebpf::LD_ABS_H => {}  //16位
            ebpf::LD_ABS_W => {}  //32位
            ebpf::LD_ABS_DW => {} //64位
            // LD_IND 间接偏移
            // IND 支持动态计算偏移，灵活性更强。
            ebpf::LD_IND_B => {}  //8位
            ebpf::LD_IND_H => {}  //16位
            ebpf::LD_IND_W => {}  //32位
            ebpf::LD_IND_DW => {} //64位
            // 64 指令读取时处理
            //insn #0: LD_DW_IMM R1, 0xABCDEF00  ; 低32位
            //insn #1: 0x00000000, 0x12345678    ; 高32位（操作码为0）
            ebpf::LD_DW_IMM => {
                //R10可存储
                store = true;
                //检查是否为连续位
                check_load_dw(prog, insn_ptr)?;
                insn_ptr += 1;
            }
            //通过索引寄存器加载数据
            // BPF_LDX class
            ebpf::LD_B_REG => {}  //8位
            ebpf::LD_H_REG => {}  //16位
            ebpf::LD_W_REG => {}  //32位
            ebpf::LD_DW_REG => {} //64位
            //立即数 存储操作
            // BPF_ST class
            ebpf::ST_B_IMM => store = true,  //8位
            ebpf::ST_H_IMM => store = true,  //16位
            ebpf::ST_W_IMM => store = true,  //32位
            ebpf::ST_DW_IMM => store = true, //64位
            //寄存器 存储操作
            // BPF_STX class
            ebpf::ST_B_REG => store = true,  //8位
            ebpf::ST_H_REG => store = true,  //16位
            ebpf::ST_W_REG => store = true,  //32位
            ebpf::ST_DW_REG => store = true, //64位

            //----------原子性内存操作--------
            ebpf::ST_W_XADD => {
                unimplemented!();
            }
            ebpf::ST_DW_XADD => {
                unimplemented!();
            }
            //------------------------------
            //算术和逻辑运算的操作码
            // BPF_ALU class
            ebpf::ADD32_IMM => {}  //立即数 +
            ebpf::ADD32_REG => {}  //寄存器 +
            ebpf::SUB32_IMM => {}  //立即数  -
            ebpf::SUB32_REG => {}  //寄存器 -
            ebpf::MUL32_IMM => {}  //立即数 32位乘
            ebpf::MUL32_REG => {}  //寄存器 32位乘
            ebpf::DIV32_IMM => {}  //立即数 32位除
            ebpf::DIV32_REG => {}  //寄存器 32位除
            ebpf::OR32_IMM => {}   //立即数 32位或
            ebpf::OR32_REG => {}   //寄存器 32位或
            ebpf::AND32_IMM => {}  //立即数 32位与
            ebpf::AND32_REG => {}  //寄存器 32位与
            ebpf::LSH32_IMM => {}  //立即数 32位左移
            ebpf::LSH32_REG => {}  //寄存器 32位左移
            ebpf::RSH32_IMM => {}  //立即数 32位右移
            ebpf::RSH32_REG => {}  //寄存器 32位右移
            ebpf::NEG32 => {}      //32位取反
            ebpf::MOD32_IMM => {}  //立即数 32位取模
            ebpf::MOD32_REG => {}  //寄存器 32位取模
            ebpf::XOR32_IMM => {}  //立即数 32位异或
            ebpf::XOR32_REG => {}  //寄存器 32位异或
            ebpf::MOV32_IMM => {}  //立即数 32位赋值
            ebpf::MOV32_REG => {}  //寄存器 32位赋值
            ebpf::ARSH32_IMM => {} //立即数 32位算术右移
            ebpf::ARSH32_REG => {} //寄存器 32位算术右移
            ebpf::LE => {
                //小端
                check_imm_endian(&insn, insn_ptr)?; //检查imm是否为16 32 64位
            }
            ebpf::BE => {
                //大端

                check_imm_endian(&insn, insn_ptr)?; //检查imm是否为16 32 64位
            }

            // BPF_ALU64 class
            ebpf::ADD64_IMM => {}  //立即数 64位加
            ebpf::ADD64_REG => {}  //寄存器 64位加
            ebpf::SUB64_IMM => {}  //立即数 64位减
            ebpf::SUB64_REG => {}  //寄存器 64位减
            ebpf::MUL64_IMM => {}  //立即数 64位乘
            ebpf::MUL64_REG => {}  //寄存器 64位乘
            ebpf::DIV64_IMM => {}  //立即数 64位除
            ebpf::DIV64_REG => {}  //寄存器 64位除
            ebpf::OR64_IMM => {}   //立即数 64位或
            ebpf::OR64_REG => {}   //寄存器 64位或
            ebpf::AND64_IMM => {}  //立即数 64位与
            ebpf::AND64_REG => {}  //寄存器 64位与
            ebpf::LSH64_IMM => {}  //立即数 64位左移
            ebpf::LSH64_REG => {}  //寄存器 64位左移
            ebpf::RSH64_IMM => {}  //立即数 64位右移
            ebpf::RSH64_REG => {}  //寄存器 64位右移
            ebpf::NEG64 => {}      //64位取反
            ebpf::MOD64_IMM => {}  //立即数 64位取模
            ebpf::MOD64_REG => {}  //寄存器 64位取模
            ebpf::XOR64_IMM => {}  //立即数 64位异或
            ebpf::XOR64_REG => {}  //寄存器 64位异或
            ebpf::MOV64_IMM => {}  //立即数 64位赋值
            ebpf::MOV64_REG => {}  //寄存器 64位赋值
            ebpf::ARSH64_IMM => {} //立即数 64位算术右移
            ebpf::ARSH64_REG => {} //寄存器 64位算术右移

            // BPF_JMP class
            ebpf::JA => {
                //无条件跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JEQ_IMM => {
                //立即数相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JEQ_REG => {
                //寄存器相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGT_IMM => {
                //立即数大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGT_REG => {
                //寄存器大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGE_IMM => {
                //立即数大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGE_REG => {
                //寄存器大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLT_IMM => {
                //立即数小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLT_REG => {
                //寄存器小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLE_IMM => {
                //立即数小于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLE_REG => {
                //寄存器小于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSET_IMM => {
                //立即数位与跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSET_REG => {
                //寄存器位与跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JNE_IMM => {
                //立即数不相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JNE_REG => {
                //寄存器不相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGT_IMM => {
                //立即数有符号大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGT_REG => {
                //寄存器有符号大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGE_IMM => {
                //立即数有符号大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGE_REG => {
                //寄存器有符号大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSLT_IMM => {
                //立即数有符号小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSLT_REG => {
                //寄存器有符号小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSLE_IMM => {
                //立即数有符号小于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSLE_REG => {
                //寄存器有符号小于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }

            // BPF_JMP32 class
            ebpf::JEQ_IMM32 => {
                //32位立即数相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JEQ_REG32 => {
                //32位寄存器相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGT_IMM32 => {
                //32位立即数大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGT_REG32 => {
                //32位寄存器大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGE_IMM32 => {
                //32位立即数大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JGE_REG32 => {
                //32位寄存器大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLT_IMM32 => {
                //32位立即数小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLT_REG32 => {
                //32位寄存器小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLE_IMM32 => {
                //32位立即数小于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JLE_REG32 => {
                //32位寄存器小于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSET_IMM32 => {
                //32位立即数位与跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSET_REG32 => {
                //32位寄存器位与跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JNE_IMM32 => {
                //32位立即数不相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JNE_REG32 => {
                //32位寄存器不相等跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGT_IMM32 => {
                //32位立即数有符号大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGT_REG32 => {
                //32位寄存器有符号大于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGE_IMM32 => {
                //32位立即数有符号大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSGE_REG32 => {
                //32位寄存器有符号大于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSLT_IMM32 => {
                //32位立即数有符号小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSLT_REG32 => {
                //32位寄存器有符号小于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            ebpf::JSLE_IMM32 => {
                //32位立即数有符号小于等于跳转
                check_jmp_offset(prog, insn_ptr)?;
            }
            //32位寄存器有符号小于等于跳转
            ebpf::JSLE_REG32 => {
                check_jmp_offset(prog, insn_ptr)?;
            }
            // BPF_CALL class
            ebpf::CALL => {} //调用
            ebpf::TAIL_CALL => {
                //尾调用
                unimplemented!()
            }
            ebpf::EXIT => {} //退出

            _ => {
                //未知操作码
                reject(format!(
                    "unknown eBPF opcode {:#2x} (insn #{insn_ptr:?})",
                    insn.opc
                ))?;
            }
        }

        //仅当LD_DW_IMM类型时R10可写入
        check_registers(&insn, store, insn_ptr)?; //寄存器写入权限

        insn_ptr += 1; //指令指针+1
    }

    // insn_ptr should now be equal to number of instructions.
    if insn_ptr != prog.len() / ebpf::INSN_SIZE {
        //检查是否跳出指令范围
        reject(format!("jumped out of code to #{insn_ptr:?}"))?;
    }

    Ok(())
}
