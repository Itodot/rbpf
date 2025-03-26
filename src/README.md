## Verifier.rs

### `check_prog_len` - 程序长度检查

```rust
fn check_prog_len(prog: &[u8]) -> Result<(), Error> {
    // 检查是否为8字节倍数
    if prog.len() % ebpf::INSN_SIZE != 0 {
        reject(...)?;
    }
    // 检查最大长度
    if prog.len() > ebpf::PROG_MAX_SIZE {
        reject(...)?;
    }
    // 检查非空
    if prog.is_empty() {
        reject(...)?;
    }
    // 检查必须以EXIT结束
    let last_opc = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1).opc;
    if last_opc & ebpf::BPF_CLS_MASK != ebpf::BPF_JMP {
        reject(...)?;
    }
    Ok(())
}
```

### `check_load_dw` - LD_DW指令检查

```rust
fn check_load_dw(prog: &[u8], insn_ptr: usize) -> Result<(), Error> {
    // 获取下一条指令
    let next_insn = ebpf::get_insn(prog, insn_ptr + 1);
    // 下一条指令的操作码必须为0
    if next_insn.opc != 0 {
        reject(...)?;
    }
    Ok(())
}
```

### `check_jmp_offset` - 跳转指令检查

```rust
fn check_jmp_offset(prog: &[u8], insn_ptr: usize) -> Result<(), Error> {
    let insn = ebpf::get_insn(prog, insn_ptr);
    // 检查死循环
    if insn.off == -1 {
        reject(...)?;
    }
    // 检查跳转目标是否在程序范围内
    let dst_insn_ptr = insn_ptr as isize + 1 + insn.off as isize;
    if dst_insn_ptr < 0 || dst_insn_ptr as usize >= (prog.len() / ebpf::INSN_SIZE) {
        reject(...)?;
    }
    // 检查是否跳转到LD_DW指令的中间
    let dst_insn = ebpf::get_insn(prog, dst_insn_ptr as usize);
    if dst_insn.opc == 0 {
        reject(...)?;
    }
    Ok(())
}
```

### `check_registers` - 寄存器访问检查

```rust
fn check_registers(insn: &ebpf::Insn, store: bool, insn_ptr: usize) -> Result<(), Error> {
    // 源寄存器检查
    if insn.src > 10 {
        reject(...)?;
    }
    // 目标寄存器检查
    match (insn.dst, store) {
        (0..=9, _) | (10, true) => Ok(()),  // R0-R9总是可写，R10仅在store=true时可写
        (10, false) => reject(...),         // 不可写入R10
        (_, _) => reject(...),               // 无效寄存器
    }
}
```

## ebpf.rs

```rust
pub fn get_insn(prog: &[u8], idx: usize) -> Insn {
    // 检查是否超出指令范围
    if (idx + 1) * INSN_SIZE > prog.len() {
        panic!(
            "Error: cannot reach instruction at index {:?} in program containing {:?} bytes",
            idx,
            prog.len()
        );
    }
    Insn {
        // Byte 0   | Byte 1   | Bytes 2-3 | Bytes 4-7
        // ---------|----------|-----------|-----------
        // opc      | dst_src  | off       | imm
        opc: prog[INSN_SIZE * idx],            //操作码 1个字节 0-255
        dst: prog[INSN_SIZE * idx + 1] & 0x0f, //源寄存器 0-15 后四位
        src: (prog[INSN_SIZE * idx + 1] & 0xf0) >> 4, //目标寄存器 0-15 前四位
        off: LittleEndian::read_i16(&prog[(INSN_SIZE * idx + 2)..]), // 偏移位 2个字节
        imm: LittleEndian::read_i32(&prog[(INSN_SIZE * idx + 4)..]), // 立即数 4个字节
    }
}
```
