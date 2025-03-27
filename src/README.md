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

### **eBPF 指令的 Opcode 组成部分**
在 eBPF 中，每个指令的 **opcode（操作码）** 由 **8-bit（1 字节）** 组成，结构如下：

```
  7   6   5   4   |  3   2   |  1   0  
+---------------+--------+--------+
|     操作码    |  访问模式  |  大小   |
+---------------+--------+--------+
```

eBPF 的 `opcode` 主要由以下几个部分组成：

| 位范围 | 名称         | 作用                      |
|--------|------------|-------------------------|
| 7-4   | **操作码（OP）**  | 指定基本操作类型，如 `BPF_LD`, `BPF_ALU`, `BPF_JMP` 等 |
| 3-2   | **访问模式（MODE）**  | 指定操作的数据来源，如 `BPF_MEM`, `BPF_IMM`（立即数）等 |
| 1-0   | **数据大小（SIZE）**  | 指定数据的大小，如 `BPF_W`（4 字节）, `BPF_H`（2 字节）, `BPF_B`（1 字节） |

---

## **eBPF 指令格式**
完整的 eBPF 指令通常是 **8 字节**（64 位），其中 **opcode** 仅占 **低 8 位**，其余部分包含寄存器编号、立即数等。

```
  31      24 23     16 15      8 7       0
+--------+--------+--------+--------+
|    dst  |    src  |  offset  |  opcode |
+--------+--------+--------+--------+
|           immediate / address          |
+----------------------------------------+
```

字段说明：
| **字段**      | **位数** | **说明**  |
|-------------|--------|---------|
| **opcode**  | 8-bit  | 操作码，包括 OP、MODE 和 SIZE |
| **dst**     | 4-bit  | 目标寄存器编号 |
| **src**     | 4-bit  | 源寄存器编号（用于二元运算） |
| **offset**  | 16-bit | 偏移量（用于内存访问或跳转） |
| **immediate** | 32-bit | 立即数（用于算术或跳转指令） |

---

## **Opcode 具体字段解释**
### **1. 操作码（OP，7~4位）**
| Opcode 值 | 名称            | 说明 |
|-----------|---------------|---------------------------|
| `0x00`    | `BPF_LD`      | 立即数/内存加载指令 |
| `0x40`    | `BPF_LDX`     | 从内存加载到寄存器 |
| `0x60`    | `BPF_ST`      | 存储指令（寄存器 → 内存） |
| `0x61`    | `BPF_STX`     | 存储指令（寄存器 → 内存，带索引） |
| `0x80`    | `BPF_ALU`     | 算术运算（立即数模式） |
| `0xc0`    | `BPF_ALU64`   | 64 位算术运算 |
| `0xa0`    | `BPF_JMP`     | 跳转指令 |
| `0xe0`    | `BPF_JMP32`   | 32 位跳转指令 |

---

### **2. 访问模式（MODE，3~2位）**
| Mode 值  | 名称        | 说明 |
|---------|-----------|--------------------------------|
| `0x00`  | `BPF_IMM`  | 立即数模式（直接使用值） |
| `0x10`  | `BPF_ABS`  | 绝对地址模式（用于 `BPF_LD`） |
| `0x20`  | `BPF_IND`  | 间接地址模式（用于 `BPF_LD`） |
| `0x60`  | `BPF_MEM`  | 内存模式（从内存读取/写入） |
| `0x70`  | `BPF_LEN`  | 报文长度（仅在 `BPF_LD` 使用） |

---

### **3. 数据大小（SIZE，1~0位）**
| Size 值 | 名称      | 说明 |
|---------|---------|----------------|
| `0x00`  | `BPF_W`  | 4 字节（32 位） |
| `0x08`  | `BPF_H`  | 2 字节（16 位） |
| `0x10`  | `BPF_B`  | 1 字节（8 位）  |
| `0x18`  | `BPF_DW` | 8 字节（64 位） |

---

## **示例：解析具体 Opcode**
假设 `opcode = 0x71`，我们解析它的组成部分：
```plaintext
opcode = 0x71 = 0b0111 0001
```
| 部分      | 二进制值 | 解析  |
|----------|--------|---------------------------|
| **OP (7-4 位)**  | `0111`  | `BPF_LDX` (加载寄存器) |
| **MODE (3-2 位)** | `00`   | `BPF_MEM` (内存模式)  |
| **SIZE (1-0 位)** | `01`   | `BPF_B` (1 字节) |

最终指令：`BPF_LDX | BPF_MEM | BPF_B`，表示 **“从内存加载 1 字节到寄存器”**。

---

## **总结**
- eBPF 指令的 `opcode` 由 **操作码（OP）、访问模式（MODE）、数据大小（SIZE）** 组成，共 8 位。
- `opcode` 只是完整 eBPF 指令的一部分，完整指令还包含 **寄存器编号、偏移量、立即数** 等字段。
- 通过 `opcode` 的位运算（按位或 `|`），可以组合不同的指令，例如：
  ```rust
  pub const LD_B_REG: u8 = BPF_LDX | BPF_MEM | BPF_B;
  ```
  计算结果是 `0x71`，表示 **从内存加载 1 字节到寄存器** 的 eBPF 指令。

这种设计方式使得 eBPF 指令 **紧凑且可扩展**，可以通过 **不同组合方式** 定义新的操作。

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
