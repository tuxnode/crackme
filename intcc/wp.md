# HCTF — intcc Writeup

## 题目概述

一道反调试 + 静态分析综合题。程序将 flag 分为三段加密存储，每段解密前都会调用 Rust 编写的 `scan()` 函数扫描自身可执行代码区域，检测是否存在 `int3`（`0xCC`）断点指令。同时，C 代码中大量使用内联汇编进行控制流混淆（opaque predicates、间接跳转、RDTSC 反单步调试）。

**Flag**: `HCTF{you_c4n7_br34k_m3}`

---

## 项目结构

```
intcc/
├── main.c      # 主程序：三阶段解密 + 反调试 guard + 汇编混淆
├── scan.rs     # Rust 实现的内存扫描器（int3 检测核心）
├── Makefile    # 编译脚本：C → .o，Rust → .a，链接
└── wp.md       # 本 writeup
```

编译流程：`rustc --crate-type=staticlib scan.rs` 生成静态库，与 `main.o` 链接。

---

## 第一步：识别反调试机制

拿到二进制后，用 IDA/Ghidra 打开，首先观察到三个关键函数：

```
guard_a()  →  scan(guard_a, guard_b)
guard_b()  →  scan(guard_b, guard_c)
guard_c()  →  scan(guard_c, guard_c + 1024)
```

每个 guard 函数调用 `scan()` 扫描自己的代码区域。`scan()` 的 Rust 实现如下：

```rust
pub extern "C" fn scan(start_ptr, end_ptr) -> i32 {
    let slice = from_raw_parts(start_ptr as *const u8, len);
    for (i, &byte) in slice.iter().enumerate() {
        if byte == 0xCC { return i as i32; }  // 找到 int3
    }
    -2  // 干净，没有断点
}
```

**核心原理**：x86 调试器（GDB/LLDB）设置软件断点时，会将目标地址的第一个字节替换为 `0xCC`（int3 指令）。程序在执行解密前扫描自身代码，如果发现任何 `0xCC`，就判定有人在调试。

### 扫描范围分析

| Guard 函数 | 扫描起始 | 扫描结束 | 实际覆盖 |
|-----------|---------|---------|---------|
| `guard_a` | `guard_a` 函数地址 | `guard_b` 函数地址 | `guard_a` 全部代码 |
| `guard_b` | `guard_b` 函数地址 | `guard_c` 函数地址 | `guard_b` 全部代码 |
| `guard_c` | `guard_c` 函数地址 | `guard_c + 1024` | `guard_c` 及后续 1KB |

**关键洞察**：扫描范围是 **函数地址到下一个函数地址** 之间的所有字节。如果调试者在 `guard_a` 内部设置断点，`0xCC` 会出现在 `guard_a` 的代码段内，`scan()` 就能检测到。

### 反调试触发后果

```c
if (g >= 0) {
    memset(chunk, 'X', sizeof(chunk));  // 破坏加密数据
    _exit(1);                           // 直接退出
}
```

检测到断点后，程序会用 `'X'` 覆盖加密数据，然后立即退出。

---

## 第二步：绕过反调试

### 方案 A：静态分析（推荐）

既然不能下断点，就纯静态分析：

1. **定位加密数据**：在 `.data` 段找到三个全局数组 `chunk1[8]`、`chunk2[8]`、`chunk3[7]`
2. **定位密钥**：找到 `keybox[] = {0xDE, 0xAD, 0xBE, 0xEF}`
3. **理解解密逻辑**：每个 stage 对 chunk 进行 XOR 操作，密钥按 `i % 3` 滚动
4. **手动解密**

### 方案 B：二进制补丁

用十六进制编辑器将 `scan()` 函数的开头替换为 `mov eax, -2; ret`，使其永远返回"未检测到断点"。

### 方案 C：修改 Rust 源码重新编译

直接修改 `scan.rs`，让 `scan()` 永远返回 `-2`：

```rust
pub extern "C" fn scan(_start: *const c_char, _end: *const c_char) -> i32 {
    -2  // 永远返回"干净"
}
```

### 方案 D：绕过 RDTSC 检测

Guard 函数还包含 RDTSC 时间检测：

```c
__asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                 : "=r"(tsc_start) : : "rax", "rdx");
// ... scan() ...
__asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                 : "=r"(tsc_end) : : "rax", "rdx");

if (tsc_end - tsc_start > 1000000) {
    return -3;  // 单步调试检测
}
```

如果用 GDB 单步执行，两次 RDTSC 之间的差值会远超 1000000 cycles。解决方案：
- 使用硬件断点（DR0-DR3）代替软件断点，不修改内存
- 使用 `catch syscall` 代替断点
- 使用 GDB 的 `record` 模式

---

## 第三步：解密 Flag

### 加密数据分析

```
chunk1[8]  = {0x96, 0xEE, 0xEA, 0x98, 0xD6, 0xC7, 0xB1, 0xD8}
chunk2[8]  = {0xE1, 0xAD, 0x79, 0xD0, 0xE9, 0xF2, 0xDC, 0xAC}
chunk3[7]  = {0x9E, 0x8A, 0xB5, 0xF2, 0xD3, 0xED, 0xD0}
keybox[]   = {0xDE, 0xAD, 0xBE, 0xEF}
```

### 解密算法

每个 stage 的核心逻辑：

```c
// Stage 1: XOR with keybox[i % 3]
for (int i = 0; i < 8; i++)
    chunk1[i] ^= keybox[i % 3];

// Stage 2: XOR with keybox[(8 + i) % 3]
for (int i = 0; i < 8; i++)
    chunk2[i] ^= keybox[(8 + i) % 3];

// Stage 3: XOR with keybox[(16 + i) % 3]
for (int i = 0; i < 7; i++)
    chunk3[i] ^= keybox[(16 + i) % 3];
```

### 手动解密脚本

```python
keybox = [0xDE, 0xAD, 0xBE, 0xEF]

chunk1 = [0x96, 0xEE, 0xEA, 0x98, 0xD6, 0xC7, 0xB1, 0xD8]
chunk2 = [0xE1, 0xAD, 0x79, 0xD0, 0xE9, 0xF2, 0xDC, 0xAC]
chunk3 = [0x9E, 0x8A, 0xB5, 0xF2, 0xD3, 0xED, 0xD0]

# Stage 1
for i in range(8):
    chunk1[i] ^= keybox[i % 3]

# Stage 2
for i in range(8):
    chunk2[i] ^= keybox[(8 + i) % 3]

# Stage 3
for i in range(7):
    chunk3[i] ^= keybox[(16 + i) % 3]

flag = bytes(chunk1 + chunk2 + chunk3)
print(f"Flag: {flag.decode()}")
```

### 解密过程验证

以 chunk1 为例：

| i | chunk1[i] | keybox[i%3] | XOR 结果 | ASCII |
|---|-----------|-------------|---------|-------|
| 0 | 0x96 | 0xDE | 0x48 | H |
| 1 | 0xEE | 0xAD | 0x43 | C |
| 2 | 0xEA | 0xBE | 0x54 | T |
| 3 | 0x98 | 0xDE | 0x46 | F |
| 4 | 0xD6 | 0xAD | 0x7B | { |
| 5 | 0xC7 | 0xBE | 0x79 | y |
| 6 | 0xB1 | 0xDE | 0x6F | o |
| 7 | 0xD8 | 0xAD | 0x75 | u |

chunk1 解密为 `HCTF{you`。同理解密 chunk2 和 chunk3 得到 `c4n7_br34k_m3}`。

---

## 第四步：理解汇编混淆

程序使用了多层汇编混淆来增加逆向难度：

### 1. Opaque Predicates（不透明谓词）

```c
// 始终为真，但静态分析难以证明
volatile long _tmp = r + 1;
__asm__ volatile (
    "imul %0, %0\n\t"   // _tmp = (r+1)^2
    "shr $63, %0\n\t"   // 右移63位
    : "+r"(_tmp) : : "cc"
);
```

分析器无法证明 `x^2 >> 63` 的值，导致控制流图（CFG）中出现虚假分支。

### 2. RDTSC 反单步调试

```c
__asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                 : "=r"(tsc_start) : : "rax", "rdx");
// ... 被保护的代码 ...
__asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                 : "=r"(tsc_end) : : "rax", "rdx");

if (tsc_end - tsc_start > 1000000) return -3;
```

`RDTSC` 读取 CPU 时间戳计数器。单步调试时，两次 RDTSC 之间的差值会非常大。

### 3. 间接调用

```c
stage_fn stages[3] = { stage_1, stage_2, stage_3 };
for (int i = 0; i < 3; i++) {
    __asm__ volatile ("call *%0\n\t" : : "r"(stages[i]) : "memory");
}
```

通过函数指针表 + 内联汇编间接调用，IDA/Ghidra 的 CFG 恢复无法识别调用目标。

### 4. Dead Branch（死代码分支）

```c
#define DEAD_BRANCH(var) \
    do { \
        unsigned long _v = (unsigned long)(var); \
        __asm__ volatile ( \
            "bt $0, %0\n\t" \
            "jc 1f\n\t" \
            "1:\n\t" \
            : "+r"(_v) : : "cc" \
        ); \
    } while (0)
```

`bt` 测试某一位，`jc` 条件跳转。无论是否跳转，都到达 `1:` 标签。但反汇编器会将两条路径都显示为可达，增加分析复杂度。

---

## 第五步：解题总结

### 推荐解题路径

```
1. 运行程序，发现无输出 → 静态分析
2. 用 IDA/Ghidra 打开二进制
3. 识别 main() → stage_1/2/3 → guard_a/b/c → scan() 调用链
4. 在 .data 段找到 chunk1/2/3 和 keybox
5. 从 scan() 的 Rust 符号中理解扫描逻辑
6. 识别 XOR 解密 + 密钥滚动
7. 编写 Python 脚本解密
8. 注意 keybox[3]=0xEF 是干扰项，密钥只有前 3 字节
```

### 关键逆向点

| 要点 | 说明 |
|-----|------|
| `scan()` 的扫描目标 | 自身代码段的每个字节 |
| `0xCC` 的含义 | x86 int3 断点指令 |
| `__attribute__((noinline))` | 防止函数内联，保证 guard 函数有独立的代码段 |
| 密钥滚动 `i % 3` | 三字节密钥循环使用 |
| `keybox[3] = 0xEF` | DEADBEEF 红鲱鱼，不参与解密 |
| RDTSC 检测 | 防止单步调试，需要硬件断点或补丁绕过 |

---

## 附录：完整解密脚本

```python
#!/usr/bin/env python3
# intcc flag decryptor

keybox = [0xDE, 0xAD, 0xBE]  # 只取前3字节，0xEF 是红鲱鱼

c1 = [0x96, 0xEE, 0xEA, 0x98, 0xD6, 0xC7, 0xB1, 0xD8]
c2 = [0xE1, 0xAD, 0x79, 0xD0, 0xE9, 0xF2, 0xDC, 0xAC]
c3 = [0x9E, 0x8A, 0xB5, 0xF2, 0xD3, 0xED, 0xD0]

for i in range(8):
    c1[i] ^= keybox[i % 3]
for i in range(8):
    c2[i] ^= keybox[(8 + i) % 3]
for i in range(7):
    c3[i] ^= keybox[(16 + i) % 3]

flag = ''.join(chr(b) for b in c1 + c2 + c3)
print(f"Flag: {flag}")
```

输出：`Flag: HCTF{you_c4n7_br34k_m3}`
