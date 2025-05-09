# Rust OS 学习总结

从2024年10月开始，我在郭老师和陈老师的指导下开始系统学习 Rust 操作系统，到目前为止已有半年时间，现总结如下。

## 学习过程

学习主要分为 3 个阶段：Rust 语言学习阶段，操作系统训练营阶段和 Starry 实践阶段。

### Rust 语言学习阶段

2024年10月-11月，我参加了 Rust 学习赛。在此之前我对 Rust 的了解仅限于一些最基本的语法，没有用 Rust 写代码的经历。这次比赛于我而言是以赛促学，直接投入实践。我先是通过看训练营的课件和网上的一些资料，完成 rustlings 的练习，初步熟悉了 Rust 的语法和一些基本概念。然后参加比赛。初赛相对简单，只需要完成一些相对短的代码片段。复赛难度提高，特别是最后一题的内存分配器，我尝试了 c2rust 库，但由于需要一些改造才能适配，最终失败了。通过这一个多月的学习，我对 Rust 有了初步的了解。

### 操作系统训练营阶段

2024年11月-12月，我参加了操作系统训练营，学习了 rCore 的基本原理和实现和组件化操作系统的设计和实现，并且在项目阶段参加了对应用的支持。训练营的专业阶段和项目基础阶段中，我学习了如何从零开始实现一个 Rust 操作系统，以及在此之上拓展到 unikernel 和宏内核。我完成了这两个阶段的课后练习，加深对 Rust 和操作系统的理解。训练营的第四阶段中，我选择了在 new Starry 上支持 Python。经过一段时间的 debug 以及和同学的交流后，实现了在 new Starry 上运行最基本的 Python 测例。通过两个月的学习，我对 Rust 操作系统有了基本的认识，并且获得了一些实践的经验。

### Starry 实践阶段

2025年1月-4月，我参与了 starry-next 的开发。一开始是熟悉 starry-next 的代码结构，通过运行并尝试补充实现2024年操作系统比赛的测例来加深理解，在这个过程中我也参考了其他同学的一些实现。开学之后的工作转移到在四种硬件架构上通过2025年操作系统比赛的测例，比2024年的测例多了许多。我与大实验和本科毕设的同学一起开发。3月中旬之前主要专注于 basic 测例的实现，一开始2024年版本的 starry-next 可以通过所有的测例，但 2025 年版本代码改动，所以花了一些时间去适配。之后专注于 libc-test、busybox、lua、iozone 测例。除了硬件层面的问题，大多数测例实质上是要完成一些 syscall，以及可能对操作系统的一些组件的改动。一开始我主要负责若干个文件系统相关的 syscall 的实现，但随着开发的进展，涉及的 syscall 也不限于文件系统。在这个过程中我学习了许多其他同学的实现，也向主线提了一些 PR。4月底，我一直在尝试实现 iozone，目前定位到原先无法通过测试的原因是共享内存和 select（实际 iozone 调用 select 是为了 sleep）未实现，而目前粗糙的实现依然存在 iozone 会不断调用 select 陷入死循环的问题，有待进一步排查。

## 学习成效

Rust 学习方面，通过了训练营 rustlings 的所有练习，通过了 Rust 比赛的初赛所有题目和复赛除了最后一题之外的所有题目，获得优秀奖。

操作系统方面，完成了训练营的所有练习，为 starry-next 和 ArceOS 提了若干个 PR，最终能通过2025年操作系统比赛初赛的大部分测例。

## 问题和解决

第一是语言问题，一开始学习 Rust 的时候虽然过了一遍内容，但并没有完全理解，在后续开发的时候依然会遇到一些看不懂的报错，只能上网搜索。但是语言的学习确实也只能这样，在运用的过程中记忆。

第二是环境和开发方式问题，我尝试了许多不同的环境，包括 WSL、GitHub codespace、阿里云服务器、实验室服务器等，以及在其上的 Docker 环境。starry-next 的配环境确实有点麻烦，另一方面也是我自己对于容器环境的了解不够深入。最终我选择在实验室服务器上自己配环境，以及在 GitHub codespace 用其他同学写好的配置。

第三是开发过程中遇到的各式各样的操作系统的问题，也是我需要实现的地方，比如 glibc 的 tmpfile 函数依赖 fcntl 函数的 F_GETFL 参数，比如 fstatat 函数中 to_string 函数会在字符串后 padding，导致 utf-8 解析错误，比如 glibc 的 fstat 函数调用的是 fstatat 函数，而代码中在unlink 之后依然用文件名访问等等。这些问题都在我阅读代码和 man 手册后得到解决。具体问题和解决过程见 [starry-next 宏内核扩展实践记录](https://docs.qq.com/doc/DZHVReE11a1FCZFl4)。

## 下一步

2025年4月开始，我补充学习了操作系统训练营中之前没有学的虚拟化章节，并且通过阅读 axvisor 的代码和文档来进一步学习虚拟化。接下来我将参与到组件化虚拟机方面的实习研究工作中，从 riscv 入手，逐步延伸到 aarch。

# [starry-next 宏内核扩展实践记录](https://docs.qq.com/doc/DZHVReE11a1FCZFl4)

# 2024 秋冬季开源操作系统训练营学习记录

# rCore

## 应用程序与基本执行环境

### 应用程序执行环境与平台支持

**应用程序** --函数调用--> **标准库** --系统调用--> **内核/操作系统** --指令集--> **硬件平台**

Rust 有一个不需要任何操作系统支持的核心库 `core`， 它包含了 Rust 语言相当一部分核心机制。为了以裸机平台为目标编译程序，我们要将对标准库 `std` 的引用换成核心库 `core`。

### 移除标准库依赖

`#![no_std]` 告诉 Rust 编译器不使用 Rust 标准库 `std` 转而使用核心库 `core`。

`start` 语义项代表了标准库 `std` 在执行应用程序之前需要进行的一些初始化工作。

`#![no_main]` 告诉编译器：没有一般意义上的 `main` 函数。

### 构建用户态执行环境

入口函数 `_start()`

```rust
#[no_mangle]
extern "C" fn _start() {
    //
}
```

> QEMU 有两种运行模式：
>
> `User mode` 模式，即用户态模拟，如 `qemu-riscv64` 程序， 能够模拟不同处理器的用户态指令的执行，并可以直接解析ELF可执行文件， 加载运行那些为不同处理器编译的用户级 Linux 应用程序。
>
> `System mode` 模式，即系统态模式，如 `qemu-system-riscv64` 程序， 能够模拟一个完整的基于不同 CPU 的硬件系统，包括处理器、内存及其他外部设备，支持运行完整的操作系统。

直接执行空的 `_start()` 导致 segment fault，因为执行环境缺少退出机制，需要操作系统提供的 `exit` 系统调用来退出程序。

### 构建裸机执行环境

加载内核程序命令

```shell
qemu-system-riscv64 -machine virt -nographic -bios $(BOOTLOADER) -device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA)
```

`-bios $(BOOTLOADER)` 表示硬件加载了一个 BootLoader 程序，即 **RustSBI**。

`-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA)` 表示硬件内存中的特定位置 `$(KERNEL_ENTRY_PA)` 放置了操作系统的二进制代码 `$(KERNEL_BIN)` 。 `$(KERNEL_ENTRY_PA)` 的值是 `0x80200000`（内核入口物理地址）。

当我们执行包含上述启动参数的 qemu-system-riscv64 软件，就意味给这台虚拟的 RISC-V64 计算机加电了。 此时，CPU 的其它通用寄存器清零，而 **`PC` 会指向 `0x1000` 的位置**，这里有固化在硬件中的一小段引导代码， 它会很快**跳转到 `0x80000000` 的 RustSBI 处**。 **RustSBI 完成硬件初始化后，会跳转到 `$(KERNEL_BIN)` 所在内存位置 `0x80200000` 处， 执行操作系统的第一条指令**。

> SBI 是 RISC-V 的一种底层规范，RustSBI 是它的一种实现。 操作系统内核与 RustSBI 的关系有点像应用与操作系统内核的关系，后者向前者提供一定的服务。SBI 提供的服务很少， 比如关机，显示字符串等。

应用程序访问操作系统提供的系统调用的指令是 `ecall` ，操作系统访问 RustSBI 提供的 SBI 调用的指令也是 `ecall` ， 虽然指令一样，但它们所在的特权级是不一样的。 应用程序位于最弱的**用户**特权级， 操作系统位于**内核**特权级， RustSBI 位于**机器**特权级。 

通过 **链接脚本** 调整链接器的行为，使得最终生成的可执行文件的内存布局符合我们的预期。

初始化栈空间

```assembly
    .section .text.entry
    .globl _start
_start:                            # 操作系统的入口地址, 被放在 BASE_ADDRESS 处
    la sp, boot_stack_top          # 将 sp 设置为栈空间的栈顶
    call rust_main

    .section .bss.stack            # 栈空间名
    .globl boot_stack_lower_bound  # 栈底地址
boot_stack_lower_bound:
    .space 4096 * 16               # 栈空间大小
    .globl boot_stack_top
boot_stack_top:                    # 栈顶地址
```

`global_asm` 宏将同目录下的汇编文件 `entry.asm` 嵌入到代码中。

## 批处理系统

### 实现应用程序

目录结构

- `user/src/bin/*.rs` ：各个应用程序
- `user/src/*.rs` ：用户库（包括入口函数、初始化函数、I/O 函数和系统调用接口等）
- `user/src/linker.ld` ：应用程序的内存布局说明

`#[link_section = ".text.entry"]` 将 `_start` 函数编译后的汇编代码放在名为 `.text.entry` 的代码段中， 方便用户库链接脚本将它作为用户程序的入口。

使用`#[linkage = "weak"]`将`lib.rs` 中的 `main` 函数标志为弱链接。在最后链接的时候， 虽然 `lib.rs` 和 `bin` 目录下的某个应用程序中都有 `main` 符号， 但**由于 `lib.rs` 中的 `main` 符号是弱链接， 链接器会使用 `bin` 目录下的函数作为 `main`** 。 如果在 `bin` 目录下找不到任何 `main` ，那么编译也能通过，但会在运行时报错。

`ecall` 指令会触发名为 `Environment call from U-mode` 的异常， 并 Trap 进入 S 模式执行批处理系统针对这个异常特别提供的服务程序。

> RISC-V 寄存器编号从 `0~31` ，表示为 `x0~x31` 。 其中： - `x10~x17` : 对应 `a0~a7` - `x1` ：对应 `ra`

寄存器 `a0~a6` （`x10~x16`）保存系统调用的参数， `a0` （`x10`）保存系统调用的返回值， 寄存器 `a7`（`x17`） 用来传递 syscall ID。

```rust
pub fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("x10") args[0] => ret,
            in("x11") args[1],
            in("x12") args[2],
            in("x17") id
        );
    }
    ret
}
```

所有的**系统调用**（如`sys_exit()`）只需包装 `syscall()`，**系统调用**进一步在用户库中封装为标准库（如`exit()`）。

应用程序的构建：

1. 对于 `src/bin` 下的每个应用程序， 在 `target/riscv64gc-unknown-none-elf/release` 目录下生成一个同名的 ELF 可执行文件；
2. 使用 objcopy **删除所有 ELF header 和符号**，得到 `.bin` 后缀的**纯二进制镜像文件**。它们将被链接进内核，并由内核在合适的时机加载到内存。

### 实现批处理操作系统

用 `core::arch::global_asm!(include_str!("link_app.S"))` 引入汇编代码 `link_app.S`

```assembly

    .align 3
    .section .data
    .global _num_app                                  # 64 位整数数组
_num_app:
    .quad 7                                           # 应用程序的数量
    .quad app_0_start                                 # 按照顺序放置每个应用程序的起始地址
    .quad app_1_start
    .quad app_2_start
    .quad app_3_start
    .quad app_4_start
    .quad app_5_start
    .quad app_6_start
    .quad app_6_end                                   # 最后一个应用程序的结束位置

# 省略

    .section .data
    .global app_3_start
    .global app_3_end
app_3_start:                                          # 开始位置
    .incbin "../user/build/bin/ch2b_hello_world.bin"
app_3_end:                                            # 结束位置

# 省略
```

应用管理器 `AppManager` 初始化：找到 `link_app.S` 中提供的符号 `_num_app` ，并从这里开始解析出应用数量以及各个应用的开头地址。用容器 `UPSafeCell` 包裹 `AppManager` 防止全局对象 `APP_MANAGER` 被重复获取。

`lazy_static!` 宏提供了全局变量的运行时初始化功能。一般情况下，全局变量必须在编译期设置初始值，但是**有些全局变量的初始化依赖于运行期间才能得到的数据**。这里借助 `lazy_static!` 声明了一个 `AppManager` 结构的名为 `APP_MANAGER` 的全局实例， 只有在它第一次被使用到的时候才会进行实际的初始化工作。

```rust
const APP_BASE_ADDRESS: usize = 0x80400000;
const APP_SIZE_LIMIT: usize = 0x20000;

unsafe fn load_app(&self, app_id: usize) {
    if app_id >= self.num_app {
        println!("All applications completed!");
        use crate::board::QEMUExit;
        crate::board::QEMU_EXIT_HANDLE.exit_success();
    }
    core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, APP_SIZE_LIMIT).fill(0); // 清空以 0x80400000 起始的一块内存
    let app_src = core::slice::from_raw_parts( // 应用程序的二进制镜像, 从 app_start[app_id] 开始, 长 app_start[app_id + 1] - app_start[app_id]
        self.app_start[app_id] as *const u8,
        self.app_start[app_id + 1] - self.app_start[app_id],
    );
    let app_dst = core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, app_src.len());
    app_dst.copy_from_slice(app_src); // 复制到 0x80400000
    asm!("fence.i"); // 清理 i-cache
}
```

这里会修改会被 CPU 取指的内存区域，使得 i-cache 中含有与内存不一致的内容， 必须使用 `fence.i` 指令手动清空 i-cache ，让里面所有的内容全部失效， 才能够保证程序执行正确性。

`batch` 子模块对外暴露出如下接口：

- `init` ：调用 `print_app_info` 的时第一次用到了全局变量 `APP_MANAGER` ，它在这时完成初始化；
- `run_next_app` ：加载并运行下一个应用程序。 批处理操作系统完成初始化，或者应用程序运行结束/出错后会调用该函数。

### 实现特权级的切换

当 CPU 执行完一条指令并准备从用户特权级陷入（ `Trap` ）到 S 特权级的时候，硬件会自动完成如下这些事情：

- `sstatus` 的 `SPP` 字段会被修改为 **CPU 当前的特权级**（U/S）。
- `sepc` 会被修改为 Trap 处理完成后默认会执行的**下一条指令的地址**。
- `scause/stval` 分别会被修改成这次 Trap 的原因以及相关的附加信息。
- CPU 会跳转到 `stvec` 所设置的 **Trap 处理入口地址**，并将**当前特权级设置为 S** ，然后从 Trap 处理入口地址处开始执行。

> 在 RV64 中， `stvec` 是一个 64 位的 CSR，在中断使能的情况下，保存了**中断处理的入口地址**。它有两个字段：
>
> - `MODE` 位于 `[1:0]`，长度为 2 bits；
> - `BASE` 位于 `[63:2]`，长度为 62 bits。
>
> 当 `MODE` 字段为 0 的时候， `stvec` 被设置为 Direct 模式，此时进入 S 模式的 Trap 无论原因如何，处理 Trap 的入口地址都是 `BASE << 2` ， CPU 会跳转到这个地方进行异常处理。

当 CPU 完成 Trap 处理准备返回的时候，需要通过一条 S 特权级的特权指令 `sret` 来完成：

- CPU 会将当前的特权级**按照 `sstatus` 的 `SPP` 字段设置为 U 或者 S** ；
- CPU 会跳转到 **`sepc` 寄存器指向的那条指令**，然后继续执行。

在 Trap 触发的一瞬间， CPU 会切换到 S 特权级并跳转到 `stvec` 所指示的位置。在正式进入 S 特权级的 Trap 处理之前，我们必须**保存原控制流的寄存器状态**到**内核栈**。

`TrapContext` 在 Trap 发生时需要保存的物理资源内容。

对于**通用寄存器**而言，两条控制流（**应用程序**控制流和**内核**控制流）**运行在不同的特权级**，所属的软件也可能由不同的编程语言编写，虽然在 Trap 控制流中只是会执行 Trap 处理相关的代码，但依然可能直接或间接调用很多模块，因此很难甚至不可能找出哪些寄存器无需保存。所以只能**全部保存**了。

对于 **CSR** 而言，进入 Trap 的时候，硬件会立即覆盖掉 `scause/stval/sstatus/sepc` 的全部或其中一部分。`scause/stval` 总是在 Trap 处理的第一时间就被使用或者是在其他地方保存下来了，因此它**没有被修改并造成不良影响的风险**。 而 `sstatus/sepc` 会**在 Trap 处理的全程有意义**（在 Trap 控制流最后 `sret` 的时候还用到了它们），而且确实会出现 **Trap 嵌套**的情况使得**它们的值被覆盖掉**。所以我们需要将它们也一起保存下来，并在 `sret` 之前恢复原样。

```rust
global_asm!(include_str!("trap.S"));

pub fn init() {
    extern "C" {
        fn __alltraps();
    }
    unsafe {
        stvec::write(__alltraps as usize, TrapMode::Direct); // 将 stvec 设置为 Direct 模式指向外部符号 __alltraps 的地址
    }
}
```

引入了一个外部符号 `__alltraps` ，并将 `stvec` 设置为 Direct 模式指向它的地址。

在 `os/src/trap/trap.S` 中实现 Trap 上下文保存/恢复的汇编代码，分别用外部符号 `__alltraps` 和 `__restore` 标记为函数，并通过 `global_asm!` 宏将 `trap.S` 这段汇编代码插入进来。

Trap 处理的总体流程：通过 `__alltraps` 将 Trap 上下文保存在内核栈上，然后跳转到 `trap_handler` 函数完成 Trap 分发及处理。当 `trap_handler` 返回之后，使用 `__restore` 从保存在内核栈上的 Trap 上下文恢复寄存器。最后通过一条 `sret` 指令回到应用程序执行。

```assembly
.macro SAVE_GP n
    sd x\n, \n*8(sp)
.endm

.align 2 # 将 __alltraps 的地址 4 字节对齐
__alltraps:
    csrrw sp, sscratch, sp # 将 CSR 的值读到 sp 中，然后将 sp 的值写入该 CSR, 即交换 sscratch 和 sp
    # 现在 sp->内核栈, sscratch->用户栈
    # 在内核栈上分配一个 TrapContext
    addi sp, sp, -34*8 # 预先分配 34 * 8 字节的栈帧
    # 保存通用寄存器
    sd x1, 1*8(sp)
    # 跳过 sp(x2), 之后再保存
    sd x3, 3*8(sp)
    # 跳过 tp(x4), 应用不会用到
    # 保存 x5~x31
    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr
    # 可以自由使用 t0/t1/t2, 因为已经保存到内核栈了
    csrr t0, sstatus # 将 sstatus 的值读到 t0 中
    csrr t1, sepc # 将 sepc 的值读到 t1 中
    sd t0, 32*8(sp) # 保存 sstatus
    sd t1, 33*8(sp) # 保存 sepc
    # read user stack from sscratch and save it on the 内核栈
    csrr t2, sscratch # 将 sscratch 的值读到 t2
    sd t2, 2*8(sp) # 保存 sscratch
    # 设置 trap_handler 的入参(cx: &mut TrapContext)
    mv a0, sp
    call trap_handler
```

```assembly
.macro LOAD_GP n
    ld x\n, \n*8(sp)
.endm

__restore:
    # case1: start running app by __restore
    # case2: back to U after handling trap
    mv sp, a0 # ???
    # 现在 sp->内核栈(分配后的), sscratch->用户栈
    # 恢复 sstatus/sepc
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    # 恢复通用寄存器, 除了 sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # 释放内核栈上的 TrapContext 内存
    addi sp, sp, 34*8
    csrrw sp, sscratch, sp # 交换 sscratch 和 sp
    # 现在 sp->内核栈, sscratch->用户栈
    sret # 回到 U 特权级, 继续运行应用程序控制流
```

Trap 分发与处理

```rust
#[no_mangle]
pub fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
    let scause = scause::read(); // get trap cause
    let stval = stval::read(); // get extra value
    match scause.cause() { // 根据 scause 寄存器所保存的 Trap 的原因进行分发处理
        Trap::Exception(Exception::UserEnvCall) => { // 触发 Trap 的原因是来自 U 特权级的 Environment Call，即系统调用
            cx.sepc += 4; // ecall 的下一条指令地址, 即返回地址
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize; // 系统调用
        }
        Trap::Exception(Exception::StoreFault) | Trap::Exception(Exception::StorePageFault) => { // 访存错误
            println!("[kernel] PageFault in application, kernel killed it.");
            run_next_app();
        }
        Trap::Exception(Exception::IllegalInstruction) => { // 非法指令错误
            println!("[kernel] IllegalInstruction in application, kernel killed it.");
            run_next_app();
        }
        _ => { // 目前还不支持的 Trap 类型
            panic!(
                "Unsupported trap {:?}, stval = {:#x}!",
                scause.cause(),
                stval
            );
        }
    }
    cx // __restore 时在调用 trap_handler 前后 a0 并没有发生变化，仍然指向分配 Trap 上下文之后的内核栈栈顶，和此时 sp 的值相同，sp <- a0 并不会有问题
}
```

在运行应用程序之前要完成如下这些工作：

- 跳转到应用程序入口点 `0x80400000`；
- 将使用的栈切换到**用户栈**；
- `sscratch` 指向内核栈；
- 从 S 特权级切换到 U 特权级。

可以通过**复用 `__restore` 的代码**来实现。只需要在内核栈上压入一个**为启动应用程序而特殊构造的 Trap 上下文**，再通过 `__restore` 函数，就能让这些寄存器到达启动应用程序所需要的上下文状态。

```rust
impl TrapContext {
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    pub fn app_init_context(entry: usize, sp: usize) -> Self {
        let mut sstatus = sstatus::read(); // CSR sstatus
        sstatus.set_spp(SPP::User); // 将 sstatus 的 SPP 字段设置为 User
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry, // 修改 sepc 为应用程序入口点 entry
        };
        cx.set_sp(sp); // 修改 sp 寄存器为我们设定的一个栈指针
        cx // 返回原来的应用 trap 上下文
    }
}
```

```rust
pub fn run_next_app() -> ! {
    let mut app_manager = APP_MANAGER.exclusive_access();
    let current_app = app_manager.get_current_app();
    unsafe {
        app_manager.load_app(current_app);
    }
    app_manager.move_to_next_app();
    drop(app_manager);
    // 在此之前必须手动丢弃和资源相关的局部变量并释放资源
    extern "C" {
        fn __restore(cx_addr: usize);
    }
    unsafe { // 在内核栈上压入一个 Trap 上下文
        __restore(KERNEL_STACK.push_context(TrapContext::app_init_context(
            APP_BASE_ADDRESS, // sepc 是应用程序入口地址 0x80400000
            USER_STACK.get_sp(), // sp 指向用户栈
        )) as *const _ as usize);
    }
    panic!("Unreachable in batch::run_current_app!");
}
```

## 多道程序与分时多任务

### 多道程序放置与加载

要一次加载运行多个程序，就要求**每个用户程序被内核加载到内存中的起始地址都不同**。对于每一个应用程序，使用 `cargo rustc` 单独编译， 用 `-Clink-args=-Ttext=xxxx` 选项指定链接时 `.text` 段的地址为 `0x80400000 + app_id * 0x20000` 。

```rust
pub fn load_apps() {
    extern "C" {
        fn _num_app();
    }
    let num_app_ptr = _num_app as usize as *const usize;
    let num_app = get_num_app();
    let app_start = unsafe { core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1) };
    unsafe {
        asm!("fence.i"); // 清除指令缓存
    }
    for i in 0..num_app { // 加载应用
        let base_i = get_base_i(i); // 0x80400000 + i * 0x20000
        (base_i..base_i + APP_SIZE_LIMIT).for_each(|addr| unsafe { (addr as *mut u8).write_volatile(0) }); // 清除内存
        let src = unsafe {
            core::slice::from_raw_parts(app_start[i] as *const u8, app_start[i + 1] - app_start[i])
        };
        let dst = unsafe { core::slice::from_raw_parts_mut(base_i as *mut u8, src.len()) };
        dst.copy_from_slice(src); // 把应用从数据段加载到内存
    }
}
```

### 任务切换

- 与 Trap 切换不同，任务切换**不涉及特权级切**换，部分由编译器完成；
- 与 Trap 切换相同，任务切换**对应用是透明的**。

任务切换是**来自两个不同应用在内核中的 Trap 控制流**之间的切换。 当一个应用 Trap 到 S 态 OS 内核中进行进一步处理时， 其 Trap 控制流可以调用一个特殊的 `__switch` 函数。 在 `__switch` 返回之后，Trap 控制流将继续从调用该函数的位置继续向下执行。 而在调用 `__switch` 之后到返回前的这段时间里， 原 Trap 控制流 `A` 会先被暂停并被切换出去， CPU 转而运行另一个应用的 Trap 控制流 `B` 。 `__switch` 返回之后，原 Trap 控制流 `A` 才会从某一条 Trap 控制流 `C` 切换回来继续执行。

`__switch` 的实现：先把 `current_task_cx_ptr` 中包含的寄存器值逐个保存，再把 `next_task_cx_ptr` 中包含的寄存器值逐个恢复。

```assembly
.altmacro
.macro SAVE_SN n
    sd s\n, (\n+2)*8(a0)
.endm
.macro LOAD_SN n
    ld s\n, (\n+2)*8(a1)
.endm
    .section .text
    .globl __switch
__switch:
    # __switch(
    #     current_task_cx_ptr: *mut TaskContext,
    #     next_task_cx_ptr: *const TaskContext
    # )
    # 保存当前任务的内核栈
    sd sp, 8(a0) # a0 是当前任务上下文指针
    # 保存当前执行的 ra & s0~s11
    sd ra, 0(a0)
    .set n, 0
    .rept 12
        SAVE_SN %n
        .set n, n + 1
    .endr
    # 恢复下一个执行的 ra & s0~s11
    ld ra, 0(a1) # a1 是下一个任务上下文指针
    .set n, 0
    .rept 12
        LOAD_SN %n
        .set n, n + 1
    .endr
    # 恢复下一个任务的内核栈
    ld sp, 8(a1)
    ret
```

### 管理多道程序

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/multiprogramming.png" alt="../_images/multiprogramming.png" style="zoom:50%;" />

开始时，蓝色应用向外设提交了一个请求，外设随即开始工作， 但是它要一段时间后才能返回结果。蓝色应用于是调用 `sys_yield` **交出 CPU 使用权**， 内核让绿色应用继续执行。一段时间后 CPU 切换回蓝色应用，发现外设仍未返回结果， 于是再次 `sys_yield` 。直到第二次切换回蓝色应用，外设才处理完请求，于是蓝色应用终于可以向下执行了。

初始化 `TaskManager` 的全局实例 `TASK_MANAGER`：

```rust
pub fn init_app_cx(app_id: usize) -> usize { // 向内核栈压入一个 Trap 上下文
    KERNEL_STACK[app_id].push_context(TrapContext::app_init_context(
        get_base_i(app_id),
        USER_STACK[app_id].get_sp(),
    )) // 返回压入 Trap 上下文后 sp 的值
}

pub fn goto_restore(kstack_ptr: usize) -> Self {
    extern "C" {
        fn __restore();
    }
    Self {
        ra: __restore as usize, // 将 ra 设置为 __restore 的入口地址
        sp: kstack_ptr,
        s: [0; 12],
    }
}

lazy_static! {
    pub static ref TASK_MANAGER: TaskManager = {
        let num_app = get_num_app(); // 链接到内核的应用总数
        let mut tasks = [TaskControlBlock {
            task_cx: TaskContext::zero_init(),
            task_status: TaskStatus::UnInit,
        }; MAX_APP_NUM];
        for (i, task) in tasks.iter_mut().enumerate() {
            task.task_cx = TaskContext::goto_restore(init_app_cx(i));
            task.task_status = TaskStatus::Ready; // 运行状态设置为 Ready
        }
        TaskManager {
            num_app,
            inner: unsafe {
                UPSafeCell::new(TaskManagerInner {
                    tasks,
                    current_task: 0,
                })
            },
        }
    };
}
```

`task::run_first_task` 执行第一个应用

```rust
fn run_first_task(&self) -> ! {
    let mut inner = self.inner.exclusive_access();
    let task0 = &mut inner.tasks[0];
    task0.task_status = TaskStatus::Running;
    let next_task_cx_ptr = &task0.task_cx as *const TaskContext;
    drop(inner);
    let mut _unused = TaskContext::zero_init(); // 空的任务上下文, 声明 _unused 是为了避免其他数据被覆盖
    // before this, we should drop local variables that must be dropped manually
    unsafe { // 将 _unused 的地址作为第1个参数传给 __switch
        __switch(&mut _unused as *mut TaskContext, next_task_cx_ptr);
    }
    panic!("unreachable in run_first_task!");
}
```

### 分时多任务系统

RISC-V 要求处理器维护时钟计数器 `mtime`，还有另外一个 CSR `mtimecmp` 。 **一旦计数器 `mtime` 的值超过了 `mtimecmp`，就会触发一次时钟中断**。

```rust
const CLOCK_FREQ: usize = 12500000; // 时钟频率（Hz）
const TICKS_PER_SEC: usize = 100; // 每秒 tick 次数

pub fn set_next_trigger() {
    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC); // 在 10 ms 后设置时钟中断
}
```

默认情况下，当 Trap 进入某个特权级之后，在 Trap 处理的过程中**同特权级的中断都会被屏蔽**。

- 当 Trap 发生时，`sstatus.sie` 会被保存在 `sstatus.spie` 字段中，同时 `sstatus.sie` 置零， 在 Trap 处理的过程中屏蔽了所有 S 特权级的中断；
- 当 Trap 处理完毕 `sret` 的时候， `sstatus.sie` 会恢复到 `sstatus.spie` 内的值。

所以，如果不去手动设置 `sstatus` CSR ，在只考虑 S 特权级中断的情况下，是**不会出现嵌套中断**的。

> **嵌套中断**可以分为两部分：在处理一个中断的过程中又被**同**特权级/**高**特权级中断所打断。默认情况下硬件会避免前一部分，也可以通过手动设置来允许前一部分的存在；而后一部分则是无论如何设置都不可避免的。
>
> **嵌套 Trap** 是指处理一个 Trap 过程中又再次发生 Trap ，嵌套中断算是**嵌套 Trap** 的一种。

为了避免 S 特权级时钟中断被屏蔽，需要在执行第一个应用前调用 `enable_timer_interrupt()` 设置 `sie.stie`， 使得 S 特权级时钟中断不会被屏蔽；再设置第一个 10ms 的计时器。

## 地址空间

### 实现 SV39 多级页表机制

**默认情况下 MMU 不启用**，无论 CPU 处于哪个特权级，访存的地址都将直接被视作物理地址。 可以通过**修改 S 特权级的 `satp` CSR** 来启用分页模式，此后 S 和 U 特权级的访存地址会被视为虚拟地址，经过 MMU 的地址转换获得对应物理地址，再通过它来访问物理内存。

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/satp.png" alt="../_images/satp.png" style="zoom:50%;" />

RV64 架构下 `satp` 的字段分布。当 `MODE` 设置为 0 的时候，所有访存都被视为**物理地址**；而设置为 8 时，SV39 分页机制被启用，所有 S/U 特权级的访存被视为一个 **39 位的虚拟地址**，MMU 会将其转换成 **56 位的物理地址**；如果转换失败，则会触发异常。

> 在启用 SV39 分页模式下，只有低 39 位是真正有意义的。 SV39 分页模式规定 **64 位虚拟地址的 `[63:39]` 这 25 位必须和第 38 位相同**，否则 MMU 会直接认定它是一个不合法的虚拟地址。

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/sv39-pte.png" alt="../_images/sv39-pte.png" style="zoom:50%;" />

SV39 分页模式下的页表项，`[53:10]` 这 44 位是物理页号，最低的 8 位 `[7:0]` 是标志位，它们的含义如下：

- 仅当 `V`(Valid) 位为 1 时，页表项才是合法的；
- `R`/`W`/`X` 分别控制索引到这个页表项的对应虚拟页面是否允许读/写/取指；
- `U` 控制索引到这个页表项的对应**虚拟页面在 CPU 处于 U 特权级的情况下是否被允许访问**；
- `A`(Accessed) 记录自从页表项上的这一位被清零之后，页表项的对应虚拟页面是否被访问过；
- `D`(Dirty) 则记录自从页表项上的这一位被清零之后，页表项的对应虚拟页表是否被修改过。

物理内存的起始物理地址为 `0x80000000` ，物理内存的终止物理地址为 `0x80800000`，所以可用内存大小为 8 MiB。

栈式物理页帧管理策略 `StackFrameAllocator`

```rust
pub struct StackFrameAllocator {
    current: usize, // 物理页号区间 [current, end) 此前均从未被分配
    end: usize,
    recycled: Vec<usize>, // 栈式保存被回收的物理页号
}
```

物理页帧分配和回收

```rust
impl FrameAllocator for StackFrameAllocator {
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            Some(ppn.into()) // 栈 recycled 内有之前回收的物理页号
        } else if self.current == self.end {
            None // 空间耗尽
        } else {
            self.current += 1; // 分配新页号
            Some((self.current - 1).into())
        }
    }
    fn dealloc(&mut self, ppn: PhysPageNum) {
        let ppn = ppn.0;
        if ppn >= self.current || self.recycled.iter().any(|&v| v == ppn) { // 检查有效性
            panic!("Frame ppn={:#x} has not been allocated!", ppn);
        }
        self.recycled.push(ppn);
    }
}
```

物理页号 `PhysPageNum` 包装为 `FrameTracker`。

`PageTable` 要保存它根节点的物理页号 `root_ppn` 作为**页表唯一的区分标志**。向量 `frames` 以 `FrameTracker` 的形式保存了**页表所有的节点（包括根节点）所在的物理页帧**。

每个**节点**都被保存在一个**物理页帧**中，在多级页表的架构中，我们以一个节点被存放在的物理页帧的**物理页号作为指针**指向该节点，对于每个节点来说，一旦我们知道了指向它的物理页号，我们就能够修改这个节点的内容。

这就需要**提前扩充多级页表维护的映射**，使得**对于每一个对应于某一特定物理页帧的物理页号 `ppn` ，均存在一个虚拟页号 `vpn` 能够映射到它**，而且要能够较为简单的针对一个 `ppn` 找到某一个能映射到它的 `vpn` 。采用最简单的**恒等映射**，**对于物理内存上的每个物理页帧，都在多级页表中用一个与其物理页号相等的虚拟页号映射到它**。

```rust
fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
    let idxs = vpn.indexes();
    let mut ppn = self.root_ppn;
    let mut result: Option<&mut PageTableEntry> = None;
    for (i, idx) in idxs.iter().enumerate() {
        let pte = &mut ppn.get_pte_array()[*idx]; // 页表项
        if i == 2 {
            result = Some(pte);
            break;
        }
        if !pte.is_valid() {
            let frame = frame_alloc().unwrap();
            *pte = PageTableEntry::new(frame.ppn, PTEFlags::V); // 新建页表项
            self.frames.push(frame);
        }
        ppn = pte.ppn();
    }
    result
}
```

### 内核与应用的地址空间

逻辑段：地址区间中的一段**实际可用**（即 MMU 通过查多级页表可以正确完成地址转换）的地址连续的**虚拟地址区间**，该区间内包含的所有虚拟页面都以一种相同的方式映射到物理页帧，具有可读/可写/可执行等属性。

当逻辑段采用 `MapType::Framed` 方式映射到物理内存的时候， `data_frames` 是一个保存了该逻辑段内的每个**虚拟页面**和它被映射到的**物理页帧** `FrameTracker` 的一个键值对容器 `BTreeMap`，这些物理页帧被用来存放**实际内存数据**而不是作为多级页表中的中间节点。

地址空间是一系列有关联的逻辑段，这种关联一般是指**这些逻辑段属于一个运行的程序**。 用来表明正在运行的应用所在执行环境中的可访问内存空间，在这个内存空间中，包含了一系列的**不一定连续的逻辑段**。 

```rust
pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
    let ppn: PhysPageNum;
    match self.map_type {
        MapType::Identical => {
            ppn = PhysPageNum(vpn.0); // 恒等映射, 物理页号 == 虚拟页号
        }
        MapType::Framed => {
            let frame = frame_alloc().unwrap(); // 分配一个物理页帧
            ppn = frame.ppn;
            self.data_frames.insert(vpn, frame);
        }
    }
    let pte_flags = PTEFlags::from_bits(self.map_perm.bits).unwrap();
    page_table.map(vpn, ppn, pte_flags);
}
```

启用分页模式下，内核代码的访存地址也会被视为一个虚拟地址并需要经过 MMU 的地址转换，因此需要为内核对应构造一个地址空间，它除了仍然需要允许内核的各数据段能够被正常访问之后，还需要包含**所有应用的内核栈**以及一个**跳板** (Trampoline) 。

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/kernel-as-high.png" alt="../_images/kernel-as-high.png" style="zoom:50%;" />

64 位地址空间在 SV39 分页模式下实际可能通过 MMU 检查的**最高** 256 GiB。跳板放在**最高**的一个虚拟页面中。接下来则是从高到低放置每个应用的内核栈，内核栈的大小由 `config` 子模块的 `KERNEL_STACK_SIZE` 给出。它们的映射方式为 `MapPermission` 中的 `rw` 两个标志位，这个逻辑段**仅允许 CPU 处于内核态访问，且只能读或写**。

两个内核栈之间会预留一个 **保护页面** (Guard Page) ，它是内核地址空间中的空洞，**多级页表中并不存在与它相关的映射**。 它的意义在于当**内核栈空间不足**（如调用层数过多或死递归）的时候，**代码会尝试访问 空洞区域内的虚拟地址，然而它无法在多级页表中找到映射，便会触发异常**，此时控制权会交给 trap handler 对这种情况进行处理。由于编译器会对访存顺序和局部变量在栈帧中的位置进行优化，我们难以确定一个已经溢出的栈帧中的哪些位置会先被访问， 但总的来说，空洞区域被设置的越大，我们就能越早捕获到这一错误并避免它覆盖其他重要数据。由于我们的内核非常简单且内核栈 的大小设置比较宽裕，在当前的设计中我们仅将空洞区域的大小设置为单个页面。

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/kernel-as-low.png" alt="../_images/kernel-as-low.png" style="zoom:50%;" />

内核地址空间的低 256 GiB 的布局。四个逻辑段 `.text/.rodata/.data/.bss` 被恒等映射到物理内存，这使得我们在无需调整内核内存布局 `os/src/linker.ld` 的情况下就仍能和启用页表机制之前那样访问内核的各数据段。

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/app-as-full.png" alt="../_images/app-as-full.png" style="zoom:50%;" />

应用地址空间最低 256 GiB 的布局：从 `0x0` 开始向高地址放置应用内存布局中的各个逻辑段，最后放置带有一个保护页面的用户栈。这些逻辑段都是以 `Framed` 方式映射到物理内存的，从访问方式上来说都加上了 `U` 标志位代表 CPU 可以在 U 特权级也就是执行应用代码的时候访问它们。

应用地址空间最高的 256 GiB，和内核地址空间一样将跳板放置在最高页，还将 **Trap 上下文**放置在次高页中。这两个虚拟页面虽然位于应用地址空间， 但是它们并不包含 `U` 标志位，在地址空间切换的时候才会发挥作用。

```rust
pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize) {
    let mut memory_set = Self::new_bare();
    memory_set.map_trampoline(); // 将跳板插入到应用地址空间
    // map program headers of elf, with U flag
    let elf = xmas_elf::ElfFile::new(elf_data).unwrap(); // 解析传入的应用 ELF 数据并取出各个部分
    let elf_header = elf.header;
    let magic = elf_header.pt1.magic;
    assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!"); // 取出 ELF 的魔数来判断它是不是一个合法的 ELF
    let ph_count = elf_header.pt2.ph_count(); // program header 的数目
    let mut max_end_vpn = VirtPageNum(0);
    for i in 0..ph_count { // 遍历所有的 program header 并将合适的区域加入到应用地址空间中
        let ph = elf.program_header(i).unwrap();
        if ph.get_type().unwrap() == xmas_elf::program::Type::Load { // 确认 program header 的类型是 LOAD: 有被内核加载的必要
            let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
            let end_va: VirtAddr = ((ph.virtual_addr() + ph.mem_size()) as usize).into();
            let mut map_perm = MapPermission::U;
            let ph_flags = ph.flags();
            if ph_flags.is_read() {
                map_perm |= MapPermission::R;
            }
            if ph_flags.is_write() {
                map_perm |= MapPermission::W;
            }
            if ph_flags.is_execute() {
                map_perm |= MapPermission::X;
            }
            let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
            max_end_vpn = map_area.vpn_range.get_end();
            memory_set.push(
                map_area,
                Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
            );
        }
    }
    let max_end_va: VirtAddr = max_end_vpn.into();
    let mut user_stack_bottom: usize = max_end_va.into();
    user_stack_bottom += PAGE_SIZE;
    let user_stack_top = user_stack_bottom + USER_STACK_SIZE;
    memory_set.push( // 映射用户栈
        MapArea::new(
            user_stack_bottom.into(),
            user_stack_top.into(),
            MapType::Framed,
            MapPermission::R | MapPermission::W | MapPermission::U,
        ),
        None,
    );
    memory_set.push( // 映射堆
        MapArea::new(
            user_stack_top.into(),
            user_stack_top.into(),
            MapType::Framed,
            MapPermission::R | MapPermission::W | MapPermission::U,
        ),
        None,
    );
    memory_set.push( // 映射 Trap 上下文
        MapArea::new(
            TRAP_CONTEXT_BASE.into(),
            TRAMPOLINE.into(),
            MapType::Framed,
            MapPermission::R | MapPermission::W,
        ),
        None,
    );
    (
        memory_set, // 应用地址空间
        user_stack_top, // 用户栈虚拟地址
        elf.header.pt2.entry_point() as usize, // 解析 ELF 得到的该应用入口点地址
    )
}
```

### 基于地址空间的分时多任务

从直接访问物理内存到**虚拟地址转换**，这两种模式之间的过渡在**内核初始化**期间完成。

内存管理子系统的初始化

```rust
pub fn init() {
    heap_allocator::init_heap(); // 全局动态内存分配器的初始化
    frame_allocator::init_frame_allocator(); // 初始化物理页帧管理器
    KERNEL_SPACE.exclusive_access().activate(); // 创建内核地址空间并让 CPU 开启分页模式
}

pub fn init_heap() {
    unsafe {
        HEAP_ALLOCATOR.lock().init(HEAP_SPACE.as_ptr() as usize, KERNEL_HEAP_SIZE);
    }
}

pub fn init_frame_allocator() {
    extern "C" {
        fn ekernel();
    }
    FRAME_ALLOCATOR.exclusive_access().init(
        PhysAddr::from(ekernel as usize).ceil(),
        PhysAddr::from(MEMORY_END).floor(),
    );
}

pub fn activate(&self) {
    let satp = self.page_table.token();
    unsafe {
        satp::write(satp); // 将这个值写入当前 CPU 的 satp CSR
        // SV39 分页模式已启用
        asm!("sfence.vma"); // 清空 TLB
    }
}

pub fn token(&self) -> usize { // 按照 satp CSR 格式要求构造一个 u64，使得其分页模式为 SV39，且将当前多级页表的根节点所在的物理页号填充进去
    8usize << 60 | self.root_ppn.0
}
```

我们必须注意切换 satp CSR 是否是一个**平滑**的过渡：切换 satp 的指令和下一条指令的**虚拟地址是相邻的**（由于切换 satp 的指令并不是一条跳转指令， pc 只是简单的自增当前指令的字长），而它们所在的**物理地址一般情况下也是相邻的**，但是它们所经过的**地址转换流程却是不同的**——切换 satp 导致 MMU 查的多级页表是不同的。这就要求前后两个地址空间在切换 satp 的指令**附近**的映射满足某种意义上的连续性。这条写入 satp 的指令及其下一条指令都在内核内存布局的代码段中，在**切换之后是一个恒等映射**，而在**切换之前是视为物理地址直接取指**，也可以将其看成一个恒等映射。

**无论是内核还是应用的地址空间，最高的虚拟页面都是一个跳板**。同时应用地址空间的次高虚拟页面还被设置为用来存放应用的 Trap 上下文。那么跳板究竟起什么作用呢？为何不直接把 Trap 上下文仍放到应用的内核栈中呢？

当一个应用 Trap 到内核的时候， `sscratch` 指出了该应用内核栈的栈顶，我们用一条指令即可**从用户栈切换到内核栈**，然后直接将 Trap 上下文压入内核栈栈顶。当 Trap 处理完毕返回用户态的时候，将 Trap 上下文中的内容恢复到寄存器上，最后将保存着应用用户栈顶的 `sscratch` 与 `sp` 进行交换，**从内核栈切换回用户栈**。`sscratch` 使得在不破坏任何通用寄存器的情况下完成**用户栈和内核栈顶的 Trap 上下文这两个工作区域之间的切换**。

然而，一旦启用了分页机制，我们必须在这个过程中同时完成地址空间的切换。 当 `__alltraps` 保存 Trap 上下文的时候，我们必须通过修改 satp 从应用地址空间切换到内核地址空间，因为 **trap handler 只有在内核地址空间中才能访问**；同理，在 `__restore` 恢复 Trap 上下文的时候，我们也必须从内核地址空间切换回应用地址空间，因为**应用的代码和数据只能在它自己的地址空间中才能访问**。 进而，地址空间的切换不能影响指令的连续执行，这就要求**应用和内核地址空间在切换地址空间指令附近是平滑的**。

> 目前的设计是有一个唯一的内核地址空间存放内核的代码、数据，同时对于每个应用维护一个它们自己的地址空间，因此在 **Trap** 的时候就需要进行地址空间切换，而在**任务切换**的时候无需进行（因为这个过程全程在内核内完成）。
>
> 之前的设计是每个应用都有一个地址空间，可以将其中的逻辑段分为内核和用户两部分，分别映射到内核和 用户的数据和代码，且分别在 CPU 处于 S/U 特权级时访问。此设计中并不存在一个单独的内核地址空间。
>
> 之前设计的优点在于：Trap 的时候无需切换地址空间，而在任务切换的时候才需要切换地址空间。由于后者比前者更容易实现，这降低了实现的复杂度。而且**在应用高频进行系统调用的时候能够避免地址空间切换的开销**，这通常源于快表或 cache 的失效问题。但是这种设计方式也有缺点：即**内核的逻辑段需要在每个应用的地址空间内都映射一次**，这会带来一些无法忽略的内存占用开销，并显著限制了嵌入式平台的任务并发数。此外，这种做法无法应对处理器的[熔断 (Meltdown) 漏洞](https://cacm.acm.org/magazines/2020/6/245161-meltdown/fulltext) ， 使得恶意应用能够以某种方式看到它本来无权访问的地址空间中内核部分的数据。将内核与地址空间隔离便是修复此漏洞的一种方法。

为何将应用的 Trap 上下文放到**应用地址空间的次高页面**而不是**内核地址空间中的内核栈**中？因为，假如将其放在内核栈中，在保存 Trap 上下文之前我们必须先切换到内核地址空间，这就需要我们将内核地址空间的 token 写入 satp 寄存器，之后我们还需要有一个通用寄存器保存内核栈栈顶的位置，这样才能以它为基址保存 Trap 上下文。在保存 Trap 上下文之前我们必须完成这两项工作。然而，我们无法在不破坏任何一个通用寄存器的情况下做到这一点。因为事实上我们需要用到内核的两条信息：**内核地址空间的 token** 还有**应用内核栈顶的位置**，硬件却只提供一个 `sscratch` 可以用来进行周转。所以，不得不将 Trap 上下文保存在应用地址空间的一个虚拟页面中以避免切换到内核地址空间才能保存。

Trap 上下文实现：

```rust
pub struct TrapContext {
    pub x: [usize; 32], // 通用寄存器
    pub sstatus: Sstatus, // 超级状态寄存器
    pub sepc: usize, // 异常程序计数器
    pub kernel_satp: usize, // 内核地址空间的 token
    pub kernel_sp: usize, // 当前应用在内核地址空间中的内核栈栈顶的虚拟地址
    pub trap_handler: usize, // 内核中 trap handler 入口点的虚拟地址
}
```

```assembly
    .section .text.trampoline
    .globl __alltraps
    .globl __restore
    .align 2
__alltraps:
    csrrw sp, sscratch, sp
    # 现在 sp->用户空间的 Trap 上下文, sscratch->用户栈
    sd x1, 1*8(sp)
    # 跳过 sp(x2), 之后再保存
    sd x3, 3*8(sp)
    # 跳过 tp(x4), 应用不会用到
    .set n, 5 # 保存 x5~x31
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    # read user stack from sscratch and save it in TrapContext
    csrr t2, sscratch
    sd t2, 2*8(sp)
    ld t0, 34*8(sp) # 将内核地址空间的 token 载入到 t0 寄存器中
    ld t1, 36*8(sp) # 将 trap handler 入口点的虚拟地址载入到 t1 寄存器中
    ld sp, 35*8(sp) # 将 sp 修改为应用内核栈顶的地址
    csrw satp, t0 # 将 satp 修改为内核地址空间的 token, 切换到内核地址空间
    sfence.vma # 刷新 TLB
    jr t1 # 跳转到 trap handler

__restore:
    # 常数 a0: Trap 上下文在应用地址空间中的位置 (常数); a1: 即将回到的应用的地址空间的 token
    csrw satp, a1 # 切换到用户空间
    sfence.vma # 刷新 TLB
    csrw sscratch, a0 # 将传入的 Trap 上下文位置保存在 sscratch 寄存器中
    mv sp, a0
    # 现在 sp-> Trap 上下文在应用地址空间中的位置
    # 恢复 sstatus/sepc
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    ld sp, 2*8(sp) # 回到用户栈
    sret # 返回用户态
```

将 `trap.S` 中的整段汇编代码放置在 `.text.trampoline` 段，并在调整内存布局时将它对齐到代码段的一个页面中。这段汇编代码**放在一个物理页帧中**，且 `__alltraps` 恰好位于这个物理页帧的开头，其物理地址被外部符号 `strampoline` 标记。在开启分页模式之后，内核和应用代码都只能看到各自的虚拟地址空间，而在它们的视角中，这段汇编代码被放在它们地址空间的最高虚拟页面上，由于**这段汇编代码在执行的时候涉及到地址空间切换**，故而被称为跳板页面。

在产生 trap 前后的一小段时间内会有一个比较**极端**的情况：刚产生 trap 时，**CPU 已经进入了内核态**，但此时**执行代码和访问数据还是在应用程序所处的用户态虚拟地址空间中**，而不是我们通常理解的内核虚拟地址空间。在这段特殊的时间内，CPU 指令为什么能够被连续执行呢？**无论是内核还是应用的地址空间，跳板的虚拟页均位于同样位置**，且它们也将会映射到同一个实际存放这段汇编代码的物理页帧。在执行 `__alltraps` 或 `__restore` 函数进行地址空间切换的时候，应用的用户态虚拟地址空间和操作系统内核的内核态虚拟地址空间对切换地址空间的指令所在页的映射方式均是相同的，这段切换地址空间的指令控制流仍是可以连续执行的。

```rust
pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;

fn map_trampoline(&mut self) {
    self.page_table.map( // 直接在多级页表中插入从地址空间的最高虚拟页面映射到跳板汇编代码所在的物理页帧的键值对
        VirtAddr::from(TRAMPOLINE).into(),
        PhysAddr::from(strampoline as usize).into(),
        PTEFlags::R | PTEFlags::X,
    );
}
```

为何在 `__alltraps` 中需要借助寄存器 `jr` 而不能直接 `call trap_handler`？在内存布局中，`.text.trampoline` 段中的跳转指令和 `trap_handler` 都在代码段之内，汇编器和链接器会根据 `linker.ld` 的地址布局描述，设定电子指令的地址，计算二者地址偏移量，让**跳转指令的实际效果为当前 pc 自增这个偏移量**。但这条跳转指令在被执行的时候，它的虚拟地址被操作系统内核设置在地址空间中的最高页面之内，加上这个偏移量并不能正确的得到 `trap_handler` 的入口地址。问题的本质可以概括为：**跳转指令实际被执行时的虚拟地址**和在编译器/汇编器/链接器**进行后端代码生成和链接形成最终机器码时设置此指令的地址**是不同的。 

为了让应用在运行时有一个安全隔离且符合编译器给应用设定的地址空间布局的虚拟地址空间，操作系统需要对任务进行更多的管理

```rust
pub struct TaskControlBlock {
    pub task_cx: TaskContext, // 任务上下文
    pub task_status: TaskStatus, // 任务状态
    pub memory_set: MemorySet, // 应用地址空间
    pub trap_cx_ppn: PhysPageNum, // Trap 上下文被实际存放在物理页帧的物理页号
    pub base_size: usize, // 应用数据的大小，在应用地址空间中从开始到用户栈结束一共包含多少字节
    pub heap_bottom: usize, // 堆底
    pub program_brk: usize, // program break
}
```

任务控制块的创建

```rust
pub fn new(elf_data: &[u8], app_id: usize) -> Self {
    // 解析传入的 ELF 格式数据构造应用的地址空间 memory_set 并获得其他信息
    let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
    // 从地址空间中查多级页表找到应用地址空间中的 Trap 上下文实际被放在哪个物理页帧
    let trap_cx_ppn = memory_set.translate(VirtAddr::from(TRAP_CONTEXT_BASE).into()).unwrap().ppn();
    let task_status = TaskStatus::Ready;
    // 根据传入的应用 ID 找到应用的内核栈预计放在内核地址空间中的哪个位置
    let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(app_id);
    // 将这个逻辑段加入到内核地址空间中
    KERNEL_SPACE.exclusive_access().insert_framed_area(
        kernel_stack_bottom.into(),
        kernel_stack_top.into(),
        MapPermission::R | MapPermission::W,
    );
    let task_control_block = Self {
        task_status,
        task_cx: TaskContext::goto_trap_return(kernel_stack_top),
        memory_set,
        trap_cx_ppn,
        base_size: user_sp,
        heap_bottom: user_sp,
        program_brk: user_sp,
    };
    // prepare TrapContext in user space
    let trap_cx = task_control_block.get_trap_cx();
    *trap_cx = TrapContext::app_init_context(
        entry_point,
        user_sp,
        KERNEL_SPACE.exclusive_access().token(),
        kernel_stack_top,
        trap_handler as usize,
    );
    task_control_block
}
```

Trap 处理

```rust
fn set_kernel_trap_entry() {
    unsafe { // 将 stvec 修改为函数 trap_from_kernel 的地址
        stvec::write(trap_from_kernel as usize, TrapMode::Direct);
    }
}

pub fn trap_handler() -> ! {
    set_kernel_trap_entry();
    let cx = current_trap_cx();
    let scause = scause::read(); // get trap cause
    let stval = stval::read(); // get extra value
    match scause.cause() {
        // ...
    }
    trap_return();
}
```

一旦进入内核后再次触发到 S 的 Trap，则会在硬件设置一些 CSR 之后跳过寄存器 的保存过程直接跳转到 `trap_from_kernel` 函数，在这里我直接 `panic` 退出。这是因为内核和应用的地址空间分离之后，从 U 还是从 S Trap 到 S 的 Trap 上下文保存与恢复实现方式和 Trap 处理逻辑有很大差别，我们不得不实现两遍而不太可能将二者整合起来。这里简单起见我们弱化了从 S 到 S 的 Trap ，省略了 Trap 上下文保存过程而直接 `panic` 。

在 `trap_handler` 完成 Trap 处理之后，我们需要调用 `trap_return` 返回用户态

```rust
fn set_user_trap_entry() {
    unsafe {
        stvec::write(TRAMPOLINE as usize, TrapMode::Direct);
    }
}

pub fn trap_return() -> ! {
    set_user_trap_entry(); // 让应用 Trap 到 S 的时候可以跳转到 __alltraps
    let trap_cx_ptr = TRAP_CONTEXT_BASE; // Trap 上下文在应用地址空间中的虚拟地址
    let user_satp = current_user_token(); // 要继续执行的应用地址空间的 token
    extern "C" {
        fn __alltraps();
        fn __restore();
    }
    let restore_va = __restore as usize - __alltraps as usize + TRAMPOLINE;
    unsafe {
        asm!(
            "fence.i", // 清空指令缓存
            "jr {restore_va}",         // jump to new addr of __restore asm function
            restore_va = in(reg) restore_va,
            in("a0") trap_cx_ptr,      // a0 = virt addr of Trap Context
            in("a1") user_satp,        // a1 = phy addr of usr page table
            options(noreturn)
        );
    }
}
```

我们需要跳转到 `__restore`，切换到应用地址空间，从 Trap 上下文中恢复通用寄存器，并 `sret` 继续执行应用。关键在于如何找到 **`__restore` 在内核/应用地址空间中共同的虚拟地址**。由于 `__alltraps` 是对齐到地址空间跳板页面的起始地址 `TRAMPOLINE` 上的， 则 `__restore` 的虚拟地址只需在 `TRAMPOLINE` 基础上加上 `__restore` 相对于 `__alltraps` 的偏移量即可。这里 `__alltraps` 和 `__restore` 都是指**编译器在链接时看到的内核内存布局中的地址**。

页表模块 `page_table` 提供了将**应用地址空间中一个缓冲区**转化为**在内核空间中能够直接访问的形式**的辅助函数

```rust
pub fn translated_byte_buffer(token: usize, ptr: *const u8, len: usize) -> Vec<&'static mut [u8]> {
    let page_table = PageTable::from_token(token); // 页表
    let mut start = ptr as usize; // 缓冲区起始地址
    let end = start + len; // 缓冲区结束地址
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start); // 起始虚拟地址
        let mut vpn = start_va.floor();
        let ppn = page_table.translate(vpn).unwrap().ppn();
        vpn.step();
        let mut end_va: VirtAddr = vpn.into(); // 结束虚拟地址
        end_va = end_va.min(VirtAddr::from(end));
        if end_va.page_offset() == 0 {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
        } else {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
        }
        start = end_va.into();
    }
    v // 以向量的形式返回一组可以在内核空间中直接访问的字节数组切片
}
```

## 进程及进程管理

### 与进程有关的重要系统调用

用户初始进程

```rust
fn main() -> i32 {
    if fork() == 0 {
        exec("ch5b_user_shell\0", &[0 as *const u8]); // 子进程, 需要在字符串末尾手动加入 \0
    } else {
        loop { // 父进程
            let mut exit_code: i32 = 0;
            let pid = wait(&mut exit_code); // 等待并回收系统中的僵尸进程占据的资源
            if pid == -1 {
                yield_(); // 回收失败, 交出 CPU 资源
                continue;
            }
            println!(
                "[initproc] Released a zombie process, pid={}, exit_code={}",
                pid, exit_code,
            );
        }
    }
    0
}
```

shell

```rust
pub fn main() -> i32 {
    println!("Rust user shell");
    let mut line: String = String::new(); // 用户当前输入的命令内容
    print!(">> ");
    flush();
    loop {
        let c = getchar(); // 获取一个用户输入的字符
        match c {
            LF | CR => { // 回车
                print!("\n");
                if !line.is_empty() {
                    line.push('\0');
                    let pid = fork();
                    if pid == 0 { // 子进程
                        if exec(line.as_str(), &[0 as *const u8]) == -1 {
                            println!("Error when executing!");
                            return -4;
                        }
                        unreachable!();
                    } else { // 父进程
                        let mut exit_code: i32 = 0;
                        let exit_pid = waitpid(pid as usize, &mut exit_code);
                        assert_eq!(pid, exit_pid);
                        println!("Shell: Process {} exited with code {}", pid, exit_code);
                    }
                    line.clear();
                }
                print!(">> ");
                flush();
            }
            BS | DL => { // 退格
                if !line.is_empty() {
                    print!("{}", BS as char);
                    print!(" ");
                    print!("{}", BS as char);
                    flush();
                    line.pop();
                }
            }
            _ => {
                print!("{}", c as char);
                flush();
                line.push(c as char);
            }
        }
    }
}
```

### 进程管理的核心数据结构

`exec` 系统调用根据**应用的名字**来获取应用的 ELF 格式数据。 在链接器 `os/build.rs` 中，我们按顺序保存链接进来的每个应用的名字：

```rust
writeln!(
    f,
    r#"
    .global _app_names
    _app_names:"#
)?;
for app in apps.iter() { // 各个应用的名字通过 .string 伪指令放到数据段中
    writeln!(f, r#"    .string "{}""#, app)?;
}
```

在加载器 `loader.rs` 中，用一个全局可见的只读向量 `APP_NAMES` 来按照顺序将所有应用的名字保存在内存中：

```rust
lazy_static! {
    static ref APP_NAMES: Vec<&'static str> = {
        let num_app = get_num_app();
        extern "C" {
            fn _app_names();
        }
        let mut start = _app_names as usize as *const u8;
        let mut v = Vec::new();
        unsafe {
            for _ in 0..num_app {
                let mut end = start;
                while end.read_volatile() != b'\0' {
                    end = end.add(1);
                }
                let slice = core::slice::from_raw_parts(start, end as usize - start as usize);
                let str = core::str::from_utf8(slice).unwrap();
                v.push(str);
                start = end.add(1);
            }
        }
        v
    };
}
```

任务控制块中包含两部分：

- 在初始化之后就不再变化的作为一个字段直接放在任务控制块中。这里将进程标识符 `PidHandle` 和内核栈 `KernelStack` 放在其中；
- 在运行过程中可能发生变化的则放在 `TaskControlBlockInner` 中，将它再包裹上一层 `UPSafeCell<T>` 放在任务控制块中。 在此使用 `UPSafeCell<T>` 可以**提供互斥**从而避免数据竞争。

```rust
pub struct TaskControlBlock {
    // 不可变
    pub pid: PidHandle,
    pub kernel_stack: KernelStack,
    /// 可变
    inner: UPSafeCell<TaskControlBlockInner>,
}

pub struct TaskControlBlockInner {
    pub trap_cx_ppn: PhysPageNum, // 应用地址空间中的 Trap 上下文被放在的物理页帧的物理页号
    pub base_size: usize, // 应用数据仅有可能出现在应用地址空间低于 base_size 字节的区域中
    pub task_cx: TaskContext, // 任务上下文，用于任务切换
    pub task_status: TaskStatus, // 当前进程的执行状态
    pub memory_set: MemorySet, // 应用地址空间
    pub parent: Option<Weak<TaskControlBlock>>, // 当前进程的父进程
    pub children: Vec<Arc<TaskControlBlock>>, // 当前进程的所有子进程
    pub exit_code: i32, // 当进程调用 exit 系统调用主动退出或者执行出错由内核终止的时候, 退出码会被内核保存在它的任务控制块中
    pub heap_bottom: usize, // 堆底
    pub program_brk: usize,
}
```

每个 `Processor` 都有一个 idle 控制流，它们运行在每个核各自的启动栈上，功能是**尝试从任务管理器中选出一个任务来在当前核上执行**。在内核初始化完毕之后，核通过调用 `run_tasks` 函数来进入 idle 控制流：

```rust
pub fn run_tasks() {
    loop {
        let mut processor = PROCESSOR.exclusive_access();
        if let Some(task) = fetch_task() { // 从任务管理器中取出一个任务
            let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
            let mut task_inner = task.inner_exclusive_access();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext; // 下个任务上下文
            task_inner.task_status = TaskStatus::Running;
            drop(task_inner); // 手动释放
            processor.current = Some(task); // 手动释放
            drop(processor); // 手动释放
            unsafe {
                __switch(idle_task_cx_ptr, next_task_cx_ptr); // 任务切换
            }
        } else {
            warn!("no tasks available in run_tasks");
        }
    }
}
```

当一个应用交出 CPU 使用权时，进入内核后它会调用 `schedule` 函数来切换到 idle 控制流并开启新一轮的任务调度。

```rust
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = PROCESSOR.exclusive_access();
    let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
    drop(processor);
    unsafe {
        __switch(switched_task_cx_ptr, idle_task_cx_ptr);
    }
}
```

### 进程管理机制的设计实现

`TaskControlBlock::new` 创建一个进程控制块，它需要传入 ELF 可执行文件的数据切片作为参数，这可以通过加载器 `loader` 子模块提供的 `get_app_data_by_name` 接口查找 `initproc` 的 ELF 数据来获得。初始化 `INITPROC` 之后，在 `add_initproc` 中可以调用 `task` 的任务管理器 `manager` 子模块提供的 `add_task` 接口将其加入到任务管理器。

```rust
pub fn new(elf_data: &[u8]) -> Self {
    // 解析 ELF 得到应用地址空间、用户栈在应用地址空间中的位置、应用的入口点
    let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
    // 手动查页表找到应用地址空间中的 Trap 上下文实际所在的物理页帧
    let trap_cx_ppn = memory_set.translate(VirtAddr::from(TRAP_CONTEXT_BASE).into()).unwrap().ppn();
    let pid_handle = pid_alloc(); // 为新进程分配 PID
    let kernel_stack = kstack_alloc(); // 为新进程分配内核栈
    let kernel_stack_top = kernel_stack.get_top(); // 内核栈在内核地址空间的位置
    // push a task context which goes to trap_return to the top of kernel stack
    let task_control_block = Self {
        pid: pid_handle,
        kernel_stack,
        inner: unsafe {
            UPSafeCell::new(TaskControlBlockInner {
                trap_cx_ppn,
                base_size: user_sp,
                // 在该进程的内核栈上压入初始化的任务上下文，使得第一次任务切换到它的时候可以跳转到 trap_return 并进入用户态开始执行
                task_cx: TaskContext::goto_trap_return(kernel_stack_top),
                task_status: TaskStatus::Ready,
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                heap_bottom: user_sp,
                program_brk: user_sp,
            })
        },
    };
    // prepare TrapContext in user space
    let trap_cx = task_control_block.inner_exclusive_access().get_trap_cx();
    // 初始化位于该进程应用地址空间中的 Trap 上下文，使得第一次进入用户态时，能正确跳转到应用入口点并设置好用户栈，同时也保证在 Trap 的时候用户态能正确进入内核态
    *trap_cx = TrapContext::app_init_context(
        entry_point,
        user_sp,
        KERNEL_SPACE.exclusive_access().token(),
        kernel_stack_top,
        trap_handler as usize,
    );
    task_control_block
}
```

调用 `task` 子模块提供的 `suspend_current_and_run_next` 函数可以暂停当前任务，并切换到下一个任务

```rust
pub fn suspend_current_and_run_next() {
    let task = take_current_task().unwrap(); // 当前正在执行的任务
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    task_inner.task_status = TaskStatus::Ready; // 修改其进程控制块内的状态
    drop(task_inner);
    add_task(task); // 将这个任务放入任务管理器的队尾
    schedule(task_cx_ptr); // 触发调度并切换任务
}
```

fork 系统调用的实现

```rust
pub fn from_another(another: &Self) -> Self {
    Self {
        vpn_range: VPNRange::new(another.vpn_range.get_start(), another.vpn_range.get_end()),
        data_frames: BTreeMap::new(),
        map_type: another.map_type,
        map_perm: another.map_perm,
    }
}

pub fn from_existed_user(user_space: &Self) -> Self {
    let mut memory_set = Self::new_bare();
    // map trampoline
    memory_set.map_trampoline();
    // copy data sections/trap_context/user_stack
    for area in user_space.areas.iter() {
        let new_area = MapArea::from_another(area);
        memory_set.push(new_area, None);
        // copy data from another space
        for vpn in area.vpn_range {
            let src_ppn = user_space.translate(vpn).unwrap().ppn();
            let dst_ppn = memory_set.translate(vpn).unwrap().ppn();
            dst_ppn
            .get_bytes_array()
            .copy_from_slice(src_ppn.get_bytes_array());
        }
    }
    memory_set
}
```

## 文件系统与 I/O 重定向

### 文件与文件描述符

在进程看来，所有文件的访问都可以通过一个简洁统一的抽象接口 `File` 进行

```rust
pub trait File: Send + Sync {
    fn readable(&self) -> bool;
    fn writable(&self) -> bool;
    fn read(&self, buf: UserBuffer) -> usize;
    fn write(&self, buf: UserBuffer) -> usize;
}
```

`UserBuffer` 是在 `mm` 子模块中定义的应用地址空间中的一段缓冲区，我们可以将它看成一个 `&[u8]` 切片。

```rust
pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>
```

- `Vec` 的动态长度特性使得我们**无需设置一个固定的文件描述符数量上限**；
- `Option` 使得我们可以**区分一个文件描述符当前是否空闲**，当它是 `None` 的时候是空闲的，而 `Some` 则代表它已被占用；
- `Arc` 提供了**共享引用**能力。可能会有多个进程共享同一个文件对它进行读写。被它包裹的内容会被放到内核堆而不是栈上，它**不需要在编译期有着确定的大小**；
- `dyn` 关键字表明 `Arc` 里面的类型实现了 `File/Send/Sync` 三个 Trait ，但是**编译期无法知道它具体是哪个类型**（可能是任何实现了 `File` Trait 的类型如 `Stdin/Stdout` ，故而**它所占的空间大小自然也无法确定**），需要等到运行时才能知道它的具体类型。

### 文件系统接口

我们实现的文件系统进行了很大的简化：

- 扁平化：**仅存在根目录 `/` 一个目录**，所有的文件都放在根目录内。直接以文件名索引文件。
- 不设置用户和用户组概念，不记录文件访问/修改的任何时间戳，不支持软硬链接。
- 只实现了最基本的文件系统相关系统调用。

```rust
fn sys_openat(dirfd: usize, path: &str, flags: u32, mode: u32) -> isize
```

- 如果 `flags` 为 0，则表示以**只读**模式 *RDONLY* 打开；
- 如果 `flags` 第 0 位被设置（`0x001`），表示以**只写**模式 *WRONLY* 打开；
- 如果 `flags` 第 1 位被设置（`0x002`），表示既**可读又可写** *RDWR* ；
- 如果 `flags` 第 9 位被设置（`0x200`），表示允许**创建**文件 *CREATE* ，在找不到该文件的时候应创建文件；如果该文件已经存在则应该将该文件的大小归零；
- 如果 `flags` 第 10 位被设置（`0x400`），则在打开文件的时候应该**清空**文件的内容并将该文件的大小归零，也即 *TRUNC* 。

本教程只实现文件的**顺序读写**，而不考虑随机读写。

### 简易文件系统 easy-fs

出于解耦合考虑，文件系统 easy-fs 被从内核中分离出来，分成两个不同的 crate ：

- `easy-fs` 是简易文件系统的本体；
- `easy-fs-fuse` 是能在开发环境中运行的应用程序，用于**将应用打包为 easy-fs 格式的文件系统镜像**，也可以用来**对 `easy-fs` 进行测试**。

easy-fs与底层设备驱动之间通过抽象接口 `BlockDevice` 来连接，采用**轮询**方式访问 `virtio_blk` 虚拟磁盘设备，**避免调用外设中断的相关内核函数**。easy-fs **避免了直接访问进程相关的数据和函数**，从而能独立于内核开发。

`easy-fs` crate 以层次化思路设计，自下而上可以分成五个层次：

1. **磁盘块设备接口**层：以**块**为单位对磁盘块设备进行读写的 trait 接口
2. **块缓存**层：**在内存中缓存磁盘块的数据**，避免频繁读写磁盘
3. **磁盘数据结构**层：磁盘上的**超级块、位图、索引节点、数据块、目录项**等核心数据结构和相关处理
4. **磁盘块管理器**层：合并了上述核心数据结构和磁盘布局所形成的磁盘文件系统数据结构
5. **索引节点**层：管理索引节点，实现了文件创建/文件打开/文件读写等成员函数

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/easy-fs-demo.png" alt="../_images/easy-fs-demo.png" style="zoom:48%;" />

```rust
pub const BLOCK_SZ: usize = 512;

pub struct BlockCache {
    cache: [u8; BLOCK_SZ], // 位于内存中的缓冲区
    block_id: usize, // 块的编号
    block_device: Arc<dyn BlockDevice>, // 块所属的底层设备
    modified: bool, // 自从这个块缓存从磁盘载入内存之后，它有没有被修改过
}
```

内存只能同时缓存有限个磁盘块。当要对一个磁盘块进行读写时，块缓存全局管理器检查它是否已经被载入内存中，如果是则直接返回，否则就读取磁盘块到内存。如果内存中驻留的磁盘块缓冲区的数量已满，则需要进行缓存替换。这里使用一种类 **FIFO** 的缓存替换算法，在管理器中只需维护一个队列。

```rust
pub struct BlockCacheManager {
    queue: VecDeque<(usize, Arc<Mutex<BlockCache>>)>,
}
```

队列 `queue` 维护块编号和块缓存的二元组。块缓存的类型是一个 `Arc<Mutex<BlockCache>>` ，它可以同时提供**共享引用**和**互斥访问**。共享引用意义在于块缓存既需要**在管理器 `BlockCacheManager` 保留一个引用**，还需要**将引用返回给块缓存的请求者**。而互斥访问在**单核**上的意义在于**提供内部可变性通过编译**，在**多核**环境下则可以帮助我们**避免可能的并发冲突**。

easy-fs 磁盘按照块编号从小到大顺序分成 5 个连续区域：

- 第一个区域只包括一个块，它是**超级块** (Super Block)，用于**定位其他连续区域的位置**，**检查文件系统合法性**。
- 第二个区域是一个**索引节点位图**，长度为若干个块。它记录了**索引节点区域中有哪些索引节点已经被分配出去使用了**。
- 第三个区域是**索引节点区域**，长度为若干个块。其中的每个块都存储了若干个索引节点。
- 第四个区域是一个**数据块位图**，长度为若干个块。它记录了后面的**数据块区域中有哪些已经被分配出去使用了**。
- 最后的区域则是数据块区域，其中的每个被分配出去的块保存了文件或目录的具体内容。

每个位图都由若干个块组成，**每个块大小 4096 bits**。每个 bit 都代表一个索引节点/数据块的分配状态。`Bitmap` 是位图区域的管理器，它保存了位图区域的起始块编号和块数。而 `BitmapBlock` 将位图区域中的一个**磁盘块**解释为**长度为 64 的一个 `u64` 数组**。

`Bitmap` 分配一个bit：

```rust
const BLOCK_BITS: usize = BLOCK_SZ * 8;

pub fn alloc(&self, block_device: &Arc<dyn BlockDevice>) -> Option<usize> {
    for block_id in 0..self.blocks { // 枚举区域中的每个块
        let pos = get_block_cache( // 获取块缓存
            block_id + self.start_block_id as usize, // 区域起始块编号 + 区域内的块编号 == 块设备上的块编号
            Arc::clone(block_device),
        )
        .lock() // 获取块缓存的互斥锁, 从而可以对块缓存进行访问
        .modify(0, |bitmap_block: &mut BitmapBlock| { // 从缓冲区偏移量为 0 的位置开始将一段连续的数据（数据的长度随具体类型而定）解析为一个 BitmapBlock 并要对该数据结构进行修改
            if let Some((bits64_pos, inner_pos)) = bitmap_block
                .iter()
                .enumerate()
                .find(|(_, bits64)| **bits64 != u64::MAX)
                .map(|(bits64_pos, bits64)| (bits64_pos, bits64.trailing_ones() as usize))
            { // 找到最低的一个 0 并置为 1
                bitmap_block[bits64_pos] |= 1u64 << inner_pos;
                Some(block_id * BLOCK_BITS + bits64_pos * 64 + inner_pos as usize)
            } else {
                None
            }
        });
        if pos.is_some() {
            return pos;
        }
    }
    None
}
```

每个文件/目录在磁盘上均以一个 `DiskInode` 的形式存储。其中包含文件/目录的元数据：`size` 表示文件/目录内容的字节数， `type_` 表示索引节点的类型 `DiskInodeType`，目前仅支持文件 `File` 和目录 `Directory` 两种类型。`direct/indirect1/indirect2` 是存储文件内容/目录内容的数据块的索引。

为了尽可能节约空间，在进行索引的时候，块的编号用一个 `u32` 存储。索引方式分成**直接索引**和**间接索引**两种：

- 当文件很小的时候，只需用到直接索引，`direct` 数组中最多可以指向 `INODE_DIRECT_COUNT` 个数据块，当取值为 28 的时候，通过直接索引可以找到 14 KiB 的内容（每个数据块 4096 bit = 512 B）。
- 当文件比较大的时候，不仅直接索引的 `direct` 数组装满，还需要用到一级间接索引 `indirect1` 。它指向一个一级索引块，这个块也位于磁盘布局的数据块区域中。这个一级索引块中的每个 `u32` 都用来指向数据块区域中一个保存该文件内容的数据块，最多能够索引 512 / 4 = 128 个数据块，对应 64 KiB 的内容。
- 当文件大小超过直接索引和一级索引支持的容量上限 78 KiB 的时候，就需要用到二级间接索引 `indirect2` 。它指向一个位于数据块区域中的二级索引块。二级索引块中的每个 `u32` 指向一个不同的一级索引块，这些一级索引块也位于数据块区域中。通过二级间接索引最多能够索引 128 × 64 KiB = 8 MiB 的内容。

为了充分利用空间，`DiskInode` 的大小设置为 128 B，每个块正好能够容纳 4 个 `DiskInode` 。在后续需要支持更多类型的元数据的时候，可以适当缩减直接索引 `direct` 的块数，并将节约出来的空间用来存放其他元数据，仍可保证 `DiskInode` 的总大小为 128 B。

对于文件而言，它的内容在文件系统或内核看来没有任何既定的格式，只是一个字节序列。**目录**的内容却需要遵从一种特殊的格式，它可以看成一个**目录项**的序列，每个目录项都是一个二元组，包括目录下文件的**文件名**和**索引节点编号**。

在块设备上创建并初始化一个 easy-fs 文件系统：

```rust
pub fn create(block_device: Arc<dyn BlockDevice>, total_blocks: u32, inode_bitmap_blocks: u32) -> Arc<Mutex<Self>> {
    // 计算每个区域各应该包含多少块
    let inode_bitmap = Bitmap::new(1, inode_bitmap_blocks as usize); // 索引位图
    let inode_num = inode_bitmap.maximum(); // 索引数
    let inode_area_blocks = ((inode_num * core::mem::size_of::<DiskInode>() + BLOCK_SZ - 1) / BLOCK_SZ) as u32;
    let inode_total_blocks = inode_bitmap_blocks + inode_area_blocks; // 索引总块数
    let data_total_blocks = total_blocks - 1 - inode_total_blocks; // 数据总块数
    let data_bitmap_blocks = (data_total_blocks + 4096) / 4097; // 数据位图块数
    let data_area_blocks = data_total_blocks - data_bitmap_blocks; // 数据区域块数
    let data_bitmap = Bitmap::new(
        (1 + inode_bitmap_blocks + inode_area_blocks) as usize,
        data_bitmap_blocks as usize,
    );
    let mut efs = Self { // 创建实例
        block_device: Arc::clone(&block_device),
        inode_bitmap,
        data_bitmap,
        inode_area_start_block: 1 + inode_bitmap_blocks,
        data_area_start_block: 1 + inode_total_blocks + data_bitmap_blocks,
    };
    for i in 0..total_blocks { // 将块设备的前 total_blocks 个块清零
        get_block_cache(i as usize, Arc::clone(&block_device))
            .lock()
            .modify(0, |data_block: &mut DataBlock| {
                for byte in data_block.iter_mut() {
                    *byte = 0;
                }
            });
    }
    // 将位于块设备编号为 0 块上的超级块进行初始化
    get_block_cache(0, Arc::clone(&block_device)).lock().modify(
        0,
        |super_block: &mut SuperBlock| {
            super_block.initialize(
                total_blocks,
                inode_bitmap_blocks,
                inode_area_blocks,
                data_bitmap_blocks,
                data_area_blocks,
            );
        },
    );
    // 立即写回
    // 创建根目录 /
    assert_eq!(efs.alloc_inode(), 0); // 在 inode 位图中分配一个 inode
    let (root_inode_block_id, root_inode_offset) = efs.get_disk_inode_pos(0);
    get_block_cache(root_inode_block_id as usize, Arc::clone(&block_device))
        .lock()
        .modify(root_inode_offset, |disk_inode: &mut DiskInode| {
            disk_inode.initialize(DiskInodeType::Directory);
        });
    block_cache_sync_all();
    Arc::new(Mutex::new(efs))
}
```

`EasyFileSystem` 实现了磁盘布局并能够将所有块有效的管理起来。但是文件系统的使用者不关心磁盘布局是如何实现的，而是更希望能够直接看到目录树结构中逻辑上的文件和目录。设计索引节点 `Inode` 暴露给文件系统的使用者，让他们能够直接对文件和目录进行操作。`DiskInode` 放在**磁盘块中比较固定的位**置，而 `Inode` 是**放在内存中的记录文件索引节点信息**的数据结构。

**所有暴露给文件系统的使用者的文件系统操作，全程均需持有 `EasyFileSystem` 的互斥锁**（文件系统内部的操作都是假定在已持有 efs 锁的情况下才被调用的，因此它们不应尝试获取锁）。这能够保证**在多核情况下，同时最多只能有一个核在进行文件系统相关操作**。如果我们在这里加锁的话，其实就能够保证块缓存的互斥访问了。

之前需要将所有的应用都链接到内核中，随后在应用管理器中通过应用名进行索引来找到应用的 ELF 数据。这样做会**造成内核体积过度膨胀**，同时也会**浪费内存资源**，因为未被执行的应用也占据了内存空间。在实现了我们自己的文件系统之后，可以**将这些应用打包到 easy-fs 镜像中放到磁盘中**，当我们要执行应用的时候只需从文件系统中取出ELF 执行文件格式的应用 并加载到内存中执行即可，这样就避免了上面的那些问题。

### 在内核中使用 easy-fs

在 qemu 上，我们使用 `VirtIOBlock` 访问 VirtIO 块设备，并将它全局实例化为 `BLOCK_DEVICE` ，使内核的其他模块可以访问。

在启动 Qemu 模拟器的时候，我们可以配置参数来添加一块 VirtIO 块设备：

```shell
FS_IMG := ../user/target/$(TARGET)/$(MODE)/fs.img

run-inner:
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) \
		-drive file=$(FS_IMG),if=none,format=raw,id=x0 \ # 为虚拟机添加一块虚拟硬盘，内容为通过 easy-fs-fuse 打包的包含应用 ELF 的 easy-fs 镜像，并命名为 x0
        -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 # 将硬盘 x0 作为一个 VirtIO 总线中的一个块设备接入到虚拟机系统中。 VirtIO 总线通过 MMIO 进行控制，且该块设备在总线中的编号为 0
```

**内存映射 I/O** (MMIO, Memory-Mapped I/O) 指**通过特定的物理内存地址来访问外设的设备寄存器**。VirtIO 总线的 MMIO 物理地址区间为从 `0x10001000` 开头的 4 KiB 。

在 `config` 子模块中我们硬编码 Qemu 上的 VirtIO 总线的 MMIO 地址区间（起始地址，长度）。在创建内核地址空间的时候需要建立页表映射：

## 进程间通信

### 管道

```rust
pub struct Pipe {
    readable: bool,
    writable: bool,
    buffer: Arc<Mutex<PipeRingBuffer>>,
}

const RING_BUFFER_SIZE: usize = 32;

#[derive(Copy, Clone, PartialEq)]
enum RingBufferStatus {
    FULL,
    EMPTY,
    NORMAL,
}

pub struct PipeRingBuffer {
    arr: [u8; RING_BUFFER_SIZE],
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    write_end: Option<Weak<Pipe>>, // 写端的一个弱引用计数，在某些情况下需要确认该管道所有的写端是否都已经被关闭了
}
```

每个读端或写端中都保存着所属管道自身的**强引用计数**，这些引用计数只会出现在管道端口 `Pipe` 结构体中。一旦一个管道所有的读端和写端均被关闭，便会导致它们所属管道的引用计数变为 0 ，循环队列缓冲区所占用的资源被自动回收。虽然 `PipeRingBuffer` 中保存了一个指向写端的引用计数，但是它是一个弱引用，也就不会出现循环引用的情况导致内存泄露。

```rust
pub fn all_write_ends_closed(&self) -> bool {
    self.write_end.as_ref().unwrap().upgrade().is_none()
}
```

判断管道的所有写端是否都被关闭了，这是通过**尝试将管道中保存的写端的弱引用计数升级为强引用计数**来实现的。如果升级失败的话，说明管道写端的强引用计数为 0 ，也就意味着管道所有写端都被关闭了，从而管道中的数据不会再得到补充，待管道中仅剩的数据被读取完毕之后，管道就可以被销毁了。

### 命令行参数与标准 I/O 重定向

在 shell 程序中，一旦接收到一个回车，就会将当前行的内容 `line` 作为一个名字并试图去执行同名的应用。但是现在 `line` 还可能包含一些命令行参数，**只有最开头的一个才是要执行的应用名**。因此要做的第一件事情就是将 `line` 用空格分割。经过分割， `args` 中的 `&str` 都是 `line` 中的一段子区间，它们的结尾并没有包含 `\0` ，因为 `line` 是输入得到的，中间本来就没有 `\0` 。由于在向内核传入字符串的时候，只能传入字符串的起始地址，因此必须保证其结尾为 `\0` 。用 `args_copy` 将 `args` 中的字符串**拷贝一份到堆上并在末尾手动加入 `\0`** 。这样就可以安心的将 `args_copy` 中的字符串传入内核了。

<img src="https://learningos.cn/rCore-Camp-Guide-2024A/_images/user-stack-cmdargs.png" alt="../_images/user-stack-cmdargs.png" style="zoom:50%;" />

首先在用户栈上分配一个**字符串指针数组**（蓝色区域），数组中的每个元素都指向一个用户栈更低处的命令行参数字符串的起始地址。最开始只是分配空间，具体的值要等到字符串被放到用户栈上之后才能确定更新。然后逐个将传入的 `args` 中的字符串压入到用户栈中（橙色区域），在用户栈上预留空间之后逐字节进行复制。`args` 中的字符串是通过 `translated_str` 从应用地址空间取出的，它的末尾不包含 `\0` 。为了应用能知道每个字符串的长度，需要手动在末尾加入 `\0` 。

## 并发

### 内核态的线程管理

操作系统让进程拥有相互隔离的虚拟的地址空间， 让进程感到在独占一个虚拟的处理器。其实这只是操作系统通过时分复用和空分复用技术来让每个进程复用有限的物理内存和物理 CPU。 而线程是在进程内中的一个新的抽象。**在没有线程之前，一个进程在一个时刻只有一个执行点**（即程序计数器 (PC) 寄存器保存的要执行指令的指针）。但**线程的引入把进程内的这个单一执行点给扩展为多个执行点**，即在进程中存在多个线程， 每个线程都有一个执行点。而且这些线程共享进程的地址空间，所以可以不必采用相对比较复杂的 IPC 机制（一般需要内核的介入）， 而可以很方便地直接访问进程内的数据。

在线程的具体运行过程中，需要有**程序计数器寄存器**来记录当前的执行位置，需要有一组**通用寄存器**记录当前的指令的操作数据， 需要有一个**栈**来保存线程执行过程的函数调用栈和局部变量等，这就形成了**线程上下文**的主体部分。 这样如果两个线程运行在一个处理器上，就需要采用类似两个进程运行在一个处理器上的调度/切换管理机制， 即需要在一定时刻进行线程切换，并进行线程上下文的保存与恢复。这样在一个进程中的多线程可以独立运行， 取代了进程，成为操作系统调度的基本单位。

由于把进程的结构进行了细化，通过线程来表示对处理器的虚拟化，使得进程成为了管理线程的容器。 在进程中的线程没有父子关系，大家都是兄弟，但还是有个老大。这个代表老大的线程其实就是创建进程（比如通过 `fork` 系统调用创建进程）时，建立的第一个线程，它的线程标识符（TID）为 `0` 。

当进程调用 `thread_create` 系统调用后，内核会在这个进程内部创建一个新的线程，这个线程能够访问到进程所拥有的代码段， 堆和其他数据段。但内核会给这个新线程分配一个它专有的用户态栈，这样每个线程才能相对独立地被调度和执行。 由于用户态进程与内核之间有各自独立的页表，所以二者需要有一个跳板页 `TRAMPOLINE` 来处理用户态切换到内核态的地址空间平滑转换的事务。当出现线程后，**在进程中的每个线程也需要有一个独立的跳板页 `TRAMPOLINE`** 来完成同样的事务。相比于创建进程的 `fork` 系统调用，**创建线程不需要要建立新的地址空间**，这是二者之间最大的不同。 另外属于同一进程中的线程之间没有父子关系，这一点也与进程不一样。

当一个线程执行完代表它的功能后，会通过 `exit` 系统调用退出。内核在收到线程发出的 `exit` 系统调用后， 会回收线程占用的部分资源，即**用户态用到的资源**，比如**用户态的栈，用于系统调用和异常处理的跳板页**等。 而该线程的**内核态用到的资源**，比如**内核栈**等，需要**通过进程/主线程调用 `waittid` 来回收**了， 这样整个线程才能被彻底销毁。

一般情况下进程/主线程要负责通过 `waittid` 来等待它创建出来的线程（不是主线程）结束并回收它们在内核中的资源 （如线程的内核栈、**线程控制块**等）。**如果进程/主线程先调用了 `exit` 系统调用来退出，那么整个进程 （包括所属的所有线程）都会退出，而对应父进程会通过 `waitpid` 回收子进程剩余还没被回收的资源**。

### 锁机制

如何能够实现轻量的可睡眠锁？**让等待锁的线程睡眠，让释放锁的线程显式地唤醒等待锁的线程**。 如果有多个等待锁的线程，可以全部释放，让大家再次竞争锁；也可以只释放最早等待的那个线程。这就需要更多的操作系统支持，特别是需要一个等待队列来保存等待锁的线程。

**在线程的眼里，互斥是一种每个线程能看到的资源**，且在一个进程中，可以存在多个不同互斥资源，可以**把所有的互斥资源放在一起让进程来管理**。

### 信号量机制

信号量的两种操作：P 操作和 V 操作。 P 操作是检查信号量的值是否大于 0，若该值大于 0，则将其值减 1 并继续（表示可以进入临界区了）；若该值为 0，则线程将睡眠。此时 P 操作还未结束。而且由于信号量本身是一种临界资源，在 P 操作中，检查/修改信号量值以及可能发生的睡眠这一系列操作， 是一个不可分割的原子操作过程。通过原子操作才能保证，一旦 P 操作开始，则在该操作完成或阻塞睡眠之前， 其他线程均不允许访问该信号量。

V 操作会对信号量的值加 1 ，然后检查是否有一个或多个线程在该信号量上睡眠等待。如有， 则选择其中的一个线程唤醒并允许该线程继续完成它的 P 操作；如没有，则直接返回。信号量的值加 1， 并可能唤醒一个线程的一系列操作同样也是不可分割的原子操作过程。不会有某个进程因执行 V 操作而阻塞。

信号量的另一种用途是用于实现同步。比如，把信号量的初始值设置为 0 ， 当一个线程 A 对此信号量执行一个 P 操作，那么该线程立即会被阻塞睡眠。之后有另外一个线程 B 对此信号量执行一个 V 操作，就会将线程 A 唤醒。这样线程 B 中执行 V 操作之前的代码序列 B-stmts 和线程 A 中执行 P 操作之后的代码 A-stmts 序列之间就形成了一种确定的同步执行关系，即线程 B 的 B-stmts 会先执行，然后才是线程 A 的 A-stmts 开始执行。

### 条件变量机制

管程有一个很重要的特性，即**任一时刻只能有一个活跃线程调用管程中的过程**， 这一特性使**线程在调用执行管程中过程时能保证互斥**，这样线程就可以放心地访问共享变量。 管程是编程语言的组成部分，编译器知道其特殊性，因此可以采用与其他过程调用不同的方法来处理对管程的调用。

管程虽然借助编译器提供了一种实现互斥的简便途径，但这还不够，还需要一种线程间的沟通机制。 首先是等待机制：由于线程在调用管程中某个过程时，发现某个条件不满足，那就在无法继续运行而被阻塞。 其次是唤醒机制：另外一个线程可以在调用管程的过程中，把某个条件设置为真，并且还需要有一种机制，及时唤醒等待条件为真的阻塞线程。为了避免管程中同时有两个活跃线程， 我们需要一定的规则来约定线程发出唤醒操作的行为。目前有三种典型的规则方案：

- Hoare 语义：线程发出唤醒操作后，**马上阻塞自己，让新被唤醒的线程运行**。注：**此时唤醒线程的执行位置还在管程中**。
- Hansen 语义：执行唤醒操作的线程必须**立即退出管程**，即唤醒操作只可能作为一个管程过程的最后一条语句。 注：**此时唤醒线程的执行位置离开了管程**。
- Mesa 语义：唤醒线程在发出行唤醒操作后**继续运行**，并且**只有它退出管程之后，才允许等待的线程开始运行**。 注：**此时唤醒线程的执行位置还在管程中**。

基于 Mesa 语义的沟通机制。具体实现就是 **条件变量** 和对应的操作：wait 和 signal。线程使用条件变量来等待一个条件变成真。 条件变量其实是一个线程等待队列，当条件不满足时，线程通过执行条件变量的 wait 操作就可以把自己加入到等待队列中，睡眠等待该条件。另外某个线程，当它改变条件为真后， 就可以通过条件变量的 signal 操作来唤醒一个或者多个等待的线程（通过在该条件上发信号），让它们继续执行。

# ArceOS

## Unikernel 基础与框架

### Hello World

**内核系统**：运行在内核态的软件，向下管理硬件，向上为应用提供运行环境。**可以**独立运行。在 Rust 中，相当于`[bin].crate`

**内核组件**：用于构建内核系统的最基本元素，最小可部署单元。组件可以独立构建和分发，**不能**独立运行。在 Rust 中，相当于`[lib].crate`

应用与内核：

1. 处于**同一特权级** - 内核态
2. 共享**同一地址空间** - 相互可见
3. 编译形成**一个Image，一体运行**
4. Unikernel既是应用又是内核，是二者**合体**

优势：简单高效。

劣势：安全性低。

引导过程: axhal(riscv64)

```rust
#[naked]
#[no_mangle]
#[link_section = ".text.boot"]
unsafe extern "C" fn _start() -> ! {
    // PC = 0x8020_0000
    // a0 = hartid
    // a1 = dtb
    core::arch::asm!("
        mv      s0, a0                  // hartid 用于将来识别 CPU
        mv      s1, a1                  // dtb_ptr 传入 DTB 的指针
        la      sp, {boot_stack}
        li      t0, {boot_stack_size}
        add     sp, sp, t0              // 尽早建立栈，后面可以开展函数调用
        call    {init_boot_page_table}
        call    {init_mmu}              // 准备页表，启用MMU分页机制
        li      s2, {phys_virt_offset}  // 由于地址空间切换了，重置栈指针
        add     sp, sp, s2
        mv      a0, s0
        mv      a1, s1
        la      a2, {entry}
        add     a2, a2, s2
        jalr    a2                      // call rust_entry(hartid, dtb)
        j       .",
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        boot_stack_size = const TASK_STACK_SIZE,
        boot_stack = sym BOOT_STACK,
        init_boot_page_table = sym init_boot_page_table,
        init_mmu = sym init_mmu,
        entry = sym super::rust_entry,
        options(noreturn),
    )
}

unsafe extern "C" fn rust_entry(cpu_id: usize, dtb: usize) {
    crate::mem::clear_bss();
    crate::cpu::init_primary(cpu_id);
    crate::arch::set_trap_vector_base(trap_vector_base as usize);
    self::time::init_early();
    rust_main(cpu_id, dtb); // 进入axruntime
}
```

引导过程: axruntime

```rust
#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn rust_main(cpu_id: usize, dtb: usize) -> ! {
    ax_println!("{}", LOGO); // 打印LOGO和基本信息
    ax_println!(
        "\
        arch = {}\n\
        platform = {}\n\
        target = {}\n\
        smp = {}\n\
        build_mode = {}\n\
        log_level = {}\n\
        ",
        option_env!("AX_ARCH").unwrap_or(""),
        option_env!("AX_PLATFORM").unwrap_or(""),
        option_env!("AX_TARGET").unwrap_or(""),
        option_env!("AX_SMP").unwrap_or(""),
        option_env!("AX_MODE").unwrap_or(""),
        option_env!("AX_LOG").unwrap_or(""),
    );

    #[cfg(feature = "rtc")]
    ax_println!(
        "Boot at {}\n",
        chrono::DateTime::from_timestamp_nanos(axhal::time::wall_time_nanos() as _),
    );
    axlog::init();
    axlog::set_max_level(option_env!("AX_LOG").unwrap_or("")); // 初始化日志机制
    info!("Logging is enabled.");
    info!("Primary CPU {} started, dtb = {:#x}.", cpu_id, dtb);
    info!("Found physcial memory regions:");
    for r in axhal::mem::memory_regions() { // 显示kernel各个段的范围和属性
        info!(
            "  [{:x?}, {:x?}) {} ({:?})",
            r.paddr,
            r.paddr + r.size,
            r.name,
            r.flags
        );
    }

    #[cfg(any(feature = "alloc", feature = "alt_alloc"))]
    init_allocator(); // 初始化Rust的全局内存分配器(堆)

    #[cfg(feature = "paging")]
    axmm::init_memory_management(); // 重新映射kernel的各个段, 精确控制各段安全权限
    info!("Initialize platform devices...");
    axhal::platform_init(); // 本平台platform初始化(platform和arch的关联)

    #[cfg(feature = "multitask")]
    axtask::init_scheduler(); // 基于task的调度器，即thread调度

    #[cfg(any(feature = "fs", feature = "net", feature = "display"))]
    {
        #[allow(unused_variables)]
        let all_devices = axdriver::init_drivers(); // 设备与驱动初始化

        #[cfg(feature = "fs")]
        axfs::init_filesystems(all_devices.block); // 文件系统

        #[cfg(feature = "net")]
        axnet::init_network(all_devices.net); // 网络系统

        #[cfg(feature = "display")]
        axdisplay::init_display(all_devices.display);
    }

    #[cfg(feature = "smp")]
    self::mp::start_secondary_cpus(cpu_id); // 启动其它CPU, 传参排除primary

    #[cfg(feature = "irq")]
    {
        info!("Initialize interrupt handlers...");
        init_interrupt(); // 初始化中断
    }

    #[cfg(all(feature = "tls", not(feature = "multitask")))]
    {
        info!("Initialize thread local storage...");
        init_tls();
    }

    info!("Primary CPU {} init OK.", cpu_id);
    INITED_CPUS.fetch_add(1, Ordering::Relaxed); // Primary cpu信号自加1 (其它secondary cpu类似)

    while !is_init_ok() {
        core::hint::spin_loop(); // 等待所有cpu都已经启动
    }

    unsafe { main() }; // 进入apps/helloworld/main

    #[cfg(feature = "multitask")]
    axtask::exit(0); // 退出前清理
    #[cfg(not(feature = "multitask"))]
    {
        debug!("main task exited: exit_code={}", 0);
        axhal::misc::terminate();
    }
}
```

`axhal`用于屏蔽体系结构和平台差异，例如本示例在编译时指定`ARCH=riscv64`，则会产生对应feature，指示`axhal`条件编译对应的代码，最终通过`sbi::putchar`打印到console。

```rust
#![cfg_attr(feature = "axstd", no_std)] // 没有std标准库支持
#![cfg_attr(feature = "axstd", no_main)] // 不提供main入口

#[cfg(feature = "axstd")]
use axstd::println;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    println!("Hello, Arceos!");
}
```

`println!`调用链

```rust
// arceos/ulib/axstd/src/macros.rs
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {
        $crate::io::__print_impl(format_args!("{}\n", format_args!($($arg)*)));
    }
}

// arceos/ulib/axstd/src/io/stdio.rs
#[doc(hidden)]
pub fn __print_impl(args: core::fmt::Arguments) {
    if cfg!(feature = "smp") {
        // synchronize using the lock in axlog, to avoid interleaving
        // with kernel logs
        arceos_api::stdio::ax_console_write_fmt(args).unwrap();
    } else {
        stdout().lock().write_fmt(args).unwrap();
    }
}

// arceos/ulib/axstd/src/io/stdio.rs
fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    arceos_api::stdio::ax_console_write_bytes(buf)
}

// arceos/api/arceos_api/src/imp/mod.rs
pub fn ax_console_write_bytes(buf: &[u8]) -> crate::AxResult<usize> {
    axhal::console::write_bytes(buf);
    Ok(buf.len())
}

// arceos/modules/axhal/src/lib.rs
pub fn write_bytes(bytes: &[u8]) {
    for c in bytes {
        putchar(*c);
    }
}

// arceos/modules/axhal/src/platform/riscv64_qemu_virt/console.rs
pub fn putchar(c: u8) {
    #[allow(deprecated)]
    sbi_rt::legacy::console_putchar(c as usize);
}
```

在编译并运行`helloworld`时，可以指定`LOG`环境变量，以输出不同级别的日志。

```shell
make LOG=info run
```

这是通过features传递，改变kernel行为的具体方法。可以通过三种方式指定features：这是通过features传递，改变kernel行为的具体方法。可以通过三种方式指定features：

- App: `Cargo.toml`
- 具体环境变量: `LOG`
- 通用环境变量: `FEATURES`

### Collections

**对基于“堆”的动态数据结构类型的支持？**Rust Collections 标准类型需要动态内存分配支持。在内核开发层面，没有另外一个 OS 内核为其提供内存管理的支持。只能由内核自己实现`global_allocator`适配自身的内存管理子系统。

内存分配 – 接口和数据结构

```rust
unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Ok(ptr) = GlobalAllocator::alloc(self, layout) {
            ptr.as_ptr()
        } else {
            alloc::alloc::handle_alloc_error(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        GlobalAllocator::dealloc(self, NonNull::new(ptr).expect("dealloc null ptr"), layout)
    }
}

#[cfg_attr(all(target_os = "none", not(test)), global_allocator)]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

/// Returns the reference to the global allocator.
pub fn global_allocator() -> &'static GlobalAllocator {
    &GLOBAL_ALLOCATOR
}

pub struct GlobalAllocator {
    balloc: SpinNoIrq<DefaultByteAllocator>,
    palloc: SpinNoIrq<BitmapPageAllocator<PAGE_SIZE>>,
}
```

内存分配 – 框架初始化

```rust
pub fn init(&self, start_vaddr: usize, size: usize) {
    assert!(size > MIN_HEAP_SIZE);
    let init_heap_size = MIN_HEAP_SIZE;
    self.palloc.lock().init(start_vaddr, size);
    let heap_ptr = self
    .alloc_pages(init_heap_size / PAGE_SIZE, PAGE_SIZE)
    .unwrap();
    self.balloc.lock().init(heap_ptr, init_heap_size);
}

pub fn alloc(&self, layout: Layout) -> AllocResult<NonNull<u8>> {
    // simple two-level allocator: if no heap memory, allocate from the page allocator.
    let mut balloc = self.balloc.lock();
    loop {
        if let Ok(ptr) = balloc.alloc(layout) {
            return Ok(ptr);
        } else {
            let old_size = balloc.total_bytes();
            let expand_size = old_size
            .max(layout.size())
            .next_power_of_two()
            .max(PAGE_SIZE);
            let heap_ptr = self.alloc_pages(expand_size / PAGE_SIZE, PAGE_SIZE)?;
            debug!(
                "expand heap memory: [{:#x}, {:#x})",
                heap_ptr,
                heap_ptr + expand_size
            );
            balloc.add_memory(heap_ptr, expand_size)?;
        }
    }
}
```

**TLSF (Two-Level Segregated Fit)**

两级 bitmap + List 管理空闲块

bitmap第一级：每一位对应一个范围的内存块，示例中分别对应$2^4$ ~ $2^{31}$。1表示空闲。

bitmap第二级：有几位就表示几等分。例如， $2^6$ 表示64\~127，然后进行4等分就是64~79, 80~95, 96~107, 108~127，每一位对应一个范围，1表示空闲。

然后就能找到包含对应范围大小的空闲块链表List。链表耗尽或者新建时，对应维护两级bitmap。

**Buddy**

分配单元：一般不会采用1字节，通常8，16，32…字节

分配：寻找匹配需要(order)的最小块。如果order大于目标，则二分切割，直至相等，每级剩余的部分挂到对应的 Order List

释放：查看是否有邻居空闲块，有则尽可能向高Oder合并，直至无法合并，挂到 Order List。

**Slab**

结构：

1) 通过OrderList维护一系列Slab
2) Slab维持一个空闲的block链表

分配：从block空闲链表中弹出一个block。依靠 Buddy Allocator提供内存分配支持，初始时以及block不足时，从Buddy Allocator申请，分割block后加入block空闲链表。

释放：放回block空闲链表。

## Unikernel 地址空间与分页、多任务支持(协作式)

### ReadPFlash

PFlash的作用？Qemu 的 PFlash **模拟闪存磁盘**，启动时自动从文件加载内容到固定的 MMIO 区域，而且对读操作不需要驱动，可以直接访问。

为何不指定"paging"时导致读PFlash失败？ArceOS Unikernel包括**两阶段地址空间映射**，Boot阶段默认开启1G空间的恒等映射；如果需要支持设备MMIO区间，通过指定一个feature - "paging"来实现重映射。

分页启用的两个阶段：早期启用(必须)和后期重建映射(可选) 。

阶段1：内核启动的早期，采用规定的恒等映射方式。但是只映射一部分物理空间。

**目标**：完成Paging切换后，建立从虚拟空间`0xffff_ffc0_8000_0000` ~ `0xffff_ffc0_c000_0000`到物理空间`0x8000_0000`~`0xc000_0000` 的映射，范围 1G。

两步完成Paging切换：

1.恒等映射保证虚拟空间与物理空间有一个相等范围的地址空间映射(`0x8000_0000`~`0xc000_0000`)。切换前后地址范围不变，但地址空间已经从物理空间切换到虚拟空间。

2.给指令指针寄存器`pc`，栈寄存器`sp`等加偏移，在图中该偏移是`0xffff_ffc0_0000_0000`。如此在虚拟空间执行平移后，就完成到最终目标地址的映射。

```rust
#[link_section = ".data.boot_page_table"]
static mut BOOT_PT_SV39: [u64; 512] = [0; 512]; // 使用的是LDS定义布局时，直接预留的一页，所以不用额外内存分配

unsafe fn init_boot_page_table() {
    // 0x8000_0000..0xc000_0000, VRWX_GAD, 1G block
    BOOT_PT_SV39[2] = (0x80000 << 10) | 0xef;
    // 0xffff_ffc0_8000_0000..0xffff_ffc0_c000_0000, VRWX_GAD, 1G block
    BOOT_PT_SV39[0x102] = (0x80000 << 10) | 0xef;
}

unsafe fn init_mmu() {
    let page_table_root = BOOT_PT_SV39.as_ptr() as usize;
    satp::set(satp::Mode::Sv39, 0, page_table_root >> 12);
    riscv::asm::sfence_vma_all();
}	
```

初始化根页表`BOOT_PT_SV39`，只有一级，即**每个页表项直接映射到 1G 的地址空间**。1G = $2^{30}$ 因此页表项 ID `pgd_idx == (VA >> 30) & (512 - 1)`

`0x8000_0000 >> 30 == 2`，即页表第 2 项指向`0x8000_0000`~`0xc000_0000`

`(0xffff_ffc0_8000_0000 >> 30) & (512 - 1) == 102`，即页表第 102 项指向`0xffff_ffc0_8000_0000`~`0xffff_ffc0_c000_0000`

物理页帧号 == 物理地址 `0x8000_0000 >> 12 == 0x80000`

指定paging feature的情况下，启动后期重建完整的空间映射。paging不是决定分页是否启用，而是决定是否包含阶段2。

内存管理框架与功能：

1) 内存分配功能

内含两类分配器，**字节分配器**和**页分配器**。框架与算法分离，松耦合支持多种内存分配算法。

2) 分页功能

启动早期基于静态恒等映射完成分页切换，如果指定paging feature则会在启动后期重新建立范围更大，权限控制更细的映射。

### ChildTask

```rust
pub struct TaskInner {
    id: TaskId,
    name: String,
    is_idle: bool, // 是否为系统任务idle
    is_init: bool, // 是否为主线程

    entry: Option<*mut dyn FnOnce()>, // 实现任务逻辑函数的入口
    state: AtomicU8, // 任务状态

    in_wait_queue: AtomicBool,
    #[cfg(feature = "irq")]
    in_timer_list: AtomicBool,

    #[cfg(feature = "preempt")]
    need_resched: AtomicBool,
    #[cfg(feature = "preempt")]
    preempt_disable_count: AtomicUsize,

    exit_code: AtomicI32,
    wait_for_exit: WaitQueue,

    kstack: Option<TaskStack>, // 栈空间
    ctx: UnsafeCell<TaskContext>, // 上下文
    task_ext: AxTaskExt, // 任务的扩展属性，对于Unikernel为空

    #[cfg(feature = "tls")]
    tls: TlsArea,
}
```

接口公开的是runqueue的对应方法

`spawn`&`spawn_raw`：产生一个新任务，加入runqueue，处于Ready

`yield_now` (协作式调度的关键)：主动让出CPU执行权

`sleep`&`sleep_until`：睡眠固定的时间后醒来，在timers定时器列表中注册，等待唤醒

`exit`：当前任务退出，标记状态，等待GC回收

```rust
pub fn init_scheduler() {
    info!("Initialize scheduling...");
    crate::run_queue::init(); // 任务调度框架的核心
    #[cfg(feature = "irq")]
    crate::timers::init(); // 负责维护定时器列表，支持sleep等API的实现
    info!("  use {} scheduler.", Scheduler::scheduler_name());
}

pub(crate) fn init() {
    // Create the `idle` task (not current task).
    const IDLE_TASK_STACK_SIZE: usize = 4096;
    let idle_task = TaskInner::new(|| crate::run_idle(), "idle".into(), IDLE_TASK_STACK_SIZE);
    IDLE_TASK.with_current(|i| {
        i.init_once(idle_task.into_arc());
    });
    // Put the subsequent execution into the `main` task.
    let main_task = TaskInner::new_init("main".into()).into_arc();
    main_task.set_state(TaskState::Running);
    unsafe { CurrentTask::init_current(main_task) };
    RUN_QUEUE.init_once(AxRunQueue::new());
}
```

### MsgQueue

上下文Context包含寄存器:

1)`ra`: 函数返回地址寄存器，这个切换实现了任务执行指令流的切换。

2)`sp`: 任务即线程，这个是线程栈

3)`s0`~`s11`：按照riscv规范，callee不能改这组寄存器的信息，所以需要保存。

自旋锁：

对于单CPU，加锁时只需要**关中断** + **关抢占**。无须额外的临界区互斥操作。

对于SMP，才需要**基于相互可见的内存变量**进行原子互斥操作。

互斥锁：

通常可以认为是：**等待队列**waitq + **自旋锁**spinlock。

等待队列是针对某种资源，任务之间进行协调。至多只能有一个任务持有资源，多于一个的任务进入睡眠状态，转入等待队列；直至被唤醒。

## Unikernel 任务调度-抢占式、块设备与文件系统

### FairSched

抢占式调度：调度器依据策略，可以打断当前任务的执行，移交CPU执行权给当前“更”有资格 的任务。抢占机制的根本保障是系统定时器。所以抢占针对的主要操作目标就是current task当前任务。

机制与时机：**不是无条件**的抢占，要两个条件都具备

- 一是任务内部达到了某种条件，例如时间片耗尽；

- 二是外部条件与时机，在preempt从disable到enable的那个状态切换点触发抢占。

1. 只有内外条件都满足时，才发生抢占；内部条件举例任务时间片耗尽，外部条件类似定义某种临界区，控制什么时候不能抢占，本质上它基于当前任务的`preempt_disable_count`。
2. 只在 禁用->启用 切换的下边沿触发；下边沿通常在自旋锁解锁时产生，此时是切换时机。
3. 推动内部条件变化(例: 任务时间片消耗)和边沿触发产生(例: 自旋锁加解锁)的根本源是时钟中断。

抢占针对的目标就是当前任务，由外部控制的抢占开关是当前任务的`preempt_disable_count`。作为计数：**0代表开抢占，大于0则关抢占**(可叠加，所以可能大于1)

时钟中断与抢占式调度

```rust
#[cfg(feature = "irq")]
fn init_interrupt() {
    use axhal::time::TIMER_IRQ_NUM;

    // Setup timer interrupt handler
    const PERIODIC_INTERVAL_NANOS: u64 =
        axhal::time::NANOS_PER_SEC / axconfig::TICKS_PER_SEC as u64;

    #[percpu::def_percpu]
    static NEXT_DEADLINE: u64 = 0;

    fn update_timer() {
        let now_ns = axhal::time::monotonic_time_nanos();
        // Safety: we have disabled preemption in IRQ handler.
        let mut deadline = unsafe { NEXT_DEADLINE.read_current_raw() };
        if now_ns >= deadline {
            deadline = now_ns + PERIODIC_INTERVAL_NANOS;
        }
        unsafe { NEXT_DEADLINE.write_current_raw(deadline + PERIODIC_INTERVAL_NANOS) };
        axhal::time::set_oneshot_timer(deadline);
    }
	// 通过axhal 注册时钟中断，定期触发 axtask::on_timer_tick
    axhal::irq::register_handler(TIMER_IRQ_NUM, || {
        update_timer();
        #[cfg(feature = "multitask")]
        axtask::on_timer_tick();
    });

    // Enable IRQs before starting app
    axhal::arch::enable_irqs();
}

#[cfg(feature = "irq")]
#[doc(cfg(feature = "irq"))]
pub fn on_timer_tick() {
    crate::timers::check_events();
    RUN_QUEUE.lock().scheduler_timer_tick();
}

#[cfg(feature = "irq")]
pub fn scheduler_timer_tick(&mut self) {
    let curr = crate::current();
    // 触发特定调度器的task_tick，决定是否标记抢占标志，并可能进一步的导致任务队列的重排
    if !curr.is_idle() && self.scheduler.task_tick(curr.as_task_ref()) {
        #[cfg(feature = "preempt")]
        curr.set_preempt_pending(true);
    }
}
```

### ReadBlock

**AllDevices**管理系统所有的设备，为上层的子系统如文件系统FS、网络协议栈NET提供访问服务。三种设备类型：

- 网络设备
- 块设备
- 图形设备

设备发现与初始化过程

- 主干组件`axruntime`在启动后期，发现设备并用相应驱动进行初始化
- `axdriver`负责发现设备和对其初始化的过程，核心结构`AllDevices`
- `probe`基于总线发现设备，逐个匹配驱动并初始化
- 按照平台，有两种总线：
  1) PCI总线：基于PCI总线协议发现和管理设备，对应PC & Server
  2) MMIO总线：通常基于FDT解析发现和管理设备(目前未实现)

目前管理设备和驱动数量少，采用简单方式，两级循环探测发现设备：

第一级：遍历所有`virtio_mmio`地址范围，由平台物理内存布局决定并进行过分页映射

第二级：用`for_each_drivers`宏枚举设备，然后对每个virtio设备`probe_mmio`进行探查

virtio设备的probe过程

1) qemu模拟器基于命令行产生设备

```shell
-device virtio-blk-device,drive=disk0
-drive id=disk0,format=raw,file=disk**.**img
```

2) qemu将设备mmio地址区域映射到Guest中

qemu-virt平台默认有8个区域槽位，通常只有部分会形成映射，其它处于未映射状态，即表现为空设备

3) virtio-mmio驱动逐个发请求区探查3这些区域槽位

对应映射设备响应请求，返回本设备的类型ID；

没有映射的槽位返回零，表示空设备。

4) virtio-mmio驱动把probe结果报告上层

### LoadApp

mount可以理解为文件系统在内存中的展开操作（unflatten），把易于存储的扁平化的形态转化为易于搜索遍历的立体化形态。

把一棵目录树的“根” "嫁接"到另一棵树的某个结点，两棵树就形成了一棵树。两棵目录树基于的文件系统可以相同也可以不同。

被mount的结点及其子孙结点都会被遮蔽，直至unmount。lookup操作到达mount点时，将会发生访问目录树的切换。

## 从 Unikernel 到宏内核

### UserPrivilege

如何以 Unikernel 为基础，构建最小化宏内核？

1. 能够创建和管理内核**地址空间**，为用户地址空间保留低端内存区域

2. 可以从基于块设备的**文件系统**中搜索和读入应用程序文件

3. 能够创建**子线程**任务，与主线程并发运行单独的逻辑代码

4. 能够响应**异常和中断**

从 Unikernel 基础到目标最小化宏内核需要完成的增量工作：

1. 用户地址空间的创建和区域映射
2. 在异常中断响应的基础上增加系统调用
3. 复用 Unikernel 原来的调度机制，针对宏内核扩展 Task 属性
4. 在内核与用户两个特权级之间的切换机制

示例`m_1_0`的执行逻辑：

1. 创建用户地址空间
2. 加载应用origin到地址空间
3. 在地址空间中建立用户栈
4. 伪造一个返回应用的环境上下文现场
5. 把伪造现场设置到到新任务的内核栈上
6. 启动新任务执行`sret`指令返回到用户态，从应用origin的entry开始执行
7. 应用origin只包含一行代码，即执行系统调用`sys_exit`
8. 注册在异常中断向量表中的系统调用响应函数处理`sys_exit`，内核退出

宏内核模式为用户应用建立了两类上下文，用户应用进程在它们之间交替运行：

1. **任务上下文** - 用户态：正常执行应用逻辑，也称为进程上下文
2. **异常上下文** - 内核态：处理系统调用与异常

```rust
fn main() {
    // 为应用创建独立的用户地址空间
    let mut uspace = axmm::new_user_aspace().unwrap();
    // 加载应用程序代码到地址空间
    if let Err(e) = load_user_app("/sbin/origin", &mut uspace) {
        panic!("Cannot load app! {:?}", e);
    }
    // 初始化用户栈
    let ustack_top = init_user_stack(&mut uspace, true).unwrap();
    ax_println!("New user address space: {:#x?}", uspace);
    // 创建用户任务
    let user_task = task::spawn_user_task(
        Arc::new(Mutex::new(uspace)),
        UspaceContext::new(APP_ENTRY.into(), ustack_top),
    );
    // 让出CPU，使得用户任务运行
    let exit_code = user_task.join();
    ax_println!("monolithic kernel exit [{:?}] normally!", exit_code);
}
```

页表分为高低两个部分：**高**端作为**内核**空间，**低端**作为**用户**应用空间。

以初始的**内核根页表**为模板，为**每个应用进程复制独立页表**。**内核空间共享，用户空间独立使用**。

用户应用构建方式：Rust工具链 + Rust嵌入式汇编

示例：payload/origin

```rust
#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "addi sp, sp, -4",
        "sw a0, (sp)",
        "li a7, 93", // 93是 Sys_exit编号
        "ecall", // 通过ecall触发系统调用
        options(noreturn)
    )
}
```

首先编译`origin`生成ELF格式，然后被工具链转化为二进程BIN格式。

```shell
cargo build -p origin --target riscv64gc-unknown-none-elf --release
rust-objcopy --binary-architecture=riscv64 --strip-all -O binary [origin_elf] [origin_bin]
```

`BIN`格式作为`exercises/m_1_0`使用的用户应用image。

通过命令行`make disk_img`已经创建磁盘设备`disk.img`，并建立文件系统(fat32)。安装用户应用就是mount该磁盘设备文件到 `./mnt`目录，然后更新应用程序image。例如，安装应用`origin`的二进制Image：

```shell
mkdir -p ./mnt
mount $(1) ./mnt
mkdir -p ./mnt/sbin
cp /tmp/origin.bin ./mnt/sbin
umount ./mnt
```

把应用加载到用户地址空间

第一步，从文件加载代码到内存缓冲区。

第二步，为用户地址空间代码区域建立映射，拷贝代码到被映射页面中。

对于各类内核模式，调度子系统机制是基本一致的，调度仅关心 Task 中与调度相关的属性，不关心资源属性。模式之间区别主要就在于资源属性不同。Unikernel 模式下，资源都是全局的，**Task 几乎不包含资源属性**；宏内核模式下，以进程为单位管理和隔离资源，**Task 表示进程时，其中就要包含属于自己的资源引用**。

任务属性扩展机制的目的：尽可能复用共性的调度子系统，又能兼容处理各种模式的个性部分 - 资源管理。

对于 RiscV 等多数体系结构来说，并**不存在一个专门指令实现从内核态到用户态的切换**。

解决方法：在内核态伪造一个异常上下文现场，假装来自用户态，然后用`sret`指令返回去。

## 宏内核地址空间映射和 Linux 应用支持

### UserAspace

地址空间管理涉及的主要对象：`AddrSpace`，`MemorySet`，`MemoryArea`和`Backend`的两种实现。

`AddrSpace`：包含一系列有序的区域并对应一个页表。

`MemorySet`：对`BTreeMap`的简单封装，对空间下的各个`MemoryArea`进行有序管理。

`MemoryArea`：对应一个连续的虚拟地址内存区域，关联一个负责具体映射操作的后端`Backend`。

`Backend`：负责具体的映射操作，不同的区域`MemoryArea`可以对应不同的`Backend`。目前支持两种后端类型：`Linear`和`Alloc`。

对地址空间的主要操作就是查找目标区域或者是查找区域之间的空隙，因此对它们的有序管理是保证性能的关键。

后端负责针对空间中特定区域的具体的映射操作，`Backend`从实现角度是一个Trait。

`Linear`的应用场景：**目标物理地址空间区域已经存在，直接建立映射关系**。可以用于设备MMIO区域映射以及特殊的共享地址区域映射等。**对应的物理页帧必须连续**。

`Alloc`的应用场景：**仅建立空映射，当真正被访问时将会触发缺页异常**，然后在缺页响应函数内部完成物理页帧的申请和补齐映射。也就是 **Lazy** 方式。按页映射，**对应的物理页帧通常情况下不连续**。

### LinuxApp

如何让Linux的原始应用（二进制）直接在我们的宏内核上直接运行？

在应用和内核交互界面上实现兼容。兼容界面包含三类：

1. syscall
2. procfs & sysfs等伪文件系统
3. 应用、编译器和libc对地址空间的假定，涉及某些参数定义或某些特殊地址的引用

Linux 常用的文件系统包括 ProcFS、SysFS 和 DevFS，与普通文件系统不同，它们属于**伪文件系统**，具有相同的接口和抽象，但是 Backend 却不是普通的数据。

Procfs 用于提供**内核和进程**信息的接口。它通常挂载在 `/proc` 目录下，包含了大量关于系统和进程的信息。

Sysfs 用于向用户空间暴露**设备**信息。它通常挂载在 `/sys` 目录下。该文件系统主要用于**替代传统的 devfs**。

Devfs 用于向用户空间暴露**设备和驱动**信息。目前主要是为了**兼容性**而存在。

## 组件化内核的异构拓展实现

### 快速构建异构内核的设想

总结共性：Unikernel 基座

区分特性：

- 宏内核：进程、地址空间等
- 虚拟机管理程序：模拟 CPU 状态、虚拟机抽象与接口管理
- 微内核：IPC 机制实现

构建共通基座，利用组件化获取定制性

### 组件化异构内核的实践：ArceOS

基础架构：Unikernel

提供各类组件

- 内核无关组件：buddy、pagetable
- 内核相关组件：任务调度、驱动接口适配

提供对外接口，运行上层应用（称为内核应用）

- 区别于用户态应用
- 内核应用仍然运行在内核态

如何接入异构发展：对内核应用进行扩展

### ArceOS 接入异构内核

Backbone：Unikernel 本体

宏内核扩展：starry-next

- 地址空间管理
- 以进程为单位管理、隔离资源
- 引入 syscall 支持

Hypervisor：arceos-umhv

- Guest OS 调度与地址空间等管理
- 设备虚拟化（中断、串口等）
- VM exit 接口支持

### ArceOS 接入异构内核细节：Backbone 兼容

什么内容需要放在 Backbone？

- 与 Backbone 功能相关，如调度、trap
- 放在上层会导致模块关系混乱或打破依赖
- 可为其他架构所或其他内核所复用
- 实例：地址空间管理 axmm 模块

异构内核的核心：不同架构的资源管理兼容

- 如何做到兼容、可扩展、高性能兼顾？

### ArceOS 接入异构内核细节：task 扩展

内核资源的核心：任务单元设计

- 可以将任务视为内核资源的集合
- Unikernel：单个任务运行的必要信息，如上下文
- 宏内核：页表信息、文件描述符等
- Hypervisor：vcpu 状态等

如何实现异构任务的扩展，达到如下要求：

- 扩展性：尽可能减少对 backbone 的修改，易于复用
- 高性能：不应当为了兼容而让性能有较高损耗

方案一：在 task 中直接添加字段 

- 利用 feature 添加字段
- 用编译选项控制启动哪个架构
- **不会有性能影响**（编译期决定）
- **不利于可读性和异构扩展性**

方案二：利用**索引**指向完整扩展实现

- 仍然保留 Task 的机制
- 将扩展内容额外实现在新的结构中
- 两者通过某一个共通字段关联
- - 常用 TaskID 进行联系
- - 由于 Rust 限制，关联方式可选用 BTreeMap 等形式
- 保留了一定的**可扩展性**
- 但在查询索引的过程会带来**性能开销**

方案三：简化版 TLS 机制 —— 引入 extension 扩展机制

- 为 Task 引入一个 extension 域
- 当外部实现了扩展内容，可初始化 extension 域
- 使用**指针**进行调用，和传统结构体的访存开销近似
- 在**保证扩展性**的同时**不影响性能开销**

宏内核的扩展

- 预先定义好扩展对象
- 调用相关宏来初始化扩展域
- 之后便可像正常域使用

实现原理

- 编译期确定扩展域大小
- 在堆上申请内存
- 将扩展域指针指向该内存
- 对外提供相关的引用接口

优势

- 较低性能开销
- 自由扩展性（自由定义 extension）

### ArceOS 接入异构内核：系统服务复用

Unikernel 已经提供的系统服务，如何方便被其他架构复用？

挑战：资源隔离与共享

已有资源举例

- Fd_table
- Virtual memory management
- API handler

资源的隔离与共享

- Unikernel：全局唯一
- 宏内核：进程拥有资源，通过 clone 控制共享

一个复用的目标：api/arceos_posix_api

原目标：为 Unikernel 提供对 POSIX 接口的适配

异构化场景需求：宏内核 SYSCALL 层

- POSIX 接口语义检查细节繁多，容易出现问题
- 为了宏内核额外实现一个 syscall 层冗余且耗费精力
- 异构资源归属不同，但**语义检查可以复用**
- 通过配置，控制资源为 global 或者 per-process 资源

引入新数据结构

Resource

- 定义“资源”
- 利用 Arc 指针进行管理，可以在不同任务共享

NameSpace

- 保存所有的 Resource
- Unikernel：全局唯一
- 宏内核：类比控制块，每个任务一份，动态分配

Namespace 要求

- Unikernel：全局唯一
- 宏内核：
- - 支持独有或共享
- - 共享时不应当产生额外开销

实现方式

- 通过 `link_section` 确定 Resource 地址
- 编译期确定 global namespace 布局
- - 所有 resource 集中在 `axns_resource` 段
- - 构成了 global namespace
- 对于每一个独有的 namespace
- - 在堆上分配一段空间
- - 将 global namespace 拷贝过去
- 对每一个共享的 namespace
- - 利用 `Arc` 指针进行共享

Namespace 总结

- 资源控制块的拆分
- 支持方便地定义新资源，并通过配置修改其属性
- 联动组件化的思想，让新功能更易接入
- 复用已有的 POSIX 接口实现并且进一步扩展，降低工作量

## 虚拟化原理和最简 Hypervisor

## Hypervisor 地址空间管理基础

## 虚拟机时钟中断和虚拟设备
