# 2024 秋冬季开源操作系统训练营学习记录

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

