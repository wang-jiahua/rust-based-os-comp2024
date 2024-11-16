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

### lab1

`TaskControlBlock` 新增字段 `syscall_times`，保存每个系统调用的次数。

 `TaskManager` 新增方法 `increase_syscall_time()` 和 `get_syscall_times()`，分别增加系统调用次数和获取系统调用次数。同时包装为同名函数，内部调用 `TASK_MANAGER` 的方法。

执行 `syscall()` 时首先调用 `increase_syscall_time()` 增加系统调用次数。

`sys_task_info()` 设置 `TaskInfo` 的 `status` 为 `TaskStatus::Running`，`syscall_times` 从 `get_syscall_times()` 中获取，`time` 从 `get_time_ms()` 中获取。

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

### lab 2
