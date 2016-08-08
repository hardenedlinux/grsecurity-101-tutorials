面向桌面的 PaX/Grsecurity 配置详细注释与评论
==============================================

**注意：不要盲目听信“建议”！适合的才是最好的！**

## → Security options → Grsecurity --->

#### [\*] Grsecurity

强烈建议选择 Y。

开启这个选项显然不需要解释……什么？你说不开启任何 Grsecurity 选项的
内核也有一些内核源码级的安全与编译加固，好吧没错，但是……

#### Configuration Method --->

- Automatic
- Custom

PaX 自带进行「安全」和「性能」两种自带配置集合。但是如果你愿意的话，
还是可以自行从头配置。

作为初学者，可能还是从自动配置的基础上微调比较好。

### 以下标签仅在 Configuration Method 选择 Automatic 的情况下出现。

#### Usage Type --->

- Server
- Desktop

就按照英文的意思选就行啦~

#### Virtualization Type --->

- None
- Guest
- Host

根据虚拟化的场景选择就好啦~

#### Virtualization Hardware --->

- EPT/RVI Processor Support
- First-gen/No Hardware Virtualization

前一个选项会启用一些对新式虚拟化技术特别的优化，但是后一个选项则是追求稳妥。

如果你的硬件够新（其实好像 Sandy Bridge+ 就够了），选第一个选项。

如果你的硬件太老，你可能需要上 http://www.jd.com 来解决这个问题，或者选择后一个选项。

#### Virtualization Software --->

- Xen
- VMware
- KVM
- VirtualBox
- Hyper-V

根据你要用到的虚拟化软件选择。

#### Required Priorities --->

- Performance (CONFIG_GRKERNSEC_CONFIG_PRIORITY_PERF)
- Security (CONFIG_GRKERNSEC_CONFIG_PRIORITY_SECURITY)

鱼与熊掌不可兼得，这里就需要在 Performance 和 Security 之间做个取舍啦~

## → Security options → Grsecurity → Customize Configuration → PaX --->

#### [\*] Enable various PaX features (CONFIG\_PAX)

强烈建议选择 Y。

\ 打 Grsecurity 不开 PaX 和咸鱼又有什么两样！ /

### → PaX Control --->

#### [ ] Support soft mode

建议选择 N，否则 PaX 只会在有主动标记的程序上启用 PaX。

当然对于某些专用的内核，可以仅对关键进程启用 PaX。

#### [\*] Use legacy ELF header marking

对 EI\_PAX PaX Flags 的处理。

（反正这么老的 PaX Flags 已经很少人用了……）

建议……看心情吧。

#### [\*] Use ELF program header marking

强烈建议选择 Y。对 PT\_PAX PaX Flags 的处理。

PT\_PAX 现在依然处于被支持状态喔~

#### [\*] Use filesystem extended attributes marking

强烈建议选择 Y。对 XATTR\_PAX PaX Flags 的处理。

XATTR\_PAX 现在被广泛使用。

*注：以上三个选项可以参见 [《PaX 基础》](pax-basic.md)*

#### MAC system integration --->

- none
- direct
- hook

与 MAC 系统的整合选项。

如果要在 Grsecurity 之外另外使用其他 MAC 系统，则需要按照 MAC 系统的要求选择对应选项。

### → Non-executable pages --->

#### [\*] Enforce non-executable pages

建议选择 Y。这个选项会启用下列的一系列用户空间代码执行相关的加固选项。

#### [\*] Paging based non-executable pages

建议选择 Y。这个特性能够使得不应该被执行的页面（比如数据/栈），真正地不被执行。（即 PAGEEXEC ）

#### [ ] Emulate trampolines

建议选择 N。这个特性是对旧的程序（执行栈里的短代码）的一种 workaround，现在已经不需要。

#### [?] Restrict mprotect()

谨慎选择。这个特性能够彻底阻止程序执行实时写入的代码，但是却会阻止很多 JIT 被运行……

这个特性威力很强大，但是也很容易影响使用，可能需要给大量程序设置例外。

所以，请三思。请三思。请三思。

*注：以上三个选项可以参见 [《PaX 基础》](pax-basic.md)*

#### [ ] Use legacy/compat protection demoting (read help)

建议选择 N。又是一个对旧系统+缺陷代码的 workaround 。

#### [ ] Allow ELF text relocations (read help)

建议选择 N。除非你有 x86\_32 的非 PIC 动态库需要使用。（这些库需要 relocation）

#### [?] Enforce non-executable kernel pages

谨慎选择，可能有坑。

相当于内核里的 MPROTECT 和 PAGEEXEC，但是有些内核代码需要这种机制。

如果出了问题，试试关掉它吧。

#### Code Pointer Instrumentation Method --->

- none
- bts
- or

“none”的话，就是“无为而治”，把保护不被执行的问题甩给 CPU 。性能和模块兼容性都最好，但是需要 Sandy Bridge 或更新的处理器。

“bts“ 和 ”or“ 都是用 GCC Plugin 的做法。前者性能影响较大，但是与 Binary Modules 兼容；后者性能影响较小，但是与第三方模块兼容性比较差。

### Address Space Layout Randomization --->

#### [\*] Address Space Layout Randomization

强烈建议选择 Y！这个特性能够以较小 Performance Overhead 换来对很多攻击的直接防范，物超所值。

而且下面两个特性也依赖于这个特性。

#### [?] Randomize kernel stack base

比较建议选择 Y，但使用 VirtualBox 或者其他写的不太好的第三方模块的话，需要关掉这个特性。

这个特性可以抵御一些 Ring0 的提权攻击。

#### [\*] Randomize user stack and mmap() bases

建议选择 Y。这个特性可以在一定程度上避免用户空间的攻击。（如对 mmap 地址的探测）

（反正这个特性可以通过 PaX Flags 开关）（逃）

### → Miscellaneous hardening features --->

#### [\*] Sanitize all freed memory

建议选择 Y，PaX 会在内核释放内存时，自动清空内存。降低内核存在漏洞导致
敏感信息被攻击者获得的可能性。这在单核系统上的开销约为 3%。

#### [\*] Sanitize kernel stack

建议选择 Y，PaX 会在内核系统调用返回时自动清空内核栈，降低内核存在漏洞导致
敏感信息被攻击者获得的可能性。这在单核系统上的开销约为 1%。

#### [\*] Forcibly initialize local variables copied to userland

建议选择 Y，PaX 会在将一些内核局部变量在拷贝到用户空间之前，以 0 初始化这些
变量。这在单核系统上的开销小于 1%。

#### [ ] Prevent invalid userland pointer dereference

建议关闭，坑太多。PaX 会在内核内部代码中阻止用户空间指针的解引用，因为这些指针在本不
该出现内核。这可以避免相当一大类针对内核漏洞的攻击。但这在某些虚拟化环境下可能会
导致可见的性能损失，特别是在 x86 和不支持虚拟化指令集的 CPU 上。如果这是一台虚拟
机容器母机你可能需要在启用前考虑考虑。

对于 Broadwell 以上的处理器，可以使用处理器的 SMAP 特性代替本软件特性，能够避免许多坑。

（注： SMAP 当被单独依赖的情况下有一定可能性被 Bypass ，UDEREF 并没有）

#### [\*] Prevent various kernel object reference counter overflows

建议选择 Y，PaX 会避免许多内核引用计数器溢出，杜绝多数对内核的此类攻击。为避免后续的内
存破坏，当 PaX 发现引用计数器出现泄漏时，对应的内存将永远不会被释放，但这对于
数字节的内核数据结构很少成为问题，而且这项保护措施几乎不会导致任何性能影响。

#### [ ] Automatically constify eligible structures

建议选择 N。这个选项会常量化很多内核里的函数指针数组，从而避免函数被“重载”。

同样，这可能对第三方模块造成伤害。

#### [\*] Harden heap object copies between kernel and userland

建议选择 Y，PaX 会在数据在用户空间与内核空间互相传递时，进行一系列的双向保护和检查措施，
严防途中出现疏漏。这些保护措施几乎不会导致任何性能损失。

然而，这会导致第三方内核不能通过检查，需要修改。明显了两个例子是 ZFS 与 nvidia-drivers，前者
得到了官方上游支持，后者得到了 PaX Team 的支持。但对于其他补丁和模块就没有办法了。然而使用
PaX 内核本身，你显然已经做好了不使用这些模块的准备。

注：该特性已并入 linux-next ，很可能出现在 4.9 内核中。第三方模块开发者们，面对疾风吧！

#### [ ] Prevent various integer overflows in function size parameters

建议选择 N，否则 PaX 会使用 GCC 插件检查所有函数的整数变量溢出问题，一旦发现就终止函数的
执行。这在几乎没有什么内核模块的服务器上是非常建议开启的，但在桌面系统上会导致大量驱动
程序触发保护，日志数量能卡死内核。而修补这些驱动则是一个没有尽头的工作，但绝大多数代码
都会在几年之内被修补。

#### [\*] Generate some entropy during boot and runtime

建议选择 Y，让 PaX 在内核启动和运行时生产一些随机量提供给熵池。缺少熵是当今 Linux 系统安全
的重大威胁，在完全没有用户交互的服务器上更加严重。因此务必引起警觉，安装 haveged 等程序。
但就算是采取了这样的措施，在系统启动时也没有初始的熵，PaX 为这类情况提供了这个很好的应急措施。

当然了，PaX 的熵是不具备密码学安全性的，但我们时常过于担心熵池中的随机量不够随机导致安全问题，
而忽略了完全没有熵这个更大的问题。

#### [ ] Prevent code reuse attacks

建议选择 N。这个选项能避免代码重用攻击。代码重用攻击是一类相当危险的攻击，在各种代码执行漏洞
都被安全措施规避后，攻击者开始利用程序自身的代码来发动攻击，而不是跳转执行攻击者的代码来发动攻击。
这相当成功，绝大多数时候一个图灵完全的运行环境都是可行的。

在不需要二进制驱动和模块的服务器以及（使用 Intel 的）桌面机器上，这是一项相当不错的特性。但这会导
致 Nvidia 等私有驱动无法运行。

## → Customize Configuration → Memory Protections --->

#### [ ] Deny reading/writing to /dev/kmem, /dev/mem, and /dev/port

建议选择 N，否则 PaX 会禁止 /dev/kmem、/dev/mem、和 /dev/port 的读写，同时也禁止写入 CPU 的
MSR 寄存器，以及移除对 kexec 的支持。这是一项保护内存，特别是内核本身遭到修改的有力措施。
如今几乎没有什么应用程序直接通过这三个设备直接操作硬件，因此这是一个非常好的选择。然而
问题在于，CPU 的电源管理需要修改 MSR 寄存器，然而这也被禁止了，因此使用工具查看或修改
CPU 电源管理策略将是不可能的（CPU 的调速器依然可以修改，因为这是内核而不是 CPU 的一部分）。
在一台台式机或工作站上，这完全不是问题；然而对于需要支持笔记本的桌面系统来说只能有所牺牲。

#### [\*] Disable privileged I/O

建议选择 Y，这个特性能让 PaX 禁止应用程序使用 ioperm() 等系列函数直接访问 CPU 上的 IO 端口，所有
操作均会返回权限不足的错误。如今几乎已经没有什么用户程序会直接操作硬件了，但仍然有一些老的程序
可能会用到，所以在没有古董硬件的情况下可以启用。唯一需要担心的程序一是 hwclock 可能会直接操作
硬件写入时间，但现代 hwclock 通过的是内核的 /dev/rtc0 接口，因此这不是问题；另一个需要担心的
程序是 X，但如今现代的 X 驱动均使用 DRI, DRM 与 KMS 等内核提供的接口，而不是直接操作硬件，因
此这在 2012 年之后已经不成问题，你可能会在 X 中看到 ioperm() 失败的警告，但 X 会正确的
fallback，不会有任何问题。

#### [\*] Harden BPF interpreter

建议选择 Y，这会让 PaX 加固内核的 BPF 解释器。BPF 是内核自身提供的低级网络脚本语言，可以用来
编写网络脚本从而实现内核态高效的网络包处理。在 BPF 几乎没有什么用途的绝大多数机器，建议
直接在 → Networking support → Networking options 的 [  ] enable BPF Just In Time compiler
中选择 N，完全禁用 BPF 解释器。

#### [\*] Disable unprivileged PERF\_EVENTS usage by default

建议选择 Y，这会让 PaX 禁止普通用户使用 PERF\_EVENTS 性能计数器。PERF\_EVENTS 计数器对于程序的
性能调试很有帮助，但常规用户则不会用到它，而且 PERF\_EVENTS 在过去几年已经发现了多个漏洞，
禁止普通用户使用 PERF\_EVENTS 有助于杜绝攻击。当此选项启用时，`/proc/sys/kernel/perf\_event\_paranoid`
将会新增一个新的选项 `3`，并且设定为默认值，以禁用非 root 用户使用 PERF\_EVENTS。在需要进行
性能调试开发时，root 可以轻易把它修改回更低的值（在原始内核中规定的），来允许 PERF\_EVENTS。

#### [\*] Prevent kernel stack overflows

建议选择 Y，这会让 PaX 使用内核中带有安全特性的 vmalloc()，而不是内核默认的简单内存分配器来
分配内核进程的栈。内核本身不使用 vmalloc() 显然是处于性能考虑，但这并不是一个问题。这可以
杜绝内核的栈溢出。注意，栈溢出不是缓冲区溢出。

#### [\*] Deter exploit bruteforcing

建议选择 Y，这会 PaX 在让一个程序 fork() 但子进程却触发保护被 PaX 杀死时，在 30 秒内不允许进行第二次
fork()，以避免某些程序以不断 fork() 的形式利用某个漏洞。这个特性的一个明显效果时，某程序
运行时至少 30 秒内没反应，而且有 PaX 警告，这时请排除警告。另一个例子是 gdb 每次都会在
调试程序时触发 PaX 的 mprotect()，产生一条警告，然后「卡死」，但等待 30 秒就会恢复。对于系统
管理员来说，应该定期检查内核日志里是否有记录，以及时发现攻击尝试。

#### [ ] Harden module auto-loading

建议选择 N。当这个特性被选择时，非 root 用户访问设备文件时不会自动加载内核模块。这样能够避免一些
可能导致漏洞暴露的攻击（如要求一个有漏洞的模块被加载），但是却会导致桌面的一些不方便（如 GNOME VFS
需要 fuse 模块被加载）。

#### [\*] Hide kernel symbols

建议选择 Y，这会让 PaX 禁止 /proc 中某些符号表和内存表的访问，从而保护内核符号，以防攻击者知道了
某个关键的内核内存地址并发动攻击。获取加载模块信息以及内核符号的程序将只限于拥有 CAP\_SYS\_MODULE
的程序，而 /proc/kallsyms 则只限于 root 访问。

然而，如果系统使用的内核是由发行版编译的，那么攻击者可以轻易下载内核。然后查看 System.map 或者
内核二进制来找到内存地址。因此，你必须自己编译自己内核，而且保证你的 System.map 和内核二进制等
文件不被别人看到才有效。但考虑到某些自动程序会主动读取 System.map，发行版开启这个选项还是有点用
的。为了避免一些疏漏，PaX 编译脚本会自动在内核编译时修改 /boot, /lib/modules 和内核源码目录的权限，
只允许 root 访问。

#### [\*] Randomize layout of sensitive kernel structures

建议选择 Y，这会让 PaX 以利用编译时生成的随机种子，对内核中重要的数据结构加以随机化。攻击者将
需要更多信息才能攻击内核数据，加大攻击难度。随机种子将保存在 tools/gcc/randomize\_layout\_seed.h，
换句话说，如果攻击者获得了你的种子，那么这个特性就没有用了。但这个文件并不会在 make clean 时清空，
因为后续的模块编译需要知道种子。

#### [\*] Use cacheline-aware structure randomization

建议选择 Y。选择这个选项的话，在随机化内核数据结构的时候，会考虑到 CPU 的性能问题。虽然这弱化了随机性，
但是提高了内核性能。

#### [\*] Active kernel exploit response

建议选择 Y，这会让 PaX 在怀疑某程序尝试入侵内核时，准确的说是 KERNEXEC/UDEREF/USERCOPY 保护触发，
或者内核访问内存但 kernel oops 时，杀死此程序主人所有的进程，并且禁止任何新进程创建，换句话说，
就是封禁该用户，直到重启；如果此用户是 root，那么 PaX 将触发 kernel panic 让内核自杀。
