# PaX 基础

PaX 是 Grsecurity 里专注于 Memory corruption 的部分。

## PaX 特性介绍

### PAGEEXEC (Paging based non-executable pages)

PAGEEXEC 特性，通过处理器的分页机制，实现了对执行数据段内的代码的防护。

参见 [《PAGEEXEC的最早设计文档》](http://hardenedlinux.org/system-security/2015/05/25/pageexec-old.html)

一般的程序不会被 PAGEEXEC 影响。但是少数程序会执行被 PAGEEXEC 禁止的操作：

- Google Chrome NaCl Helper
- Chromium NaCl Helper

### SEGMEXEC (Segmentation based non-executable pages)

SEGMEXEC 特性，同样避免了对数据段内代码的执行。与 PAGEEXEC 不同，它是通过 x86_32 的分段特性实现的，所以仅适用于 x86_32 。

参见 [《SEGMEXEC设计文档》](http://hardenedlinux.org/system-security/2015/05/26/segmexec.html)

笔者并没有用过 SEGMEXEC ，所以也不知道会有多少程序出问题。

欢迎贡献 SEGMEXEC 相关的报告。

### MPROTECT (Restrict mprotect())

MPROTECT 特性，彻底阻断了程序实时生成可以执行的代码的途径，保证了程序的运行不会超出现有代码。

参见 [《MPROTECT早期设计文档》](http://hardenedlinux.org/system-security/2016/03/14/mprotect.html)

MPROTECT 误杀的程序比较多，所有使用 JIT 技术的程序都无法幸免于难，包括各种浏览器以及各种 JavaScript 滥用者。

[MPROTECT 误杀的程序列表](mprotect-victim.md)

### EMUTRAMP (Emulate trampolines)

Trampolines ，即在不可执行的代码段上的一段小跳转代码（通常在栈上）。

EMUTRAMP 特性是对早期 Linux 程序滥用 trampolines 的一种 workaround。

现代 Linux Userspace 已经几乎很少依赖 trampolines 。

### KERNEXEC (Enforce non-executable kernel pages)

相对于上面的用户空间内存执行防护，KERNEXEC 是对内核空间的内存执行防护。

KERNEXEC 一般不会对正常使用造成影响，但是会大大提升通过内核漏洞提权的难度。

注意：KERNEXEC 有多种实现，但是这些实现要么需要 GCC Plugins ，要么需要 Sandy Bridge 以上的处理器（使用 SMEP）。

在编译内核的时候，需要选择使用的实现。请谨慎考虑！

### ASLR (Address Space Layout Randomization)

ASLR ，是一项著名的用户控件防代码注入技术。

它能够使用户空间程序（前提程序文件应该是 PIE (Position Independent Executable)）的加载地址随机化，导致难以确定代码应该插入的位置。

ASLR 的性能影响很小，但是带来的安全性增强非常高。

### GCC Plugins

PaX/Grsecurity 为了实现极致的安全性，在内核编译过程中，加入了大量的 GCC Plugins 对内核代码进行自动化处理。

上面提到的 KERNEXEC 实现即为一例。

注：GCC Plugins 框架已于 4.8 加入 Linux 主线内核，各个 Plugin 正在逐渐向主线推送。将来主线也能享受 GCC Plugins 带来的加固。

## PaX 可执行文件标记

很多可执行文件由于使用了被 PaX 限制的特性，从而需要从 PaX 那里获得特许。

需要 PaX 特许的可执行文件需要被进行标记。

当前标记方式有三种：
