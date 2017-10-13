# PaX/Grsecurity 代码分析  
## 简介  
这个目录主要是针对 PaX/Grsecurity 的代码分析的文档, 这个文档是针对这部分文档的简介。

PaX/Grsecurity是一组针对Linux Kernel的加固补丁，跟“传统”的基于LSM( SELinux/AppArmor/etc)不同的是PaX/GRsecurity不仅是具备RBAC对权限以及信息流的控制，而是通过一系列的安全改进让Linux内核在为用户空间提供防御能力( ASLR/PAGEEXEC/SEGEXEC/etc)的同时内核本身的防护能力也大大加强，PaX/GRsecurity作为整个系统安全防御领域最重要的起源，[不仅仅影响了Linux内核](https://hardenedlinux.github.io/system-security/2015/05/17/grsec-interview.html)，也大大的影响了Windows以及BSD内核的安全特性，甚至影响了包含Intel和ARM系列处理器在内的硬件厂商，在可预见的未来必然会影响[RISC-V的安全特性](https://github.com/hardenedlinux/embedded-iot_profile/blob/master/docs/riscv/riscv_security.md)支持，由于Linux内核社区多年以来都奉行"A bug is bug"和"security through obscurity"的哲学导致了Linux内核自第一枚核弹null-ptr ref利用方式曝光后进入了“隐蔽战争纪元”，大规模利用安全事件持续性危害着数据中心的GNU/Linux用户，后来随着Android手机的崛起因为其使用的是Linux内核而必须承受极大风险，下一个受害者或许是嵌入式设备( Internet of Shxt)，虽然在[2015年华盛顿邮报向公众曝光了Linux安全真相](http://www.washingtonpost.com/sf/business/2015/11/05/net-of-insecurity-the-kernel-of-the-argument/)后Linux内核社区迫于Linux基金会的压力成立了KSPP（内核自防护项目），KSPP的参与者大多为Linux基金会的客户（Google/RedHat/Intel/etc)，参与者基在移植PaX/GRsecurity的某些特性或者代码级加固的过程中多次没有理解代码造成的抄袭错误引入了新的漏洞，加上一些其他社区政治因素导致PaX/GRsecurity停止公开下载，HardenedLinux社区认为这一切的罪魁祸首是Linux基金会，在这篇“[方舟之役](https://hardenedlinux.github.io/announcement/2017/04/29/hardenedlinux-statement2.html#%E6%96%B9%E8%88%9F%E4%B9%8B%E5%BD%B9)”的申明中已经有详细的阐述这里不再描述。过去的17年中PaX/GRsecurity对自由软件社区和内核安全领域的巨大贡献但并不是被很多技术人员所了解，这是HardenedLinux社区公开一些PaX/GRsecurity特性的代码分析的主要原因，也算是对社区的馈赠。

##### PaX 部分  
PaX 部分主要是针对内核 Memory corruption 的漏洞利用的防御补丁。PaX 的特性有大的完整特性,比如整个 ASLR 实现,也有零散的针对加固特性。下面的文档会把特性进行归类,并做相应简介,尽可能勾画出某个特性在整体加固中发挥的作用,方便后续文档阅读。

### ASLR  
#### 简介  
PaX 针对进程地址空间实现的 ASLR，是目前最强的 ASLR 实现，也是 PaX 的一个非常重要的特性。能够有效的抵挡很多基于地址的攻击，比如一些代码注入，执行流重定向，代码复用等问题。上述基于内存的利用往往要知道目标代码的位置，进程内存布局的随机化，使得每一次执行程序都有不同的虚拟地址空间。无论是注入代码的硬编码地址、使用相对偏移或者共享库代码的复用等都会因为地址的随机化，使得攻击难度上升。尝试克服随机化的常见方法有暴力破解、漏洞的内存信息泄漏。前者需要克服的是随机化的程度高低（熵），后者依赖于具体漏洞。
#### 设计实现  
ASLR 设计的目的是：在进程地址空间的执行代码主程序，堆，共享库，映射区域，栈的地址都引入随机化，使得每一次运行都有不同的虚拟地址。引入随机化主要由三个子特性来实现，包括： PAX_RANDMMAP、PAX_RANDEXEC、PAX_RANDUSTACK。他们承担的任务如下：

| Option            |特性          |
| ----------------- |-------------|
| PAX_RANDMMAP      | 映射基址（包括共享库映射），堆基址，  ET_DYN 类型 ELF 主程序基址的随机化 |
| PAX_RANDEXEC      | ET_EXE 类型 ELF 主程序基址的随机化 |
| PAX_RANDUSTACK    | 栈基址的随机化 |

这三个的特性的代码盘踞在进程地址空间变化的各个阶段，大部分位于初始化的时候。比如针对 ELF 类型的可执行代码，进程代码的加载，共享库的映射，内存资源的分配，都是在 load_elf_binary 函数里面完成的，随机化在这里面也是最多的，一些随机化只需要随机化基址，有些需要后续操作的配合。这些子特性的文档介绍如下：

1. [PAX_RANDMMAP](PAX_RANDMMAP.md) 按照随机化的对象分节分析。
2. [PAX_RANDUSTACK](PAX_RANDUSTACK.md) 按照栈初始化流程中引入随机化的点逐点分析。
3. PAX_RANDEXEC 。

虽然 ASLR 是由几个子特性组成的，但是子特性之间有时会有交叉或者相关的代码，应该以一个整体的特性去看待。比如栈的随机化会影响到映射区域的随机化。  

#### 相关漏洞分析    
[这篇文档](elf_offset2lib.md)从二进制可执行文件加载函数 load_elf_binary 开始，引出以 offset2lib 为例，分析 offset2lib 原理和加固的实现,具体可以结合 ASLR 其他三个文档一起阅读。

### PAX_NOEXEC  
#### 简介  
PAX_NOEXEC 是 PaX 针对代码注入的利器，斩断了执行流重定向到数据所在区域的可能。由于代码注入往往是透过数据操作写入到内存的数据段中，若将这部分内存区域保持为不可执行，一旦 ip 指针执行到这种区域，就会被拦截，防止恶意代码的执行。
#### 设计实现  
PAX_NOEXEC 设计的目的是：保持内存的健康状态，防止非代码段的内存被执行。他的设计方案有两个环节：  

| Option     |特性   |
| ---------- | ---- |
| PAX_MPROTECT | 在内存初始映射时和修改映射性质时确保内存的健康状态（例如写/执行不可同时）|
| PAX_PAGEEXEC/SEGMEXEC | 透过软件或者硬件的方式，保持不可执行的内存不被执行。|

这个特性的关键点在于内存性质的维持和执行时的配合，有不合法内存映射的行为都是不允许的。文档索引如下:
1. [PAX_MPROTECT](PAX_MPROTECT.md) 按照内存映射初始化和映射修改两个方面分析 PaX 对内存的限制。
2. [PAX_PAGEEXEC](PAX_PAGEEXEC.md) 基于分页机制包括初始化和 page-fault 时的维护。
3. [PAX_SEGMEXEC](PAX_SEGMEXEC.md) 

### PAX_USERCOPY  
#### 简介  
PAX_USERCOPY 是 PaX 针对用户/内核空间之间的内存相互拷贝的溢出检查。解决了拷贝目的缓冲区(包括栈和堆)溢出的问题。

### 关于内核栈  
#### 简介  
PaX/Grsecurity  
1. [Kernel stack 的演变](kstack.md) 按照内核版本分析内核栈的实现。
2. [GRSECURITY_KSTACKOVERFLOW](KSTACKOVERFLOW.md) 按照 Grsecurity 的 KSTACKOVERFLOW 特性加固的地方逐个分析。


### PAX_REFCOUNT

### PXN
