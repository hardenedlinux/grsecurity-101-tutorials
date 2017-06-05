# PAX_REFCOUNT
## 简述
针对引用计数溢出的加固。内核对象引用计数不断增加，当发生溢出时，引用计数为 0，内存即可被释放，而此时程序还有对该指针所值内存的引用，就有可能发生 use-after-free,可以用做攻击利用。  
例如，内核中常见此类调用：
```
atomic_inc(&card->refcount);
```
atomic_inc() 又调用 atomic_add() 对引用计数进行增加的操作，若 atomic_add() 不进行溢出检查，则有可能存在引用计数溢出。  
* 以下的实现分析将会根据对 atomic_add() 函数的加固作为例子。  

## 实现
实现包括两个部分，一部分是探测引用计数的溢出，一部分是溢出发生时的异常处理。  
##### 溢出探测部分

以 atomic_add() 函数为例，探测溢出发生与否的代码如下：
```
__asm__ __volatile__("@ atomic_add\n"
   "1:   ldrex   %1, [%3]\n"
   "   adds   %0, %1, %4\n"    递增计数

#ifdef CONFIG_PAX_REFCOUNT
   "   bvc   3f\n"                   若没有发生溢出，则跳过
   "2: " REFCOUNT_TRAP_INSN "\n"   若发生溢出，将执行异常处理程序
   "3:\n"
   #endif
   "   strex   %1, %0, [%3]\n"
   "   teq   %1, #0\n"
   "   bne   1b"

#ifdef CONFIG_PAX_REFCOUNT
   "\n4:\n"
   _ASM_EXTABLE(2b, 4b)              这里定义了标签2可能产生异常跳转到标签4处？
   #endif
```

以下异常处理的定义(代码位于 arch/arm/include/asm/atomic.h)：
```
#ifdef CONFIG_THUMB2_KERNEL
#define REFCOUNT_TRAP_INSN "bkpt   0xf1"
#else
#define REFCOUNT_TRAP_INSN "bkpt   0xf103"
#endif
```
类似的函数有：  
arch/arm/include/asm/atomic.h:
- static inline void atomic_add()
- static inline int atomic_add_return()
- static inline void atomic_sub()

##### 异常处理部分
在 ARM 架构中，bkpt 显式调用后则会陷入异常处理之中。
arch/arm/mm/fault.c 中的 do_PrefetchAbort() 是异常处理的具体实现函数, 而 v7_pabort 才是异常发生时被直接调用的函数，然后在 v7_pabort 中调用 do_PrefetchAbort()，代码如下：
```
ENTRY(v7_pabort)
	mrc	p15, 0, r0, c6, c0, 2		@ get IFAR
	mrc	p15, 0, r1, c5, c0, 1		@ get IFSR
	b	do_PrefetchAbort
ENDPROC(v7_pabort)
```
## 案例
- [CVE-2016-4558] bpf:refcnt overflow 
kernel/bpf 中的 /inode.c、syscall.c 、verifier.c 多处调用了 atomic_inc 函数，导致引用计数溢出


###### 参考资料
https://forums.grsecurity.net/viewtopic.php?f=7&t=4173#ARM
