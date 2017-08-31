## 关于内存信息泄漏
### PAX_MEMORY_SANITIZE
PAX_MEMORY_SANITIZE 是一个用于将已被释放的内存，进行全面的擦除的特性。这个实现十分简单但是也十分有用，能够有效的抵御 “use after free” 类的攻击以及减少一些 infoleak。  
PAX_MEMORY_SANITIZE 的实现非常简单，slab 分配的流程是先申请 kmem_cache 再分配 slab，kmem_cache往往在初始化中做。真正实现擦除数据的工作只是在 slab 的释放中去做即可，但是还有一些琐碎的维护一些标志的工作。  
首先，PaX 通过 pax_sanitize_slab_setup 函数，在内核接收的 cmdline 里检测关于 pax_sanitize_slab 的设置，这里维护的标志供后面分配cache时读取（ pax_sanitize_slab_flags）来决定 sanitize 的模式。这部分代码比较简单，不做展开。  
接下来我们直接看到 slab obj 被释放时 CONFIG_PAX_MEMORY_SANITIZE 增加的处理。代码如下：
```  
void ___cache_free(struct kmem_cache *cachep, void *objp,
		unsigned long caller)
{
	struct array_cache *ac = cpu_cache_get(cachep);

	check_irq_off();

#ifdef CONFIG_PAX_MEMORY_SANITIZE
	/* 先检测前面维护的 SLAB_* 的标志位 */
	if (cachep->flags & (SLAB_POISON | SLAB_NO_SANITIZE))
		/* 原子操作递增 kmem_cache 下的 not_sanitized 变量 */
		STATS_INC_NOT_SANITIZED(cachep);
	else {
		/* 擦除内存 */
		memset(objp, PAX_MEMORY_SANITIZE_VALUE, cachep->object_size);

		if (cachep->ctor)
			cachep->ctor(objp);
		/* 原子操作递增 kmem_cache 下的 sanitized 变量 */
		STATS_INC_SANITIZED(cachep);
	}
#endif

        ......

}
```  
这个函数是用于释放 obj 的，这里插入了一段代码，先检测前面维护的 SLAB_* 的标志位来确定是否进行擦除，若不擦除，只需操作not_sanitized 变量，这里是 PaX 新维护的用于标记释放的 slab 和擦除的状况。若需擦除，只需调用 memset 在 objp 的内存区域内填上 PaX 设定的值，然后在操作 sanitized 变量即可。下面是 slabinfo 接口的信息，增加了擦处的情况。  
```  
void slabinfo_show_stats(struct seq_file *m, struct kmem_cache *cachep)
{
	......
	
#ifdef CONFIG_PAX_MEMORY_SANITIZE
	{
		unsigned long sanitized = atomic_read_unchecked(&cachep->sanitized);
		unsigned long not_sanitized = atomic_read_unchecked(&cachep->not_sanitized);

		seq_printf(m, " : pax %6lu %6lu", sanitized, not_sanitized);
	}
#endif
}
```  
### PAX_MEMORY_STACKLEAK
PAX_MEMORY_STACKLEAK 是一个依赖 gcc-plugin 针对进程内核栈的溢出和泄漏做加固的安全特性。这个特性的实现分为两部分，一是实现了 pax_erase_kstack 在进出内核空间时对进程内核栈的数据进行擦除，另一部分是借助 gcc-plugin，实现两个函数 pax_check_alloca 和 pax_track_stack 检查是否发生进程內核栈的溢出。在这个文档中，我们主要讲内存泄漏，第二个实现会在别的文档里讨论。  
我们先看 pax_erase_kstack 函数的实现：  
```  
ENTRY(pax_erase_kstack)
	pushl %edi
	pushl %ecx
	pushl %eax
	pushl %ebp

	GET_CURRENT(%ebp)
	mov TASK_lowest_stack(%ebp), %edi
	mov $0xB4DD00D5, %eax
	std                         /* 设置内存增长方向，向地址小的增长 */

1:	mov %edi, %ecx
	and $THREAD_SIZE_asm - 1, %ecx       /* 掩码或的栈起始偏移 */
	shr $2, %ecx        /* 检查单位为双字，4-byte */
	repne scasl         /* 从ES：DI(进程内核栈）开始，搜索有无 EAX( $0xB4DD00D5) 的双字 */
	jecxz 2f            /* 找到跳转 */

	cmp $2*16, %ecx     /* 当 ecx 小于 2×16 即，距离栈底（高地址），2×16×4-byte处 */
	jc 2f

	mov $2*16, %ecx
	repe scasl           /* 搜寻直到没有 EAX */
	jecxz 2f
	jne 1b

2:	cld                 /* 向高地址方向增长 */
	or $2*4, %edi
	mov %esp, %ecx
	sub %edi, %ecx

	cmp $THREAD_SIZE_asm, %ecx
	jb 3f               /* 检查 ecx，是否超出*/
	ud2
3:

	shr $2, %ecx  /* 检查单位为双字，对计数掩码 */
	rep stosl     /* 在 edi 到 edi + ecx之间填充 eax */

	mov TASK_thread_sp0(%ebp), %edi
	sub $128, %edi
	mov %edi, TASK_lowest_stack(%ebp)

	popl %ebp
	popl %eax
	popl %ecx
	popl %edi
	pax_ret pax_erase_kstack
ENDPROC(pax_erase_kstack)
#endif
```  
由于这个函数本身使用汇编实现，细节较为繁琐。上面代码尝试着尽量详细的注释，这里附上总体函数的实现描述。这个函数是基于 repne scasl 以及同类指令，在进程的内核栈中搜索固定的字符串，凡是不是固定字符串的区域说明他是使用过而未擦除的，包含有调用信息，把未擦除的栈空间全部填充上固定字符串。结合整体流程来看，每次退出内核的前，使用过的栈空间，会覆盖掉上一次擦除过的固定字符串，留下调用和数据的信息，这时函数会通过检测栈的内容向上向下去探测出这片空间并且填充固定字符串，这样就你达到退出内核空间后，进程內核栈的内容都是固定的字符串，即使存在着 user after free 的漏洞，也没法进行漏洞利用（因为已经被擦除），信息也不会被泄漏。  
而这个函数本身插入在进程进出内核的代码上。以 x86_64 为例，进程进入内核空间是透过系统调用来陷入的，`ENTRY(entry_SYSCALL_64)` 是系统调用的入口和出口。他的流程是：首先是进内核前，调用 swapgs 切换到内核空间，一些现场保护，然后调用 sys_call_table 来进入系统调用，系统调用的内核代码处理完毕后，开始准备返回值恢复现场并调用 swapgs 切换到用户空间。PaX 把这个函数插在了 return_from_SYSCALL_64 标签下，也就是系统调用的内核代码刚刚结束准备恢复返回到用户空间的时候。插入点在出内核栈之前而不是进内核之前，除了说防止从信息从内核流向用户空间的原因，还有就是考虑到这部分代码在中断等的复用问题。
