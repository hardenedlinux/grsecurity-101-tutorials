## Kstack 的演变
本文分析了从内核 v4.8 到 Grsec/Pax 的加固再到内核 v4.9 的内核栈的设计。  
### Kernel v4.8 的实现  
进程内核栈的初始化在进程创建的时候就会被分配初始化，创建进程的工作由 fork 完成，路线如下：  
  fork -> do\_fork -> \_do\_fork -> copy\_process  
  copy\_process 返回后，wake\_up\_new\_task调用就是子进程开始进入正常运行。  
 
```  
long _do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr,
	      unsigned long tls)
{
	struct task_struct *p;
        ...

	p = copy_process(clone_flags, stack_start, stack_size,
			 child_tidptr, NULL, trace, tls, NUMA_NO_NODE);
       /*一些结构体的初始化，包括进程信息，栈信息等*/
       ...
		wake_up_new_task(p);
       ...
		/* fork 完成，子进程开始运行 */
       ...
	return nr;
}
```  
copy_process 完成的工作如下：  
```  
static struct task_struct *copy_process(unsigned long clone_flags,
					unsigned long stack_start,
					unsigned long stack_size,
					int __user *child_tidptr,
					struct pid *pid,
					int trace,
					unsigned long tls,
					int node)
{
   ...
   retval = security_task_create(clone_flags);
   ...
   p = dup_task_struct(current, node); /*申请进程栈内存，task_struct->stack*/
   ...
   ftrace_graph_init_task(p); /*申请返回栈内存,task_struct -> ret_stack*/
   ...
   ...
   retval = sched_fork(clone_flags, p); /*初始化子进程调度*/
   ...	
   retval = perf_event_init_task(p);
   ...
   retval = audit_alloc(p);
   ...
   /* copy all the process information */
   /* 一些进程的信息的拷贝，有的继承自父进程*/
   shm_init_task(p);
   ...	
   retval = copy_files(clone_flags, p);
   ...	
   retval = copy_fs(clone_flags, p);
   ...	
   retval = copy_sighand(clone_flags, p);
   ...	
   retval = copy_signal(clone_flags, p);
   ...	
   retval = copy_mm(clone_flags, p);
   ...
   retval = copy_namespaces(clone_flags, p);
   ...	
   retval = copy_io(clone_flags, p);
   ...
   retval = copy_thread_tls(clone_flags, stack_start, stack_size, p, tls);
   /*这里会涉及栈的 thread_info、pt_reg 的设置*/
   ...
   ...
}
```  
其中，dup_task_struct 包括申请内核栈所需的空间，返回内存地址：  
```  
static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
{
	struct task_struct *tsk;
	unsigned long *stack;
	int err;

	...
	tsk = alloc_task_struct_node(node);         /*子进程描述符内存申请*/
	...

	stack = alloc_thread_stack_node(tsk, node);  /*子进程内核栈内存申请*/
	...

	err = arch_dup_task_struct(tsk, orig);     /*初始化子进程描述符*/
	...

        ...

	tsk->stack = stack;              /*将 task_struct 和对应的栈挂钩，赋值 task_struct->stack*/
	setup_thread_stack(tsk, orig);    /*初始化内核进程栈*/
	clear_user_return_notifier(tsk);
	clear_tsk_need_resched(tsk); 
	set_task_stack_end_magic(tsk);     /*设置栈边界，用于溢出探测*/
#ifdef CONFIG_CC_STACKPROTECTOR
	tsk->stack_canary = get_random_int();
#endif
       ...
```  
setup_thread_stack 函数承担了一下内核栈上信息的初始化，包括栈顶（低地址）的 thread_info：  
```  
static inline void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
	*task_thread_info(p) = *task_thread_info(org);
	task_thread_info(p)->task = p;
}
```  
宏函数 task_thread_info() 的实现如下：
```
#define task_thread_info(task)	((struct thread_info *)(task)->stack)
```
也就是获得上述申请分配用于内核栈的内存的首地址（低地址），这也说明 thread_info 是放置在内核栈顶（低地址端）的位置，thread_info 直接继承父进程的信息，将 task 指针指向当前的进程描述符。完成这些以后由 dup_task_struct 返回栈指针，继续 copy_process 函数，来到 copy_thread_tls 会对已申请的内核栈进行一些操作：  
```  
int copy_thread_tls(unsigned long clone_flags, unsigned long sp,
		unsigned long arg, struct task_struct *p, unsigned long tls)
{
	int err;
	struct pt_regs *childregs;
	struct task_struct *me = current;

	p->thread.sp0 = (unsigned long)task_stack_page(p) + THREAD_SIZE; 
        /*获取子进程栈顶地址（低地址，通过 task_stack_page（p）），加 THREAD_SIZE 栈长度或者栈底地址（高地址）*/
	childregs = task_pt_regs(p);
        /*获取子进程的 pt_reg 指针，这个结构放在内核栈底（高地址），thread.sp0 增加一个 sizeof(pt_reg) 获得*/
        /*在 32-bit 的情况下，会预留 8 个 byte 确保 pt_regs 的完整*/
	p->thread.sp = (unsigned long) childregs;
        /*sp 指针指向此处，进程内核栈增长从此开始*/
	set_tsk_thread_flag(p, TIF_FORK);
	p->thread.io_bitmap_ptr = NULL;
        
        ...

	if (unlikely(p->flags & PF_KTHREAD)) {
		/*进程是内核进程*/
                /* kernel thread */
		memset(childregs, 0, sizeof(struct pt_regs));
		childregs->sp = (unsigned long)childregs;
		childregs->ss = __KERNEL_DS;
		childregs->bx = sp; /* function */
		childregs->bp = arg;
		childregs->orig_ax = -1;
		childregs->cs = __KERNEL_CS | get_kernel_rpl();
		childregs->flags = X86_EFLAGS_IF | X86_EFLAGS_FIXED;
		return 0;
	}
	*childregs = *current_pt_regs();
        /*用当前进程的 pt_regs 初始化子进程的*/

	childregs->ax = 0;
	if (sp)
		childregs->sp = sp;
        /*这里的 sp 是在前文已经分配的作为内核栈的内存区域*/

	err = -ENOMEM;
	if (unlikely(test_tsk_thread_flag(me, TIF_IO_BITMAP))) {
		...
		if (!p->thread.io_bitmap_ptr) {
			...
			return -ENOMEM;
		}
		set_tsk_thread_flag(p, TIF_IO_BITMAP);
	}

	err = 0;
out:
	if (err && p->thread.io_bitmap_ptr) {
		kfree(p->thread.io_bitmap_ptr);
		p->thread.io_bitmap_max = 0;
	}
 
	return err;
}
```  
这个函数主要涉及进程描述符 task_struct 中的 thread_info 字段和内核栈栈底（高地址）的 pt_reg 的一些初始化，该字段包含这进程上下文的一下寄存器的信息。  
`p->thread.sp0 = (unsigned long)task_stack_page(p) + THREAD_SIZE; `  
task_stack_page(p) 获取得到内核栈的低地址指针，加上 THREAD_SIZE 偏移获得栈底地址，赋值给 p->thread.sp0。  
childregs = task_pt_regs(p);
是获得内核栈的 pt_regs 的指针，其中 task_pt_regs() 的实现如下：
```
#define task_pt_regs(tsk)	((struct pt_regs *)(tsk)->thread.sp0 - 1)
```
将刚赋值指向栈底（高地址）的 thread.sp0 强制转化为 struct pt_regs 指针，然后向上偏移一个指针，也就是空出一个距离栈底 sizeof（pt_regs） 大小的位置，获得栈底的 pt_regs 指针。此时 childregs 不仅仅是 pt_regs 指针，也是栈的增长起始点，任何压栈行为都从此开始。
接下来的代码会对获得 pt_regs 指针 childregs 进行复制，填入栈底的 pt_regs 字段，非内核进程时，直接复制父进程的一些上下文即可。而 sp 作为每个进程独立的栈，在指定 sp 不为空的情况下赋值给childregs->sp（上文的stack分配完成后传递进来）。
总体看来，4.8维护的进程内核栈形态如下:  
    low_mem----------------------------------------------------->high_mem  
    |---thread_info---|----------stack---buf-----------|---pt_regs---|  
    
## Pax 实现的 thread_info 的分离  
针对 4.8 的内核，为了防止栈溢出时将内核的 thread_info 信息泄漏，Pax 将 thread_info 移出放到 task_struct 结构体中去：  
```  
@@ -1924,6 +1929,10 @@ struct task_struct {
 #ifdef CONFIG_MMU
 	struct task_struct *oom_reaper_list;
 #endif
+/* thread_info moved to task_struct */
+#ifdef CONFIG_X86
+	struct thread_info tinfo;
+#endif
 /* CPU-specific state of this task */
 	struct thread_struct thread;
 /*
```  
首先由于对 thread_info 的位置修改，凡是涉及 thread_info 的操作都需要进行修改，例如内核实现初始化时用 task_thread_info 来获取这个结构体的指针，只需做如下修改：
```
+#define task_thread_info(task)	(&(task)->tinfo)
```
```
struct thread_info {
 	struct pt_regs		*kern_una_regs;
 	unsigned int		kern_una_insn;
 
+	unsigned long		lowest_stack;
+
 	unsigned long		fpregs[(7 * 256) / sizeof(unsigned long)]
 		__attribute__ ((aligned(64)));
 };
```
thread_info 移除出栈后，Pax 又在 thread_info 里维护了一个 lowest_stack 字段，指向实际可用的栈首（添加了一些填充物），在 copy_thread_tls 时做如下修改：
```
@@ -144,9 +144,10 @@ int copy_thread_tls(unsigned long clone_
 	struct pt_regs *childregs;
 	struct task_struct *me = current;
 
-	p->thread.sp0 = (unsigned long)task_stack_page(p) + THREAD_SIZE;
+	p->thread.sp0 = (unsigned long)task_stack_page(p) + THREAD_SIZE - 16;/* 16byte 是栈底填充？*/
 	childregs = task_pt_regs(p);
 	p->thread.sp = (unsigned long) childregs;
+	p->tinfo.lowest_stack = (unsigned long)task_stack_page(p) + 2 * sizeof(unsigned long);
        /*这个指针是 pax 新加的，作为栈首地址（低地址），2 * sizeof(unsigned long)=16byte 是栈顶填充物？*/
        ...
+	savesegment(ss, p->thread.ss);
+	BUG_ON(p->thread.ss == __UDEREF_KERNEL_DS); /*检查*/
 	...
```
这里看起来是在栈顶和栈底都填充了 16byte，可能是关系 overflow 探测的设置？  

获取 thread_info 的函数要做相应修改：
```
 static inline struct thread_info *current_thread_info(void)
 {
-	return (struct thread_info *)(current_top_of_stack() - THREAD_SIZE);
+	return this_cpu_read_stable(current_tinfo);
 }
+#define task_thread_info(task)	(&(task)->tinfo)
```
在栈顶设置 magic 用于探测 overflow 时，需要做如下变换：
```  
void set_task_stack_end_magic(struct task_struct *tsk)
{
	unsigned long *stackend;

	stackend = end_of_stack(tsk);
	*stackend = STACK_END_MAGIC;	/* for overflow detection */
}
```
```  
+#define end_of_stack(p) ((unsigned long *)task_stack_page(p) + 1)
```  
这会在栈顶端填入 8byte 的 STACK_END_MAGIC，用于后续 overflow 的探测。  

## 4.9 以及 Grsec 的实现
Grsecurity的实现是在Pax的基础上，在分配内核进程栈时使用虚拟地址连续的内存块（物理不连续），分离thread_info方面和Pax的代码一样，栈分配时，task->stack是由原来alloc_thread_stack_node分配得到的lowmem_stack经过vmap映射出去的，lowmem_stack是由task_struct维护的，在一些需要连续内存需求的地方，用的就是这个栈，默认栈起点都是从task->stack开始。
- 这个实现的分析放在本目录下的[KSTACKOVERFLOW.md](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/KSTACKOVERFLOW.md)里面。  

相似的，4.9 的代码也做了 thread_info 的分离和分配虚拟地址连续的内存块（又是抄袭PaX/Grsecurity?），不同点在于 4.9 直接分配出物理上不连续的內核栈。  
[这篇文章](https://lwn.net/Articles/692208/)可以窥探CONFIG_VMAP_STACK的最初设计和意图，里面提及 32 位实现问题，特性增加以后的性能问题，vmalloc 自带 guard page 的安全优势，一些 DMA 的 I/O 需要物理连续的内存的问题，thread_info 分离的问题等等。  
最初的[patch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ba14a194a434ccc8f733e263ad2ce941e35e5787)只是实现了分配虚拟地址连续的内存块(thread_info后来加上)。
```  
+# if THREAD_SIZE >= PAGE_SIZE || defined(CONFIG_VMAP_STACK)
+static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 {
+#ifdef CONFIG_VMAP_STACK 
+	void *stack = __vmalloc_node_range(THREAD_SIZE, THREAD_SIZE,
+					   VMALLOC_START, VMALLOC_END,
+					   THREADINFO_GFP | __GFP_HIGHMEM,
+					   PAGE_KERNEL,
+					   0, node,
+					   __builtin_return_address(0));
        /*申请内存用的是 vmalloc，内存在物理上是不连续的*/
+	/*
+	 * We can't call find_vm_area() in interrupt context, and
+	 * free_thread_stack() can be called in interrupt context,
+	 * so cache the vm_struct.
+	 */
+	if (stack)
+		tsk->stack_vm_area = find_vm_area(stack); 
        /*通过 find_vm_area 找出相应的虚拟地址内存块，映射好的内存块在内存里有 rbtree 维护,得到地址后赋值给 stack_vm_area*/
+	return stack;
+#else
 	struct page *page = alloc_pages_node(node, THREADINFO_GFP,
 					     THREAD_SIZE_ORDER);
        /*未开启 CONFIG_VMAP_STACK 的情形，一些架构没有支持*/
 
 	return page ? page_address(page) : NULL;
+#endif
 }
```  
由于性能问题，4.9 最终还加入了 cache_stack，减小了 fork 程序时带来的 vmalloc 的开销。[实现的patch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ac496bf48d97f2503eaa353996a4dd5e4383eaf0)主要是复用了已经申请映射过的内存，和修改程序销毁时释放内核栈的行为来配合复用。这个特性在完整移植期间做了很多次的修改，包括一些模块的配合整改，后期一些bug的修复，值得注意的是主线4.9内核的vmalloc stack的实现原本应该是防御机制但实际上[引入了更多的漏洞](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/kernel_vuln_exp.md)，从设计和实现上看，主线内核的vmalloc stack几乎是抄袭PaX/Grsecurity，或许因为“政治正确”的原因全盘否认阅读过GRSEC_KSTACKOVERFLOW相关代码的说法也只能见仁见智了，HandenedLinux社区提供的[Kernel mitigation文档](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/kernel_mitigation.md)有这些设计变动信息的收集，可供参考。

