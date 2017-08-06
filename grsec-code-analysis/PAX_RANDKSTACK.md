# PAX_RANDKSTACK
## 简述
由 PaX Team 实现的 PAX_RANDKSTACK，是针对进程内核栈的随机化。由于内核栈本身的实现，内核中是可以任意访问没有任何防护的。随机化对栈布局的打乱，配合内核栈信息的擦除，能够有效防止内核信息泄漏，不容易猜透内存的布局。
## 实现
首先，PaX 实现了一个用于随机化内核栈的函数，这个函数读取时钟，掩码后与栈基址进行异或操作，使栈基址有一定范围的随机化偏移，代码如下：
```  
#ifdef CONFIG_PAX_RANDKSTACK
void pax_randomize_kstack(struct pt_regs *regs)
{
	struct thread_struct *thread = &current->thread;
	unsigned long time;

	if (!randomize_va_space)
		return;

	if (v8086_mode(regs))
		return;

	time = rdtsc();      /*读取时钟，作为随机数*/

	/* P4 seems to return a 0 LSB, ignore it */
#ifdef CONFIG_MPENTIUM4      /*这里不同的架构，选择的随机位数，偏移不同*/
	time &= 0x3EUL;    /*掩码*/
	time <<= 2;        /*移位*/
#elif defined(CONFIG_X86_64)
	time &= 0xFUL;    /*4-bit 位随机化*/
	time <<= 4;       /*向左偏移四位，这里有 (2^4 * 2^4)-byte 的偏移*/
#else
	time &= 0x1FUL;   /*5-bit 位随机化*/
	time <<= 3;       /*向左偏移三位，这里有 (2^5 * 2^3)-byte 的偏移*/
#endif

	thread->sp0 ^= time;        /*进程内核栈底地址（高地址）与 time 做异或操作，加入随机化比特位*/
	load_sp0(cpu_tss + smp_processor_id(), thread);   /*修改 thread.sp0 和 cpu_tss 相关位*/
	this_cpu_write(cpu_current_top_of_stack, thread->sp0);
}
#endif
```  
异或操作的结果是：掩码后， time 的置零位，得出的地址位还是原来的数，置一位翻转，以 CONFIG_X86_64 为例，sp0 的 bit4-7 反转，其他位不变，也就是会有 （2^4 (随机化位) × 2^4 (左移位)） byte 的偏移。需要注意的是，偏移位数和内核的页对齐有关。还有一个小细节就是，内核页对齐会导致栈的起始位置为 PAGE_SIZE 对齐的，也就是随机化的位都落在了对齐的位置也就是0，随机化位翻转后会越过栈低（0翻转为1，往高地址增长），所以 PaX 在栈初始化的时候加了一点偏移，可以参考[这个文档](kstack.md)。  
需要被随机化的栈起始地址在内核的结构体有两个，thread->sp0 和 cpu_tss，用于进程上下文的保存，进程切换等。  

### 系统调用的入口
实现了随机化的具体函数以后，我们需要在相应的地方插入随机化函数，这是 32 位的系统调用的入口：  
```  
ENTRY(entry_SYSENTER_32)
	movl	TSS_sysenter_sp0(%esp), %esp  /* 读取tss.sp0作为进程内核的起始地址 */
sysenter_past_esp:           /*pt_reg 一些寄存器的推栈保存，上下文的保存*/
	pushl	$__USER_DS		/* pt_regs->ss */
	pushl	%ebp			/* pt_regs->sp (stashed in bp) */
	pushfl				/* pt_regs->flags (except IF = 0) */
	orl	$X86_EFLAGS_IF, (%esp)	/* Fix IF */
	pushl	$__USER_CS		/* pt_regs->cs */
	pushl	$0			/* pt_regs->ip = 0 (placeholder) */
	pushl	%eax			/* pt_regs->orig_ax */
	SAVE_ALL pt_regs_ax=$-ENOSYS	/* save rest */

#ifdef CONFIG_PAX_RANDKSTACK
	pax_erase_kstack      /*这是 PaX 实现的内核/用户空间切换时的内存清理*/
#endif
	testl	$X86_EFLAGS_NT|X86_EFLAGS_AC|X86_EFLAGS_TF, PT_EFLAGS(%esp)  /*TF置位和单步debug有关*/
	jnz	.Lsysenter_fix_flags
.Lsysenter_flags_fixed:

	TRACE_IRQS_OFF   /*关中断*/

	movl	%esp, %eax
	pax_direct_call do_fast_syscall_32    /*这里面调用do_syscall_32_irqs_on开始系统调用，退出后开始返回*/

    ......

#ifdef CONFIG_PAX_RANDKSTACK
	movl	%esp, %eax
	pax_direct_call pax_randomize_kstack  /*这里调用了随机化，注意是在系统调用退出时进行的*/
#endif

	pax_erase_kstack                   /*即将退出内核空间，填充栈擦除信息*/

/* Opportunistic SYSEXIT */    /*开中断，恢复上下文*/
	TRACE_IRQS_ON			/* User mode traces as IRQs on. */
	movl	PT_EIP(%esp), %edx	/* pt_regs->ip */
	movl	PT_OLDESP(%esp), %ecx	/* pt_regs->sp */
1:	mov	PT_FS(%esp), %fs
2:	mov	PT_DS(%esp), %ds
3:	mov	PT_ES(%esp), %es
	PTGS_TO_GS
	popl	%ebx			/* pt_regs->bx */
	addl	$2*4, %esp		/* skip pt_regs->cx and pt_regs->dx */
	popl	%esi			/* pt_regs->si */
	popl	%edi			/* pt_regs->di */
	popl	%ebp			/* pt_regs->bp */
	popl	%eax			/* pt_regs->ax */

	addl	$PT_EFLAGS-PT_DS, %esp	/* point esp at pt_regs->flags */
	btr	$X86_EFLAGS_IF_BIT, (%esp)
	popfl

	sti
	sysexit             /*退出内核空间*/

.pushsection .fixup, "ax"
4:	......
5:	......
6:	......
.popsection
	......

.Lsysenter_fix_flags:
    ......
GLOBAL(__end_SYSENTER_singlestep_region)
ENDPROC(entry_SYSENTER_32)
```  
用户空间的进程申请一次系统调用后，就会陷入内核空间，这个切换是由系统调用的入口 entry_SYSENTER_32 来进行的。切换到内核时，会读取进程相关的信息，初始化sp指针指向进程的内核栈。为了随机化每一次进入内核的起始地址，我们需要在系统调用入口的地方加插随机化函数。但是实现上，PaX把随机化放在了系统调用返回前，这和中断异常等的处理函数有关。随机化完更新给内核的结构体，下一次进入的时候读取的是上次随机化过的栈起始地址。  
类似的，64 位的系统调用入口实现代码如下：  
```  
ENTRY(entry_SYSCALL_64)

	SWAPGS_UNSAFE_STACK                /*swapgs指令切换到内核模式*/

GLOBAL(entry_SYSCALL_64_after_swapgs)

	movq	%rsp, PER_CPU_VAR(rsp_scratch)              /*保存旧栈的值*/
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp /*加载内核栈赋值 sp*/

	TRACE_IRQS_OFF                                      /*关中断*/

	/* Construct struct pt_regs on stack */       /*压栈 pt_reg 的一些寄存器*/
	pushq	$__USER_DS			/* pt_regs->ss */
	pushq	PER_CPU_VAR(rsp_scratch)	/* pt_regs->sp */
	pushq	%r11				/* pt_regs->flags */
	pushq	$__USER_CS			/* pt_regs->cs */
	pushq	%rcx				/* pt_regs->ip */
	pushq	%rax				/* pt_regs->orig_ax */
	pushq	%rdi				/* pt_regs->di */
	pushq	%rsi				/* pt_regs->si */
	pushq	%rdx				/* pt_regs->dx */
	pushq	%rcx				/* pt_regs->cx */
	pushq	$-ENOSYS			/* pt_regs->ax */
	pushq	%r8				/* pt_regs->r8 */
	pushq	%r9				/* pt_regs->r9 */
	pushq	%r10				/* pt_regs->r10 */
	pushq	%r11				/* pt_regs->r11 */
	sub	$(6*8), %rsp			/* pt_regs->bp, bx, r12-15 not saved */

#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq	%r12, R12(%rsp)
#endif

	pax_enter_kernel_user     /* PaX 实现的进入内核栈地址空间的一些准备*/

#ifdef CONFIG_PAX_RANDKSTACK
	pax_erase_kstack          /*擦除栈上的原有信息，防止信息泄漏*/
#endif

	movq	PER_CPU_VAR(current_task), %r11
	testl	$_TIF_WORK_SYSCALL_ENTRY|_TIF_ALLWORK_MASK, TASK_TI_flags(%r11) /*这个标志位置位和单步 debug 有关*/
	jnz	entry_SYSCALL64_slow_path

entry_SYSCALL_64_fastpath:
	TRACE_IRQS_ON                           /*现场保护完，开中断*/
	ENABLE_INTERRUPTS(CLBR_NONE)
#if __SYSCALL_MASK == ~0
	cmpq	$__NR_syscall_max, %rax
#else
	andl	$__SYSCALL_MASK, %eax
	cmpl	$__NR_syscall_max, %eax    /*检查系统调用号是否超出范围*/
#endif
	ja	1f				/* return -ENOSYS (already in pt_regs->ax) */
	movq	%r10, %rcx

	pax_indirect_call "sys_call_table(, %rax, 8)", sys_ni_syscall /*sys_call_table 内核初始化的系统调用表*/
.Lentry_SYSCALL_64_after_fastpath_call:

	movq	%rax, RAX(%rsp)
1:

	DISABLE_INTERRUPTS(CLBR_NONE)     /*系统调用结束，开始准备回到用户空间的现场恢复，关中断*/
	TRACE_IRQS_OFF
	movq	PER_CPU_VAR(current_task), %r11
	testl	$_TIF_ALLWORK_MASK, TASK_TI_flags(%r11)
	jnz	1f

	pax_exit_kernel_user          /*PaX 实现的退出内核空间的一些准备，随机化栈起点会在这里调用*/
	pax_erase_kstack              /*防止内核栈信息泄漏给用户空间，擦除栈*/

	LOCKDEP_SYS_EXIT
	TRACE_IRQS_ON		/* user mode is traced as IRQs on */
	movq	RIP(%rsp), %rcx
	movq	EFLAGS(%rsp), %r11
	RESTORE_C_REGS_EXCEPT_RCX_R11
	movq	RSP(%rsp), %rsp
	USERGS_SYSRET64                /*切换到用户空间，ring-0，包括 swapgs 和 sysretq 两条指令*/

1:
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS(CLBR_NONE)
	SAVE_EXTRA_REGS
	movq	%rsp, %rdi
	pax_direct_call syscall_return_slowpath	/* returns with IRQs disabled */
	jmp	return_from_SYSCALL_64

entry_SYSCALL64_slow_path:
	/* IRQs are off. */
	SAVE_EXTRA_REGS
	movq	%rsp, %rdi
	pax_direct_call do_syscall_64		/* returns with IRQs disabled */

return_from_SYSCALL_64:
	pax_exit_kernel_user              /*PaX 实现的一些离开栈的工作，他会调用随机化栈起点的函数*/
	pax_erase_kstack

	RESTORE_EXTRA_RELOCKDEP_SYS_EXITGS
	TRACE_IRQS_IRETQ		/* we're about to change IF */

	/*
	 * Try to use SYSRET instead of IRET if we're returning to
	 * a completely clean 64-bit userspace context.
	 */
	movq	RCX(%rsp), %rcx
	movq	RIP(%rsp), %r11
	cmpq	%rcx, %r11			/* RCX == RIP */
	jne	opportunistic_sysret_failed

	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the user take over
	 * the kernel, since userspace controls RSP.
	 *
	 * If width of "canonical tail" ever becomes variable, this will need
	 * to be updated to remain correct on both old and new CPUs.
	 */
	.ifne __VIRTUAL_MASK_SHIFT - 47
	.error "virtual address width changed -- SYSRET checks need update"
	.endif

	/*
	 * If the top 17 bits are not 0 then RIP isn't a userland address,
	 * it may not even be canonical, fall back to iret
	 */
	shr	$(__VIRTUAL_MASK_SHIFT), %r11     /*地址检查*/
	jnz	opportunistic_sysret_failed

	cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
	jne	opportunistic_sysret_failed

	movq	R11(%rsp), %r11
	cmpq	%r11, EFLAGS(%rsp)		/* R11 == RFLAGS */
	jne	opportunistic_sysret_failed

	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
	jnz	opportunistic_sysret_failed

	/* nothing to check for RSP */

	cmpq	$__USER_DS, SS(%rsp)		
	jne	opportunistic_sysret_failed

syscall_return_via_sysret:        /*一些特殊情况的出口*/
	......

opportunistic_sysret_failed:
	......
ENDPROC(entry_SYSCALL_64)

```  
64 位的系统调用的入口函数中，PaX 在系统调用返回前随机化栈基址，插入的随机化调用放到宏汇编内完成：
```  
	.macro pax_exit_kernel_user
#ifdef CONFIG_PAX_MEMORY_UDEREF
	pax_direct_call pax_exit_kernel_user
#endif
#ifdef CONFIG_PAX_RANDKSTACK
	pushq	%rax
	pushq	%r11
	pax_direct_call pax_randomize_kstack   /*随机化栈*/
	popq	%r11
	popq	%rax
#endif
	.endm

```  
实际上，内核还保持了 INT 80 的老的系统调用接口的兼容，相应的地方也需要插入随机化函数，和上述代码类似，此处不赘述。  
总结起来，PAX_RANDKSTACK主要是实现了：
1. pax_randomize_kstack的实现。这个函数读取时钟（随机数）对进程内核栈基址进行掩码异或，获取有随机化偏移的栈基址，赋值给相应的内核结构，栈增长时就会基于这个随机化地址。
2. 在相应的系统调用入口处插入随机化的函数。因为进程內核栈的使用是通过进程触发系统调用（当然还有异常和中断），陷进内核，来切换到进程内核栈，随机化应该在这些地方插入执行。
3. 配合性地，PaX 实现了 pax_erase_kstack 函数，在内核/用户空间切换的时候进行内核信息抹除，填充。
