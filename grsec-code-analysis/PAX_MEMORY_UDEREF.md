# PAX_MEMORY_UDEREF

## 简述
PAX_MEMORY_UDEREF 是针对 Linux 的内核/用户空间分离的重要特性，连同 KERNEXEC 构成了强悍的地址空间划分隔离，防御了大量针对内核的漏洞利用，比如 ret2usr/ret2dir 这类将特权级执行流引向用户空间的攻击方式，即便是陆续被硬件实现的 SMEP/SMAP( x86) 或者 PXN/PAN( ARMv7/ARMv8.1) 亦难与 UDEREF 比肩。在 32-bit 的 x86 下，分离的特性很大部分是透过分段机制的寄存器去实现的，而 amd64 以后由于段寄存器功能的削弱，PaX 针对 64-bit 精心设计了 KERNEXEC/UDEREF，包括使用 PCID 特性和 per-cpu-pgd 的实现等。UDEREF诞生于ret2usr攻击已经在地下大规模使用的年代，虽然2004年PaX/Grsecurity公布了i386版本的KERNEXEC，但并未对数据访问严格限制，所以在一定程度上也方便了ret2usr和任意写的漏洞利用，随后PaX/Grsecurity为了弥补这一风险于2007年公布了i386版本的UDEREF，之后又实现了x64以及armv7的UDEREF，在众多UDEREF实现中安全性和性能最好的是[i386](https://grsecurity.net/~spender/uderef.txt)和[armv7](https://forums.grsecurity.net/viewtopic.php?f=7&t=3292&sid=d67decb18f1c9751e8b3c3de3d551075)，在x64的进化之路则显得更坎坷，2010年x64的版本很弱，且无法防御多层deref后的情况，之后在2013年的实现中被称为强实现的版本极大的增强防护的同时也利用Sandybridge+开始后的硬件特性PCID提升性能，后续UDEREF的改进(2017版)主要是利用硬件特性SMAP提升了性能的同时保证安全性，这篇分析是基于2013版的实现进行的。

UDEREF的实现主要包括几个方面：  
* per-cpu-pgd 的实现，将内核/用户空间的页目录彻底分离，彼此无法跨界访问
* PCID 特性的使用，跨界访问的时候产生硬件检查
* 内核/用户空间切换时，将用户空间映射为不可执行以及一些刷新 TLB 配合实现

## per_cpu_pgd 的实现
UDEREF 一个非常重要的子特性就是 PaX 重新为用户空间和内核空间维护了一个页目录( pgd)。  
```  
#ifdef CONFIG_PAX_PER_CPU_PGD
extern pgd_t cpu_pgd[NR_CPUS][2][PTRS_PER_PGD];
enum cpu_pgd_type {kernel = 0, user = 1};
static inline pgd_t *get_cpu_pgd(unsigned int cpu, enum cpu_pgd_type type)
{
	return cpu_pgd[cpu][type];
}
```  
可以看到，这里维护了一个 cpu_pgd 的全局变量，是一个三维数组,第一个索引号是 cpu,第二个是用户/内核,第三个是pgd个数。他的意义在于，隔离了用户/内核的 pgd 项，当发生切换的时候不能互相引用到彼此的项。  
下面这段代码是初始化的时候申请内存并且填"0":
```  
# ifdef CONFIG_PAX_PER_CPU_PGD
ENTRY(cpu_pgd)
	.rept 2*NR_CPUS
	.fill	PTRS_PER_PGD,8,0
	.endr
EXPORT_SYMBOL(cpu_pgd)
# endif
```  
这里复制了 swapper_pg_dir，是原本内核所实现的 pgd，并且用 cpu_pgd 赋值给 cr3 寄存器(代码位于setup_arch -> init_mem_mapping):
```  
#ifdef CONFIG_PAX_PER_CPU_PGD
	clone_pgd_range(get_cpu_pgd(0, kernel) + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);
	clone_pgd_range(get_cpu_pgd(0, user) + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);
	load_cr3(get_cpu_pgd(0, kernel));
#else
	load_cr3(swapper_pg_dir);
#endif
```  

在缺页中断的处理函数 __do_page_fault 中，vmalloc_fault用于检查内核访问地址（vmalloc/module mapping)是否在表中:
```  
#ifdef CONFIG_PAX_PER_CPU_PGD
	/* 获取该 cpu 内核空间的 pgd，与访问地址的掩码做比较 */
	BUG_ON(__pa(get_cpu_pgd(smp_processor_id(), kernel)) != (pgd_paddr & __PHYSICAL_MASK));
	vmalloc_sync_one(__va(pgd_paddr + PTRS_PER_PGD * sizeof(pgd_t)), address);
#endif
```  
为了减少新维护 pgd 所带来的损耗，PaX 将 ASLR 的随机化降低了。

## CR3.pcid 的使用
PCID 是一个 X86_64 处理器支持的特性，由 CR4.PCIDE 控制使能，在内存访问时，比对 CR3.PCID( 12-bit) 来确定进程是否具有访问权限。
```  
#define PCID_KERNEL		0UL
#define PCID_USER		1UL
#define PCID_NOFLUSH		(1UL << 63)
```  
这是 PaX 实现的标志位，可以看到 PaX 只是分离了内核和用户空间。最后一个标志不在 0-11bit 之中，表示当 cr3 被重载时不刷新 TLB，默认是会刷新的，籍此可减少刷新频率减少性能损失。这些相关的置位可以在 [Intel 的手册里找到](https://software.intel.com/sites/default/files/managed/a4/60/325384-sdm-vol-3abcd.pdf)(UDEREF 所用到的另一个硬件支持 INVPCID 也可以参考手册)。  
一个典型的例子，PaX 在 /arch/x86/mm/uderef.c 里实现了这样一对函数：
```  
void __used __pax_open_userland(void)
{
	unsigned int cpu;

	if (unlikely(!segment_eq(get_fs(), USER_DS)))
		return;

	cpu = raw_get_cpu();
	/* 检查切换是否来自内核空间 */
	BUG_ON((read_cr3() & ~PAGE_MASK) != PCID_KERNEL);
	/* 修改 cr3 切换到用户空间 */
	write_cr3(__pa_nodebug(get_cpu_pgd(cpu, user)) | PCID_USER | PCID_NOFLUSH);
	/* 关闭抢断？ */
	raw_put_cpu_no_resched();
}

void __used __pax_close_userland(void)
{
	unsigned int cpu;

	if (unlikely(!segment_eq(get_fs(), USER_DS)))
		return;

	cpu = raw_get_cpu();
	/* 检查切换是否来自用户空间 */
	BUG_ON((read_cr3() & ~PAGE_MASK) != PCID_USER);
	/* 修改 cr3 切换到内核空间 */
	write_cr3(__pa_nodebug(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL | PCID_NOFLUSH);
	raw_put_cpu_no_resched();
}
EXPORT_SYMBOL(__pax_close_userland);
```  
这两个函数用在提供给内核访问用户空间的内存 __uaccess_begin/end 这组函数用，在原来内核的实现中是直接关掉 SMEP 的保护。这里 PaX 的实现则非常有效的检查了切换的方向，并且借用 PCID 的特性控制访问的空间，而不是简单的关掉 SMEP。类似[CVE-2014-9322( "BadIRET")](https://hardenedlinux.github.io/system-security/2015/07/05/badiret-exp.html)和[CVE-2017-5123](https://salls.github.io/Linux-Kernel-CVE-2017-5123/)都无法打穿UDEREF， 在CVE-2017-5123的漏洞利用中，针对内核空间的任意写是无法达成的，因为内核空间和用户空间使用被 PCID 所限制，并且 pgd 是隔离的，切换前后是相互独立的空间。而原内核的实现则可以实现整个内核空间的任意写入。


## pax_switch_mm 的处理
switch_mm 用于进程切换的时候处理进程间地址空间的切换，pax_switch_mm 是另外实现的专门处理由于 UDEREF 引入带来的区别，其调用过程如下：  
schedule -> __schedule -> context_switch ->switch_mm_irq_off -> pax_switch_mm
```  
static void pax_switch_mm(struct mm_struct *next, unsigned int cpu)
{

	/* 只读区域的修改需要调用该函数关闭 CR0 的写保护才能修改 */
#ifdef CONFIG_PAX_PER_CPU_PGD
	pax_open_kernel();

	/* 若无pcid，只会用到一个页表 */
#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
	if (static_cpu_has(X86_FEATURE_PCIDUDEREF))
		__clone_user_pgds(get_cpu_pgd(cpu, user), next->pgd);
	else
#endif
                /* 将新的进程 pgd 复制进内核 pgd */
		__clone_user_pgds(get_cpu_pgd(cpu, kernel), next->pgd);

	/* 这里将用户空间的 pgd 备份进内核，并且撤销了可执行 */
	__shadow_user_pgds(get_cpu_pgd(cpu, kernel) + USER_PGD_PTRS, next->pgd);

	pax_close_kernel();

	/* 检查 pgd 的备份是否有 PCID 位的错误 */
	BUG_ON((__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL) != (read_cr3() & __PHYSICAL_MASK) && (__pa(get_cpu_pgd(cpu, user)) | PCID_USER) != (read_cr3() & __PHYSICAL_MASK));

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
	/* 清除大量的映射缓存造成的性能损耗比较大，必须有 INVPCID 的硬件支持 */
	if (static_cpu_has(X86_FEATURE_PCIDUDEREF)) {
		if (static_cpu_has(X86_FEATURE_INVPCID)) {
			/* 清除所有带有 PCID_USER 映射缓存 */
			invpcid_flush_single_context(PCID_USER);
			if (!static_cpu_has(X86_FEATURE_STRONGUDEREF))
				/* 清除所有带有 PCID_KERNEL 映射缓存 */
				invpcid_flush_single_context(PCID_KERNEL);
		} else {
                        /* 分别加载 pgd 到 cr3，注意 PCID_* 的置位，能够导致映射缓存刷新 */
			write_cr3(__pa(get_cpu_pgd(cpu, user)) | PCID_USER);
                        /* NOFLUSH 是为了提高性能，减少刷新，因为内核/用户的pgd已经彻底分离，内核常驻无需刷新 */
			if (static_cpu_has(X86_FEATURE_STRONGUDEREF))
				write_cr3(__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL | PCID_NOFLUSH);
			else
                        /* weakuderef 仍在内核的 pgd 中留有 shadow 备份，需刷新 */
				write_cr3(__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL);
		}
	} else
#endif
		/* 读取 pgd 到 cr3,这里只是原来 kernel 正常逻辑 */
		load_cr3(get_cpu_pgd(cpu, kernel));
#endif

}
```  
这里是 __shadow_user_pgds 的实现：  
```  
#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
void __shadow_user_pgds(pgd_t *dst, const pgd_t *src)
{
	unsigned int count = USER_PGD_PTRS;

        /* 只有 weakuderef 才有 shadow */
	if (!pax_user_shadow_base)
		return;
        /* 这里注意备份的时候标志位的掩码 */
	while (count--)
		*dst++ = __pgd((pgd_val(*src++) | (_PAGE_NX & __supported_pte_mask)) & ~_PAGE_USER);
}
#endif
```  
这里可以看到，stronguderef 彻底分离了 pgd，只有 weakuderef 才留有用户空间的备份
```  
/* 这是加载内核时的初始化 */
static int __init setup_pax_weakuderef(char *str)
{
	if (uderef_enabled)
		pax_user_shadow_base = 1UL << TASK_SIZE_MAX_SHIFT;
	return 1;
}
__setup("pax_weakuderef", setup_pax_weakuderef);
```  
这里 pax_switch_mm 的修改主要涉及两个方面：  
1. 由于 per_cpu_pgd 引入进行的配合实现进程切换 pgd 和 刷新 TLB 等(clone_user_pgd，write_cr3)。
2. 进程切换过程中 pgd 的处理(shadow_user_pgds、invpcid_flush_single_context)
由于 per_cpu_pgd 和内核/用户空间分隔和 PCID 以及 shadow 备份的引入，内核许多地方需要做配合性的修改，比如一些刷新 TLB 的地方，我们不再一一进行代码分析，只选取有代表性的部分。	

## 系统调用陷入 kernel 前的检查
下面这段代码在 pax_enter_kernel_user 中，在系统调用陷入内核时( entry_SYSCALL_64)会被调用
```  
#ifdef CONFIG_PAX_MEMORY_UDEREF
ENTRY(pax_enter_kernel_user)
GLOBAL(patch_pax_enter_kernel_user)
	pushq	%rdi
	pushq	%rbx

#ifdef CONFIG_PARAVIRT
	PV_SAVE_REGS(CLBR_RDI)
#endif
        /* 视乎处理器特性选择指令 */
	ALTERNATIVE "jmp 111f", "", X86_FEATURE_PCID
	GET_CR3_INTO_RDI
	/* 检查 CR3 中关于 PCID 的置位，若未置位，是内核空间，直接结束 CR3 的切换 */
	cmp	$1,%dil
	jnz	4f
	/* 将页表目录切到 kernel 态的，并且带PCID_KERNEL */
	sub	$4097,%rdi
	/* 尝试置位高地址，使得内核的 TLB 不会被强刷 */
	bts	$63,%rdi
	/* 写入 CR3 不会导致 TLB的强制刷新 */
	SET_RDI_INTO_CR3
	/* 在有 PCID 的处理器实际处理到此为止 */
	jmp	3f
111：

	/* 取得内核 pgd 的虚拟地址 */
	GET_CR3_INTO_RDI
	mov	%rdi,%rbx
	add	$__START_KERNEL_map,%rbx
	sub	phys_base(%rip),%rbx

#ifdef CONFIG_PARAVIRT
	......
#else
	/* 循环将用户空间的页表项某些标志位清除，防止内核的非法访问
         * 参见内核 pgd 的标志位，USER_PGD_PTRS 为用户空间页表宽度 
         */
	i = 0
	.rept USER_PGD_PTRS
	movb	$0,i*8(%rbx)
	i = i + 1
	.endr
#endif
	/* 写入CR3，会发生 TLB 的刷新 */
	SET_RDI_INTO_CR3

#ifdef CONFIG_PAX_KERNEXEC
	GET_CR0_INTO_RDI
	bts	$X86_CR0_WP_BIT,%rdi
	SET_RDI_INTO_CR0
#endif

3:

#ifdef CONFIG_PARAVIRT
	PV_RESTORE_REGS(CLBR_RDI)
#endif

	popq	%rbx
	popq	%rdi
	pax_ret pax_enter_kernel_user
4:	ud2
ENDPROC(pax_enter_kernel_user)
```  
相应的在 pax_exit_kernel_user 中会有一个逆过程,会将 pgd 项的标志位( _PAGE_BIT_*)恢复访问权限，但是不再强制刷新 TLB，因为不需要剔除任何缓存。
```  
ENTRY(pax_exit_kernel_user)
GLOBAL(patch_pax_exit_kernel_user)
	pushq	%rdi
	pushq	%rbx

#ifdef CONFIG_PARAVIRT
	......
#endif

        /* 这是上述的逆过程 */
	GET_CR3_INTO_RDI
	ALTERNATIVE "jmp 1f", "", X86_FEATURE_PCID
	cmp	$0,%dil
	jnz	3f
	add	$4097,%rdi
	bts	$63,%rdi
	SET_RDI_INTO_CR3
	jmp	2f
1:

	mov	%rdi,%rbx

#ifdef CONFIG_PAX_KERNEXEC
	GET_CR0_INTO_RDI
	btr	$X86_CR0_WP_BIT,%rdi
	jnc	3f
	SET_RDI_INTO_CR0
#endif

	add	$__START_KERNEL_map,%rbx
	sub	phys_base(%rip),%rbx

#ifdef CONFIG_PARAVIRT
        ......
#else
        /* 这里恢复用户空间的页表项，注意这里为了性能，没有再刷新 TLB */
	i = 0
	.rept USER_PGD_PTRS
	movb	$0x67,i*8(%rbx)
	i = i + 1
	.endr
#endif

2:

#ifdef CONFIG_PARAVIRT
	......
#endif

	popq	%rbx
	popq	%rdi
	pax_ret pax_exit_kernel_user
3:	ud2
ENDPROC(pax_exit_kernel_user)
#endif
```  
## user_shadow_base
```  
static int __init setup_pax_weakuderef(char *str)
{
	if (uderef_enabled)
		pax_user_shadow_base = 1UL << TASK_SIZE_MAX_SHIFT;
	return 1;
}
```  
因为 PER_CPU_PGD 的引入，为了降低损耗能够实现 pgd 的备份，PaX 缩减了进程地址空间
```  
config TASK_SIZE_MAX_SHIFT
	int
	depends on X86_64
	default 47 if !PAX_PER_CPU_PGD
	default 42 if PAX_PER_CPU_PGD
```  
缩减的结果是将用户空间的 pgd 项减少到 8 个，ASLR 的随机位也都会缩减。

## __do_page_fault 的处理
```  
#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
	/* 陷入内核而访问用户地址空间, pax_user_shadow_base 是用户空间的最大范围 */
	if (!user_mode(regs) && address < 2 * pax_user_shadow_base) {
		if (!search_exception_tables(regs->ip)) {
			printk(KERN_EMERG "PAX: please report this to pageexec@freemail.hu\n");
			bad_area_nosemaphore(regs, error_code, address, NULL);
			return;
		}
		if (address < pax_user_shadow_base) {
			printk(KERN_EMERG "PAX: please report this to pageexec@freemail.hu\n");
			printk(KERN_EMERG "PAX: faulting IP: %pS\n", (void *)regs->ip);
			show_trace_log_lvl(current, regs, (void *)regs->sp, KERN_EMERG);
		} else
			address -= pax_user_shadow_base;
	}
#endif
```  
