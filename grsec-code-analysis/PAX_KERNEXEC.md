## 简介
PAX_KERNEXEC 是 PaX 针对内核的 No-execute 实现，可以说是内核空间版的 pageexec/mprotect。由于 PAGEEXEC 的实现已经完成了一部分工作（实际上内核的内存访问同样也是透过 page-fault 去处理），KERNEXEC 代码主要包括这几方面：  
* 对内核空间的内存属性进行设置（RO & NX）
* 内核态的内存访问的控制
* 可加载内核模块（W^X）和 bios/efi 内存属性的控制
* 透过 gcc-plugin 的配合实现

## GDT/IDT 的 RO
/arch/x86/kernel/head_32.S 的这部分代码是初始化 gdt 和 idt 的,在 startup_32 会调用 lgdt 和 lidt 加载他们,PaX 将这部分内存设置为 __READ_ONLY,代码如下:
```  
#ifdef CONFIG_PAX_KERNEXEC
#define __READ_ONLY	.section	".data..read_only","a",%progbits
#else
#define __READ_ONLY	.section	".data..mostly","aw",%progbits
#endif
```  
```  
__READ_ONLY
.globl boot_gdt_descr
.globl idt_descr

	ALIGN
# early boot GDT descriptor (must use 1:1 address mapping)
	.word 0				# 32 bit align gdt_desc.address
boot_gdt_descr:
	.word __BOOT_DS+7
	.long pa(boot_gdt)

	.word 0				# 32-bit align idt_desc.address
idt_descr:
	.word IDT_ENTRIES*8-1		# idt contains 256 entries
	.long idt_table

# boot GDT descriptor (later on used by CPU#0):
	.word 0				# 32 bit align gdt_desc.address
ENTRY(early_gdt_descr)
	.word GDT_ENTRIES*8-1
	.long cpu_gdt_table		/* Overwritten for secondary CPUs */

/*
 * The boot_gdt must mirror the equivalent in setup.S and is
 * used only for booting.
 */
	.align L1_CACHE_BYTES
ENTRY(boot_gdt)
	.fill GDT_ENTRY_BOOT_CS,8,0
	.quad 0x00cf9b000000ffff	/* kernel 4GB code at 0x00000000 */
	.quad 0x00cf93000000ffff	/* kernel 4GB data at 0x00000000 */

	.align PAGE_SIZE_asm
ENTRY(cpu_gdt_table)
	.rept NR_CPUS
	.quad 0x0000000000000000	/* NULL descriptor */
	.quad 0x0000000000000000	/* 0x0b reserved */
	.quad 0x0000000000000000	/* 0x13 reserved */
	.quad 0x0000000000000000	/* 0x1b reserved */

#ifdef CONFIG_PAX_KERNEXEC
	.quad 0x00cf9b000000ffff	/* 0x20 alternate kernel 4GB code at 0x00000000 */
#else
	.quad 0x0000000000000000	/* 0x20 unused */
#endif

	......

	/*
	 * Segments used for calling PnP BIOS have byte granularity.
	 * The code segments and data segments have fixed 64k limits,
	 * the transfer segment sizes are set at run time.
	 */
	
	......

	/*
	 * The APM segments have byte granularity and their bases
	 * are set at run time.  All have 64k limits.
	 */
	
	......	

	/* Be sure this is zeroed to avoid false validations in Xen */
	.fill PAGE_SIZE_asm - GDT_SIZE,1,0
	.endr

EXPORT_SYMBOL_GPL(cpu_gdt_table)
```  
cpu_gdt_table 在后续内核初始化的时候,还会被用到,mark_rodata_ro 以 get_cpu_gdt_table 为参数,返回的其实就是 cpu_gdt_table 数组( 数组 index 是 cpu 的 id)。注意，这里 gdt 维护了一个 __KERNEXEC_KERNEL_CS 以及 64-bit 维护多的 __UDEREF_KERNEL_DS。

## 初始化时的配合实现
这里我们介绍修改 gdt 项所用到的一组 PaX 实现的基于 x86_CR0_WP 的硬件支持的写保护控制的函数，调用路径如下所示：  
mark_rodata_ro -> write_gdt_entry -> pax_open_kernel/memcpy/pax_close_kernel  
mark_rodata_ro 在下文会讲述，他是内核进行初始化时一个重要的函数，write_gdt_entry 是修改 gdt 的项的行为，实现的步骤是：pax_open_kernel（关闭写保护） -> memcpy（修改相应内存） -> pax_close_kernel（恢复写保护）
```  
#ifdef CONFIG_PAX_KERNEXEC
static inline unsigned long native_pax_open_kernel(void)
{
	unsigned long cr0;

	preempt_disable();
	barrier();
	/* CR0 的 WP 用于写保护 */
	cr0 = read_cr0() ^ X86_CR0_WP;
	/* 异或操作后会被求反,求反后仍然置位说明有错 */
	BUG_ON(cr0 & X86_CR0_WP);
	/* 赋值 cr0 寄存器,进行下面的操作 */
	write_cr0(cr0);
	barrier();
	return cr0 ^ X86_CR0_WP;
}
static inline unsigned long native_pax_close_kernel(void)
{
	unsigned long cr0;

	/* 这个实现是和 pax_open_kernel 相反的 */
	barrier();
	cr0 = read_cr0() ^ X86_CR0_WP;
	BUG_ON(!(cr0 & X86_CR0_WP));
	write_cr0(cr0);
	barrier();
	preempt_enable_no_resched();
	return cr0 ^ X86_CR0_WP;
}
#else
static inline unsigned long native_pax_open_kernel(void) { return 0; }
static inline unsigned long native_pax_close_kernel(void) { return 0; }
#endif
```  
native_pax_open_kernel 函数实际上是在关闭写保护，让特权用户可以任意操作内存。
* 附注：这个 x86 的实现，ARM 的实现是基于进程的 domain 来做的。  
这里再附上 PAX_KERNEXEC 在系统调用陷进内核的时候用到的 pax_enter_kernel，他同样涉及到 CR0 的 WP 位的操作：
```  
ENTRY(pax_enter_kernel)
	pushq	%rdi

#ifdef CONFIG_PARAVIRT
	......
#endif

#ifdef CONFIG_PAX_KERNEXEC
	GET_CR0_INTO_RDI
	/* bts 检查置位 %rdi 的 $X86_CR0_WP_BIT，若进行了置位则 CF 为 0 */
	bts	$X86_CR0_WP_BIT,%rdi
	/* 若 CF 为 0 即 %rdi 被置位，跳转到标签 3 处 */
	jnc	3f
	mov	%cs,%edi
	cmp	$__KERNEL_CS,%edi
	jnz	2f
1:
#endif

#ifdef CONFIG_PAX_MEMORY_UDEREF
	......
112:	
	......
113:	
	......
111:
#endif

#ifdef CONFIG_PARAVIRT
	......
#endif

	popq	%rdi
	pax_ret pax_enter_kernel

#ifdef CONFIG_PAX_KERNEXEC
2:	ljmpq	__KERNEL_CS,1b
3:	ljmpq	__KERNEXEC_KERNEL_CS,4f
	/* 将置位写入 CR0 寄存器 */
4:	SET_RDI_INTO_CR0
	jmp	1b
#endif
ENDPROC(pax_enter_kernel)
```  
这里的实现是把 CR0 的 WP 位开启。和前面不同的是，因为这是用户空间进程陷入内核的入口，他的行为都是来自进程的系统调用，在这里内核不能被哄骗去修改一些已经被设置只读的空间，因此此处的写保护应该开启，前述属于内核自身的初始化行为，则应该关闭写保护。而实现方面，后者使用了汇编代码大概是因为性能问题，因为系统调用较为频繁。

## 初始化内核的代码段、只读数据段的 RO 和数据段的 NX  
在内核加载运行起来，完成基础的初始化后，开始 fork 进程前，内核就应该把相应的内核态的内存属性做好设置，下面是调用路径：  
`start_kernel -> resr_init -> kernel_init -> mark_readonly -> mark_rodata_ro`  
mark_rodata_ro 承担了内核的代码段、只读数据段的 RO 和数据段的 NX 设置工作，设置是基于分页机制去完成的，设置的一些基址可以在内核源码的 arch/x86/kernel/vmlinux.lds.S 找到，这个文件登记着内核构建时的链接信息。（注意，这部分代码也有主线完成好，PaX 只针对性的做修改）。  
下面先看 32-bit 的代码实现：
```  
void mark_rodata_ro(void)
{
	unsigned long start = PFN_ALIGN(_text);
	unsigned long size = PFN_ALIGN(_etext) - start;

#ifdef CONFIG_PAX_KERNEXEC
	/* PaX: limit KERNEL_CS to actual size */
	unsigned long limit;
	struct desc_struct d;
	int cpu;

	limit = get_kernel_rpl() ? ktva_ktla(0xffffffff) : (unsigned long)&_etext;
	limit = (limit - 1UL) 

	memset(__LOAD_PHYSICAL_ADDR + PAGE_OFFSET, POISON_FREE_INITMEM, PAGE_SIZE);
	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		pack_descriptor(&d, get_desc_base(&get_cpu_gdt_table(cpu)[GDT_ENTRY_KERNEL_CS]), limit, 0x9B, 0xC);
		write_gdt_entry(get_cpu_gdt_table(cpu), GDT_ENTRY_KERNEL_CS, &d, DESCTYPE_S);
		write_gdt_entry(get_cpu_gdt_table(cpu), GDT_ENTRY_KERNEXEC_KERNEL_CS, &d, DESCTYPE_S);
	}

	......

	start = ktla_ktva(start);
#ifdef CONFIG_PAX_KERNEXEC
	/* PaX: make KERNEL_CS read-only */
	if (!get_kernel_rpl()) {
#endif
	kernel_set_to_readonly = 1;

	/* 这里将内核代码段设置为只读 */
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
	printk(KERN_INFO "Write protecting the kernel text: %luk\n", size >> 10);

#ifdef CONFIG_CPA_DEBUG
	......
#endif
#ifdef CONFIG_PAX_KERNEXEC
	}
#endif

	start += size;
	size = PFN_ALIGN(_sdata) - start;
	/* 这里是内核的只读数据段 */
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
	printk(KERN_INFO "Write protecting the kernel read-only data: %luk\n", size >> 10);
	rodata_test();

#ifdef CONFIG_CPA_DEBUG
	printk(KERN_INFO "Testing CPA: undo %lx-%lx\n", start, start + size);
	set_pages_rw(virt_to_page(start), size >> PAGE_SHIFT);

	printk(KERN_INFO "Testing CPA: write protecting again\n");
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
#endif
	/* 内核数据段的 no-execute 的设置，起点是 etext */
	mark_nxdata_nx();
	/* 这里检测了 nx-bit 的支持 */
	if (__supported_pte_mask & _PAGE_NX)
		debug_checkwx();
}
```  
下面的代码是 64-bit 的实现，这里除了内核代码段，内存均设置为不可执行，代码段和只读数据段设置为只读。并且添加了一段基于分页机制验证内存属性的代码
```  
void mark_rodata_ro(void)
{
	unsigned long start = PFN_ALIGN(_text);
#ifdef CONFIG_PAX_KERNEXEC
	unsigned long addr;
	unsigned long end = PFN_ALIGN(_sdata);
	unsigned long text_end = end;
#else
	unsigned long rodata_start = PFN_ALIGN(__start_rodata);
	unsigned long end = (unsigned long) &__end_rodata_hpage_align;
	unsigned long text_end = PFN_ALIGN(&__stop___ex_table);
	unsigned long rodata_end = PFN_ALIGN(&__end_rodata);
#endif
	unsigned long all_end;

	kernel_set_to_readonly = 1;

	printk(KERN_INFO "Write protecting the kernel read-only data: %luk\n", (end - start) >> 10);
	/* 只读内核代码段数据段 */
	set_memory_ro(start, (end - start) >> PAGE_SHIFT);

	/*
	 * The rodata/data/bss/brk section (but not the kernel text!)
	 * should also be not-executable.
	 *
	 * We align all_end to PMD_SIZE because the existing mapping
	 * is a full PMD. If we would align _brk_end to PAGE_SIZE we
	 * split the PMD and the reminder between _brk_end and the end
	 * of the PMD will remain mapped executable.
	 *
	 * Any PMD which was setup after the one which covers _brk_end
	 * has been zapped already via cleanup_highmem().
	 */
	all_end = roundup((unsigned long)_brk_end, PMD_SIZE);
	/* text_end 是内核代码段的终点，除此之外均为不可执行 */
	set_memory_nx(text_end, (all_end - text_end) >> PAGE_SHIFT);

	rodata_test();

#ifdef CONFIG_CPA_DEBUG
	......
#endif

#ifdef CONFIG_PAX_KERNEXEC
	/* PaX: ensure that kernel code/rodata is read-only, the rest is non-executable */
	/* 这里 PaX 实现了一个验证内存属性的过程，基于分页机制 */
	for (addr = __START_KERNEL_map; addr < __START_KERNEL_map + KERNEL_IMAGE_SIZE; addr += PMD_SIZE) {
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;

		pgd = pgd_offset_k(addr);
		pud = pud_offset(pgd, addr);
		pmd = pmd_offset(pud, addr);
		if (!pmd_present(*pmd))
			continue;
		if (addr >= (unsigned long)_text)
			BUG_ON(!pmd_large(*pmd));
		if ((unsigned long)_text <= addr && addr < (unsigned long)_sdata)
			BUG_ON(pmd_write(*pmd));
//			set_pmd(pmd, __pmd(pmd_val(*pmd) & ~_PAGE_RW));
		else
			BUG_ON(!(pmd_flags(*pmd) & _PAGE_NX));
//			set_pmd(pmd, __pmd(pmd_val(*pmd) | (_PAGE_NX & __supported_pte_mask)));
	}

	addr = (unsigned long)__va(__pa(__START_KERNEL_map));
	end = addr + KERNEL_IMAGE_SIZE;
	for (; addr < end; addr += PMD_SIZE) {
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;

		pgd = pgd_offset_k(addr);
		pud = pud_offset(pgd, addr);
		pmd = pmd_offset(pud, addr);
		if (!pmd_present(*pmd))
			continue;
		if (addr >= (unsigned long)_text)
			BUG_ON(!pmd_large(*pmd));
		if ((unsigned long)__va(__pa(_text)) <= addr && addr < (unsigned long)__va(__pa(_sdata)))
			BUG_ON(pmd_write(*pmd));
//			set_pmd(pmd, __pmd(pmd_val(*pmd) & ~_PAGE_RW));
	}
#else
	free_init_pages("unused kernel",
			(unsigned long) __va(__pa_symbol(text_end)),
			(unsigned long) __va(__pa_symbol(rodata_start)));
	free_init_pages("unused kernel",
			(unsigned long) __va(__pa_symbol(rodata_end)),
			(unsigned long) __va(__pa_symbol(_sdata)));
#endif
```  
这里由于本身内核的也有相应的实现，PaX 所做的是一些设置范围的修正。

## 缺页中断 page-fault 针对内核空间的处理
缺页中断是处理内存访问权限错误的重要一环，任何经过映射的内存区域，第一次进行访问的时候都会触发缺页（写入 TLB 后则不用）。无论内核或者用户空间，都需要走这个流程。而 __do_page_fault 函数正是完成这个中断的实际处理函数，我们这里只抽出处理内核部分：
```  
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	int fault, major = 0;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	tsk = current;
	mm = tsk->mm;

	......

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * This verifies that the fault happens in kernel space
	 * (error_code & 4) == 0, and that the fault was not a
	 * protection error (error_code & 9) == 0.
	 */
	/* 这里进入发生在内核空间的 page_fault 的处理 */
	if (unlikely(fault_in_kernel_space(address))) {
		/* error code 是保留位被置位、访问地址在用户空间或者为保护模式
		 * 直接进入 bad_area_nosemaphore的处理
		 */
		if (!(error_code & (PF_RSVD | PF_USER | PF_PROT))) {
			/* 处理访问 vmalloc 区域的内存 */
			if (vmalloc_fault(address) >= 0)
				return;
			/* 这里 PaX 增加了 CS 寄存器不在 __KERNEXEC_KERNEL_CS 的检查 */
			if (kmemcheck_fault(regs, address, error_code))
				return;
		}

		/* Can handle a stale RO->RW TLB: */
		/* 基于分页机制，当修改只读区域或者执行到设置 nx 位的会触发，具体处理用 spurious_fault_check */
		if (spurious_fault(error_code, address))
			return;

		......

		/*
		 * Don't take the mm semaphore here. If we fixup a prefetch
		 * fault we could otherwise deadlock:
		 */
		bad_area_nosemaphore(regs, error_code, address, NULL);

		return;
	}

	......

}
NOKPROBE_SYMBOL(__do_page_fault);
```  
这里我们附上缺页中断产生时的 error code 每一个位代表的含义：
```  
/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 *   bit 5 ==				1: protection keys block access
 */
enum x86_pf_error_code {

	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
	PF_PK		=		1 << 5,
};
```  
首先，经过 fault_in_kernel_space(address) 的检查，进入访问内核空间发生缺页的处理流程。接着调用检查 error_code 是否为(PF_RSVD（保留位被置位） | PF_USER（发生在用户空间） | PF_PROT（权限问题）)，若非，则调用 vmalloc_fault 和 kmemcheck_fault 分别处理。vmalloc_fault 用于处理内核 vmalloc 区域的情况（比如模块加载），kmemcheck_fault 验证内存的操作合法与否，这个函数 PaX 添加了配合检查寄存器 CS 是否在 __KERNEXEC_KERNEL_CS。若非上述情况之一，则调用 spurious_fault 函数处理非法访问（仅限于对只读区域的写操作和不可执行区域取指操作）。spurious_fault 处理的一种情况是：TLB 尚未刷新导致导致的权限问题，需调用 spurious_fault_check 重新确认访问权限是否有问题。最后若为有问题操作，会调用 bad_area_nosemaphore 进行处理。  
下面是 spurious_fault 的代码：
```  
static noinline int
spurious_fault(unsigned long error_code, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;

	/* 只有写入只读或者执行到不可执行的内存才进行处理 */
	if (error_code != (PF_WRITE | PF_PROT)
	    && error_code != (PF_INSTR | PF_PROT))
		return 0;

	/* init_mm.pgd 是内核使用的页目录 */
	pgd = init_mm.pgd + pgd_index(address);
	/* *_present 都是检测相应的页表项是否驻存在内存当中 */
	if (!pgd_present(*pgd))
		return 0;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return 0;

	/* spurious_fault_check 会对相应的页表项做权限的检查 */
	if (pud_large(*pud))
		return spurious_fault_check(error_code, (pte_t *) pud);

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return spurious_fault_check(error_code, (pte_t *) pmd);

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte))
		return 0;

	ret = spurious_fault_check(error_code, pte);
	if (!ret)
		return 0;

	/*
	 * Make sure we have permissions in PMD.
	 * If not, then there's a bug in the page tables:
	 */
	ret = spurious_fault_check(error_code, (pte_t *) pmd);
	WARN_ONCE(!ret, "PMD has incorrect permission bits\n");

	return ret;
}
NOKPROBE_SYMBOL(spurious_fault);

```  
这里个函数针对具体地址，基于分页机制去做权限的检查，主要是写操作和执行操作的检查，内核态的只读和不可执行会在这里进行处理。

### NULL derefs 的处理
针对内核的空指针引用，PaX 也给出来相应的补救措施。  
ENTRY(stext) 是内核 "text segment" 的真正起始处,PaX 在这了填充了如下代码:
```  
#ifdef CONFIG_PAX_KERNEXEC
	jmp startup_32
/* PaX: fill first page in .text with int3 to catch NULL derefs in kernel mode */
/* 0xcc 是中断指令 INT3 的机器码 */
.fill PAGE_SIZE-5,1,0xcc
#endif
```  
这里 PaX 在代码段起始出填充了 INT3 的指令机器码，但凡内核态的 NULL 指针被引用执行，就会产生一个 INT3 的软中断，防止进一步漏洞利用。

## gcc-plugin 的配合
由于 amd64 的段寄存器的功能削弱，为了实现如同在 i386 架构般强悍，PaX 为 KERNEXEC 的 amd64 版引入 gcc-plugin 的配合实现。主要是基于内核/用户空间的地址区别，实现内核/用户空间的执行代码的地址的验证。实现的选择有两个选项：
1. CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_BTS 将内核函数的地址第63位置位，用户空间指针置位后变成非法指针
2. CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR  配合 r12 寄存器对内核函数地址掩码，用户空间指针掩码后变成非法指针  

籍此便可验证跳转/返回的地址是否为内核空间，非内核空间的指针都是非法的，触发缺页中断去处理

gcc-plugin 的相关配合实现都在 /script/gcc-plugins/kernexec_plugin.c 中：

plugin_init 将 kernexec_instrument_fptr 初始化为 kernexec_instrument_fptr_bts/or 和 kernexec_instrument_fptr 初始化为 kernexec_instrument_fptr_bts/or。若为 PAX_KERNEXEC_PLUGIN_METHOD_OR 模式还需调用 register_callback(kernexec_reload/fptr/retaddr_pass_info)。

kernexec_fptr_execute：用 for 循环调用 kernexec_instrument_fptr 置位所有内核函数指针地址的最高位，kernexec_instrument_fptr 在 plugin_init 中被初始化好为具体实现：
* kernexec_instrument_fptr_bts：置位函数地址最高位。
* kernexec_instrument_fptr_or：设置 r12 寄存器为函数地址掩码，gimple_build_asm_vec 可以找到插入修正地址的内联汇编（“orq %%r12, %0\n\t" : "=r"(new_fptr) : "0"(old_fptr)”）。

kernexec_retaddr_execute：用 for 循环调用 kernexec_retaddr_execute 检查返回地址，kernexec_retaddr_execute 在 plugin_init 中被初始化好为具体实现：
* kernexec_instrument_retaddr_bts：在函数返回前添加 btsq $63,(%rsp)
* kernexec_instrument_retaddr_or： 在函数返回前添加 orq %r12,(%rsp)

两种设置都基于内核处于高地址，设置完这些位并不会对内核的函数指针有影响，而用户空间的地址经过设置后会变成非法地址导致错误，这样就能防止内核执行流引向用户空间。

kernexec_reload_execute： 当有汇编代码操作到 r12 寄存器的时候，调用 kernexec_reload_fptr_mask 重新修复好 r12 的值。

尽管 PaX 在 gcc-plugin 这部分的代码注释比较详细，代码结构也不复杂，这里我们还是为 [kernexec_plugin.c](kernexec_plugin.c) 增加一些注释，有助于理解，以供参考。
相应的，在一些场景中，需要修改内核代码，对 r12 寄存器做现场保护，这里举出调度切换内核进程栈的现场保护，其他不再赘述:
```  
/*
 * %rdi: prev task
 * %rsi: next task
 */
ENTRY(__switch_to_asm)
	/*
	 * Save callee-saved registers
	 * This must match the order in inactive_task_frame
	 */
	......
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	/* 将 r12 寄存器用于后续配合 gcc-plugin 实现 */
	pushq	%r12
#endif
	......


	/* 保存好现场，切换进程内核栈 */
	movq	%rsp, TASK_threadsp(%rdi)
	movq	TASK_threadsp(%rsi), %rsp

#ifdef CONFIG_CC_STACKPROTECTOR
	......
#endif

	/* restore callee-saved registers */
	......
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	popq	%r12
#endif
	......
	/* 恢复好现场，进行切换 */

	jmp	__switch_to
ENDPROC(__switch_to_asm)
```  
[这篇文章](https://lwn.net/Articles/712161/)讨论了一些关于 KERNEXEC gcc-plugin 的设计问题，供读者参阅。

## efi 相关
固件 EFI 提供了内核运行时的调用接口，称为 EFI runtime service，以使用运行时服务接口将 EFI 置为虚拟模式( virtual mode)为例，调用路径如下：  
`start_kernel -> efi_enter_virtual_mode -> __efi_enter_virtual_mode -> phys_efi_set_virtual_address_map ->  	efi_call_phys_prolog/efi_call_phys_epilog`
这里我们以 i386 的实现为例
```  
static efi_status_t __init phys_efi_set_virtual_address_map(
	unsigned long memory_map_size,
	unsigned long descriptor_size,
	u32 descriptor_version,
	efi_memory_desc_t *virtual_map)
{
	efi_status_t status;
	unsigned long flags;
	pgd_t *save_pgd;

	save_pgd = efi_call_phys_prolog();

	/* Disable interrupts around EFI calls: */
	local_irq_save(flags);
	/* 这里调用 set_virtual_address_map 将 efi 设置为虚拟地址模式 
	 * efi_call_phys 是物理地址形式去调用 efi 的服务
	 */
	status = efi_call_phys(efi_phys.set_virtual_address_map,
			       memory_map_size, descriptor_size,
			       descriptor_version, virtual_map);
	local_irq_restore(flags);

	efi_call_phys_epilog(save_pgd);

	return status;
}
```  
由于将 efi 映射到内存，PaX 在进入调用 efi_call_phys 之前，先把 EFI 的代码段和数据段相关置位（RO & NX）写入到 GDT 项中（退出的时候则由 efi_call_phys_epilog 承担相反的工作）：
```  
 /* 对 bios 而言，类似的设置在 bios32_service 中 
  * 对 64-bit 的机器而言，相应的设置函数名是一样的，在 /arch/x86/platform/efi/efi_64.c 下
  * 但是基于分页机制去做这个权限的限制
  */
pgd_t * __init efi_call_phys_prolog(void)
{
	struct desc_ptr gdt_descr;
	pgd_t *save_pgd;

#ifdef CONFIG_PAX_KERNEXEC
	struct desc_struct d;
#endif

	......
	load_cr3(initial_page_table);
	__flush_tlb_all();

#ifdef CONFIG_PAX_KERNEXEC
	/* pack_descriptor 承担了将标志位，地址，范围等信息转化为 GDT 项
	 * 注意参数 type、limit 的值，查阅 segment descriptor 的
	 * 可以发现是针对代码段和数据段的置位
	 */
	pack_descriptor(&d, 0, 0xFFFFF, 0x9B, 0xC);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_CS, &d, DESCTYPE_S);
	pack_descriptor(&d, 0, 0xFFFFF, 0x93, 0xC);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_DS, &d, DESCTYPE_S);
#endif

	......

	return save_pgd;
}
```  
相应的，我们可以在 efi_call_phys( /arch/x86/platform/efi/efi_stub_32.S)的实现中看到，PaX 会将运行时的一些寄存器切换到 __KERNEXEC_EFI_DS 段，关闭分页机制，使用物理地址直接访问调用 EFI 的 set_virtual_address_map 服务，开启虚拟地址模式，后续的 efi_enter_virtual_mode 将 EFI 的服务重映射到虚拟地址，基于分页机制设置 pte 性质，后续内核申请服务直接使用 efi_call_virt 来调用服务。

## Kernel module handle
PAX_KERNEXEC 针对内核可加载模块的加固是非常重要的一部分，主要实现是将可加载模块的数据和模块代码的分离。首先我们看到：
```  
/* 原先的内核并没有分开 rx/rw，整片内存一次性申请*/
struct module_layout {
	/* The actual code. */
	void *base_rx;
	/* The actual data. */
	void *base_rw;
	/* Code size. */
	unsigned int size_rx;
	/* Data size. */
	unsigned int size_rw;

#ifdef CONFIG_MODULES_TREE_LOOKUP
	......
#endif
};
```  
内核可加载模块初始化的调用路径：
init_module -> load_module -> layout_and_allocate -> move_module
其中，move_module 承担的工作就是申请分配内存，并且最终将模块加载到相应的内存中去。
```  
static int move_module(struct module *mod, struct load_info *info)
{
	/* 申请的内存包括仅供初始化使用的代码和常驻内存的代码 */
	int i;
	void *ptr;

	/* Do the allocs. */
	/* 这个是经过 PaX 修改的，默认申请不可执行的内存（PAGE_KERNEL） */
	ptr = module_alloc(mod->core_layout.size_rw);
	/*
	 * The pointer to this block is stored in the module structure
	 * which is inside the block. Just mark it as not being a
	 * leak.
	 */
	kmemleak_not_leak(ptr);
	if (!ptr)
		return -ENOMEM;

	memset(ptr, 0, mod->core_layout.size_rw);
	mod->core_layout.base_rw = ptr;

	/* 此处专用于内核模块加载时的初始化所用，初始化后可以释放 */
	if (mod->init_layout.size_rw) {
		ptr = module_alloc(mod->init_layout.size_rw);
		/*
		 * The pointer to this block is stored in the module structure
		 * which is inside the block. This block doesn't need to be
		 * scanned as it contains data and code that will be freed
		 * after the module is initialized.
		 */
		kmemleak_ignore(ptr);
		if (!ptr) {
			module_memfree(mod->core_layout.base_rw);
			return -ENOMEM;
		}
		memset(ptr, 0, mod->init_layout.size_rw);
		mod->init_layout.base_rw = ptr;
	} else
		mod->init_layout.base_rw = NULL;

	/* 显式分配 PAGE_KERNEL_RX 的区域，这个函数的实现是原来内核的 module_alloc 实现 */
	ptr = module_alloc_exec(mod->core_layout.size_rx);
	kmemleak_not_leak(ptr);
	if (!ptr) {
		if (mod->init_layout.base_rw)
			module_memfree(mod->init_layout.base_rw);
		module_memfree(mod->core_layout.base_rw);
		return -ENOMEM;
	}

	pax_open_kernel();
	memset(ptr, 0, mod->core_layout.size_rx);
	pax_close_kernel();
	mod->core_layout.base_rx = ptr;

	/* 用于初始化的代码段 */
	if (mod->init_layout.size_rx) {
		ptr = module_alloc_exec(mod->init_layout.size_rx);
		kmemleak_ignore(ptr);
		if (!ptr) {
			module_memfree(mod->core_layout.base_rx);
			if (mod->init_layout.base_rw)
				module_memfree(mod->init_layout.base_rw);
			module_memfree(mod->core_layout.base_rw);
			return -ENOMEM;
		}

		pax_open_kernel();
		memset(ptr, 0, mod->init_layout.size_rx);
		pax_close_kernel();
		mod->init_layout.base_rx = ptr;
	} else
		mod->init_layout.base_rx = NULL;

	/* Transfer each section which specifies SHF_ALLOC */
	pr_debug("final section addresses:\n");
	/* 这里解析 ELF 格式的可加载模块 */
	for (i = 0; i < info->hdr->e_shnum; i++) {
		void *dest;
		Elf_Shdr *shdr = &info->sechdrs[i];

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		/* 这里根据解析的结果确定不同段的加载地址 */
		if (shdr->sh_entsize & INIT_OFFSET_MASK) {
			if ((shdr->sh_flags & SHF_WRITE) || !(shdr->sh_flags & SHF_ALLOC))
				dest = mod->init_layout.base_rw
					+ (shdr->sh_entsize & ~INIT_OFFSET_MASK);
			else
				dest = mod->init_layout.base_rx
					+ (shdr->sh_entsize & ~INIT_OFFSET_MASK);
		} else {
			if ((shdr->sh_flags & SHF_WRITE) || !(shdr->sh_flags & SHF_ALLOC))
				dest = mod->core_layout.base_rw + shdr->sh_entsize;
			else
				dest = mod->core_layout.base_rx + shdr->sh_entsize;
		}

		if (shdr->sh_type != SHT_NOBITS) {

#ifdef CONFIG_PAX_KERNEXEC
#ifdef CONFIG_X86_64
			/* 因为后续要加载代码，此处可写可执行 */
			if ((shdr->sh_flags & SHF_WRITE) && (shdr->sh_flags & SHF_EXECINSTR))
				set_memory_x((unsigned long)dest, (shdr->sh_size + PAGE_SIZE) >> PAGE_SHIFT);
#endif
			/* 这是模块需要的只读数据段 */
			if (!(shdr->sh_flags & SHF_WRITE) && (shdr->sh_flags & SHF_ALLOC)) {
				/* 因为没有可写标志，复制需要关掉 wp 位 */
				pax_open_kernel();
				memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);
				pax_close_kernel();
			} else
#endif
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);
		}
		/* Update sh_addr to point to copy in image. */

#ifdef CONFIG_PAX_KERNEXEC
		/* 线性地址和虚拟地址的转换，只和 32-bit 有关 */
		if (shdr->sh_flags & SHF_EXECINSTR)
			shdr->sh_addr = ktva_ktla((unsigned long)dest);
		else
#endif

			shdr->sh_addr = (unsigned long)dest;
		pr_debug("\t0x%lx %s\n",
			 (long)shdr->sh_addr, info->secstrings + shdr->sh_name);
	}

	return 0;
}
```  
该函数最终调用 memcpy 将可加载模块的相应代码数据加载到内存中去。加载结束后若有CONFIG_DEBUG_KMEMLEAK，强制进行一遍权限的检查，防止 W&X。分离数据和代码除了内存属性的不同，也使得他们不再连续的内存区域。

