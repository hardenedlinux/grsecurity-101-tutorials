# PAX_RANDMMAP
PAX_RANDMMAP 是由 PaX Team 实现的随机化进程地址空间的一个重要特性。这个特性和 RANDUSTACK 和 RANDEXEC 协同完成了进程地址空间的全部随机化，构筑出最具防御能力的 ASLR。  
PAX_RANDMMAP 实现了堆的随机化，映射基址的随机化（这会影响共享库的加载地址，和防御offset2lib有关），以及 ET_DYN 类型的可执行文件加载基址随机化。因为 RANDMMAP 的实现盘踞在内核分配进程地址空间时的各个环节，流程较为漫长，这里截取的是 PaX 针对性加固所在的位置以及相关代码逻辑，上下文的简要介绍，内核普通情况的实现逻辑不会过多解释。

## main executable
在 RANDMMAP 里关于主程序（main executable）的处理仅限于 ET_DYN 类型的可执行文件，ET_EXEC 类型的由 RANDEXEC 处理。因为 ET_DYN 类型的可执行文件主程序相对要简单的多，所以不通过 RANDEXEC 实现，下面是代码：  
```  
		/* ET_EXEC 类型的不做处理 */
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			/* load_bias 用于后面作为映射基址 */
			load_bias = ELF_ET_DYN_BASE - vaddr;
                        /* 这是主线内核在 offset2lib 后引入的随机化 */
			if (current->flags & PF_RANDOMIZE)
				load_bias += arch_mmap_rnd();
			load_bias = ELF_PAGESTART(load_bias);
#ifdef CONFIG_PAX_RANDMMAP
			/* PaX: randomize base address at the default exe base if requested */
			if ((current->mm->pax_flags & MF_PAX_RANDMMAP) && elf_interpreter) {
#ifdef CONFIG_SPARC64
				load_bias = (pax_get_random_long() & ((1UL << PAX_DELTA_MMAP_LEN) - 1)) << (PAGE_SHIFT+1);
#else
				/* PaX 在这里引入了 PAX_DELTA_MMAP_LEN-bit 的随机化 */
				load_bias = (pax_get_random_long() & ((1UL << PAX_DELTA_MMAP_LEN) - 1)) << PAGE_SHIFT;
#endif
				load_bias = ELF_PAGESTART(PAX_ELF_ET_DYN_BASE - vaddr + load_bias);
				elf_flags |= MAP_FIXED;
			}
#endif

			total_size = total_mapping_size(elf_phdata, loc->elf_ex.e_phnum);
			if (!total_size) {
				retval = -EINVAL;
				goto out_free_dentry;
			}
		}

		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags, total_size);
```  
这段代码在 fs/binfmt_elf.c 的 load_elf_binary 中，用于加载映射可执行文件，是程序装载的处理函数。关于这部分代码的一些细节可以从[这个文档](elf_offset2lib.md)获取。

## mmap randomize
随机化映射是一个很重要的部分，经过随机化的映射可以让运行时的内存布局难以猜透。例如一些代码注入需要硬编码地址会变得困难，ret2lib 也因为映射随机化不容易找到地址。而通过爆破去实现内存布局的探测则取决于随机化程度的高低，而 PaX 实现的随机化程度是比较高的（相比主线）。  

进程的最初的映射行为发生在可执行文件的加载，映射随机化的一些初始化也在这里进行：
```  
#ifdef CONFIG_PAX_ASLR
	current->mm->delta_mmap = 0UL;
	current->mm->delta_stack = 0UL;
#endif
```  
这两个变量是用于映射和栈初始化的随机化的。在 mm_struct 结构中：
```  
#ifdef CONFIG_PAX_ASLR
	unsigned long delta_mmap;		/* randomized offset */
	unsigned long delta_stack;		/* randomized offset */
#endif
```  
随后 PaX 用随机化的值去初始化他们，随机和长度为 PAX_DELTA_MMAP_LEN-bit：
```  
#ifdef CONFIG_PAX_ASLR
	if (current->mm->pax_flags & MF_PAX_RANDMMAP) {
		current->mm->delta_mmap = (pax_get_random_long() & ((1UL << PAX_DELTA_MMAP_LEN)-1)) << PAGE_SHIFT;
		current->mm->delta_stack = (pax_get_random_long() & ((1UL << PAX_DELTA_STACK_LEN)-1)) << PAGE_SHIFT;
	}
#endif
```  
上述对 delta_mmap 的初始化只是埋下随机化的种子，这两个随机化变量会在后文用到。我们还需要理清 mmap 的区域在内存布局中是怎样的。  
事实上，在对用户空间内存的布局的分配上，可以比较灵活去实现，现在普遍的是依次由低地址到高地址分别是，可执行代码，堆，共享库以及其他映射区域，栈，vdso等。这些内存区域的安排，通常是选择一个地址加上一定随机化偏移作为基址实现随机化，但是要考虑如果相邻的区域大到越界的问题。因为这是内核态进行资源的分配问题，不是静态的。  
在 load_elf_binary 函数中，在实际映射之前，调用了 setup_new_exec 函数，这个函数地一个调用函数就是 arch_pick_mmap_layout 函数，代码如下  
```  
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	unsigned long random_factor = 0UL;

#ifdef CONFIG_PAX_RANDMMAP
	if (!(mm->pax_flags & MF_PAX_RANDMMAP))
#endif
	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	/* mmap_legacy_base 的实现是基于机制去增加偏移量 */
	mm->mmap_legacy_base = mmap_legacy_base(mm, random_factor);

	/* 
	 * 这里有两种内存布局，一是基于固定地址去偏移，一是和栈大小有关 *
	 * proc/sys/vm/legacy_va_layout 用于改变内存布局的内核接口 *
	 */
	if (mmap_is_legacy()) {
		mm->mmap_base = mm->mmap_legacy_base;
		mm->get_unmapped_area = arch_get_unmapped_area;
	} else {
		mm->mmap_base = mmap_base(mm, random_factor);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
	}

#ifdef CONFIG_PAX_RANDMMAP
	/* 注意只是 PaX 加上的随机化实现 */
	if (mm->pax_flags & MF_PAX_RANDMMAP) {
		mm->mmap_legacy_base += mm->delta_mmap;
		mm->mmap_base -= mm->delta_mmap + mm->delta_stack;
	}
#endif
}

```  
这个函数承担了映射基址的初始化工作，PaX 加入了相应的随机化。可以看到，这里有两种布局模式，可以通过/proc的接口去设置（proc/sys/vm/legacy_va_layout）。在不开 PaX 随机化的前提下，可以发现两种模式的进程布局是不同的，前者的堆栈相邻，共享库则是在比堆的地址小的地方。他们的实现差别是 mm->mmap_base 赋值采取的获取地址方式不一样，而这个变量是随后进行映射的基地址。
```  
static unsigned long mmap_base(struct mm_struct *mm, unsigned long rnd)
{
	unsigned long gap = rlimit(RLIMIT_STACK);
	unsigned long pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(pax_task_size - gap - rnd);
}
```  
gap获取到的是进程最小的栈大小，和 MIN/MAX_GAP 比对以后，将地址空间大小减去栈大小，再加随机化偏移就得到 mmap 的映射起始地址。然后 PaX　又做了一次随机化：
```  
#ifdef CONFIG_PAX_RANDMMAP
	if (mm->pax_flags & MF_PAX_RANDMMAP) {
		mm->mmap_legacy_base += mm->delta_mmap;
		mm->mmap_base -= mm->delta_mmap + mm->delta_stack;
	}
#endif
```  
这里，mm->mmap_legacy_base/mm->mmap_base 都添加了随机化，由于两种布局模式是不同的，mmap_legacy_base 基于定址做随机化偏移，而 mmap_base 则是在栈相邻的区域，需要减去进程初始化开始设定的栈以及映射基址随机化。
* 在 mmap 的系统调用的实现中，会调用到 arch_get_unmapped_area 函数，将 mmap_base 基址赋值给 vm_unmapped_area_info 类型的结构体，传递给 vm_unmapped_area 函数进行处理。

```  
/*
 * Top of mmap area (just below the process stack).
 *
 * Leave an at least ~128 MB hole with possible stack randomization.
 */
#define MIN_GAP (128*1024*1024UL + stack_maxrandom_size())
#define MAX_GAP (pax_task_size/6*5)
```  
在这个基础上，PaX 算上 delta_mmap，进一步加大基址的随机化。
## heap randmoize
在主程序映射结束后，一些 mm_struct 中的内存标记需要被更新，更新完，这里通过申请一个随机化长度的区域，然后设置brk，随机化heap的起点，这是 PaX 专门实现的：
```  
#ifdef CONFIG_PAX_RANDMMAP
	if (current->mm->pax_flags & MF_PAX_RANDMMAP) {
		unsigned long start, size, flags;
		vm_flags_t vm_flags;

		start = ELF_PAGEALIGN(elf_brk);
		size = PAGE_SIZE + ((pax_get_random_long() & ((1UL << 22) - 1UL)) << 4);
		flags = MAP_FIXED | MAP_PRIVATE;
		vm_flags = VM_DONTEXPAND | VM_DONTDUMP;

		down_write(&current->mm->mmap_sem);
		/* 这个是基于上述 mmap 基址去找内存块的 */
		start = get_unmapped_area(NULL, start, PAGE_ALIGN(size), 0, flags);
		retval = -ENOMEM;
		if (!IS_ERR_VALUE(start) && !find_vma_intersection(current->mm, start, start + size + PAGE_SIZE)) {
//			if (current->personality & ADDR_NO_RANDOMIZE)
//				vm_flags |= VM_READ | VM_MAYREAD;
			start = mmap_region(NULL, start, PAGE_ALIGN(size), vm_flags, 0);
			retval = IS_ERR_VALUE(start) ? start : 0;
		}
		up_write(&current->mm->mmap_sem);
		/* 设置随机化偏移 */
		if (retval == 0)
			retval = set_brk(start + size, start + size + PAGE_SIZE);
		if (retval < 0)
			goto out_free_dentry;
	}

```  
另外，主线内核实现了自己的 heap 随机化，他的随机化有两个点，一是主程序加载时的地址随机化，另一个是加载完毕即将进入调度时做了随机化他的起点，代码如下：
```  
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			......
		} else if (loc->elf_ex.e_type == ET_DYN) {
			load_bias = ELF_ET_DYN_BASE - vaddr;
			/* 申请了基址的初始化 */
			if (current->flags & PF_RANDOMIZE)
				load_bias += arch_mmap_rnd();
			load_bias = ELF_PAGESTART(load_bias);

	......

	/* 引入第一个随机化 */
	elf_bss += load_bias;
	elf_brk += load_bias;

	......

	retval = set_brk(elf_bss, elf_brk);

	......

#ifndef CONFIG_PAX_RANDMMAP
	if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		current->mm->brk = current->mm->start_brk =
			arch_randomize_brk(current->mm);
#ifdef compat_brk_randomized
		current->brk_randomized = 1;
#endif
	}
#endif
```  
第一个随机化被来自 load_bias 的随机化，这个值被 PaX 通过宏选项覆盖。第二个随机化被 PaX 通过宏选项在编译时忽略。删除这部分代码重编 kernel 可以看到每次 malloc 申请到的地址是固定的，也就是堆的基址是固定的。

## User stack
这部分主要是 RANDUSTACK 的安全特性，但是有部分代码和 RANDMMAP 有关联或者依赖，可以参考[这个关于 PAX_RANDUSTACK 的文档](PAX_RANDUSTACK.md)。
