# PAX_MPROTECT
## 简述
PAX_MPROTECT 的目的是防止新的可执行代码引入到进程地址空间。这个特性通过在 mmap 和 mprotect 中实现对映射行为和修改内存属性的限制。限制包括：
- 创建 executable 的匿名映射
- 创建 executable/writable 的文件影射
- 除 ET_DYN 类 ELF 文件的重定位外，将 executable/read-only 文件改变映射为 writable
- 使 non-executable 映射 executable 化

## 实现
### mmap 时的限制
mmap系统调用用于内存与文件的映射，经过映射的内存被访问时（也就是访问文件内容在内存中的拷贝），会产生缺页错误，此时内核会将文件内容正式拷贝到进程地址空间，供程序使用。mmap 会涉及内存和文件的访问执行控制，配合 mprotect 维持的初始状态，确保内存往健康的访问（所谓不健康当然是指有被攻击利用的风险）状态变化。
mmap 经过两层包裹，沿着 mmap->mmap\_pgoff->do_mmap_pgoff 进行，在 do_mmap_pgoff 进行主要的映射操作（后来在 do_mmap 里面）。
```
static unsigned long do_mmap_pgoff(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, unsigned long pgoff)
{
	struct mm_struct * mm = current->mm;
	struct inode *inode;
	vm_flags_t vm_flags;
	int error;
	unsigned long reqprot = prot;

	if ((prot & (PROT_READ | PROT_WRITE)) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && (file->f_path.mnt->mnt_flags & MNT_NOEXEC)))
			prot |= PROT_EXEC;     /*暗示带有执行权限？*/

	if (!len)                      /*检查长度*/
		return -EINVAL;

	if (!(flags & MAP_FIXED))               /*对齐修整地址*/
		addr = round_hint_to_min(addr);

	/* Careful about overflows.. */
	len = PAGE_ALIGN(len);                 /*修整长度,通过偏移 PAGE_SHIFT*/
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)  /*检查长度 len 是否溢出*/
               return -EOVERFLOW;

	/* Too many mappings? */
	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	/* 获得空闲块的地址*/
	addr = get_unmapped_area(file, addr, len, pgoff, flags | ((prot & PROT_EXEC) ? MAP_EXECUTABLE : 0));
	if (addr & ~PAGE_MASK)  /*未能找到合适的内存*/
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;
   /*计算转化为 vm_flsgs 变量*/

#ifdef CONFIG_PAX_MPROTECT
	if (mm->pax_flags & MF_PAX_MPROTECT) {         /*未打 PaX 的 flag，要检查*/
		if ((vm_flags & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC))
        /*不能同时拥有执行位和写权限位*/

#ifdef CONFIG_PAX_EMUPLT          /*和兼容一些架构有关*/
			vm_flags &= ~VM_EXEC;   /*清除可执行置位，不会导致杀死进程*/
#else
			return -EPERM;/*返回越权操作，Operation not permitted */
#endif

		if (!(vm_flags & VM_EXEC))    /*明确置位未来不可执行*/
			vm_flags &= ~VM_MAYEXEC;
		else
			vm_flags &= ~VM_MAYWRITE;   /*明确置位未来不可写*/
	}
#endif

#if defined(CONFIG_PAX_PAGEEXEC) && defined(CONFIG_X86_32)
	if ((mm->pax_flags & MF_PAX_PAGEEXEC) && file)
		vm_flags &= ~VM_PAGEEXEC;
#endif

   /*往后的代码与正常内核实现映射有关*/
   ...

   /*检查不同映射类型与文件的访问权限是否冲突*/
	if (file) {
        /*共享映射or私有映射*/
		switch (flags & MAP_TYPE) {
		case MAP_SHARE:
            ...
		case MAP_PRIVATE:
			...
			}

			if (!file->f_op || !file->f_op->mmap) /*设备没有相关操作*/
				return -ENODEV;
			break;

		default:
			return -EINVAL;
		}
	} else {
    /*匿名映射*/
		...
		}
	}

	error = security_file_mmap(file, reqprot, prot, flags, addr, 0);
	if (error)
		return error;
    /*结束 mmap 调用，进程访问时会触发缺页*/
	return mmap_region(file, addr, len, flags, vm_flags, pgoff);
}
```
vm_flags 标志保存着映射的状态以及能否进行 writable/executable 转换的信息位（转换通过后文的 mprotect 函数实现），这个标志描述了四个状态： VM_WRITE, VM_EXEC, VM_MAYWRITE and VM_MAYEXEC。
在 mmap 过程中，主要是针对申请 vm_flags 为 VM_WRITE | VM_EXEC 的映射的检查，限制：
```
#ifdef CONFIG_PAX_MPROTECT
	if (mm->pax_flags & MF_PAX_MPROTECT) { /*未打flag*/
		if ((vm_flags & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC))
			return -EPERM;     /*不能同时拥有执行位和写权限位*/
                               /*返回越权操作，Operation not permitted */
#endif
```
若发现调用是可写可执行的映射，返回 -EPERM 的越权操作。若通过检查：
```
		if (!(vm_flags & VM_EXEC))    /*明确置位不可执行*/
			vm_flags &= ~VM_MAYEXEC;
		else
			vm_flags &= ~VM_MAYWRITE;   /*明确置位不可写*/
```
不可执行的映射内存明确地赋值在未来不可转化为可执行，否则（可执行的内存映射）赋值未来不可转化为可写。


### mprotect时状态转变的限制
mprotect 是 Linux 提供给用户空间的系统调用,用于调整已经完成映射的内存的性质改变,原型如下
```
int mprotect(void *addr, size_t len, int prot);
```
addr 是待调整内存起始地址, len 是待调整长度, prot 是期望改变的性质。由于内存性质改变可能往不好的方向改变，例如原来映射的可写段被调整成可执行，这就会带来引入攻击代码的风险，这种情形应该被限制。另外，一些 ELF 共享库文件需要可写可执行的（可写用于重定位），在重定位后需要转化为可读，这些都与 mprotect 有关，需要相关代码处理。
mprotect 在内核中的代码如下:
```
SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len,
		unsigned long, prot)
{
	unsigned long vm_flags, nstart, end, tmp, reqprot;
	struct vm_area_struct *vma, *prev;
	int error = -EINVAL;
	const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);
	prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);  /*掩码将 PROT_GROWSDOWN|PROT_GROWSUP 域的比特位去掉，这两个交给 grows 去分析*/
	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) /*不能同时向上和向下增长,若同时使能则报错*/
		return -EINVAL;

	if (start & ~PAGE_MASK)   /*待改变标志位的内存地址检查*/
		return -EINVAL;
	if (!len)                 /*长度检查*/
		return 0;
	len = PAGE_ALIGN(len);    /*对齐修整长度*/
	end = start + len;
	if (end <= start)         /*检查长度溢出,内存越界*/
		return -ENOMEM;

#ifdef CONFIG_PAX_SEGMEXEC    /*检查是否超出进程地址空间*/
	if (current->mm->pax_flags & MF_PAX_SEGMEXEC) {
		if (end > SEGMEXEC_TASK_SIZE)
			return -EINVAL;
	} else
#endif

	if (end > TASK_SIZE)       /*检查是否超出进程地址空间*/
		return -EINVAL;

	if (!arch_validate_prot(prot))
		return -EINVAL;

	reqprot = prot;

	if ((prot & (PROT_READ | PROT_WRITE)) && (current->personality & READ_IMPLIES_EXEC))
		prot |= PROT_EXEC;        /*暗示带有执行权限？*/

	vm_flags = calc_vm_prot_bits(prot); /*计算转换 prot 为 vm_flags*/

	down_write(&current->mm->mmap_sem); /*准备写操作*/

	vma = find_vma(current->mm, start); /*寻找相应虚拟内存块*/
	error = -ENOMEM;
	if (!vma)
		goto out;
	prev = vma->vm_prev;

	...   /*这里有一些内存增长的检查*/

    if (start > vma->vm_start)
		prev = vma;   /*更新虚拟内存块*/

#ifdef CONFIG_PAX_MPROTECT
	if (current->mm->binfmt && current->mm->binfmt->handle_mprotect)
		current->mm->binfmt->handle_mprotect(vma, vm_flags);  /*检查标志位是否合法*/
#endif

	for (nstart = start ; ; ) {
		unsigned long newflags;

		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */
        /* vm_flags 其他置位补充给 newflags*/
		newflags = vm_flags | (vma->vm_flags & ~(VM_READ | VM_WRITE | VM_EXEC));

		/* newflags >> 4 shift VM_MAY% in place of VM_% */
        /* newflag 右移四位后，是将 VM_MAY* 和 VM* 的位对上，取反掩码后得到 VM_MAY* 不置位 && 而VM*置位的，说明修改扩增了不允许的权限（没有 VM_MAY* 的），报错*/
        if ((newflags & ~(newflags >> 4)) & (VM_READ | VM_WRITE | VM_EXEC)) {
			error = -EACCES;
			goto out;
		}

		error = security_file_mprotect(vma, reqprot, prot);
		if (error)
			goto out;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;

        /*经过检查的标志位，会在这里进行赋值，修改内存属性*/
		error = mprotect_fixup(vma, &prev, nstart, tmp, newflags);
        ...

		track_exec_limit(current->mm, nstart, tmp, vm_flags);

		nstart = tmp;

		...
		}
	}
out:
   ...
}
```
current->mm->binfmt->handle_mprotect( vma, vm_flags)会调用相应二进制文件类型的处理函数，以 ELF 为例,一些动态库需要特殊的处理，fs/binfmt_elf.c 下的 elf_handle_mprotect 函数：
```
static void elf_handle_mprotect(struct vm_area_struct *vma, unsigned long newflags)
{
	struct elfhdr elf_h;
	struct elf_phdr elf_p;
	unsigned long i;
	unsigned long oldflags;
	bool is_textrel_rw, is_textrel_rx, is_relro;

	if (!(vma->vm_mm->pax_flags & MF_PAX_MPROTECT))   /*已打flag，跳过检查*/
		return;

	oldflags = vma->vm_flags & (VM_MAYEXEC | VM_MAYWRITE | VM_MAYREAD | VM_EXEC | VM_WRITE | VM_READ);
	newflags &= VM_MAYEXEC | VM_MAYWRITE | VM_MAYREAD | VM_EXEC | VM_WRITE | VM_READ;
        /*掩码，置位*/

#ifdef CONFIG_PAX_ELFRELOCS  /*允许 ELF 代码段的重定位*/
	/* possible TEXTREL */ /*一些 ELF 共享库文件的可执行段需要重定位*/
	is_textrel_rw = vma->vm_file && !vma->anon_vma && oldflags == (VM_MAYEXEC | VM_MAYREAD | VM_EXEC | VM_READ) && newflags == (VM_WRITE | VM_READ);
    /*内存是可读可执行，申请可写可读的情形*/
	is_textrel_rx = vma->vm_file && vma->anon_vma && oldflags == (VM_MAYEXEC | VM_MAYWRITE | VM_MAYREAD | VM_WRITE | VM_READ) && newflags == (VM_EXEC | VM_READ);
    /*内存是可读可写，要申请可执行的情形*/
#else
	is_textrel_rw = false;
	is_textrel_rx = false;
#endif

	/* possible RELRO */
    /*重定位完成，调用 mprotect 修改内存区域为不可写的情形，而newflag仍含有可写*/
	is_relro = vma->vm_file && vma->anon_vma && oldflags == (VM_MAYWRITE | VM_MAYREAD | VM_READ) && newflags == (VM_MAYWRITE | VM_MAYREAD | VM_READ);

    /*若非这三种情况，检查通过返回，无敏感修改*/
	if (!is_textrel_rw && !is_textrel_rx && !is_relro)
		return;

	if (sizeof(elf_h) != kernel_read(vma->vm_file, 0UL, (char *)&elf_h, sizeof(elf_h)) ||
	    memcmp(elf_h.e_ident, ELFMAG, SELFMAG) ||

#ifdef CONFIG_PAX_ETEXECRELOCS /*除了动态链接时重定位，可执行段也可写*/
        /*非可执行文件，也不是共享库文件，申请同时可写可执行*/
	    ((is_textrel_rw || is_textrel_rx) && (elf_h.e_type != ET_DYN && elf_h.e_type != ET_EXEC)) ||
#else
        /*非共享库文件，申请同时可写可执行*/
	    ((is_textrel_rw || is_textrel_rx) && elf_h.e_type != ET_DYN) ||
#endif
         /*申请可读可写，类型为非可执行非共享库*/
	    (is_relro && (elf_h.e_type != ET_DYN && elf_h.e_type != ET_EXEC)) ||
	    !elf_check_arch(&elf_h) ||
	    elf_h.e_phentsize != sizeof(struct elf_phdr) ||
	    elf_h.e_phnum > 65536UL / sizeof(struct elf_phdr))
		return;
        /*在此处通过检查，后续在 mprotect 还有一些检查，这个函数内更多的是 ELF 格式文件的处理*/

	for (i = 0UL; i < elf_h.e_phnum; i++) {
		if (sizeof(elf_p) != kernel_read(vma->vm_file, elf_h.e_phoff + i*sizeof(elf_p), (char *)&elf_p, sizeof(elf_p)))
			return;
		switch (elf_p.p_type) {  /*段类型*/
		case PT_DYNAMIC:   /*段类型为动态链接库*/
			if (!is_textrel_rw && !is_textrel_rx) /*没有敏感修改，跳过*/
				continue;
			i = 0UL;
			while ((i+1) * sizeof(elf_dyn) <= elf_p.p_filesz) {
				elf_dyn dyn;

				if (sizeof(dyn) != kernel_read(vma->vm_file, elf_p.p_offset + i*sizeof(dyn), (char *)&dyn, sizeof(dyn)))
					return;
				if (dyn.d_tag == DT_NULL)
					return;
				if (dyn.d_tag == DT_TEXTREL || (dyn.d_tag == DT_FLAGS && (dyn.d_un.d_val & DF_TEXTREL))) { /*有期待重定位的段*/
					if (is_textrel_rw)
						vma->vm_flags |= VM_MAYWRITE; /*重定位的段可写*/
					else
						vma->vm_flags &= ~VM_MAYWRITE; /*不申请可写的清除相关可写位*/
					return;
				}
				i++;
			}
			return;

		case PT_GNU_RELRO:   /*重定位完成*/
			if (!is_relro)  /*不是重定位结束时调用 mprotect*/
				continue;
			if ((elf_p.p_offset >> PAGE_SHIFT) == vma->vm_pgoff && ELF_PAGEALIGN(elf_p.p_memsz) == vma->vm_end - vma->vm_start)
				vma->vm_flags &= ~VM_MAYWRITE;  /*已经重定位完的区域，解除可写*/
			return;
		}
	}
}
```
需要注意的是，这个函数中并不是完整的限制，更多的是和 ELF 相关的一些处理（比如重定位后转化为不可写）。一些普通的处理，比如没有 VM_MAY* 权限而新引入的处理，仍在 mprotect 之中完成。

- 这篇文章的实现代码分析都是基于[HardenedLinux 在 ARM 上的移植](https://github.com/hardenedlinux/armv7-nexus7-grsec)，新版内核代码和 PaX 的补丁和这个版本的有一定的区别。

###### 参考资料
https://pax.grsecurity.net/docs/mprotect.txt
