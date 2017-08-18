## 从 ELF 的加载实现到 Offset2lib
### 简介
这个文档从 ELF 的加载实现代码开始，引出了针对 pie 类型的可执行文件的攻击 offset2lib，通过漏洞曝光前后的代码修复以及和漏洞不在同一时间轴的 PAX_RANDMMAP 安全特性的比对，尝试解释清楚 offset2lib 的问题所在。offset2lib 其实是 ELF 文件加载映射实现上存在缺陷导致的而不是 bug 型的漏洞。对于 PaX 而言，并没有这种实现上的缺陷，而且随机化也更为完备。  
### load_elf_binary（v4.9）的代码注释  
load_elf_binary 是用于处理 ELF 格式文件的函数，这个函数所做的事情是将用户空间传递过来的 ELF 格式文件进行解析，解析检查完成后，把二进制可执行文件加载映射到内存中去，然后他的任务就完成了，后续的执行切换是由进程调度去完成（fork 的最后一步是把新建的进程放进调度队列）。也就是说，这个函数的实现，决定了进程地址空间的实际布局。ELF 文件本身带有的位置信息，只是一种登记，供系统映射时读取，真正的布局完成是取决于系统实现。  
本身加载 ELF 格式文件是一个比较繁杂的过程，因为本身 ELF 格式构造比较复杂。从行为来看，大致可以分为解析文件格式和映射加载可执行文件。加载可执行文件时，还会涉及到，解释器，共享库的链接等。在第一段代码引用中会尽可能把完整的内容注释出来，后续的讨论集中在 ET_DYN 这类格式文件的映射行为上。下面是 kernelv4.9 的 load_elf_binary 函数：  
```  
static int load_elf_binary(struct linux_binprm *bprm)
{
	struct file *interpreter = NULL; /* to shut gcc up */
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = NULL;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata, *interp_elf_phdata = NULL;
	unsigned long elf_bss, elf_brk;
	int retval, i;
	unsigned long elf_entry;
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc __maybe_unused = 0;
	int executable_stack = EXSTACK_DEFAULT;
	struct pt_regs *regs = current_pt_regs();
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;
	struct arch_elf_state arch_state = INIT_ARCH_ELF_STATE;

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}
	
	/* Get the exec-header */
	loc->elf_ex = *((struct elfhdr *)bprm->buf); /*这个 buf 是读取 ELF 文件头获得的，在 prepare_binprm 初始化*/

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0) /*ELF 魔数，ELFMAG="\177ELF"，SELFMAG=4*/
		goto out;

        /* ELF类型检查 */
	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;
        /* 检查e_machine是否与相应架构符合 */
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
        /* 文件操作的确认 */
	if (!bprm->file->f_op->mmap)
		goto out;

        /*申请空间，将elf_phdr*elf_ex->e_phnum读取，从bprm转移出来*/
	elf_phdata = load_elf_phdrs(&loc->elf_ex, bprm->file);
	if (!elf_phdata)
		goto out;

	elf_ppnt = elf_phdata;
	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

        /* 这个循环专门处理解释器加载，解释器加载早于其他段 */
	for (i = 0; i < loc->elf_ex.e_phnum; i++) {
		if (elf_ppnt->p_type == PT_INTERP) {   /* 用于解释器的段 */
			/* This is the program interpreter used for
			 * shared libraries - for now assume that this
			 * is an a.out format binary
			 */
			retval = -ENOEXEC;
			/* 检查文件大小 */
			if (elf_ppnt->p_filesz > PATH_MAX || 
			    elf_ppnt->p_filesz < 2)
				goto out_free_ph;

			retval = -ENOMEM;
			elf_interpreter = kmalloc(elf_ppnt->p_filesz,
						  GFP_KERNEL);
			if (!elf_interpreter)
				goto out_free_ph;

			/* 读取解释器的段 */
			retval = kernel_read(bprm->file, elf_ppnt->p_offset,
					     elf_interpreter,
					     elf_ppnt->p_filesz);
			/* 检查读取长度 */
                        if (retval != elf_ppnt->p_filesz) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_interp;
			}
			/* 检查字符串结尾，这是解释器的路径，objdump -s 可看到 */
			retval = -ENOEXEC;
			if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
				goto out_free_interp;
			/*解释器本身也是一个ELF，也需要读取ELF的流程*/
			interpreter = open_exec(elf_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;

			/*
			 * If the binary is not readable then enforce
			 * mm->dumpable = 0 regardless of the interpreter's
			 * permissions.
			 */
			would_dump(bprm, interpreter);

			/* 读取解释器文件头 */
			retval = kernel_read(interpreter, 0,
					     (void *)&loc->interp_elf_ex,
					     sizeof(loc->interp_elf_ex));
			if (retval != sizeof(loc->interp_elf_ex)) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_dentry;
			}

			break;
		}
		elf_ppnt++;
	}

	elf_ppnt = elf_phdata;     /*重新遍历*/
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
		switch (elf_ppnt->p_type) {
		case PT_GNU_STACK:            /*处理栈段*/
			if (elf_ppnt->p_flags & PF_X)        /*p_flags决定了能否执行*/
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;

		case PT_LOPROC ... PT_HIPROC:   /*保留地址，空实现*/
			retval = arch_elf_pt_proc(&loc->elf_ex, elf_ppnt,
						  bprm->file, false,
						  &arch_state);
			if (retval)
				goto out_free_dentry;
			break;
		}

	/* 解释器的检查，类似前面读取 ELF 的那些检查 */
	if (elf_interpreter) {
		retval = -ELIBBAD;
		/* ELF 魔数的检查 */
		if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
			goto out_free_dentry;
		/* 检查e_machine */
		if (!elf_check_arch(&loc->interp_elf_ex))
			goto out_free_dentry;

		/* 读取解释器的ELF头部 */
		interp_elf_phdata = load_elf_phdrs(&loc->interp_elf_ex,
						   interpreter);
		if (!interp_elf_phdata)
			goto out_free_dentry;

		/* PT_LOPROC..PT_HIPROC 部分是空实现 */
		elf_ppnt = interp_elf_phdata;
		for (i = 0; i < loc->interp_elf_ex.e_phnum; i++, elf_ppnt++)
			switch (elf_ppnt->p_type) {
			case PT_LOPROC ... PT_HIPROC:
				retval = arch_elf_pt_proc(&loc->interp_elf_ex,
							  elf_ppnt, interpreter,
							  true, &arch_state);
				if (retval)
					goto out_free_dentry;
				break;
			}
	}

	/*空实现*/
	retval = arch_check_elf(&loc->elf_ex,
				!!interpreter, &loc->interp_elf_ex,
				&arch_state);
	if (retval)
		goto out_free_dentry;

	/* 更新bprm，一些继承自父进程的被刷新 */
	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;

	/* Do this immediately, since STACK_TOP as used in setup_arg_pages
	   may depend on the personality.  */
        /*这个字段似乎是用于兼容UNIX的设计，这里有很多用途，和栈的可执行和随机化有关*/
	SET_PERSONALITY2(loc->elf_ex, &arch_state);
	if (elf_read_implies_exec(loc->elf_ex, executable_stack))
		current->personality |= READ_IMPLIES_EXEC;

	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		current->flags |= PF_RANDOMIZE;

	setup_new_exec(bprm);
	install_exec_creds(bprm);

	/* 设置一些执行参数，注意这里用了随机化栈顶 */
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
	if (retval < 0)
		goto out_free_dentry;

	current->mm->start_stack = bprm->p;     /* 初始化栈起点，栈加入第一个随机化 */

	/* Now we do a little grungy work by mmapping the ELF image into
	   the correct location in memory. */
	/* 到这里，我们开始正式将 ELF 镜像映射进内存 */
	for(i = 0, elf_ppnt = elf_phdata;
	    i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long k, vaddr;
		unsigned long total_size = 0;

		/* 专门处理PT_LOAD的段 */
		if (elf_ppnt->p_type != PT_LOAD)
			continue;
		/* 内存大于文件大小的情形 */
		if (unlikely (elf_brk > elf_bss)) {
			unsigned long nbyte;

			retval = set_brk(elf_bss + load_bias,
					 elf_brk + load_bias);
			if (retval)
				goto out_free_dentry;
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void __user *)elf_bss +
							load_bias, nbyte)) {
					/*
					 * This bss-zeroing can fail if the ELF
					 * file specifies odd protections. So
					 * we don't check the return value
					 */
				}
			}
		}

		/*一些映射内存性质的设置*/
		if (elf_ppnt->p_flags & PF_R)
			elf_prot |= PROT_READ;
		if (elf_ppnt->p_flags & PF_W)
			elf_prot |= PROT_WRITE;
		if (elf_ppnt->p_flags & PF_X)
			elf_prot |= PROT_EXEC;

		elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

		/*读取段虚拟地址，这登记了ELF文件的排列顺序，这个会用做映射地址*/
		vaddr = elf_ppnt->p_vaddr;
		/* ELF格式为可执行文件 */
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			/* 动态库类型段，注意编译指定pie时，可执行段也在这里处理 */
		/* 这个变量是下文会用到的映射基址， ELF_ET_DYN_BASE=(TASK_SIZE / 3 * 2) */
		/* 调用 elf_map 时会加上相应的地址，地址是固定的*/
			load_bias = ELF_ET_DYN_BASE - vaddr;  
			/* 根据标志确定随机化映射基址与否，这里的随机化打散的内存布局 */
            if (current->flags & PF_RANDOMIZE)
				load_bias += arch_mmap_rnd();
                         /* 内存地址对齐 */
			load_bias = ELF_PAGESTART(load_bias);
			total_size = total_mapping_size(elf_phdata,
							loc->elf_ex.e_phnum);
			if (!total_size) {
				retval = -EINVAL;
				goto out_free_dentry;
			}
		}
		/* 映射相应段 */
		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags, total_size);
		/* 映射完的地址检查 */
		if (BAD_ADDR(error)) {
			retval = IS_ERR((void *)error) ?
				PTR_ERR((void*)error) : -EINVAL;
			goto out_free_dentry;
		}
		/* 更新一些变量 */
		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (loc->elf_ex.e_type == ET_DYN) {
				load_bias += error -
				             ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
				reloc_func_desc = load_bias;
			}
		}
		k = elf_ppnt->p_vaddr;
		if (k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		/* 检查内存和文件大小，防止溢出 */
		if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
		    elf_ppnt->p_memsz > TASK_SIZE ||
		    TASK_SIZE - elf_ppnt->p_memsz < k) {
			/* set_brk can never work. Avoid overflows. */
			retval = -EINVAL;
			goto out_free_dentry;
		}
		/* 长度检查通过，将k指向段末 */
		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		/* 指向堆末尾 */
                if (k > elf_brk)
			elf_brk = k;
	}

	/* 一些偏移更新 */
	loc->elf_ex.e_entry += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias; 
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	retval = set_brk(elf_bss, elf_brk);
	if (retval)
		goto out_free_dentry;
	if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_dentry;
	}

	/* 若不需要解释器，直接用 ELF 格式里的 entry */
	if (elf_interpreter) {
		unsigned long interp_map_addr = 0;
	/* 获取动态链接入口，像加载其他 ELF 一样加载解释器，但有单独的函数 */
		elf_entry = load_elf_interp(&loc->interp_elf_ex,
					    interpreter,
					    &interp_map_addr,
					    load_bias, interp_elf_phdata);
		if (!IS_ERR((void *)elf_entry)) {
			/*
			 * load_elf_interp() returns relocation
			 * adjustment
			 */
			interp_load_addr = elf_entry;
			elf_entry += loc->interp_elf_ex.e_entry;
		}
		if (BAD_ADDR(elf_entry)) {
			retval = IS_ERR((void *)elf_entry) ?
					(int)elf_entry : -EINVAL;
			goto out_free_dentry;
		}
		reloc_func_desc = interp_load_addr;
        ......
	} else {
		elf_entry = loc->elf_ex.e_entry;
        ......
		}
	}

	kfree(interp_elf_phdata);
	kfree(elf_phdata);

	set_binfmt(&elf_format);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = arch_setup_additional_pages(bprm, !!elf_interpreter);
	if (retval < 0)
		goto out;
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	retval = create_elf_tables(bprm, &loc->elf_ex,
			  load_addr, interp_load_addr);
	if (retval < 0)
		goto out;
	/* N.B. passed_fileno might not be initialized? */
	/* 更新一些 current 的参数 */
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

	/* 堆增长基址随机化，randomize_va_space在proc中有接口 */
	if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		current->mm->brk = current->mm->start_brk =
			arch_randomize_brk(current->mm);
#ifdef compat_brk_randomized
		current->brk_randomized = 1;
#endif
	}
        /* 将 page-0 映射为只读，一些应用依赖这一特性，man personality可查看 */
	if (current->personality & MMAP_PAGE_ZERO) {
		error = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
	}

#ifdef ELF_PLAT_INIT
	ELF_PLAT_INIT(regs, reloc_func_desc);
#endif
	/* 作为进程开始调度 */
	start_thread(regs, elf_entry, bprm->p);
	retval = 0;
out:
	kfree(loc);     /* 释放临时结构体 */
out_ret:
	return retval;

	/* error cleanup */
out_free_dentry:
	......
out_free_interp:
	......
out_free_ph:
	......
}
```  

### 可执行文件的映射和Offset2lib  
这里筛选出 PT_LOAD 段，其他段都略过，因为有的不需要处理，解释器的段则在前面处理过。  
```  
	for(i = 0, elf_ppnt = elf_phdata;
	    i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		if (elf_ppnt->p_type != PT_LOAD)
			continue;
```  

下面我们把注意力定格在 elf_map 函数上，这个函数是专门用于映射 ELF 格式文件的，调用vm_map实现的包装函数。因为这个函数实际承担了 ELF 格式文件的直接映射，也就是他是最终内存布局的直接相关函数。  
```  
		vaddr = elf_ppnt->p_vaddr;
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			load_bias = ELF_ET_DYN_BASE - vaddr;
			if (current->flags & PF_RANDOMIZE)
				load_bias += arch_mmap_rnd();
			load_bias = ELF_PAGESTART(load_bias);
			total_size = total_mapping_size(elf_phdata,
							loc->elf_ex.e_phnum);
			if (!total_size) {
				retval = -EINVAL;
				goto out_free_dentry;
			}
		}
		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags, total_size);
```  
这里 ET_EXEC 和 ET_DYN 指的是 ELF 格式文件的类型，普通的可执行文件是 ET_EXEC， 而 pie 的可执行文件是 ET_DYN 类型。较新版本的 gcc 编译默认自带 pie。有兴趣可以在编译命令加上 `-no-pie`， 然后使用 readelf 对比默认 pie 编译产生的文件类型的不同。也就是说带有 pie 的 ELF 和共享库的类型是一样的。接下来我们把计算赋值先忽略，放到后面讲，直接来到 error = elf_map()。在这个函数里面，第二个参数决定了映射的位置：load_bias + vaddr。映射地址和这两个参数有关，vaddr 明显来自 ELF 文件格式的 elf_ppnt->p_vaddr。另一个变量是 load_bias，他是映射地址的关键。
回退到 v3.17 版本，这部分代码是这样的：
```  
		vaddr = elf_ppnt->p_vaddr;
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
#ifdef CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE
			if (current->flags & PF_RANDOMIZE)
				load_bias = 0;
			else
				load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
#else
			load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
#endif
		}
```  
在这个版本的代码，牵扯出一种攻击的方式：[offset2lib](https://cybersecurity.upv.es/solutions/aslrv2/aslrv2.html)。这种攻击方式就是依赖着加载映射时的内存布局来完成地址的猜测，bypass了ASLR。这种攻击的关键是，当系统开启随机化的时候，相应的架构会设置 CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE。最初的设计想法应该是，ELF 可执行文件在 pie 的前提下，借助加载基址的随机化，位置无关的代码也映射到随机化的地址上。若不开随机化的情形，则以ELF_ET_DYN_BASE 作为基址进行加载。但是，由于链接时加载其他的共享库的时候（具体可以参考 load_elf_library 函数的代码，实现的过程和 load_elf_binary 相似，他们映射时的地址是依次连续的），程序代码和共享库是依次被映射的，随机化只对基址起作用，代码之间的相对偏移量是固定的，这就导致了 offset2lib，即通过增减指针相对偏移量来控制执行流到目的代码，目的代码在库中。  
需要注意的是不开随机化的时候（例如幸免的 s390），因为可执行文件的代码会基于 ELF_ET_DYN_BASE 和共享库区域分离，虽然代码加载的基址是固定的，但是偏移量不是固定的（库基址是随机的），也就没法进行 offset2libc。  
当时发现这个攻击手法的团队给出了相应的[修补方案](https://cybersecurity.upv.es/solutions/aslrv2/fix_offset2lib.patch)。修补方案是，仍然保持没开启随机化时代码的执行路径，即删去由`CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE`宏控制的代码，然后在`ELF_ET_DYN_BASE`宏中强制插入随机化。实现的效果是，可执行代码被映射到距 ELF_ET_DYN_BASE 有一定随机化偏移量的区域，既不和共享库相连，基址也是随机化的。  
回头看v4.9代码的实现，从代码最终映射的内存布局来看，他的设计也是一样的。实现上是保留 ELF_ET_DYN_BASE 常量固定，将随机化提出来，配合 current->flags 来选择基址是否随机化。  
### PAX_RANDMMAP  
在 offset2lib 披露的同时，作者也赞誉有加地提到了 PaX 的 ASLR 是当时实现最先进的。作者提到的关于 PaX 的安全特性实现是多个特性，针对 offset2lib 最直接相关的特性是 PAX_RANDMMAP。下面是相关代码：
```  
+#ifdef CONFIG_PAX_RANDMMAP
+			/* PaX: randomize base address at the default exe base if requested */
+			if ((current->mm->pax_flags & MF_PAX_RANDMMAP) && elf_interpreter) {
+#ifdef CONFIG_SPARC64
+				load_bias = (pax_get_random_long() & ((1UL << PAX_DELTA_MMAP_LEN) - 1)) << (PAGE_SHIFT+1);
+#else
+				load_bias = (pax_get_random_long() & ((1UL << PAX_DELTA_MMAP_LEN) - 1)) << PAGE_SHIFT;
+#endif
+				load_bias = ELF_PAGESTART(PAX_ELF_ET_DYN_BASE - vaddr + load_bias);
+				elf_flags |= MAP_FIXED;
+			}
+#endif
```  
可以看到的时，早在 PaX 针对 v3.16 给出的 Patch 中（也许其实还更早呢）,我们就可以看到首先 PaX 给 load_bias 加上了 PAX_DELTA_MMAP_LEN 个比特位的随机化，在这个基础上再移到以 PAX_ELF_ET_DYN_BASE 为基址的地方，这就将代码和共享库分离开，并且加上了随机化的成分。这是最早针对 offset2lib 的修补，后续其他的修补实现也都很相似，都是分离和随机化。  
虽然这个修补放在 PAX_RANDMMAP 之下，而真正的 PAX_RANDMMAP 的安全特性远不止此，我们会在别的文档里面讨论。
