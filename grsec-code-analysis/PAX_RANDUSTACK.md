# PAX_RANDUSTACK
## 简述
PAX_RANDUSTACK 是针对用户空间进程地址的随机化的安全特性。
PAX_RANDUSTACK 实现了用户空间的栈随机化，主要是随机化栈基址，栈增长都是基于这个地址。他包括两个步骤的实现：
- do_execve 执行时，用户地址空间初始化时加入随机化
- set_arg_pages 初始化映射用户进程的参数变量时，加入一定偏移量的随机化

经过这些随机化,进程地址空间布局不再轻易被猜透，抬高了攻击利用成本。

## 实现
### 进程空间初始化
第一步实现在 fs/exec.c 的 do_execve 函数中，内核用一个临时栈指针 bprm.p 跟踪数据拷贝的目的栈(在用户空间,也就是进程栈基址)，这是pax首先需要将其随机化的的部分。当指针指向空时,就不会执行这个随机化。
do_execve 是一个系统调用，用于执行新的进程，在内核代码中如下：
```
int do_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp)
{
    ...
	return do_execve_common(filename, argv, envp);
}
```
函数实际调用 do_execve_common 作具体实现：
```
static int do_execve_common(const char *filename,
				struct user_arg_ptr argv,
				struct user_arg_ptr envp)
{
	struct linux_binprm *bprm;
    ...
    ...
	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);  /*bprm结构体的一些初始化*/
	if (!bprm)
		goto out_files;

	sched_exec();                              /*cpu调度执行*/

	bprm->file = file;                         /*一些结构体数据的填充*/
	bprm->filename = filename;
	bprm->interp = filename;

	retval = bprm_mm_init(bprm);               /*分配进程的地址空间*/
	...

	bprm->argc = count(argv, MAX_ARG_STRINGS); /*下面都是环境变量和一些参数的初始化*/
    ...
	bprm->envc = count(envp, MAX_ARG_STRINGS);
    ...
	retval = prepare_binprm(bprm);
	...
	retval = copy_strings_kernel(1, &bprm->filename, bprm);
	...
	bprm->exec = bprm->p;
	retval = copy_strings(bprm->envc, envp, bprm);
	...
	retval = copy_strings(bprm->argc, argv, bprm);
	...
	retval = search_binary_handler(bprm);
    ...

out_ret:
	return retval;
}
```
bprm_mm_init 函数就是用于对进程地址空间初始化,这个函数调用 \__bprm_mm_init 初始化
```
static int __bprm_mm_init(struct linux_binprm *bprm)
{
    ...
#ifdef CONFIG_PAX_RANDUSTACK
	if (randomize_va_space)
		bprm->p ^= (pax_get_random_long() & ~15) & ~PAGE_MASK;
     ...

}
```
其中的:  
`bprm->p ^= (pax_get_random_long() & ~15) & ~PAGE_MASK;`  
就是 PAX_RANDUSTACK 的针对性补丁，获得随机地址掩码，赋值给 p 针(掩码说明了只对部分比特做随机化)。bprm->p　是和用户进程空间相关的变量，具体体现到进程与可执行文件格式相关，我们一下会以 elf 为例来分析。　　
例如在 do_execve_common 中，search_binary_handle 用于各种格式二进制函数的处理函数的加载，fmt->load_binary 会寻找相应的二机制加载函数，以elf格式文件为例，会执行load_elf_binary，这个函数中会有如:  
`current->mm->start_stack = bprm->p;`  
current是指当前进程，mm字段为mm_struct类型,维护着进程地址空间的信息，而start_stack正是进程栈起始地址。也就是被随机化的p指针,最终作为进程栈增长的基址,也就实现进程栈初始化的随机化。路线图如下:  
`do_execve->do_execve_common->bprm_mm_init->__bprm_mm_init`  
这里完成了bprm.p的随机化，在后续加载二进制的时候:  
`do_execve_common->search_binary_handler->load_elf_binary`  
load_elf_binary 中把 bprm.p 传递给了进程的 current->mm->start_stack  
其实 bprm.p 随机化初始化后，并不会以上述这种形式直接对 current->mm->start_stack 赋值，还需经过setup_arg_pages 这些的操作以后才会显式赋值给 current->mm->start_stack，而 setup_arg_pages 中用到bprm.p 增长栈的时候都会update这个数据。下面我们会继续看这部分的代码。

### 初始化时的update
第二不出现在 setup_arg_pages() 函数被调用的时候，这个函数的调用是为了把先前存在内核物理栈页(do_execve_common的几个copy_string从拷贝进kernel)中的内容复制到进程地址空间(复制一些参数,环境变量等)。通常,栈顶是取决于 STACK_TOP 这个参数，PAX 会对是个变量进行一定偏移量的随机化( delta_stack )
在 load_elf_binary 函数中:
```
retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
```
而binfmt_elf.c中的 randomize_stack_top() 函数代码如下:
```
static unsigned long randomize_stack_top(unsigned long stack_top)
{
   ...
#ifdef CONFIG_PAX_RANDUSTACK
	if (randomize_va_space)
		return stack_top - current->mm->delta_stack;
```
可见，setup_arg_pages 函数的栈变化和传入参数 stack_top 相关，PAX 通过 randomize_stack_top 将 stack_top 的值和进程的 delta_stack 变量相关联(因 delta_stack 变化而变化)，而 delta_stack 在上文述及的 load_elf_binary 中有针对 delta_stack 的随机化初始化
```
#ifdef CONFIG_PAX_ASLR
	if (current->mm->pax_flags & MF_PAX_RANDMMAP) {
		current->mm->delta_mmap = (pax_get_random_long() & ((1UL << PAX_DELTA_MMAP_LEN)-1)) << PAGE_SHIFT;
		current->mm->delta_stack = (pax_get_random_long() & ((1UL << PAX_DELTA_STACK_LEN)-1)) << PAGE_SHIFT;
	}
#endif
```
于是 setup_arg_pages() 装载的参数位置在栈中也是随机化的，而且栈的变化情况会 update 给 bprm.p,完成后, load_elf_binary 显式使用:  
`current->mm->start_stack = bprm->p;`  
将程序进程空间起始地址更新了,这个地址包含了两部分的随机化，一个是 \__bprm_mm_init 对 bprm.p 的初始化随机化了，另一个是经过setup_arg_page时，栈增长随机化一定偏移量后,更新给了bprm.p，最终赋值给current->mm->delta_stack，完成进程空间地址的随机化,最后执行成功后会释放bprm结构体。

###### 参考资料: https://pax.grsecurity.net/docs/randustack.txt
