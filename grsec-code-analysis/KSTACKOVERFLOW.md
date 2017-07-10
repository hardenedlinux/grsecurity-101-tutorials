# KSTACKOVERFLOW
## 简介
Grsecurity 的 KSTACKOVERFLOW 特性是针对进程内核栈溢出的一些加固措施，主要包括：
- 进程内核栈初始化时的vmap 与 thread_info 的分离
- double_fault 中 Guard page 的检测
- 一些指针的检查
- 一些配合性的初始化

## 创建进程时內核栈的初始化  
这个部分主要介绍 GRSEURITY_KSTACKOVERFLOW 针对内核栈做了两个方面的加固，一个是基于 Pax 的实现将 thread_info 分离出去，另一个是栈空间虚拟映射，提高安全性。（[PaX的实现参考这里](kstack.md)）  
路线： do_fork -> copy_process_task_struct -> dup_task_struct -> gr_alloc_stack_node
dup_task_struct 函数是进程在 fork 初始化时被调用的，他和进程栈的初始化有关：
```
static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
 {
 ...
+	void *lowmem_stack;

-	stack = alloc_thread_stack_node(tsk, node);
+	stack = gr_alloc_thread_stack_node(tsk, node, &lowmem_stack);
 	if (!stack)
 		goto free_tsk;
 ...
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+	tsk->lowmem_stack = lowmem_stack;
+#endif
 ...
```
这里 Grsecurity 替换掉原来 kernel 的实现，调用自己实现的 gr_alloc_thread_stack_node（对应的配合实现还有 gr_free_thread_stack，此处不展开代码）：

```
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+static inline unsigned long *gr_alloc_thread_stack_node(struct task_struct *tsk,
+						  int node, void **lowmem_stack)
+{
+	struct page *pages[THREAD_SIZE / PAGE_SIZE];
+	void *ret = NULL;
+	unsigned int i;
+
+	*lowmem_stack = alloc_thread_stack_node(tsk, node);  /*原来内核的实现相对应*/
+	if (*lowmem_stack == NULL)
+		goto out;
+
+	for (i = 0; i < THREAD_SIZE / PAGE_SIZE; i++)
+		pages[i] = virt_to_page(*lowmem_stack + (i * PAGE_SIZE));
+	
+	/* use VM_IOREMAP to gain THREAD_SIZE alignment */
+	ret = vmap(pages, THREAD_SIZE / PAGE_SIZE, VM_IOREMAP, PAGE_KERNEL); /*映射到分离的内存中*/
+	if (ret == NULL) {
+		free_thread_stack(*lowmem_stack);
+		*lowmem_stack = NULL;
+	} else
+		populate_stack(ret, THREAD_SIZE);     /*强制触发页错误*/
+
+out:
+	return ret;
+}
```
其中`*lowmem_stack = alloc_thread_stack_node(tsk, node);`获得内存初始化填充 task_struct，返回进程内核栈的地址。  
在这里，lowmem_stack 就是原来内核实现分配的内核进程栈的起始指针（低地址） stack，for 循环将基于 lowmem_stack 在 THREAD_SIZE 范围内逐页映射，返回虚拟地址 ret，最终赋值给了 task->stack。也就是实现了将原来的栈（lowmem_stack)映射出去( stack)，映射到一个物理上不连续而虚拟连续的内存空间，虚拟连续的内存空间在页间有空隙，便于检测到越界访问。stack 这个栈首址在用户进程陷入内核时，在上下文切换的时候会计算出栈底（高地址）传递给栈指针，进程会基于此，在调用内核函数时增长栈。  
需要注意的是，task->stack 是映射到物理不连续的内存区域，lowmem_stack 是实际上原来栈所在的位置。由于 vmap 映射出去的栈并不是物理上连续的，所以一些 io 操作 buf 的行为，依赖于连续物理内存，task->stack 不满足需求，相应的代码在添加了 KSTACKOVERFLOW 特性时要做如下针对 buf 地址修正：  
```
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+	if (object_starts_on_stack(buf))
+		realbuf = buf - current->stack + current->lowmem_stack;   /*映射出去的栈修正成原来的栈*/
+#endif
```
buf - current->stack 算出 buf 偏移量，然后以 current->lowmem_stack 为基址增加偏移，获得真正的 realbuf 所在内核栈的位置。  
获得描述信息映射区域的指针后，KSTACKOVERFLOW 实现了以下的检查：
```
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+static inline void populate_stack(void *stack, unsigned int size)
+{
+	int c;
+	int *ptr = stack;
+	int *end = stack + size;
+
+	while (ptr < end) {
+		c = *(volatile int *)ptr;
+		(void)c;                           /*访问相应地址，触发页错误*/
+		ptr += PAGE_SIZE/sizeof(int);
+	}
+}
+#else
+static inline void populate_stack(void *stack, unsigned int size)
+{
+}
+#endif
```
这个函数遍历一遍指针，强行触发缺页，以便执行对内存的后续操作  
类似的检查还有 sched_init 的：
```
void __init sched_init(void)
 	for_each_possible_cpu(i) {
 		struct rq *rq;
 
+#if defined(CONFIG_GRKERNSEC_KSTACKOVERFLOW) && defined(CONFIG_X86_64)
+		void *newstack = vzalloc_irq_stack();
+		if (newstack == NULL)
+			panic("grsec: Unable to allocate irq stack");
+		populate_stack(newstack, IRQ_STACK_SIZE);
+		per_cpu(irq_stack_ptr, i) = newstack + IRQ_STACK_SIZE - 64;
+#endif

```
上述初始完成后，进程陷入内核系统调用时，就会基于相关的内存实现调用栈的增长。

## do_double_fault 的栈指针检查
针对 do_double_fault 的补丁，实际上是针对内核栈是否 overflow,也就是针对是否访问或者覆写越界的检查：
```
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+	if ((unsigned long)tsk->stack - regs->sp <= PAGE_SIZE)
+		die("grsec: kernel stack overflow detected", regs, error_code);	
+#endif
```
从代码上来看，这个补丁代表着，若栈指针距离内核栈的起始地址（低地址）不足一个页的大小，说明任何栈上的读写操作会覆写到内核栈，触发报错。  
其实指针检查是发生在缺页错中再次触发错误时进行的检查（例如缺页错误发生后发现对该内存无访问权限？），也就是所谓的 double_fault。而对进程内核栈的 page guard 的访问，就会触发这个检查，也就是任何访问读写 guard page 的行为，都会被捕捉并且检查，若小于一个页大小引发报错。  
主线内核的相应实现是触发后检查 cr2 寄存器，这个寄存器保存了访问缺页的地址。  
近期由 Qualys 曝光的攻击方式展示了如何绕过用户空间的guard page，就是保持栈指针不触及 page-fault 来绕过越过栈的越界检查。Grsecurity的blog提及用相似的方法绕过内核栈检查。  
- 这个栈不在进程内核栈，中断，异常都有 cpu 自己维护的栈。  
###### 相关参考资料
- https://www.grsecurity.net/an_ancient_kernel_hole_is_not_closed.php
- https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt

## 内存操作时一些指针的检查
### virt_to_page 地址合法性检查
virt_to_page 给定虚拟地址，获得地址所在的页( page*)前，先对虚拟地址在内核的合法性进行检查：
```
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+#define virt_to_page(kaddr)	
+	({ 
+		const void *__kaddr = (const void *)(kaddr); 
+		BUG_ON(!virt_addr_valid(__kaddr)); 
+		pfn_to_page(__pa(__kaddr) >> PAGE_SHIFT); 
+	})
+#else
+#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
+#endif
```

### 检查指针是否越界
内存区域可执行时（装载内核模块？），检查 start 指针是否在 vm_struct 描述的区域内，是否越界：
```
+#if defined(CONFIG_X86) && defined(CONFIG_PAX_KERNEXEC)
+	if (flags & VM_KERNEXEC) {
+		if (start != VMALLOC_START || end != VMALLOC_END)
+			return NULL;
+		start = (unsigned long)MODULES_EXEC_VADDR;
+		end = (unsigned long)MODULES_EXEC_END;
+	}
+#endif
```
### 检查目的指针
这是一些针对目的指针的合法性的检查，有些需要做 realbuf 的检查，代码如下：
use object_starts_on_stack（） check pointer
```
+bool is_usercopy_object(const void *ptr)
...
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+	    && !object_starts_on_stack(ptr)
+#endif
...
```

```
void scatterwalk_map_and_copy(void *buf, struct scatterlist *sg,
 {
 ...
+	void *realbuf = buf;
 ...
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+	if (object_starts_on_stack(buf))
+		realbuf = buf - current->stack + current->lowmem_stack;
+#endif
 ...
 }
```

```
 static void build_completion_wait(struct iommu_cmd *cmd, u64 address)
 {
+	phys_addr_t physaddr;
...
+
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+	if (object_starts_on_stack((void *)address)) {
+		void *adjbuf = (void *)address - current->stack + current->lowmem_stack;
+		physaddr = __pa((u64)adjbuf);
+	} else
+#endif
...
 }
```

```
 static inline void sg_set_buf(struct scatterlist *sg, const void *buf,
 			      unsigned int buflen)
 {
+	const void *realbuf = buf;
+
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+	if (object_starts_on_stack(buf))
+		realbuf = buf - current->stack + current->lowmem_stack;
+#endif
+
...
-	sg_set_page(sg, virt_to_page(buf), buflen, offset_in_page(buf));
+	sg_set_page(sg, virt_to_page(realbuf), buflen, offset_in_page(realbuf));
 }
```
## vmalloc_init 对 lowmem_stack 的配合实现
```
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+struct stack_deferred_llist {
+	struct llist_head list;
+	void *stack;
+	void *lowmem_stack;
+};
+struct stack_deferred {
+	struct stack_deferred_llist list;
+	struct work_struct wq;
+};
+
+static DEFINE_PER_CPU(struct stack_deferred, stack_deferred);
```

```
@@ -1228,13 +1311,27 @@ void __init vmalloc_init(void)
 	for_each_possible_cpu(i) {
 		struct vmap_block_queue *vbq;
 		struct vfree_deferred *p;
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+		struct stack_deferred *p2;
+#endif
 
 		vbq = &per_cpu(vmap_block_queue, i);
 		spin_lock_init(&vbq->lock);
 		INIT_LIST_HEAD(&vbq->free);
+
 		p = &per_cpu(vfree_deferred, i);
 		init_llist_head(&p->list);
-		INIT_WORK(&p->wq, free_work);
+		INIT_WORK(&p->wq, vfree_work);
+
+		p = &per_cpu(vunmap_deferred, i);
+		init_llist_head(&p->list);
+		INIT_WORK(&p->wq, vunmap_work);
+
+#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
+		p2 = &per_cpu(stack_deferred, i);
+		init_llist_head(&p2->list.list);
+		INIT_WORK(&p2->wq, unmap_work);
+#endif
 	}
```
