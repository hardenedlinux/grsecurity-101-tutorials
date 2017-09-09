# PaX ASLR 下的 gap
## gap 的简介  
gap 是 PaX 实现的一个没有独立成为特性的实现，直接在代码上进行加固。[Grsecurity 的这篇 blog ](https://grsecurity.net/an_ancient_kernel_hole_is_not_closed.php)把这个特性归纳在 PaX 的 ASLR 中。这篇文章还讲述了，PaX/Grsecurity 的这些特性在 [stack-clash](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt) 中发挥的防御作用。
gap 的实现是在内存分配的时候，增加 vma 内存周围的空隙，如果发出溢出覆写到这些空隙，就会触发错误。这能有效的防止溢出错误导致的漏洞利用。  

## gap 的实现
进程地址空间映射完成后，程序访问触发 page-fault，经过处理例程处理后，进程才能真正使用这片内存空间。首先实现映射的时候，在内核中走的路径虽然不尽相同，但是都会归结到几个函数去实现。以 mmap 为例，这个系统调用在内核中的调用路径如下（v4.9）：
`mmap_pgoff -> vm_mmap_pgoff -> do_mmap_pgoff -> do_mmap `
do_mmap 又需要从 vma 里找出合适大小的空隙来作为映射的空间，于是会接着调用：
` do_mmap -> get_unmapped_area -> arch_get_unmapped_area -> vm_unmapped_area `
对将所需内存的参数封装在vm_unmapped_area_info，传递给 vm_unmapped_area,然后视乎架构，会选择调用 unmapped_area_topdown/unmapped_area 函数获取空缺起始地址，这里以 unmapped_area_topdown 为例做分析：
```  
unsigned long unmapped_area_topdown(const struct vm_unmapped_area_info *info)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long length, low_limit, high_limit, gap_start, gap_end;

	/* info 是 arch_get_unmapped_area 调用传递进来的参数 */
	/* info->low_limit = mmap_base info->high_limit = TASK_SIZE 就是映射基址到进程空间极限*/
	length = info->length + info->align_mask;
	if (length < info->length)
		return -ENOMEM;

	gap_end = info->high_limit;
	if (gap_end < length)
		return -ENOMEM;
	high_limit = gap_end - length;

	if (info->low_limit > high_limit)
		return -ENOMEM;
	low_limit = info->low_limit + length;

	/* 高端内存的处理方式不走红黑树搜寻的流程 */
	gap_start = mm->highest_vm_end;
	if (gap_start <= high_limit)
		goto found_highest;

	/* 到这里，high_limit 是 vm_start 的下界，low_limit 是 vm_end 的下界 */

	/* 红黑树入口，开始搜寻符合长度需求的 gap */
	if (RB_EMPTY_ROOT(&mm->mm_rb))
		return -ENOMEM;
	vma = rb_entry(mm->mm_rb.rb_node, struct vm_area_struct, vm_rb);
	if (vma->rb_subtree_gap < length)
		return -ENOMEM;
	/* 这个循环用于遍历vma红黑树找出相应长度的gap */
	while (true) {
		/* 往小的方向搜寻 */
		gap_start = vma->vm_prev ? vma->vm_prev->vm_end : 0;
		if (gap_start <= high_limit && vma->vm_rb.rb_right) {
			struct vm_area_struct *right =
				rb_entry(vma->vm_rb.rb_right,
					 struct vm_area_struct, vm_rb);
			if (right->rb_subtree_gap >= length) {
				vma = right;
				continue;
			}
		}

	/* 注意寻找结束的时候，是一个空隙刚好够大的区域，这个区域是gap_start~gap_end */
	/* 这里 gap 的长度已经符合大于 length，PaX 要接着检查长度，实现映射区域的 gap */
check_current:
		/* 这里需要保证，gap_end 要大于 low_limit 否则区域越过 mmap_base */
		gap_end = vma->vm_start;
		if (gap_end < low_limit)
			return -ENOMEM;
		/* 这两行是 PaX 实现 gap 的关键，PaX 给 gap_start ~ gap_end 这段区域增加了空隙 */
		gap_start += skip_heap_stack_gap(vma->vm_prev, VM_GROWSUP, gap_start, gap_end);
		gap_end -= skip_heap_stack_gap(vma, VM_GROWSDOWN, gap_start, gap_end);

                /* 这两行是配合 Grsec 实现的 GRKERNSEC_RAND_THREADSTACK */
		if (gap_end - gap_start > info->threadstack_offset)
			gap_end -= info->threadstack_offset;
		else
			gap_end = gap_start;

		/* 这里需要保证，gap_start 要小于 high_limit 否则区域越过 TASK_SIZE，并且空隙长度够 */
		if (gap_start <= high_limit && gap_end - gap_start >= length)
			goto found;

		/* 下面的检查是 PaX 增加，如果不满足会返回前面的循环继续查找 */
		if (vma->vm_rb.rb_left) {
			struct vm_area_struct *left =
				rb_entry(vma->vm_rb.rb_left,
					 struct vm_area_struct, vm_rb);
			if (left->rb_subtree_gap >= length) {
				vma = left;
				continue;
			}
		}

		/* Go back up the rbtree to find next candidate node */
		while (true) {
			struct rb_node *prev = &vma->vm_rb;
			if (!rb_parent(prev))
				return -ENOMEM;
			vma = rb_entry(rb_parent(prev),
				       struct vm_area_struct, vm_rb);
			if (prev == vma->vm_rb.rb_right) {
				gap_start = vma->vm_prev ?
					vma->vm_prev->vm_end : 0;
				goto check_current;
			}
		}
	}

found:
	/* 防止越界，做修整 */
	if (gap_end > info->high_limit)
		gap_end = info->high_limit;

found_highest:
	/* 重新计算出 gap 的起始地址，包括一些对齐，这里的地址并不一定是 gap_start */
	gap_end -= info->length;
	gap_end -= (gap_end - info->align_offset) & info->align_mask;

	/* 计算得出的地址还需要重新做检查 */
	VM_BUG_ON(gap_end < info->low_limit);
	VM_BUG_ON(gap_end < gap_start);
	return gap_end;
}
```  
在这里我们可以看到，本来的实现目的是，找到一块空隙长度合适的区域，算出起始地址，交给调用函数继续映射的工作，PaX 在获取 gap 的长度上做了限制要求，也就是前后留下了空缺，前后需要延长 heap_stack_gap 的长度，他的计算在 skip_heap_stack_gap 函数里面：
```  
unsigned long skip_heap_stack_gap(const struct vm_area_struct *vma, unsigned long flag, unsigned long gap_start, unsigned long gap_end)
{
	if (!vma || !(vma->vm_flags & flag))
		return 0;

	return min(sysctl_heap_stack_gap, gap_end - gap_start);
}
```  
这里如果 gap 长度不足 sysctl_heap_stack_gap 则会导致返回的是 gap_end - gap_start，即 gap 的长度，接下来直接导致 gap 长度检查不通过。PaX 为 sysctl_heap_stack_gap 实现了一个 /proc/sys/vm/heap_stack_gap 的接口，可以在运行时进行调节，默认是 64K。这样做的原因是：在需要使用的内存块周围放置这些空缺，如果溢出发生，就会触碰到这些没有映射的区域，接着就会触发违法访问，防止溢出被进一步进行漏洞利用。由于 gap 的长度是可以被动态修改的，默认的长度带来的损耗是很小的，至于是否需要更大的空隙则取决于对安全场景和性能损耗的权衡。

## 附：GRKERNSEC_RAND_THREADSTACK 分析
之所以把这个特性放在这个文档，是因为他们的关键代码所处的位置都是在 unmapped_area_topdown 函数内，这个特性的实现并不是很复杂，包括随机化值的获取和随机化空隙的插入。
随机化值的获取在 arch_get_unmapped_area （以 x86 为例）：
```  
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	......

	struct vm_unmapped_area_info info;
	unsigned long offset = gr_rand_threadstack_offset(mm, filp, flags);
 
	......

	info.flags = 0;
	info.length = len;
	info.low_limit = mm->mmap_base;
	info.high_limit = TASK_SIZE;
	info.align_mask = 0;
	info.threadstack_offset = offset;
	return vm_unmapped_area(&info);
}
```  
这里调用 gr_rand_threadstack_offset 获取随机值，然后随着 vm_unmapped_area_info 结构体传递给 vm_unmapped_area，在 vm_unmapped_area 中，Grsecurity 加入代码如下：
```  
	......

	if (gap_end - gap_start > info->threadstack_offset)
		gap_end -= info->threadstack_offset;
	else
		gap_end = gap_start;

	......
```  
这里的实现和 PaX 很相似，都是修正他的长度，只不过这里修正的是一个随机化的长度，而不是一个定值，如果长度不够也是赋值让后续 gap 的检查不通过。但是，需要注意的是，Grsecurity 这个特性不是所有的架构，所有类型的映射都需要，这些条件限制在 gr_rand_threadstack_offset 实现的代码中，如果不满足的会返回 0，没有任何随机化。
