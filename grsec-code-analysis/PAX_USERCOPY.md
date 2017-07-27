# PAX_USERCOPY
## 简述
在 Linux 内核的设计中，内核地址空间和用户地址空间是隔离的，不能直接透过地址去访问内存。因此，当需要发生用户空间和内核空间进行数据交换时，需要将数据拷贝一份到另一个的内存空间中。在内核中 copy_from_user 和 copy_to_user 这组函数承担了数据在内核空间和用户空间之间拷贝的任务。  
这就带来一个问题，如果从用户空间拷贝到内核空间的源缓冲区长度（通过参数 usigned long n 来传递），未加检验的就拷贝到内核空间之中，我们并不知晓内核空间的目的缓冲区是否有足够的长度来容纳拷贝过来的数据。当目的缓冲区小于拷贝长度时，就有可能产生溢出，破坏栈帧，修改内核空间数据等，就会导致可利用漏洞。  
解决这个问题的一种常见方法是依靠程序员在编写代码时小心翼翼的去保持拷贝行为不会溢出，然而在 Android 设备碎片化极其严重的情况下十分困难，因为各种各样的设备驱动代码极多，代码质量较差的，这也是驱动成为漏洞的重灾区的原因（这对函数在设备驱动中使用极多）。  
PAX_USERCOPY 则在这组函数中实现了缓冲区的长度检查，当长度检查发现有溢出的可能时，就不会执行数据的复制，防止非法拷贝覆盖内存，破坏栈帧或堆。  

* 该特性在主线内核中也有实现，配置选项为 CONFIG_HARDENED_USERCOPY  

## 实现
### PAX_USERCOPY 在 ARM 上
这个小节的实现代码分析都是基于 [HardenedLinux 在 ARM 上的移植](https://github.com/hardenedlinux/armv7-nexus7-grsec)。直到这个特性被移植进 upstream 之前（v <= 4.7），这部分代码除了添加了代码段的检查，没有太多变化。  
内核调用 copy_from_user 和 copy_to_user 实现在用户空间和内核空间的数据传输。这组函数又分别由 \__copy_to_user 和 \__copy_from_user 包装而成，以 \__copy_from_user 为例代码如下：  
```
static inline unsigned long __must_check __copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (!__builtin_constant_p(n))
		check_object_size(to, n, false);       /*目的缓冲区的检查函数*/
	return ___copy_from_user(to, from, n);
}
```
函数中调用的 check_object_size 实现了对象的长度检查，其代码实现如下：
```  
void check_object_size(const void *ptr, unsigned long n, bool to)
{

#ifdef CONFIG_PAX_USERCOPY
	const char *type;

	if (!n)
		return;

	type = check_heap_object(ptr, n, to);          /*当缓冲区在堆中的检查函数*/
	if (!type) {
		if (check_stack_object(ptr, n) != -1)      /*当缓冲区在栈中的检查函数*/
			return;
		type = "<process stack>";
	}

	pax_report_usercopy(ptr, n, to, type);
#endif

}
EXPORT_SYMBOL(check_object_size);
```
他的设计思路是：
1. 若指针在堆中，检查复制数据是否会溢出到非分配区域
2. 若在栈中，检查复制数据是否将会溢出到非当前栈帧中

在堆上的检查，主要是指针合法性检查，指针指向的内存属性检查，复制的长度计算检查，返回NULL会进入栈上检查，返回包含内存信息字符串用于后续报错，代码如下：  
```  
#ifdef CONFIG_PAX_USERCOPY
const char *check_heap_object(const void *ptr, unsigned long n, bool to)
{
	struct page *page;
	struct kmem_cache *cachep;
	struct slab *slabp;
	unsigned int objnr;
	unsigned long offset;

	if (ZERO_OR_NULL_PTR(ptr))   /*指针为空指针，返回字符串，直接进入 pax_report_usercopy*/
		return "<null>";

	if (!virt_addr_valid(ptr))   /*虚拟地址不合法，进入 check_stack_object 检查*/
		return NULL;

	page = virt_to_head_page(ptr);   /*获得该地址所在的页*/

	if (!PageSlab(page))         /*不是通过 kmalloc 而来，栈上*/
		return NULL;

	cachep = page_get_cache(page);        /*获得指针相应的 kmem_cache 结构体*/
	if (!(cachep->flags & SLAB_USERCOPY))  /* SLAB_USERCOPY 若未置位，说明该内存不能进行 usercopy*/
        return cachep->name;            /*返回包含slab信息的字符串，进入pax_report_usercopy报错*/

	slabp = page_get_slab(page);               /*获得 slab* 指针*/
	objnr = obj_to_index(cachep, slabp, ptr);
	BUG_ON(objnr >= cachep->num);              /*超出分配的object个数*/
	offset = ptr - index_to_obj(cachep, slabp, objnr) - obj_offset(cachep); /*指针相对长度，这里涉及一些 slab 的 object 数组的转换计算*/
	if (offset <= obj_size(cachep) && n <= obj_size(cachep) - offset)  /*长度检查通过*/
		return NULL;

	return cachep->name;           /*返回 cache 信息，供 pax_report_usercopy 报错*/
}
#endif
```
需要注意一下，其中，SLAB_USERCOPY 是由 PaX 新维护的标志位，定义在 include/linux/slab.h 中，用于描述 cache 的特性：
```  
+#define SLAB_USERCOPY		0x00000200UL	/* PaX: Allow copying objs to/from userland */
                                            /* PaX： 允许进行向或者从用户空间拷贝*/
```  
这个标志位，算是对内存属性的细分，专门为能否进行 usercopy 增加的。第一版移植合并的 CONFIG_HARDENED_USERCOPY 没有这个属性。

接着是栈栈检查，check_stack_object 有如下代码：
```  
if (obj + len < obj)      /*目的缓冲区加上复制长度后，地址减少，说明长度溢出*/
		return -1;
if (obj + len <= stack || stackend <= obj) /*缓冲区末在栈顶之上或缓冲区头在栈底之下*/
		return 0;
if (obj < stack || stackend < obj + len)  /*缓冲区头越过栈顶或缓冲区末越过栈底*/
		return -1;
/*以下还有一些x86架构相关的，检查复制是否破坏当前栈帧，注意上面是检查內核栈整个栈，这里检查栈帧*/
```  
其中，obj 为目的缓冲区指针，len 为复制指定长度的参数，stack 是当前进程栈帧的起始地址。第一个 if 语句，是当指定复制长度为负时，报错；第二个 if，是目的缓冲区不在当前进程栈帧中的情况（为通过了heap检查的情形而设）；第三个 if 是，目的缓冲区部分在当前栈帧中，越过了栈的边界(也就是破坏了栈帧，stack overflow )，报错。注意，这里的检查顺序不能颠倒，第二个 if 排除了在栈外的情形，也就是目的缓冲区尾在或者目的缓冲区头在栈中，再检查目的缓冲区头是否超出栈首或者缓冲区末尾超过栈底。如果颠倒，栈外指针的情形会被第三个 if 误杀。  

后来 PaX/Grsecurity 又实现了指针在代码段的检查，这个检查放在栈检查之后，实现函数是 check_kernel_text_object。

### Kernel v4.8 的 CONFIG_HARDENED_USERCOPY
KSPP 基于 PaX 实现的 CONFIG_HARDENED_USERCOPY 在内核 v4.8 被合并，由于种种原因，实现代码与 PaX 的实现有一定的不同，还有一部分后续的代码修改。
仍然以 copy_from_user 为例来看，检查的代码沿着 copy_from_user -> \_copy_from_user -> \__copy_from_user -> \__copy_from_user_nocheck -> check_object_size -> \__check_object_size 来到检查代码。
```  
void __check_object_size(const void *ptr, unsigned long n, bool to_user)
{
	const char *err;

	/* Skip all tests if size is zero. */
	if (!n)
		return;

	/* Check for invalid addresses. */
	err = check_bogus_address(ptr, n); /*检查指针合法性，复制长度的是否溢出*/
	if (err)
		goto report;

	/* Check for bad heap object. */
	err = check_heap_object(ptr, n, to_user);    /*堆上指针的检查*/
	if (err)
		goto report;

	/* Check for bad stack object. */
	switch (check_stack_object(ptr, n)) {      /*栈上指针检查*/
	case NOT_STACK:
		/* Object is not touching the current process stack. */
		break;
	case GOOD_FRAME:
	case GOOD_STACK:
		/*
		 * Object is either in the correct frame (when it
		 * is possible to check) or just generally on the
		 * process stack (when frame checking not available).
		 */
		return;
	default:
		err = "<process stack>";
		goto report;
	}

	/* Check for object in kernel to avoid text exposure. */
	err = check_kernel_text_object(ptr, n);    /*不在堆上也不在栈上时检查是否在 text 段*/
	if (!err)
		return;

report:
	report_usercopy(ptr, n, to_user, err);
}
EXPORT_SYMBOL(__check_object_size);
```  

```   
static inline const char *check_heap_object(const void *ptr, unsigned long n,
					    bool to_user)
{
	struct page *page;

	/*
	 * Some architectures (arm64) return true for virt_addr_valid() on
	 * vmalloced addresses. Work around this by checking for vmalloc
	 * first.
	 *
	 * We also need to check for module addresses explicitly since we
	 * may copy static data from modules to userspace
	 */
	if (is_vmalloc_or_module_addr(ptr))      /*arm64 架构 vmalloc 的地址可以通过这个检查,而不能通过下一个检查*/
        return NULL;

	if (!virt_addr_valid(ptr))              /*指针合法性检查*/
		return NULL;

	page = virt_to_head_page(ptr);

	/* Check slab allocator for flags and size. */
	if (PageSlab(page))
		return __check_heap_object(ptr, n, page);   /*在这里面计算复制长度等，检查是否一出*/

	/* Verify object does not incorrectly span multiple pages. */
	return check_page_span(ptr, n, page, to_user);
}
```  
```  
#ifdef CONFIG_HARDENED_USERCOPY
const char *__check_heap_object(const void *ptr, unsigned long n,
				struct page *page)
{
	struct kmem_cache *cachep;
	unsigned int objnr;
	unsigned long offset;
                                       /*由于这一版的实现并没有维护 SLAB_USERCOPY，这里删掉了这个检查*/
	/* Find and validate object. */    /*以下代码，基本上是逐行复制粘帖 PaX 的代码，可以自行参阅 PaX 的实现*/
	cachep = page->slab_cache;
	objnr = obj_to_index(cachep, page, (void *)ptr);
	BUG_ON(objnr >= cachep->num);

	/* Find offset within object. */
	offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);

	/* Allow address range falling entirely within object size. */
	if (offset <= cachep->object_size && n <= cachep->object_size - offset)
		return NULL;

	return cachep->name;
}
#endif /* CONFIG_HARDENED_USERCOPY */
```  

栈上的检查代码如下：  
```  
static noinline int check_stack_object(const void *obj, unsigned long len)
{
	const void * const stack = task_stack_page(current);
	const void * const stackend = stack + THREAD_SIZE;
	int ret;

     /*相比起 PaX，这里删掉了 obj 加上 len 以后溢出的情形，PaX 在 v4.8 的补丁又补回来了*/
	/* Object is not on the stack at all. */
	if (obj + len <= stack || stackend <= obj)    /*缓冲区末在栈顶之上或缓冲区头在栈底之下*/
		return NOT_STACK;

	/*
	 * Reject: object partially overlaps the stack (passing the
	 * the check above means at least one end is within the stack,
	 * so if this check fails, the other end is outside the stack).
	 */
	if (obj < stack || stackend < obj + len)    /*越过栈的情形*/
		return BAD_STACK;

	/* Check if object is safely within a valid frame. */
	ret = arch_within_stack_frames(stack, stackend, obj, len);  /*这个函数用于检查是否在当前栈帧中*/
	if (ret)                                                   /*里面的代码也基本是逐行复制 PaX 的代码*/
		return ret;

	return GOOD_STACK;
}
```  
总结这版实现和 PaX/Grsecurity 实现的区别是：
1. kernel v4.8 删除了 SLAB_USERCOPY 的维护和检查。目前 PaX/Grsecurity 释放出的代码（针对v4.9）也去掉了，增设了 usercopy region 的维护（ kmem_cache中)。
2. kernel v4.8 增加了 is_vmalloc_or_module_addr 的检查，这和 ARM 架构有关，PaX/Grsecurity 代码也保留了，在主线这个 [commit](https://github.com/torvalds/linux/commit/517e1fbeb65f5eade8d14f46ac365db6c75aea9b) 中又删掉了这个检查，因为 virt_addr_valid 检查的缺陷被修复了。
3. kernel v4.8 将指针在栈上溢出的检查移到指针在堆栈上的检查之前，PaX 在针对 v4.8 的 patch 在栈检查中重新加入这个检查。
4. kernel v4.8 增加了 check_page_span 检查，PaX/Grsecurity 代码也保留了这部分。

### v4.8以后 PaX/Grsecurity 的修改
在 v4.8 引入 USERCOPY 特性后，由于代码结构的改变，PaX/Grsecurity 基于安全的考虑在这个特性上也做了一些针对性的代码修补。
一个比较突出的修改是被 v4.8 删除的 SLAB_USERCOPY，PaX/Grsecurity 增加了 USERCOPY region 的登记，指定了可进行 usercopy 的区域。在 kmem_cache 里维护了如下字段：
```  
struct kmem_cache {
 	......
+	size_t useroffset;	/* USERCOPY region offset 起始位置偏移 */
+	size_t usersize;	/* USERCOPY region size   可复制长度*/
    ......
 };
```  
相应的，在 create_kmalloc_cache_usercopy、kmem_cache_create 这类初始化的函数中要初始化这些值。在 check_heap_object 中的检查如下：
```  
	if (offset < cachep->useroffset)
		return cachep->name;

	if (offset - cachep->useroffset >= cachep->usersize)
		return cachep->name;

	if (n > cachep->useroffset - offset + cachep->usersize)
		return cachep->name;

```  
这些都是检查指针的位置（ offset 是通过指针算出来的相对偏移），以及复制长度有没有越过登记的可以进行 USERCOPY 的区域。

### KSPP 其他相关移植
由于 v4.8 增加了 usercopy 的特性，一方面，KSPP 没有完整的抄好所有特性，而是慢慢一点点添加；另一方面，PaX/Grsecurity 又针对新的内核做针对性加固，KSPP 跟随实现了一部分尚未被合并的 patch，主要是 [SLAB_USERCOPY](http://www.openwall.com/lists/kernel-hardening/2016/06/08/10) 和被称为[Hardened usercopy whitelisting](http://www.openwall.com/lists/kernel-hardening/2017/06/19/17) 两个实现，代码实现基本上是摘抄 PaX/Grsecurity 的，前文也都有分析。

## 案例
