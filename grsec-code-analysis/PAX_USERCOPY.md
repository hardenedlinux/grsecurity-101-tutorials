# PAX_USERCOPY
## 简述
在 Linux 内核的设计中，内核地址空间和用户地址空间是隔离的，不能直接透过地址去访问内存。因此，当需要发生用户空间和内核空间进行数据交换时，需要将数据拷贝一份到另一个的内存空间中。在内核中 copy_from_user 和 copy_to_user 这组函数承担了数据在内核空间和用户空间之间拷贝的任务。  
这就带来一个问题，如果从用户空间拷贝到内核空间的源缓冲区长度（通过参数 usigned long n 来传递），未加检验的就拷贝到内核空间之中，我们并不知晓内核空间的目的缓冲区是否有足够的长度来容纳拷贝过来的数据。当目的缓冲区小于拷贝长度时，就有可能产生溢出，破坏栈帧，修改内核空间数据等，就会导致可利用漏洞。  
解决这个问题的一种常见方法是依靠程序员在编写代码时小心翼翼的去保持拷贝行为不会溢出，然而在 Android 设备碎片化极其严重的情况下十分困难，因为各种各样的设备驱动代码极多，代码质量较差的，这也是驱动成为漏洞的重灾区的原因（这对函数在设备驱动中使用极多）。  
PAX_USERCOPY 则在这组函数中实现了缓冲区的长度检查，当长度检查发现有溢出的可能时，就不会执行数据的复制，防止非法拷贝覆盖内存，破坏栈帧或堆。  

*该特性在主线内核中也有实现，配置选项为 CONFIG_HARDENED_USERCOPY
## 实现
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

以栈帧检查为例，check_stack_object 有如下代码：
```
if (obj + len < obj)      /*目的缓冲区加上复制长度后，地址减少，说明长度为负*/
		return -1;
if (obj + len <= stack || stackend <= obj) /*缓冲区末在栈顶之上或缓冲区头在栈底之下*/
		return 0;
if (obj < stack || stackend < obj + len)  /*缓冲区头越过栈顶或缓冲区末越过栈底*/
		return -1;
```
其中，obj 为目的缓冲区指针，len 为复制指定长度的参数，stack 是当前进程栈帧的起始地址。第一个 if 语句，是当指定复制长度为负时，报错；第二个 if，是目的缓冲区不在当前进程栈帧中的情况；第三个 if 是，目的缓冲区部分在当前栈帧中，越过了栈的边界(也就是破坏了栈帧， stack overflow )，报错。  

## 案例

######参考资料
http://www.openwall.com/lists/kernel-hardening/2011/06/26/3
