# Privileged execute-never(PXN)
## 简述
PXN是一个防止用户空间代码被内核空间执行的安全特性。在arm v7的硬件支持下，通过PXN比特位的设定，决定该页的内存是否可被内核执行，可有效防止ret2usr攻击。
## 实现
首先，PXN位的硬件信息定义在pgtable-2level-hwdef.h中，在页表目录中：
```
#define PMD_PXNTABLE           (_AT(pmdval_t, 1) << 2)     /* v7 */
#define PMD_SECT_PXN    (_AT(pmdval_t, 1) << 0)     /* v7 */
```
内存初始化的时候，会调用paging_init()，该函数会继续调用build_mem_type_table()进行设置，build_mem_type_table()有如下代码：
```
if (cpu_arch == CPU_ARCH_ARMv7 &&
       (read_cpuid_ext(CPUID_EXT_MMFR0) & 0xF) >= 4) {
           user_pmd_table |= PMD_PXNTABLE;
        }
```
设置PXN的条件是：  
- cpu架构是ARMv7。因为PXN是通过硬件实现的，内核只做设置支持；  
- 通过read_cpuid_ext()，判断控制位;  

两条件一个不成立就会被阻塞。  
下面是读取协处理器的实现  
```
#define read_cpuid_ext(ext_reg)						\
	({								\
		unsigned int __val;					\
		asm("mrc	p15, 0, %0, c0, " ext_reg		\
		    : "=r" (__val)					\
		    :							\
		    : "memory");					\
		__val;							\
	})
```
其实就是调用mrc指令去读取协处理器的寄存器，然后掩码进行比较。CPUID_EXT_MMFR0的定义是：  
```
#define CPUID_EXT_MMFR0  "c1, 4"
```
MMFR表示内存模式特性寄存器(Memory Model Feature register)  
###### 参考资料
https://patchwork.kernel.org/patch/5539521/
https://www.spinics.net/lists/arm-kernel/msg381717.html
