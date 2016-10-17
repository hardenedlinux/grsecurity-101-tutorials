# PaX/Grsecurity --> KSPP --> AOSP kernel: Linux kernel mitigation checklist( WIP)

We should treat security as a whole, just like the combination of PaX/Grsecurity features/code hardening build up a defense-in-depth solution for Linux kernel, which is a core infrastructre we are highly rely on. [PaX/Grsecurity](http://grsecurity.net/) is a set of security hardening specific patch that brings the linux kernel security into another level. It's a great value to make all FLOSS community getting benefit from it. [KSPP( Kernel self protection project)](http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project) was started in Nov 2015 after [a disclosure](http://www.washingtonpost.com/sf/business/2015/11/05/net-of-insecurity-the-kernel-of-the-argument/) about linux kernel security. This is the 1st time the public had chance to know that linux kernel security might endanger the mobile platform( Android) and IoT devices. KSSP has been trying to port features/code hardening from PaX/Grsecurity to Linux upstream. Bad guys wouldn't like to see it happen, but it will, a part of it at least;-) KSPP is quite important to Android dev/user community,  because AOSP kernel security is highly rely on how KSPP goes. I'd like to see more features of PaX/Grsecurity lands in vanilla linux and AOSP kernel and more importantly, give PaX/Grsecurity the credits they deserved.

Thanks to PaX team/Spender, they guys initiated the ALPHA philosophical ideas and implementations of defensive mitigation of system security. PaX/Grsecurity may not be the OMEGA in this field, but I'm damn sure they are the fuc* ALPHA.  Also thanks to Kees Cook( not like rockstars from PROJECTZERO, he's a hidden hero), Daniel Micay( awesome contributor of AOSP kernel and interesting work of libc hardening; And, [CopperheadOS may be the only ROM](https://gist.github.com/thestinger/8b3c3467a3e88bc26fa7848a2064fa47)[**DO NOT INCLUDE PRIVATE CONSULTING SOLUTION**] trying that hard to protect individual's privacy and digital asset.) and other contributors for FLOSS security.

Before you dive into the devils, plz go get a cup of cofee or green tea and think what the hell is/isn't security..........
------------------------------------------------------------------
## Security is NOT:

* Security is NOT installing a firewall ..
* Security is NOT a Product or Service .. ( by Schneier, Bruce )
* Security is Not a Product; It's a Process .. ( by Schneier, Bruce )
* A Security Audit is NOT "running a port scan and turning things off" ..


## Security is:

* Security is "Can you still continue to work productively/safely, without compounding the security breach"
* Security is only as good as your "weakest link"
* Security is "risk management" of your corporate resources(computers/people), required expertise, time management, implementation costs, data backup/recovery proceedures ...
* Security is a Process, Methodology, Costs, Policies and People
* Security is "Can somebody physically walk out with your computers, disks, tapes, .. "
* Security is 24x7x365 ... constantly ongoing .. never ending
* Security is "learn all you can as fast as you can, without negatively affecting the network, productivity and budget"
------------------------------------------------------------------


## [GCC plugins](https://lwn.net/Articles/691102/)

* [GCC plugins infrastructure, CYC_COMPLEXITY, SANCOV](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=f716a85cd6045c994011268223706642cff7e485), merged in v4.8
* [HARDENED_USERCOPY](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1eccfa090eaea22558570054bbdc147817e1df5e) is trying to mitigate heap overflow, which is very popular class of bugs in kernel. It was originally based on PAX_USERCOPY, merged in v4.8
* PAX_LATENT_ENTROPY is trying extract more entropy on [those functions](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=0766f788eb727e2e330d55d30545db65bcf2623f) marked by __latent_entropy gcc attribute at boot time, which is very helpful to embedded system. Now it's called ["latent_entropy" plugin](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=38addce8b600ca335dc86fa3d48c890f1c6fa1f4) merged in v4.9.

## [Post-init read-only memory](https://lwn.net/Articles/666550/), merged in v4.6

* [arm64 vdso Mark vDSO code as read-only](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=88d8a7994e564d209d4b2583496631c2357d386b)
* [arm/x86: vdso: Mark vDSO code as read-only, Enable CONFIG_DEBUG_RODATA by default](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d09e356ad06a8b6f5cceabf7c6cf05fdb62b46e5)

## use-after-free reduction/mitigation
use-after-free is a very popular bug class in kernel and it can be exploited by the adversary to gain information or priviledges.

* PAX_MEMORY_SANITIZE does poisoning/sanitization the memory on free to reduces the attack surface. Laura Abbott submitted a [similar implementation](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8823b1dbc05fab1a8bec275eeae4709257c2661d)( as [debug options](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1414c7f4f7d72d138fff35f00151d15749b5beda)) inspired( which isn't?;-)) by PAX_MEMORY_SANITIZE and merged in v4.6.

* SL*B freelist randomization was submitted by Thomas Garnier. For more detail, plz read his [write-up](https://medium.com/@mxatone/randomizing-the-linux-kernel-heap-freelists-b899bb99c767#.oxwte8xb5). [SLAB freelist randomization](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c7ce4f60ac199fb3521c5fcd64da21cee801ec2b) merged in v4.7 and [SLUB freelist randomization](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=210e7a43fa905bccafa9bb5966fba1d71f33eb8b) merged in v4.8.

## ret2usr protection
I'm not sure how many incidents were getting involved with easy-to-write null-deref exploit. The truth is there were a lot. It ended by restrict minimal address of memory mapping, which is a trivial mitigation after Spender's Enlightment framework showed up in those endless crazy party;-) It was a crazy era fulfilled with ignorance and a shame to the defensive side, even not to mention the *backdoor* fix( "thanks" to the greatest GNU/Linux vendor..well, they wouldn't call themselves "GNU and slash and Linux" vendor, I suppose;-)) for the mitigation which supposed to protect your digital asset. KERNEXEC/UDEREF are the only options back in those 0ld horrible "one null-deref bug can root them all" days and remeber this: It's not very long ago. 

* [KERNEXEC](https://lwn.net/Articles/461811/), Set [syscall table, IDT, GDT, some page tables] to RO & set [data pages] to NX( Note: some tricks prevent new attacks like ret2dir, ask PaX team/Spender) in x86, which is the strongest implementation of KERNEXEC. Recommended priority selection for different architectures: x86 -> armv7 -> x86_64. Marking kernel pages as RO is very helpful to minimizing the attack surfaces and it's also an effective way to mitigate physmap spraying. armv7 has done a very similar feature [merged in v3.18](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1e6b48116a95046ec51f3d40f83aff8b006674d7) and arm64 got one [merged in v3.19](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=da141706aea52c1a9fbd28cb8d289b78819f5436). On AOSP side, [Android-3.10 got a backport](https://android.googlesource.com/kernel/common/+/b4ef696dc1fc4f5c2a8bfa84dde2586e9a652e23%5E%21/)( from  Qualcom's BSP out-of-tree patches?).

* [UDEREF](https://forums.grsecurity.net/viewtopic.php?f=7&t=3046), x86 is the strongest one, as Grsecurity's blog described. [ARMv7](https://forums.grsecurity.net/viewtopic.php?f=7&t=3292&sid=d67decb18f1c9751e8b3c3de3d551075) is also a strong implementation. [The story of x64/UDEREF](http://blog.pi3.com.pl/?p=509) is complicated a bit and it has 3 different implementations. The strong one was introduce in Aug 2013. It's Aug 2016 now...you know what you can do if you're going to deploy a new production server/desktop.

* [SMEP( Supervisor Mode Execution Protection)](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=de5397ad5b9ad22e2401c4dacdf1bb3b19c05679), it's provided by Intel x86( Ivybridge or newer) to achieve a subset functions of KERNEXEC. SMEP will prevent( mmap & exec [SHELLCODE of prepare_kernel_cred/commit_creds] shit, ring the bell?) if kernel attemp to code execution in a page not owned by kernel itself. Unlike KERNEXEC, it's not able to prevent exploitation of RWX or important data structure.

* [SMAP( Supervisor mode access prevention)](https://lwn.net/Articles/517475/), merged in v3.7. It's provided by Intel x86( Broadwell or newer) to achieve the same goal of UDEREF. But it's weaker than the current implementation of UDEREF.

* PXN( Privileged execute-never), PXN is provided by ARM hardware and it's a similar feature like SMEP. Weaker than KERNEXEC( Did someone still ask?), that's for sure. arm64's PXN implementaion is [merged in v3.7](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8e620b0476696e9428442d3551f3dad47df0e28f), and armv7's PXN implementation is [merged in v3.19](http://git.kernel.org/cgit/linux/kernel/git/davem/net.git/commit/?id=1d4d37159d013a4c54d785407dd8902f901d7bc5). citypw backported it to AOSP kernel and now [PXN for armv7 are enabled in AOSP](https://android-review.googlesource.com/#/q/topic:pxn+(status:open+OR+status:merged)) by default in 3.10/3.14/3.18/4.1/4.4. Unfortunately, [3.4 is EOL](https://android-review.googlesource.com/#/c/265892/) already. If you still need to protect old Android devices, try [Hardened PoC: PaX for Android](https://github.com/hardenedlinux/armv7-nexus7-grsec).  According to [Grsecurity's blog](https://forums.grsecurity.net/viewtopic.php?f=7&t=3292&sid=113b18536ba6764d3fd7a1a61c5b281a), the 1st PXN implementation of armv7 was from PaX/Grsecurity back in early 2013.

* [PAN( Privileged Access Never)](https://community.arm.com/groups/processors/blog/2014/12/02/the-armv8-a-architecture-and-its-ongoing-development), PAN is a new feature of ARMv8.1 to achieve the same goal like SMAP and it's [merged in v4.3](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=338d4f49d6f7114a017d294ccf7374df4f998edc). The shitty thing is that we don't have ARMv8.1 yet( probably only Cavium's chip for server), while ARMv8( arm64) is shipping hundred thousands chips for GNU/Linux and Android every day. Customers might not notice their device doesn't have supposed-to-be-off-the-shell mitigation;-) Fortunately, there's [software-based PAN implementation for armv7](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=a5e090acbf545c0a3b04080f8a488b17ec41fe02) and it's merged in v4.3. It's backported to [4.1](https://android-review.googlesource.com/#/q/topic:sw_PAN) by Kees Cook and [3.18](https://android-review.googlesource.com/#/q/topic:arm-sw-pan-3.18+(status:open+OR+status:merged)) by Sami Tolvanen. Speaking of arm64's implementation, there's a [patch](http://www.spinics.net/lists/arm-kernel/msg523579.html) not merged yet. arm64's PAN emulation will be taken care of by Google's maintainers( Backport: 3.18, 4.1, [4.4](https://android-review.googlesource.com/#/q/topic:arm64-swpan-4.4)).  Ironically, Linux kernel upstream may be willing to merge software-based PAN implementations for both armv7 and arm64 but PaX's UDEREF( armv7-only). If we are talking about software-based implementation without taking performance issue into account, we should've put security into the 1st priority...You know what I'm talking about, aren't u;-)

## [BPF JIT](https://lwn.net/Articles/437981/) hardening
This [type of attack](https://lwn.net/Articles/525609/) is aginst variable-length instruction architecture specifically. This problem is almost a disaster in some *important* application( e.g: Adobe FLash) on Desktop/Mobile. Cu'z it's more likely a RCE to be appeared. For GNU/Linux server, it's still an attack vector that we should taking very serious.

* [Constant blinding](https://forums.grsecurity.net/viewtopic.php?f=7&t=4463), the 1st implementation of this hardening feature by Grsecurity back in 2012 and it's called GRKERNSEC_BPF_HARDEN. Upstream merged a [similar feature in v4.7](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4f3446bb809f20ad56cadf712e6006815ae7a8f9). 

## [vmalloc kernel stack](https://lwn.net/Articles/692208/)
Jon Oberheide shared about [kernel stack attack surfaces](https://jon.oberheide.org/blog/2010/11/29/exploiting-stack-overflows-in-the-linux-kernel/) and [kernel stack hijacking](https://jon.oberheide.org/files/infiltrate12-thestackisback.pdf) is still useful to exploit Linux and Android kernel. PaX/Grsecurity moved thread_info off the kernel stack for x86 back in 2011. The GRKERNSEC_KSTACKOVERFLOW( there are some other features including moved thread_info off the stack) was forged in 2014 and the 1st support kernel version is v3.14. Andy Lutomirski( other contributors?) is [trying to implement](http://www.mail-archive.com/linux-kernel@vger.kernel.org/msg1168875.html) the exact what GRKERNSEC_KSTACKOVERFLOW does and this feature merged in v4.9(x64-only) via:
* [fork: Add generic vmalloced stack support](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ba14a194a434ccc8f733e263ad2ce941e35e5787)
* [dma-api: Teach the "DMA-from-stack" check about vmapped stacks](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b4a0f533e5976cb1a79f31d6152e1d322d79b7f1)
* [x86/mm/64: Enable vmapped stacks (CONFIG_HAVE_ARCH_VMAP_STACK=y)](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=e37e43a497d5a8b7c0cc1736d56986f432c394c9)
* [x86/mm: Improve stack-overflow #PF handling](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6271cfdfc0e4731b76921ef02fdd87409d71dfdf)
* [virtio_console: Stop doing DMA on the stack](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=9472fe7040bba45c6200858cbe40d643cf02bccb)
* [sched/core: Allow putting thread_info into task_struct](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c65eacbe290b8141554c71b2c94489e73ade8c8d)
* [x86: Move thread_info into task_struct](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=15f4eae70d365bba26854c90b6002aaabb18c8aa)
* [iommu/amd: Don't put completion-wait semaphore on stack](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4bf5beef578e46393f11eb69dda7d17a065e05ff)
* [sched/core: Add try_get_task_stack() and put_task_stack()](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c6c314a613cd7d03fb97713e0d642b493de42e69)
* [x86/dumpstack: Pin the target stack when dumping it](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1959a60182f48879635812a03a99c02231ea8677)
* [x86/process: Pin the target stack in get_wchan()](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=74327a3e884a0ff895ba7b51d3488e6a177407b2)
* [lib/syscall: Pin the task stack in collect_syscall()](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=aa1f1a639621672b68f654dc815a7d8298ff396f)
* [sched/core: Free the stack early if CONFIG_THREAD_INFO_IN_TASK](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=68f24b08ee892d47bdef925d676e1ae1ccc316f8)
* [fork: Optimize task creation by caching two thread stacks per CPU if CONFIG_VMAP_STACK=y](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ac496bf48d97f2503eaa353996a4dd5e4383eaf0)

## [GRKERNSEC_PERF_HARDEN](https://lwn.net/Articles/695978/)
PERF is a fuc*ing serious attack surface. We can't bear it running by default in production system. Ben Hutchings [proposed a patch](https://lkml.org/lkml/2016/1/11/587) from PaX/Grsecurity to linux kernel but it rejected by kernel maintainer. Fortunately, Jeff Vander Stoep [merged it into AOSP kernel](https://android-review.googlesource.com/#/c/234573/).


Write-up about KSPP:
* [security things in Linux v4.3](https://outflux.net/blog/archives/2016/09/26/security-things-in-linux-v4-3/)
* [security things in Linux v4.4](https://outflux.net/blog/archives/2016/09/27/security-things-in-linux-v4-4/)
* [security things in Linux v4.5](https://outflux.net/blog/archives/2016/09/28/security-things-in-linux-v4-5/)
* [security things in Linux v4.6](https://outflux.net/blog/archives/2016/09/30/security-things-in-linux-v4-6/)
* [security things in Linux v4.7](https://outflux.net/blog/archives/2016/10/03/security-things-in-linux-v4-7/)
* [security things in Linux v4.8](https://outflux.net/blog/archives/2016/10/04/security-things-in-linux-v4-8/)
