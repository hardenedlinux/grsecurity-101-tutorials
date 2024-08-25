## SLUBStick risk assessment for embedded systems

The Linux kernel is susceptible to memory safety vulnerabilities due to its size and complexity. However, most of these vulnerabilities have limited capabilities, making exploitation difficult in practice. To make these vulnerabilities even more difficult to exploit, researchers and kernel developers have included defenses such as SMEP/SMAP, KASLR, and kCFI. SLUBStick, a novel kernel exploitation method that converts a limited kernel heap vulnerability into an arbitrary read-and-write primitive, making privilege escalation easier. SLUBStick operates in multiple stages, exploiting a timing side channel of the allocator to perform a cross-cache attack reliably, and then manipulating code patterns prevalent in the Linux kernel to grant arbitrary memory read and write capabilities. The defensive measures in this documentation are specifically targeted towards embedded systems, which are defined as follows:

* Industry-specific Linux, such as aerospace, automotive, and smart factories
* Higher Mandatory Access Control (MAC) coverage compared to typical GNU/Linux distributions
* Highly customized and standardized build systems
* The patch is either delayed, incomplete, or both.


## Defense & mitigation
Runtime mitigation:

* PaX/GRsecurity is a Linux kernel security solution for large-scale deployment in high-security production environments. One of cutting-edged PaX/GRsec feature called [AUTOSLAB](https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game), is an isolation-based approach to make each k*alloc* object have their own dedicated caches. AUTOSLAB is the only existing solution can kill off this new exploitation method. Please noted that PaX/GRsecurity require rebuild the kernel but it should not be a big thing since embedded system has (usally) a process with regression test, CI/CD, reproducible build system, etc.

* VED (Vault Exploit Defense) can only mitigate the exploits target the specific data structure like [msg_msg](https://pbs.twimg.com/media/GVx_TBxWIAAeVcG?format=png&name=900x900) which likely to be the catagory of "external noise".

Attack surface reduction: system call

* This attack is highly relied on [CPU pinning](https://github.com/IAIK/SLUBStick/blob/main/exploits/include/uhelper.h#L145). To remove the syscalls related to CPU pinning can be helpful. It may impact on some applications requires CPU affinity feature. Please noted that even with disabled the syscalls, it'd only reduced the success rate from ~ 90% to ~ 70% while still requires other measures (external noises) to reduce the success probability.

MAC (Mandatory Access Control) and non-exec partition:

* Embedded system has higher MAC (SELinux/AppArmor/Smack/GRsecurity RBAC/etc) coverages typically. The assumption for the threat model behinh SLUBStick is that the attacker possesses normal user privileges. It is crucial for the system to prevent any user from being able to "drop a binary and run it." Certain directories, such as /run and /tmp, may permit this type of operation. Additionally, stealthy attackers may [inject binaries directly into memory](https://github.com/nnsee/fileless-elf-exec) using a refined layout without touching the partition, which is equivalent of bypassing the read-only partition. 

## Recent vanilla/upstream efforts on heap mitigation

* [Separate the accounted and unaccounted caches](https://github.com/torvalds/linux/commit/494c1dfe855ec1f70f89552fce5eadf4a1717552) by RedHat and SuSE merged in v5.14, making some exploits require rewrite. This feature is enabled by default for all GNU/Linux distro
* [RANDOM_KMALLOC_CACHES](https://github.com/torvalds/linux/commit/3c6152940584290668b35fa0800026f6a1ae05fe) by Huawei, implement the multiple slab cache for each size. It's merged in v6.6 which only a few GNU/Linux distro enabled it by default (e.g: Ubuntu 24.04).
 * [Per-call-site slab caches](https://github.com/torvalds/linux/commit/b32801d1255be1da62ea8134df3ed9f3331fba12) developed by Google, merged in v6.11. It's the infrastructure that allows Google to implement the "equivalent" of PaX/GRsecurity's AUTOSLAB partially in the future.

## Wrap-up for the defense
Building defense by studying exploitation methods is more practical and effective, because the systems always have exploitable bugs. A patch is not enough, and sometimes a patch is delayed. The PaX/GRsecurity philosophy of "Killing the entire bug classes and exploit vectors" fits well for it. For SLUBStick, either MAC and syscall disabled are workaround for the short-term solution. When we have dive into the stage of "down to the rabbit hole" and try different approach ended up in the same result that implementing runtime mitigations for both exploitation and post-exploitation stages becomes essential and inevitable for the long-term solution.

## Performance
Based on the analysis of these features in the upstream, some do not effectively break the cycle of the whack-a-mole game and should not be enabled on embedded platforms. Unlike PCs and servers, embedded platforms are more sensitive to performance impacts. While some users may believe that the benefits of certain minor features in the vanilla/upstream kernel are necessary, implementing security measures as kernel modules (such as VED, LKRG, and AKO) provides greater flexibility, as not all nodes have the same security requirements.

## Reference
* SLUBStick: Arbitrary Memory Writes through Practical Software Cross-Cache Attacks within the Linux Kerne https://stefangast.eu/papers/slubstick.pdf
* SLUBStick PoC https://github.com/IAIK/SLUBStick
* Linux Kernel: Exploiting a Netfilter Use-after-Free in kmalloc-cg https://blog.exodusintel.com/2022/12/19/linux-kernel-exploiting-a-netfilter-use-after-free-in-kmalloc-cg/
* Linux kernel heap feng shui in 2022  https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022
* How AUTOSLAB Changes the Memory Unsafety Game https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game
* SLAB_VIRTUAL https://github.com/thejh/linux/blob/slub-virtual-v6.1-lts/MITIGATION_README
* Exploring Linux's New Random Kmalloc Caches https://sam4k.com/exploring-linux-random-kmalloc-caches
* https://hardenedvault.net/blog/2022-11-13-msg_msg-recon-mitigation-ved/
