# SELinux bypass

![img](https://grsecurity.net/~spender/pics/mac_security_sesamestreet.jpg)

There has been exploit techniques to bypass SELinux since early 2000s. However, a recent [write-up](https://klecko.github.io/posts/selinux-bypasses/) revealed six methods for bypassing SELinux specifically targeting Android systems. There are several mitigations available to address these bypass techniques. Some of which require support from EL2 virtualization as a permission watcher (RO page), while others can be easily applied to any Linux system without virtualization. It's important to stay informed about these bypass methods and apply the appropriate mitigations to the production.

## Bypass techniques
 * Disable SELinux by overwriting the sensitive data structure

| Exploit vector | Mitigation | EL2 mitigation |
|:-------------:|:-----------------------:|:-----------------:|
| disabled field | v6.6 [removed the runtime disable feature](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f22f9aaf6c3d92ebd5ad9e67acc03afebaaeb289), for the super long-term embedded Linux maintainance, do the backport 2) Disable CONFIG_SECURITY_SELINUX_DEVELOP | No |
| enforcing field | 1) Disable CONFIG_SECURITY_SELINUX_DEVELOP 2) Code hardening by ensuring the offset being 0x00 | [RKP](https://blog.longterm.io/samsung_rkp.html#protecting-kernel-data)

 * Overwrite permissive map

| Exploit vector | Mitigation | EL2 mitigation |
|:-------------:|:-----------------------:|:-----------------:|
| permissive_map field | Code hardening: set it to 0x00 so it'd be ignored | [selinux_pool](https://blog.impalabs.com/2212_huawei-security-hypervisor.html#selinux-protection) |

 * Overwrite AVC cache

| Exploit vector | Mitigation | EL2 mitigation |
|:-------------:|:-----------------------:|:-----------------:|
| [Policy injection](https://github.com/chompie1337/s8_2019_2215_poc/blob/master/poc/selinux_bypass.c#L446) | N/A | YES |

 * SELinux initialization

| Exploit vector | Mitigation | EL2 mitigation |
|:-------------:|:-----------------------:|:-----------------:|
| [Trick/overwrite the SELinux initialization](https://www.blackhat.com/docs/us-17/thursday/us-17-Shen-Defeating-Samsung-KNOX-With-Zero-Privilege-wp.pdf) | N/A | YES |

 * Overwrite mapping

| Exploit vector | Mitigation | EL2 mitigation |
|:-------------:|:-----------------------:|:-----------------:|
| [Overwrite global data used in security_compute_av()](https://i.blackhat.com/Asia-24/Presentations/Asia-24-Wu-Game-of-Cross-Cache.pdf) | N/A | NO |

 * Remove hooks

| Exploit vector | Mitigation | EL2 mitigation |
|:-------------:|:-----------------------:|:-----------------:|
| Bypass EL2/RKP by [removing hooks](https://klecko.github.io/posts/selinux-bypasses/#linux-security-module) | N/A | NO |

## Reference

 * SELinux bypasses
    https://klecko.github.io/posts/selinux-bypasses/
 * Bypassing SELinux with init_module 
    https://seanpesce.blogspot.com/2023/05/bypassing-selinux-with-initmodule.html

