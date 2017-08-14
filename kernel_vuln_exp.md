# Ring 0: Linux kernel vulnerablity & exploitation & silent fixes

"If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle." ---  Sun Tzu

Kernel is what we called "Ring 0". It's the front line and [the last place we can defense the those underneath adversaries](https://github.com/hardenedlinux/hardenedlinux_profiles/raw/master/slide/hardening_the_core.pdf) effectively. Unfortunately, most people from [FLOSS world lost their rights to access PaX/Grsecurity](https://hardenedlinux.github.io/announcement/2017/04/29/hardenedlinux-statement2.html)'s stable and test patch, which is the only effective defense solution. KSPP is making the progress slowly and more bugs being introduced by misunderstanding some PaX/Grsecurity features and missing the context why PaX/Grsecurity created them in the 1st place. Some vulnerablities and exploits( Since KSPP started) targetting linux kernel in the wild will be listed here and most of them can be mitigated by PaX/Grsecurity without any fix.

## Exploit vectors
* [offset2lib](https://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html)
* [The Stack Clash](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt), [notes](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/notes/stack_clash.md)

## Privilege Escalation
* [Analysis and Exploitation of a Linux Kernel Vulnerability (CVE-2016-0728) - 201601](http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/)
* [CVE-2016-1583/Linux: Stack overflow via ecryptfs and /proc/$pid/environ - 201607](https://bugs.chromium.org/p/project-zero/issues/detail?id=836)
* [CVE-2017-2636/exploit the race condition in the n_hdlc Linux kernel driver bypassing SMEP - 20170324](https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html)
* [CVE-2017-0358/ntfs-3g: modprobe is executed with unsanitized environment - 201702](https://bugs.chromium.org/p/project-zero/issues/detail?id=1072)
* [Linux kernel: CVE-2017-6074: DCCP double-free vulnerability (local root) - 201702](http://seclists.org/oss-sec/2017/q1/471)
* [CVE-2017-7184/PWN2OWN 2017 Linux 内核提权漏洞分析](https://zhuanlan.zhihu.com/p/26674557)
* [sudo-CVE-2017-1000367 - 201706](https://github.com/c0d3z3r0/sudo-CVE-2017-1000367)
* [CVE-2017-1000112: Exploitable memory corruption due to UFO to non-UFO path switch - 20170813](http://www.openwall.com/lists/oss-security/2017/08/13/1), [PoC](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c)

## Auxlilary ingredients
* [CVE-2017-7616/The Infoleak that (Mostly) Wasn't - 201704](https://grsecurity.net/the_infoleak_that_mostly_wasnt.php)
* [CVE-2016-10277/CVE-2017-1000363, initroot: Bypassing Nexus 6 Secure Boot through Kernel Command-line Injection](https://alephsecurity.com/2017/05/23/nexus6-initroot/)

## Silent fixes from Linux kernel "community" ( Welcome to add more for fun!)
* [kernel: inotify: a race between inotify_handle_event() and sys_rename(): CVE-2017-7533 - 20170803](http://seclists.org/oss-sec/2017/q3/240)
* [Multiple silent fixes done by Linux kernel "community": "More CONFIG_VMAP_STACK vulnerabilities, refcount_t UAF, and an
 ignored Secure Boot bypass / rootkit method"](http://www.openwall.com/lists/oss-security/2017/06/24/1)
* [Silently (or obliviously) partially-fixed CONFIG_STRICT_DEVMEM bypass - 201704](http://seclists.org/oss-sec/2017/q2/76)
* [Multiple vulnerablities being silent fixed: CVE-2017-5546, CVE-2017-5547, CVE-2016-10154, CVE-2017-5548, CVE-2017-5549, CVE-2017-5550, CVE-2017-5551](http://seclists.org/oss-sec/2017/q1/161)

# Other resouces
[Linux Kernel Exploitation](https://github.com/xairy/linux-kernel-exploitation)
