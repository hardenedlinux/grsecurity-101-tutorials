# Ring 0: Linux kernel vulnerablity & exploit

"If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle." ---  Sun Tzu

Kernel is what we called "Ring 0". It's the front line and [the last place we can defense the those underneath adversaries](https://github.com/hardenedlinux/hardenedlinux_profiles/raw/master/slide/hardening_the_core.pdf) effectively. Unfortunately, most people from [FLOSS world lost their rights to access PaX/Grsecurity](https://hardenedlinux.github.io/announcement/2017/04/29/hardenedlinux-statement2.html)'s stable and test patch, which is the only effective defense solution. KSPP is making the progress slowly and more bugs being introduced by misunderstanding some PaX/Grsecurity features and missing the context why PaX/Grsecurity created them in the 1st place. Some vulnerablities and exploits( Since KSPP started) targetting linux kernel in the wild will be listed here and most of them can be mitigated by PaX/Grsecurity without any fix.

## Privilege Escalation
* [Analysis and Exploitation of a Linux Kernel Vulnerability (CVE-2016-0728) - 201601](http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/)
* [CVE-2016-1583/Linux: Stack overflow via ecryptfs and /proc/$pid/environ - 201607](https://bugs.chromium.org/p/project-zero/issues/detail?id=836)
* [CVE-2017-2636/exploit the race condition in the n_hdlc Linux kernel driver bypassing SMEP - 20170324](https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html)
* [CVE-2017-0358/ntfs-3g: modprobe is executed with unsanitized environment - 201702](https://bugs.chromium.org/p/project-zero/issues/detail?id=1072)
* [Linux kernel: CVE-2017-6074: DCCP double-free vulnerability (local root) - 201702](http://seclists.org/oss-sec/2017/q1/471)
* [CVE-2017-7184/PWN2OWN 2017 Linux 内核提权漏洞分析](https://zhuanlan.zhihu.com/p/26674557)

## Auxlilary ingredients
* [CVE-2017-7616/The Infoleak that (Mostly) Wasn't - 201704](https://grsecurity.net/the_infoleak_that_mostly_wasnt.php)

## Silent fixes from Linux kernel "community" ( Welcome to add...)
* [Multiple vulnerablities being silent fixed: CVE-2017-5546, CVE-2017-5547, CVE-2016-10154, CVE-2017-5548, CVE-2017-5549, CVE-2017-5550, CVE-2017-5551](http://seclists.org/oss-sec/2017/q1/161)
* [Silently (or obliviously) partially-fixed CONFIG_STRICT_DEVMEM bypass - 201704](http://seclists.org/oss-sec/2017/q2/76)

# Other resouces
[Linux Kernel Exploitation](https://github.com/xairy/linux-kernel-exploitation)
