## Notes about stack clash

The 3rd "nuclear" bomb named ["The Stack Clash"](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt) dropped by Qualys to the planet Penguin since the era of "Attacking the core". An old exploit vector being weaponized by the stack clash can target any SUID/SGID programs by exploiting the flaw in guard-page and automatic stack expansion feature. From [Grsecurity's blog](https://grsecurity.net/an_ancient_kernel_hole_is_not_closed.php)( another ["An Ancient Kernel Hole is (Not) Closed" in LWN](https://lwn.net/Articles/400746/)), we can see there are some silent fixes[1](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=320b2b8de12698082609ebbc1a17165727f4c893) [2](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=09884964335e85e897876d17783c2ad33cf8a2e0) by Linus Torvalds( as always). Let's see the summary about defensive mitigation:

1) PaX's ASLR can defeat offset2lib easily since...2001?

2) Stack/heap protectioned provided by linux kernel has only one single page( 4KB by default in i386) due to some compatibility issues. PaX's implementation doesn't have this problem and its gap is 64KB by default. You can set the number at runtime via "sysctl vm.heap_stack_gap"( We have another auditing item for the hardening solution. Thanks to the full disclosure).

3) PaX's STACKLEAK can detect if moving sp to the start of the stack.

4) Some resctrictions provided by PaX/Grsecurity on SUID programs. GRKERNSEC_BRUTE is one of them. It will raise the bar to those who try to gain the control of EIP. Qualys gave the test results about Debian 8.6 with PaX/Grsecurity:

	* GRKERNSEC_BRUTE disabled: 200 hrs to gain control of EIP, then ~1500 yrs to brute force the PaX's ASLR to getting root shell
	* GRKERNSEC_BRUTE enabled: ~1365 days to gain control of EIP, then...you don't wanna know-_-

PaX/Grsecurity also restricted SUID program's RLIMIT_STACK up to 8MB and the environment arg/strings up to 512KB.

5) GNU cflow and GCC's -fstack-check can be considered in the situational hardening solution and the performance impact trade-off must be made.

Spender/PaX team also pointing out the possibility of similar issues in kernel stack. [KSPP doesn't try](http://www.openwall.com/lists/kernel-hardening/2017/03/13/4) to [understand STACKLEAK](http://openwall.com/lists/kernel-hardening/2017/06/09/14) while trying to copy+paste stuff from PaX/Grsecurity. On the other hand, VMAP_STACK is [not solid as KSPP claimed](http://openwall.com/lists/kernel-hardening/2017/06/06/1). [Forge the mitigation by introducing more exploitable bugs](http://seclists.org/oss-sec/2017/q1/161) is not the proper way to do it. Instead, Grsecurity moved the thread_info off the kstack in the early days and then forged it with other [defensive code as a feature KSTACKOVERFLOW in 2014](https://hardenedlinux.github.io/system-security/2016/12/13/kernel_mitigation_checklist.html).

The stack clash is the full disclosure of a exploit vector after [offset2lib](https://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html). It seems Greg K Hartman didn't want to accept the original offset2lib patch( He's likely to accept more security mitigation because Linux foundation need KSPP to making more money from membership sales. That's [why we lost the ark](https://hardenedlinux.github.io/announcement/2017/04/29/hardenedlinux-statement2.html), remeber?. Maybe it's just [Google want him to do so](http://openwall.com/lists/kernel-hardening/2017/05/04/20)?;-)). Kees Cook's patch merged 5 months later. Unfortunately, the exploitation method demonstrasted in stack clash can bypass the [previous offset2lib upstream fix](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d1fd836dcf00d2028c700c7e44d2c23404062c90), which means we are expose to both high risk exploit vectors now: offset2lib and stack clash. There are tons of known/0-day bugs can be utilized by exploit writer to forge their weapon. Offset2lib troubled some industry( ask ppl from finacial industry) at once. Are we going to face massive exploitation with stack clash( maybe in the form of ransomeware?) in the future? Murphy's law seems to tell us shit happens as always. 

May we screw again!
