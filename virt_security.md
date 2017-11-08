## Ring -1: virtualization security

"If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle." ---  Sun Tzu 

Hypervisor is what we called "Ring -1" world and it becomes a very important layer in "cloud"( Someone else's computer?) environment.

## Slide

* [Adventures with a certain Xen vulnerability - 200809](http://invisiblethingslab.com/resources/misc08/xenfb-adventures-10.pdf)
* Xen 0wning Trilogy - 200808, [I](http://invisiblethingslab.com/resources/bh08/part1.pdf), [II](http://invisiblethingslab.com/resources/bh08/part2-full.pdf), [III](http://invisiblethingslab.com/resources/bh08/part3.pdf)
* [Attacking Intel® Trusted Execution Technology - 200902](http://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20paper.pdf)
* [CLOUDBURST A VMware Guest to Host Escape Story - 200908](http://www.blackhat.com/presentations/bh-usa-09/KORTCHINSKY/BHUSA09-Kortchinsky-Cloudburst-SLIDES.pdf), [paper](http://www.blackhat.com/presentations/bh-usa-09/KORTCHINSKY/BHUSA09-Kortchinsky-Cloudburst-PAPER.pdf) and [video](https://media.blackhat.com/bh-usa-09/video/KORTCHINSKY/BHUSA09-Kortchinsky-Cloudburst-VIDEO.mov)

## Article/paper

* [IsGameOver(), anyone? - 200708](http://theinvisiblethings.blogspot.com/2007/08/virtualization-detection-vs-blue-pill.html)
* [Security Challenges in Virtualized Environments - 200804](http://theinvisiblethings.blogspot.com/2008/03/kick-ass-hypervisor-nesting.html), the slide is [here](http://invisiblethingslab.com/resources/rsa08/Security%20Challanges%20in%20Virtualized%20Enviroments%20-%20RSA2008.pdf). Neo swallowed the red pill to enter the Nebuchadnezzar battleship and then he figured out that it's just another Matrix.
* [Following the White Rabbit: Software Attacks against Intel® VT-d - 201105](http://www.invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf)
* Advanced Exploitation of Xen Hypervisor Sysret VM Escape - 2012
* [CAIN: Silently Breaking ASLR in the Cloud](https://www.usenix.org/system/files/conference/woot15/woot15-paper-barresi.pdf)
* [Adventures in Xen exploitation - 201502](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2015/february/adventures-in-xen-exploitation/)
* [Xen SMEP (and SMAP) bypass Introduction - 201504](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2015/april/xen-smep-and-smap-bypass/)
* [VENOM, CVE-2015-3456 - 201505](http://venom.crowdstrike.com/)
* [VM escape: QEMU Case Study - 201704](http://phrack.org/papers/vm-escape-qemu-case-study.html)
* [Attacking a co-hosted VM: A hacker, a hammer and two memory modules](https://thisissecurity.stormshield.com/2017/10/19/attacking-co-hosted-vm-hacker-hammer-two-memory-modules/)
* [Sicherheitsanalyse KVM (Kernel-based Virtual Machine)](https://www.bsi.bund.de/DE/Publikationen/Studien/Sicherheitsanalyse_KVM/sicherheitsanalyse_kvm.html)

## Free/libre open source project

* [Xenpwn](https://github.com/felixwilhelm/xenpwn), toolkit for memory access tracing using hardware assisted virtualization.
* [guestrace](https://www.flyn.org/projects/guestrace/index.html)
* [Qubes OS](https://www.qubes-os.org/)

# Defense/Mitigation

* IOMMU( Intel vt-d)
* Restrict on /dev/mem
* Audit open() syscall with O_DIRECT
* ret2usr protection
* PaX's KERNEXEC stuff, RO for the memory areas that doesn't need write & NX on the most memory maps
* check few possible backdoor implanted funcs: IDT, hypercall_table, exception_table
* No selft-modifying code in hypervisor, code diversification won't work?
* Block all accesses from guest vm to host I/O ports
* KSM: perf trade-off
* Proper entropy bits to aginst brute-force

# NEVER Use VirtualBox

Using VirtualBox is STRONGLY DISCOURAGED, you should switch to a Xen or KVM-based virtualization.

VirtualBox depends on its kernel moudule to function properly, but the module failed to adopt state-of-art security measures. VirtualBox doesn't support KERNEXEC, UDEREF, RANDKSTACK, or SMAP, as spender once said.

> This will be reverted once the VirtualBox devs stop disabling
> SMAP unnecessarily, which seems like it will happen never.
> Anyone who cares about security of their host system shouldn't
> use VirtualBox, as it already precludes the use of KERNEXEC, UDEREF,
> and RANDKSTACK.

# AVOID Xen If You Can

Xen is one of the earliest technology for virtualization for Linux kernel, it has many undesirable designs in a security-oriented perspective. Instead of separating or isolating different components, it uses a monolithic and complicated architecture. Any bugs in Dom0 could easily lead to the compromise of the entire system.

Dozens of critical vulnerabilities are discovered from Xen, about one to three each year, allowing the Guest to subvert the Host entirely. KVM is not fundamentally more secure than Xen, but has apparently somehow comes with less vulnerabilities.

See [this paper](https://www.internetsociety.org/sites/default/files/ndss2017_02A-4_Shi_paper.pdf).

Sometimes, it's still desirable to use Xen. KVM is a Type-II hypervisor, which is simply a module runs under the "big and fat" Linux kernel, while Xen is a true bare-metal Type-I hypervisor, contains nothing but the hypervisor itself. Although in practice Dom0 always uses Linux kernel, Xen still presents smaller attack surface as a hypervisor. 

See [Qubes OS Architecture](https://www.qubes-os.org/attachment/wiki/QubesArchitecture/arch-spec-0.3.pdf), 3.2. Xen vs. KVM security architecture comparison, too see if Xen better suits your use case.

(TODO: more citations)
