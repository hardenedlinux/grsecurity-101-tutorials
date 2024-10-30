Embedded or platform software and firmware implementation involves different System-on-Chip (SoC) hardware. These fundamentals are applied in various industries such as mobile phones, game consoles, automobiles, and aerospace, where a large amount of embedded platform technology stack is utilized.

## Cellphone
* [Over The Air: Exploiting Broadcom’s Wi-Fi Stack (Part 1) - 201704](https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html)
* [Over The Air: Exploiting Broadcom’s Wi-Fi Stack (Part 2) - 201704](https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_11.html)
* [Over The Air - Vol. 2, Pt. 1: Exploiting The Wi-Fi Stack on Apple Devices - 201709](https://googleprojectzero.blogspot.com/2017/09/over-air-vol-2-pt-1-exploiting-wi-fi.html)
* [Over The Air - Vol. 2, Pt. 2: Exploiting The Wi-Fi Stack on Apple Devices - 201710](https://googleprojectzero.blogspot.com/2017/10/over-air-vol-2-pt-2-exploiting-wi-fi.html)
* [Over The Air - Vol. 2, Pt. 3: Exploiting The Wi-Fi Stack on Apple Devices  - 201710](https://googleprojectzero.blogspot.com/2017/10/over-air-vol-2-pt-3-exploiting-wi-fi.html)
* [Remotely compromise devices by using bugs in Marvell Avastar Wi-Fi: from zero knowledge to zero-click RCE - 201901](https://embedi.org/blog/remotely-compromise-devices-by-using-bugs-in-marvell-avastar-wi-fi-from-zero-knowledge-to-zero-click-rce/)

* [War of the Worlds - Hijacking the Linux Kernel from QSEE - 201605](http://bits-please.blogspot.com/2016/05/war-of-worlds-hijacking-linux-kernel.html), [PoC](https://github.com/laginimaineb/WarOfTheWorlds)
* [Lifting the (Hyper) Visor: Bypassing Samsung’s Real-Time Kernel Protection - 201702](https://googleprojectzero.blogspot.com/2017/02/lifting-hyper-visor-bypassing-samsungs.html)

We're focusing on the FullMAC implementation which had a sperate OS running inside wifi soc, while SoftMAC is matters to RING 0 only. This is a typical attack surface which is able to apply to other fields like Automotive industry.

| Wifi SoC communication protocol w/ HOST | DMA support       | Device support|
|:---------------------------------------:|:-----------------:|:-------------:|
| SDIO/v3.0                               | optional          | Nexus 5       |
| USB/v3.1             | USB protocol does not allow DMA, though USB controllers may send and receive packets via DMA | <= iPhone 5  |
| PCIe                 | by default                           | >= Nexus 6, >= iPhone 6, >= Galaxy S6 |

If there's no IOMMU/SMMU configured correctly, the attack path could be much easier:

Pwned SoC kernel (ThreadX or other RTOSes)--> infoleak via DMA (identify kernsymbols)--> hijack the function by overwriting the code--> boom!

## Vehicle platform security research
* [Experimental Security Assessment of BMW Cars: A Summary Report - 201802](https://keenlab.tencent.com/en/whitepapers/Experimental_Security_Assessment_of_BMW_Cars_by_KeenLab.pdf) and the [white paper](https://web.archive.org/web/20221208170705/http://kunnamon.io/tbone/tbone-v1.0-redacted.pdf) w/o MCU exploitation.
* |**Webkit/browser -> Linux kernel privilege escalation (CVE-2017-6261)** | [Over-the-Air: How we Remotely Compromised the Gateway, BCM, and Autopilot ECUs of Tesla Cars - 2018](https://i.blackhat.com/us-18/Thu-August-9/us-18-Liu-Over-The-Air-How-We-Remotely-Compromised-The-Gateway-Bcm-And-Autopilot-Ecus-Of-Tesla-Cars.pdf) and [white paper](https://i.blackhat.com/us-18/Thu-August-9/us-18-Liu-Over-The-Air-How-We-Remotely-Compromised-The-Gateway-Bcm-And-Autopilot-Ecus-Of-Tesla-Cars-wp.pdf).
* [0-Days & Mitigations: Roadways to Exploit and Secure Connected BMW Cars - 201908](https://i.blackhat.com/USA-19/Thursday/us-19-Cai-0-Days-And-Mitigations-Roadways-To-Exploit-And-Secure-Connected-BMW-Cars.pdf) and [white paper](https://i.blackhat.com/USA-19/Thursday/us-19-Cai-0-Days-And-Mitigations-Roadways-To-Exploit-And-Secure-Connected-BMW-Cars-wp.pdf).
* [Mercedes-Benz MBUX Security Research Report - 202105](https://keenlab.tencent.com/en/whitepapers/Mercedes_Benz_Security_Research_Report_Final.pdf)
* | **Likely Wi-Fi firmware to Linux kernel privilege escalation**| [T-BONE: Drone vs. Tesla - 202104](https://web.archive.org/web/20230129133144/https://kunnamon.io/tbone/)
* [Jailbreaking an Electric Vehicle in 2023 or What It Means to Hotwire Tesla's x86-Based Seat Heater - 202308](https://i.blackhat.com/BH-US-23/Presentations/US-23-Werling-Jailbreaking-Teslas.pdf), tools [PSPReverse](https://github.com/PSPReverse) on Github.
* [Unlocking the Drive Exploiting Tesla Model 3 - 202311](https://www.synacktiv.com/sites/default/files/2023-11/tesla_grehack.pdf)
* [0-click RCE on Tesla Model 3 through TPMS Sensors - 202411](https://www.synacktiv.com/sites/default/files/2024-10/hexacon_0_click_rce_on_tesla_model_3_through_tpms_sensors_light.pdf)

## Hardening the weak spots

The attacking path through either out-of-band SoC or browser are quite long to achieve the goals (exploitation and post-exploitation). The exploit chains can be defeated one by one, which means you need a set of building blocks to build a defense-in-depth solution. This list only contains the content cited in this document (contribution are always welcomed!).

| Weak spots/exploitation methods      | Description                 | Mitigation |
|:------------------:|:---------------------------:|:----------:|
| RTOS               | w/o modern mitigation and binary blobs (mostly)       | N/A        |
| HOST infoleak      | /proc/iomem                 | Priv only  |
| SoC infoleak       | DMA to locate kernel symbols| IOMMU/SMMU |
| Hijack kernel      | [Overwriting the code](https://bits-please.blogspot.com/2016/05/war-of-worlds-hijacking-linux-kernel.html) | CFI        |
| SoC infoleak       | DMA to locate kernel symbols| IOMMU/SMMU |
| Heap shaping       | Craft a predictive layout   | freelist randomization and pointer encryption |
| AudioManager       | No full ASLR                | PIE |
| Webkit/QtWebEngine | exploit on Browser          | sandboxing and MAC (SELinux/AppArmor)  |
| Hijacking GOT      | Writable Global Offset Table | [Full RELRO](https://www.trapkit.de/articles/relro/) |
| Hardware-based fault injection | Effective method targets at verified boot to break chain of trust | CFI, e.g: [PaX RAP enabled for firmware payload](https://www.linkedin.com/posts/shawn-c-4836063_coreboot-heads-grsecurity-activity-6578088784351584256-7TuD) |
