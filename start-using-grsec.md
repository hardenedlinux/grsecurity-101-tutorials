# 开始使用 Grsecurity

## 发行版可能提供

以下常见发行版默认使用 Grsecurity。

- Alpine

以下常见发行版可以从包管理安装带 Grsecurity 的 Linux 内核。（注意：预编译的 Linux w/ Grsecurity 不一定符合你的需求，可能你最终也要自行编译内核）

- Arch: ```linux-grsec```
- Debian: ```linux-image-grsec-amd64``` 或者 ```linux-image-grsec-i386``` （根据系统架构确定）
- Gentoo: ```hardened-sources``` （建议使用 Hardened Profile 重新编译系统）

如果你不是使用上述发行版，你可能需要自行下载补丁并编译内核。

## 自行编译 Linux Kernel w/ PaX/Grsecurity

Grsecurity 的补丁集最新版下载地址为： https://grsecurity.net/download.php

Grsecurity 的主页不会保管其历史版本，所以，如果你需要历史版本的 Grsecurity 补丁集，你需要去另一个网站下载：http://deb.digdeo.fr/grsecurity-archives/

同时，Grsecurity 需要版本匹配的 Linux 内核源码，Linux 内核源码可以从 https://www.kernel.org 下载。

注意：Grsecurity 通常需要一定时间适配最新版本内核，所以 Grsecurity 补丁最新版本适配的内核版本可能不是最新的 Linux 内核版本。

截止此部分写作时，最新版的 Grsecurity Test 版本是 grsecurity-3.1-4.6.5-201607312210.patch 。（Grsecurity 的最新 Stable 版本仅提供给付费客户。）匹配该内核补丁的 Linux 内核 Tarball 是 linux-4.6.5.tar.xz 。

编译带 Grsecurity 补丁集的 Linux 内核的过程，与编译其它带补丁的 Linux 内核过程相同，此处暂不展开叙述。

注意：在进行 ```make menuconfig``` 时，请谨慎考虑打开各种加固特性！
