# 在桌面 GNU/Linux 上使用 PaX/Grsecurity 的一点经验

欢迎投稿！

## JIT

各路使用 JIT 的程序都容易受到 MPROTECT 特性的伤害。

如果要使用带 JIT 的程序，请准备好 PaX 标记。

## Polkit

Polkit 需要通过访问 /proc 获得 Agent 或者请求提权的进程的信息。

请将 polkitd 用户加入 /proc 豁免的组。

FIXME: 在桌面系统上阻止普通用户访问 /proc 真的是好主意么？PaX Team
自己不这么认为。

而且， polkitd 属于滥用 Javascript 的程序之一。别忘了给它放开 MPROTECT。

FIXME: polkitd 使用 spidermonkey 执行 JavaScript，似乎在典型的系统上只有 polkitd
才会用 spidermonkey，浏览器都不用了，而且对于 polkitd 这么关键的程序，再加上它
所使用的那么一点点 JavaScript，关闭 spidermonkey 的 JIT 而不是放开 mprotect 是
更好的选择。

## Mesa

x86_32 版本 Mesa 的 libGL 使用了一个自修改代码的优化，会与 MPROTECT 冲突。

编译 Mesa 的时候加 --enable-glx-read-only-text 参数可以避免。

此外 Mesa 的 LLVMPipe 软件渲染器也是一个神奇的 JIT （Shader -> 机器码），所以要使用 LLVMPipe 的话，需要给所有用 OpenGL 的程序都关掉 MPROTECT。
