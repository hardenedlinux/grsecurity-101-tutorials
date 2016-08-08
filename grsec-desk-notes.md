# 在桌面 GNU/Linux 上使用 PaX/Grsecurity 的一点经验

欢迎投稿！

## JIT

各路使用 JIT 的程序都容易受到 MPROTECT 特性的伤害。

如果要使用带 JIT 的程序，请准备好 PaX 标记。

## Polkit

Polkit 需要通过访问 /proc 获得 Agent 或者请求提权的进程的信息。

如果你启用了 /proc 限制，请将 polkitd 用户加入 /proc 豁免的组。

而且， polkitd 属于滥用 Javascript 的程序之一。要么给它准备一个 js185 （无 JIT），要么给它
放开 MPROTECT 权限吧。

## Mesa

x86\_32 版本 Mesa 的 libGL 使用了一个自修改代码的优化，会与 MPROTECT 冲突。

编译 Mesa 的时候加 --enable-glx-read-only-text 参数可以避免。

此外 Mesa 的 LLVMPipe 软件渲染器也是一个神奇的 JIT （Shader -> 机器码），所以要使用 LLVMPipe 的话，需要给所有用 OpenGL 的程序都关掉 MPROTECT。
