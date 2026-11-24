# pwn problem

下面的是本次2026CTF4(2026.11.21)中解出的pwn题目writeup

## E Corp
通过反汇编代码可见，main将`rbp-0x40`处作为输入缓冲区，并调用`read(0, buf, 0x100)`读取最多256字节。缓冲区大小为64字节，保存的RBP为8字节，因此覆盖返回地址的偏移为72，此处存在的是程序上的**栈缓冲区漏洞**，`ret2win`。符号表中存在win函数，函数逻辑会打开`/flag`并将读取内容写到标准输出，正常执行流程没有调用它。该文件是固定地址的x86-64 ELF，win入口为`0x4011fd`。

返回地址改为win即可执行隐藏函数。这里在win地址前增加一个ret gadget（`0x401286`，位于win函数末尾），用于调整栈对齐。两个地址均按64位小端序编码，payload结构
```text
offset 72 byte padding + p64(0x401286) + p64(0x4011fd)
```

使用Python socket发送原始二进制输入，运行后先收到访问提示，再发送payload。成功时响应包含`Access denied.`，随后输出flag。

## backdoor
检查文件是x86-64 ELF文件，查看`main`函数可知程序为栈上缓冲区分配0x40字节，却调用`read(0, buf, 0x200)`最多读取0x200字节。因此输入可以越过缓冲区并覆盖返回地址。缓冲区到保存的rbp为64字节，再加上保存的rbp 8字节，覆盖返回地址的偏移是72字节。<br>
此外，程序还提供了可用于构造ROP(Return-Oriented Programming)的指令序列
```text
0x401366  pop rdi ; ret
0x401368  pop rsi ; pop rdx ; ret
0x40136b  mov rdi, rax ; ret
```

该手法为：不往栈上放填充，而是把已有的代码片段地址排成链，每段通常以ret结束，前一段结束则“返回”下一段
```text
override return address(72 bytes)
-> pop rdi; ret                   # 把puts@GOT地址放进rdi
-> puts@GOT                       # puts的参数
-> puts@PLT                       # 调用puts，泄露libc中puts的实际地址
-> main                           # 返回main，第二阶段
```

由于每次的进程启动时libc基址会变化，因此需要使用当前连接泄露出的地址进行计算，不能复用历史记录。在得到puts的实际地址后，计算
```text
libc基址 = puts实际地址 - 附件libc.so.6中puts的偏移
```

再次从libc.so.6中查得open，read，write，_exit的偏移地址，然后进行基址计算。利用时也需要每次将参数放入`rdi`、`rsi`、`rdx`寄存器中<br>
| 顺序 | ROP操作 | 效果 |
| :---: | --- | --- |
| 1 | read(0, 0x404500, 0x40) | 从连接接收/flag字符串，写进可写内存 |
| 2 | open(0x404500, 0) | 只读打开/flag，返回文件描述符 |
| 3 | mov rdi, rax; ret | 把open的返回值，也就是文件描述符放到rdi |
| 4 | read(fd, 0x404600, 0x100) | 从flag文件读取最多0x100字节 |
| 5 | write(1, 0x404600, 0x100) | 把读取结果写到标准输出 |
| 6 | _exit(0) | 结束进程 |

由于该题设置了seccomp过滤器以及拦截了`execve`、`execveat`、`ptrace`，所以本题不适用shell

## dark army relay
检查文件是x86-64 ELF文件，通过`strings`可以看到包含阅读flag文件路径。<br>
根据`objdump`可以看出`main`函数里，`read`把输入读入栈上的缓冲区，在反汇编代码中可见缓冲区地址、读取长度`0x1ff`和`read`调用。随后程序在输入末尾补\0。接着把同一个缓冲区地址放入rdi，调用`printf`。所以还原出printf(rdi)即`printf(user_input)`，发现这里存在程序上的**格式字符串漏洞**，因此可以控制格式符的输入让程序以不同的格式解析。<br>
在`win`函数里，它把`/flag`的字符串地址传给`open`，再把读到的内容交给write输出。再查找全局偏移表（GOT项），可以读到`puts`的重定位地址，我们可以通过`%hhn`改写`puts`的GOT项为win函数地址达到实现win函数的目的。等待程序继续调用puts从而输出flag。<br>