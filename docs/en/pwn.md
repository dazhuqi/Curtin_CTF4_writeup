# Pwn Challenge Writeups

Writeups for the pwn challenges solved during Curtin CTF4 2026 on 2026-11-21.

## E Corp
Disassembly shows that `main` uses `rbp-0x40` as an input buffer and calls `read(0, buf, 0x100)` to read up to 256 bytes. The buffer is 64 bytes, followed by the saved 8-byte RBP, so the return-address offset is 72 bytes. This is a stack buffer overflow that can be used for ret2win. The symbol table contains a `win` function that opens `/flag` and writes its contents to standard output, although the normal control flow never calls it. The binary is a fixed-address x86-64 ELF, and `win` starts at `0x4011fd`.

Overwrite the return address to reach the hidden function. Place a `ret` gadget (`0x401286`, at the end of the `win` function) before the `win` address to align the stack. Encode both addresses as 64-bit little-endian values. The payload is:
```text
72 bytes of padding + p64(0x401286) + p64(0x4011fd)
```

Use a Python socket to send the raw input. After receiving the access prompt, send the payload. On success, the response contains `Access denied.` followed by the flag.

## backdoor
The file is an x86-64 ELF. In `main`, a `0x40`-byte stack buffer is passed to `read(0, buf, 0x200)`, which can read up to `0x200` bytes. The input can therefore overflow the buffer and overwrite the return address. The offset is 72 bytes: 64 bytes to the saved RBP, plus the 8-byte saved RBP.

The program also contains instruction sequences useful for building a ROP (Return-Oriented Programming) chain:
```text
0x401366  pop rdi ; ret
0x401368  pop rsi ; pop rdx ; ret
0x40136b  mov rdi, rax ; ret
```

Instead of putting padding on the stack, arrange the addresses of existing code snippets in a chain. Each snippet usually ends in `ret`, which transfers control to the next address:
```text
overwrite return address (72 bytes)
-> pop rdi; ret                   # put the puts@GOT address in rdi
-> puts@GOT                       # argument to puts
-> puts@PLT                       # leak the runtime address of puts in libc
-> main                           # return to main for stage two
```

The libc base changes on each process start, so calculate it from the leak on the current connection rather than reusing an earlier value:
```text
libc base = leaked puts address - puts offset in the supplied libc.so.6
```

Look up the offsets of `open`, `read`, `write`, and `_exit` in `libc.so.6`, then calculate their addresses from the base. For each call, place arguments in `rdi`, `rsi`, and `rdx` as needed.

| Step | ROP operation | Effect |
| :---: | --- | --- |
| 1 | `read(0, 0x404500, 0x40)` | Receive the `/flag` string and write it to writable memory |
| 2 | `open(0x404500, 0)` | Open `/flag` read-only and return its file descriptor |
| 3 | `mov rdi, rax; ret` | Move the file descriptor returned by `open` into `rdi` |
| 4 | `read(fd, 0x404600, 0x100)` | Read up to `0x100` bytes from the flag file |
| 5 | `write(1, 0x404600, 0x100)` | Write the data to standard output |
| 6 | `_exit(0)` | Exit the process |

The challenge sets a seccomp filter that blocks `execve`, `execveat`, and `ptrace`, so a shell is not suitable here.

## dark army relay
The file is an x86-64 ELF. `strings` shows a path used to read the flag.

In `main`, `objdump` shows that `read` puts input into a stack buffer, with a read length of `0x1ff`. The program then adds a null terminator and passes the same buffer address in `rdi` to `printf`. This reconstructs to `printf(user_input)`, a format-string vulnerability that lets the input control how `printf` interprets its format specifiers.

The `win` function passes the `/flag` string address to `open`, then writes the contents it reads. Inspect the Global Offset Table (GOT) to find the relocation entry for `puts`. Use `%hhn` to overwrite the `puts` GOT entry with the address of `win`, then wait for the program to call `puts` and print the flag.
