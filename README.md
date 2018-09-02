# trace by HotIce0
## Usage : `tarce <program> <function>`
## Require : Linux 64bit and the program must be ELF executable type. (add gcc parrament -static => `gcc -static -o test test.c`)
## Function : 
1. read the executable file.
2. stop at <function> postion and print value of user regs.
# Demo
1. file[test.c]
  ```C
  #include <stdio.h>
void hotice0(int i)
{
    printf("i am hotice0 like %d\n", i);
}

int main(void)
{
    hotice0(7);
    hotice0(77);
    return 0;
}
  ```
2. Compile
  `$ gcc -static -o test test.c`
3. Run Results
  ```
  zg@ubuntu:~/Documents/trace$ ./trace test hotice0
count of the symbol : 1808
The index of .strtab : 31
strtab offset : c7148
symtab offset : bc7c8
Begginning analysis of pid: 18512 at 400b4d

Executable test (pid=18512) has hit breakpoint 0x400b4d
%r15: 0
%r14: 6b9018
%r13: 0
%r12: 401900
%rbp: 7ffd4d295e60
%rbx: 400400
%r11: 1
%r10: 2
%r9: 2
%r8: 0
%rax: 400b71
%rcx: 44ba80
%rdx: 7ffd4d295f98
%rsi: 7ffd4d295f88
%rdi: 7
%orig_rax: ffffffffffffffff
%rip: 400b4e
%cs: 33
%eflags: 246
%rsp: 7ffd4d295e58
%ss: 2b
%fs_base: 1cc5880
%gs_base: 0
%ds: 0
%es: 0
%fs: 0
%gs: 0

Please hit any key to continue:
i am hotice0 like 7

Executable test (pid=18512) has hit breakpoint 0x400b4d
%r15: 0
%r14: 6b9018
%r13: 0
%r12: 401900
%rbp: 7ffd4d295e60
%rbx: 400400
%r11: 246
%r10: 0
%r9: 14
%r8: 0
%rax: 14
%rcx: 0
%rdx: 6bbd30
%rsi: 0
%rdi: 4d
%orig_rax: ffffffffffffffff
%rip: 400b4e
%cs: 33
%eflags: 202
%rsp: 7ffd4d295e58
%ss: 2b
%fs_base: 1cc5880
%gs_base: 0
%ds: 0
%es: 0
%fs: 0
%gs: 0

Please hit any key to continue:
i am hotice0 like 77
Completed tracing pid: 18512
  ```
