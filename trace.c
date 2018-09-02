/**
 * trace
 * @usage tarce <program> <function>
 * @function 1. read the executable file.
 *           2. stop at <function> postion and print value of user regs.
 * @author HotIce0
 */ 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
 
extern int errno;

typedef struct handle {
    Elf64_Ehdr *p_ehdr;
    Elf64_Phdr *p_phdr;
    Elf64_Shdr *p_shdr;
    uint8_t *p_mem;
    char *p_symname; // save the specify function name
    Elf64_Addr addr_symaddr;
    struct user_regs_struct pt_reg;
    char *exec;
}handle_t;

Elf64_Addr lookup_symbol(handle_t *, const char *);

int main(int argc, char **argv, char **envp)
{
    int i_fd;
    pid_t i_pid;
    struct stat st;
    int i_status;
    handle_t h;
    long orig, trap;
    char * args[2];  // put into the specify executable file.

    if (argc < 3) {
        printf("Usage: %s <program> <function>\n", argv[0]);
        exit(0);
    }

    if ((h.exec = strdup(argv[1])) == NULL) {
        perror("strdup");
        exit(-1);
    }

    if ((h.p_symname = strdup(argv[2])) == NULL) {
        perror("strdup");
        exit(-1);
    }

    args[0] = h.exec;
    args[1] = NULL;

    // open file
    if ((i_fd = open(argv[1], O_RDONLY)) < 0) {
        perror("open");
        exit(-1);
    }

    // Read file info : file size(byte)
    if (fstat(i_fd, &st) < 0) {
        perror("fstat");
        exit(-1);
    }

    // Map the executable file to memeory
    h.p_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, i_fd, 0);
    if (h.p_mem == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    h.p_ehdr = (Elf64_Ehdr *)h.p_mem;
    h.p_phdr = (Elf64_Phdr *)&h.p_mem[h.p_ehdr->e_phoff];
    h.p_shdr = (Elf64_Shdr *)&h.p_mem[h.p_ehdr->e_shoff];

    // Check the file by first 4 byte. 0x7f E L F
    if (h.p_mem[0] != 0x7f || strncmp("ELF", (char *)&h.p_mem[1], 3)) {
        fprintf(stderr, "%s is not an ELF file\n", argv[1]);
        exit(-1);
    }
    
    // Check the file is an ELF executable.
    if (h.p_ehdr->e_type != ET_EXEC) {
        fprintf(stderr, "%s is not an ELF executable\n", argv[1]);
        exit(-1);
    }

    // Check the file has the section header table.
    if (h.p_ehdr->e_shstrndx == SHN_UNDEF || h.p_ehdr->e_shoff == 0 || h.p_ehdr->e_shnum == 0) {
        fprintf(stderr, "%s has no section header table\n", argv[1]);
        exit(-1);
    }

    // Lookup the symbol(get address)
    h.addr_symaddr = lookup_symbol(&h, h.p_symname);
    if (h.addr_symaddr == 0) {
        fprintf(stderr, "can't find the %s symbol in this ELF executable file\n", h.p_symname);
        exit(-1);
    }

    // Close file
    if (close(i_fd) < 0) {
        perror("close");
        exit(-1);
    }

    if ((i_pid = fork()) == 0) {
        // sub process do.
        if (ptrace(PTRACE_TRACEME, i_pid, NULL, NULL) < 0) {
            perror("PTRACE_TRACEME");
            exit(-1);
        }
        if (execve(h.exec, args, envp) < 0) {
            perror("execve");
            exit(-1);
        }
        exit(0);
    }

    // main process do.
    wait(&i_status); // Wait the sub process exit.

    printf("Begginning analysis of pid: %d at %lx\n", i_pid, h.addr_symaddr);
    
    // Test Code
    // orig = ptrace(PTRACE_PEEKTEXT, i_pid, h.addr_symaddr, NULL);
    // printf("old orig: %lx\n", orig);
    // trap = (orig & ~0xff) | 0xcc;
    // ptrace(PTRACE_POKETEXT, i_pid, h.addr_symaddr, trap);
    // orig = ptrace(PTRACE_PEEKTEXT, i_pid, h.addr_symaddr, NULL);
    // printf("orig: %lx\n", orig);
    // exit(0);

    orig = ptrace(PTRACE_PEEKTEXT, i_pid, h.addr_symaddr, NULL);
    if (errno != 0) {
        printf("orig: %lx\n", orig);
        perror("PTRACE_PEEKTEXT");
        exit(-1);
    }

    // Insert cc soft interrupt into function addr.
    trap = (orig & ~0xff) | 0xcc;

    // Set trap 0xCC(int3) : soft interrupt
    if (ptrace(PTRACE_POKETEXT, i_pid, h.addr_symaddr, trap) < 0) {
        perror("PTRACE_POKETEXT");
        exit(-1);
    }

    trace:
    // Continue the sub process.
    if (ptrace(PTRACE_CONT, i_pid, NULL, NULL) < 0) {
        perror("PTRACE_CONT");
        exit(-1);
    }
    wait(&i_status); // wait for the soft interrupt signal.

    // Check the reason of signal. (STOPED and SIGTRAP)
    if ( WIFSTOPPED(i_status) && WSTOPSIG(i_status) == SIGTRAP) {
        printf("\nExecutable %s (pid=%d) has hit breakpoint 0x%lx\n",
            h.exec,
            i_pid,
            h.addr_symaddr
        );
        // Read the user_reg
        if (ptrace(PTRACE_GETREGS, i_pid, NULL, &h.pt_reg) < 0) {
            perror("PTRACE_GETREGS");
            exit(-1);
        }
        // Print the user_regs_struct
        printf("%%r15: %llx\n%%r14: %llx\n%%r13: %llx\n%%r12: %llx\n"
        "%%rbp: %llx\n%%rbx: %llx\n%%r11: %llx\n%%r10: %llx\n"
        "%%r9: %llx\n%%r8: %llx\n%%rax: %llx\n%%rcx: %llx\n"
        "%%rdx: %llx\n%%rsi: %llx\n%%rdi: %llx\n%%orig_rax: %llx\n"
        "%%rip: %llx\n%%cs: %llx\n%%eflags: %llx\n%%rsp: %llx\n"
        "%%ss: %llx\n%%fs_base: %llx\n%%gs_base: %llx\n%%ds: %llx\n"
        "%%es: %llx\n%%fs: %llx\n%%gs: %llx\n",
        h.pt_reg.r15, h.pt_reg.r14, h.pt_reg.r13, h.pt_reg.r12,
        h.pt_reg.rbp, h.pt_reg.rbx, h.pt_reg.r11, h.pt_reg.r10,
        h.pt_reg.r9, h.pt_reg.r8, h.pt_reg.rax, h.pt_reg.rcx,
        h.pt_reg.rdx, h.pt_reg.rsi, h.pt_reg.rdi, h.pt_reg.orig_rax,
        h.pt_reg.rip, h.pt_reg.cs, h.pt_reg.eflags, h.pt_reg.rsp,
        h.pt_reg.ss, h.pt_reg.fs_base, h.pt_reg.gs_base, h.pt_reg.ds,
        h.pt_reg.es, h.pt_reg.fs, h.pt_reg.gs);

        printf("\nPlease hit any key to continue: ");
        getchar();
        
        // Recover the orig (remove trap)
        if (ptrace(PTRACE_POKETEXT, i_pid, h.addr_symaddr, orig) < 0) {
            perror("PTRACE_POKETEXT");
            exit(-1);
        }

        // Set the rip(Reg Instruction Point) back. (redo this instruction)
        h.pt_reg.rip = h.pt_reg.rip - 1;

        // Save the reg change (rip change)
        if (ptrace(PTRACE_SETREGS, i_pid, NULL, &h.pt_reg) < 0) {
            perror("PTRACE_SETREGS");
            exit(-1);
        }

        // Set single step run and continue the process
        if (ptrace(PTRACE_SINGLESTEP, i_pid, NULL, NULL) < 0) {
            perror("PTRACE_SINGLESTEP");
            exit(-1);
        }
        wait(NULL); // Get the singal of stopping(single step)

        // Set trap 0xCC(int3) : soft interrupt
        if(ptrace(PTRACE_POKETEXT, i_pid, h.addr_symaddr, trap) < 0) {
            perror("PTRACE_POKETEXT");
            exit(-1);
        }
        goto trace;
    }
    if (WIFEXITED(i_status))
        printf("Completed tracing pid: %d\n", i_pid);
    exit(0);
}

/**
 * Lookup the symbol address which named [sysmname].
 * if no find, the return value is 0.
 */ 
Elf64_Addr lookup_symbol(handle_t *p_h, const char *symname)
{
    int i, j;
    char *strtab;
    Elf64_Sym *symtab;
    for (i = 0; i < p_h->p_ehdr->e_shnum; i++) {
        if (p_h->p_shdr[i].sh_type == SHT_SYMTAB) {
            printf("count of the symbol : %ld\n", p_h->p_shdr[i].sh_size / sizeof(Elf64_Sym));
            // Get the address of the symname table(.strtab).
            strtab = (char *)&p_h->p_mem[p_h->p_shdr[p_h->p_shdr[i].sh_link].sh_offset];
            printf("The index of .strtab : %d\n", p_h->p_shdr[i].sh_link);
            // Get the address of the symtab.
            symtab = (Elf64_Sym *)&p_h->p_mem[p_h->p_shdr[i].sh_offset];

            printf("strtab offset : %lx\n", p_h->p_shdr[p_h->p_shdr[i].sh_link].sh_offset);
            printf("symtab offset : %lx\n", p_h->p_shdr[i].sh_offset);

            // Lookup the symbol.
            for (j = 0; j < p_h->p_shdr[i].sh_size / sizeof(Elf64_Sym); j++) {
                // printf("%d : %s\n", j, &strtab[symtab[j].st_name]);
                if (strcmp(&strtab[symtab[j].st_name], symname) == 0)
                    return symtab[j].st_value;
            }
            
        }
    }
    printf("find the symbol failed\n");
    return 0;
}
