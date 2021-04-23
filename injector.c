#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define MAX_INS_LENGTH 15

#if __x86_64__
#define IP REG_RIP
#else
#define IP REG_EIP
#endif

#define TF 0x0100

void *aligned_buffer;
char *ins_start;
extern void *resume, *pre_instruction_start, *pre_instruction_end;

mcontext_t fault_context;

typedef struct
{
    uint8_t bytes[MAX_INS_LENGTH];
    int length;
} insn_t;

typedef struct
{
    insn_t ins;
    int index;
    int last_len;
} inj_t;
inj_t inj = {.ins = {.bytes = {0x0f, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, .length = 0}, .index = 0, .last_len = 0};

typedef struct
{
    uint32_t length;
    int signum;
    int si_code;
    uint32_t addr;
} result_t;
result_t result = {0, 0, 0, 0};

uint64_t dummy_stack[256] __attribute__((aligned(PAGE_SIZE)));

uint64_t stack[SIGSTKSZ];
stack_t ss = {.ss_sp = stack, .ss_size = SIGSTKSZ};

void state_handler(int signum, siginfo_t *si, void *p)
{
    fault_context = ((ucontext_t *)p)->uc_mcontext; //save known good values
    ((ucontext_t *)p)->uc_mcontext.gregs[IP] += 2;
}

void fault_handler(int signum, siginfo_t *si, void *p)
{

    ucontext_t *context = (ucontext_t *)p;
    int pre_instruction_len = ((uintptr_t)&pre_instruction_end - (uintptr_t)&pre_instruction_start);
    uintptr_t ip = (uintptr_t)context->uc_mcontext.gregs[IP];
    int ins_length = ip - (uintptr_t)ins_start - pre_instruction_len; //estimated length
    if (ins_length > MAX_INS_LENGTH || ins_length < 0)
    {
        //branch instruction
        ins_length = MAX_INS_LENGTH; //?
    }

    result.signum = signum;
    result.si_code = si->si_code;
    result.addr = signum == SIGSEGV || signum == SIGBUS ? (uintptr_t)si->si_addr : -1;
    //result.length = ins_length;

    memcpy(context->uc_mcontext.gregs, fault_context.gregs, sizeof(fault_context.gregs)); //load known good values
    context->uc_mcontext.gregs[IP] = (uintptr_t)&resume;
    context->uc_mcontext.gregs[REG_EFL] &= ~TF; //reset trap flag
}

void configure_handler(void (*handler)(int, siginfo_t *, void *))
{
    sigaltstack(&ss, NULL);

    struct sigaction act;
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | SA_ONSTACK;

    sigfillset(&act.sa_mask);

    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGTRAP, &act, NULL);
    sigaction(SIGILL, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
}

//set the trap flag.
void pre_instruction()
{
#if __x86_64__
    __asm__ __volatile__("\
                        .global pre_instruction_start \n\
                        pre_instruction_start: \n\
                        pushfq \n\
                        orq $0x0100,(%rsp) \n\
                        popfq \n\
                        .global pre_instruction_end \n\
                        pre_instruction_end: \n\
                        ");
#else
    __asm__ __volatile__("\
                        .global pre_instruction_start \n\
                        pre_instruction_start: \n\
                        pushfl \n\
                        orl $0x0100,(%esp) \n\
                        popfl \n\
                        .global pre_instruction_end \n\
                        pre_instruction_end: \n\
                        ");
#endif
}

void inject(int ins_size)
{
    int i;
    int pre_instruction_len = ((uintptr_t)&pre_instruction_end - (uintptr_t)&pre_instruction_start);
    ins_start = aligned_buffer + PAGE_SIZE - ins_size - pre_instruction_len;
    for (i = 0; i < pre_instruction_len; i++)
    {
        ins_start[i] = ((char *)&pre_instruction_start)[i];
    }

    for (i = 0; i < MAX_INS_LENGTH; i++)
    {
        (ins_start + pre_instruction_len)[i] = inj.ins.bytes[i];
    }

    configure_handler(state_handler);
    __asm__ __volatile__("ud2\n");

    configure_handler(fault_handler);

//clear regs and jmp
#if __x86_64__
    __asm__ __volatile__("\
                        mov $0, %%rax \n\
                        mov $0, %%rbx \n\
                        mov $0, %%rcx \n\
                        mov $0, %%rdx \n\
                        mov $0, %%rsi \n\
                        mov $0, %%rdi \n\
                        mov $0, %%r8 \n\
                        mov $0, %%r9 \n\
                        mov $0, %%r10 \n\
                        mov $0, %%r11 \n\
                        mov $0, %%r12 \n\
                        mov $0, %%r13 \n\
                        mov $0, %%r14 \n\
                        mov $0, %%r15 \n\
                        mov $0, %%rbp \n\
                        mov %[rsp], %%rsp \n\
                        jmp *%[ins] \n\
                        "
                         :
                         :
                         [rsp] "i"(&dummy_stack),
                         [ins] "m"(ins_start));
#else
    ff __asm__ __volatile__("\
                        mov $0, %%eax \n\
                        mov $0, %%ebx \n\
                        mov $0, %%ecx \n\
                        mov $0, %%edx \n\
                        mov $0, %%esi \n\
                        mov $0, %%edi \n\
                        mov $0, %%ebp \n\
                        mov %[esp], %%esp \n\
                        jmp *%[ins] \n\
                        "
                            :
                            :
                            [esp] "i"(&dummy_stack),
                            [ins] "m"(ins_start));
#endif

    __asm__ __volatile__("\
                        .global resume\n\
                        resume:\n\
                        ");
}

bool move_next_instruction()
{
    if (result.length == 0)
        return true;
    if (result.length - 1 > inj.index && inj.last_len != result.length)
    {
        inj.index = result.length - 1;
    }

    if (inj.ins.bytes[0] == 0xff & inj.index == 0)
        return false;

    inj.ins.bytes[inj.index]++;

    while (inj.ins.bytes[inj.index] == 0)
    {
        inj.index--;
        inj.ins.bytes[inj.index]++;
    }

    return true;
}

void print_instruction()
{
    printf("0x");
    for (int i = 0; i < result.length; i++)
    {
        printf("%02x", inj.ins.bytes[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    int i;
    void *unaligned_buffer;

    unaligned_buffer = malloc(PAGE_SIZE * 3);
    aligned_buffer = (void *)(((uintptr_t)unaligned_buffer + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1)); //align the buffer on page

    //setup pages access protections
    assert(!mprotect(aligned_buffer, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    assert(!mprotect(aligned_buffer + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE));

    while (move_next_instruction())
    {
        for (i = 1; i < MAX_INS_LENGTH; i++)
        {
            inject(i);

            if (result.addr != (uint32_t)(uintptr_t)(aligned_buffer + PAGE_SIZE)) //the fault was not due to the instruction being on the border
            {
                break;
            }
        }
        inj.last_len = result.length;
        result.length = i;
        print_instruction();
        //do something with the result
    }

    return 0;
}
