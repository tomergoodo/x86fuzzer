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
#include <pthread.h>
#include <capstone/capstone.h>

#define PAGE_SIZE 4096
#define MAX_INS_LENGTH 15
#define MAX_OPCODE_LENGTH 3

#if __x86_64__
#define IP REG_RIP
#else
#define IP REG_EIP
#endif

#define TF 0x0100

#if __x86_64__
#define CS_MODE CS_MODE_64
#else
#define CS_MODE CS_MODE_32
#endif

typedef enum
{
    TEXT,
    RAW
} output_t;

struct
{
    bool allow_dup_prefix;
    int max_prefix;
    output_t out;
} config = {
    .allow_dup_prefix = false,
    .max_prefix = 1,
    .out = RAW,
};

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
inj_t inj = {.ins = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, .length = 0}, .index = 0, .last_len = 0};

typedef struct __attribute__((__packed__))
{
    int length;
    int signum;
    int si_code;
    uint32_t addr;
} result_t;
result_t result = {0, 0, 0, 0};

typedef struct __attribute__((__packed__))
{
    int length;
    int valid;
} disas_ins_t;
disas_ins_t disas;

uint64_t dummy_stack[256] __attribute__((aligned(PAGE_SIZE)));

uint64_t stack[SIGSTKSZ];
stack_t ss = {.ss_sp = stack, .ss_size = SIGSTKSZ};

typedef struct
{
    insn_t ins;
    char *mnemonic;
} blacklisted_ins_t;

#define BLACKLIST_SIZE 6
blacklisted_ins_t opcode_blacklist[BLACKLIST_SIZE] = {
    {.ins = {.bytes = {0x0f, 0x05}, .length = 2}, .mnemonic = "syscall"},
    {.ins = {.bytes = {0x0f, 0x34}, .length = 2}, .mnemonic = "sysenter"},
    {.ins = {.bytes = {0xcd, 0x80}, .length = 2}, .mnemonic = "int 0x80"},
    {.ins = {.bytes = {0x0f, 0xa1}, .length = 2}, .mnemonic = "pop fs"},
    {.ins = {.bytes = {0x0f, 0xb4}, .length = 2}, .mnemonic = "lfs"},
    {.ins = {.bytes = {0x8e}, .length = 1}, .mnemonic = "mov segment"}};

typedef struct
{
    char *prefix;
    char *mnemonic;
} blacklisted_pre_t;

blacklisted_pre_t prefix_blacklist[] = {
    {"\x64", "fs"}, //can't be fucked
    {NULL, NULL}};

csh capstone_handle;
cs_insn *capstone_insn;
int expected_length;

pthread_mutex_t *output_mutex = NULL;

#define LINE_BUFFER_SIZE 256
#define BUFFER_LINES 16
#define SYNC_LINES_STDOUT BUFFER_LINES
#define SYNC_LINES_STDERR BUFFER_LINES
char stdout_buffer[LINE_BUFFER_SIZE * BUFFER_LINES];
char *stdout_buffer_end = stdout_buffer;
int stdout_sync_counter = 0;
char stderr_buffer[LINE_BUFFER_SIZE * BUFFER_LINES];
char *stderr_buffer_end = stderr_buffer;
int stderr_sync_counter = 0;

bool is_prefix(uint8_t);







void sync_fprintf(FILE *f, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (f == stdout)
        stdout_buffer_end += vsprintf(stdout_buffer_end, format, args);
    else if (f == stderr)
        stderr_buffer_end += vsprintf(stderr_buffer_end, format, args);
    else
        assert(0);
    va_end(args);
}

void sync_fwrite(const void *ptr, size_t size, size_t count, FILE *f)
{
    if (f == stdout)
    {
        memcpy(stdout_buffer_end, ptr, size * count);
        stdout_buffer_end += size * count;
    }
    else if (f == stderr)
    {
        memcpy(stderr_buffer_end, ptr, size * count);
        stderr_buffer_end += size * count;
    }
    else
        assert(0);
}

void sync_fflush(FILE *f, bool force)
{
    if (f == stdout)
    {
        stdout_sync_counter++;
        if (stdout_sync_counter == SYNC_LINES_STDOUT || force)
        {
            pthread_mutex_lock(output_mutex);

            fwrite(stdout_buffer, stdout_buffer_end - stdout_buffer, 1, f);
            fflush(f);

            pthread_mutex_unlock(output_mutex);
            stdout_buffer_end = stdout_buffer;
            stdout_sync_counter = 0;
        }
    }
    else if (f == stderr)
    {
        stderr_sync_counter++;
        if (stderr_sync_counter == SYNC_LINES_STDERR || force)
        {
            pthread_mutex_lock(output_mutex);

            fwrite(stderr_buffer, stderr_buffer_end - stderr_buffer, 1, f);
            fflush(f);

            pthread_mutex_unlock(output_mutex);
            stderr_buffer_end = stderr_buffer;
            stderr_sync_counter = 0;
        }
    }
    else
        assert(0);
}

void state_handler(int signum, siginfo_t *si, void *p)
{
    fault_context = ((ucontext_t *)p)->uc_mcontext; //store known good values
    ((ucontext_t *)p)->uc_mcontext.gregs[IP] += 2;
}

void fault_handler(int signum, siginfo_t *si, void *p)
{
    ucontext_t *context = (ucontext_t *)p;

    result.signum = signum;
    result.si_code = si->si_code;
    result.addr = signum == SIGSEGV || signum == SIGBUS ? (uintptr_t)si->si_addr : -1;

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
    __asm__ __volatile__("\
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

bool blacklisted()
{
    for (int i = 0; i < BLACKLIST_SIZE; i++)
    {
        int j;
        for (j = 0; j < MAX_INS_LENGTH - opcode_blacklist[i].ins.length && is_prefix(inj.ins.bytes[j]); j++)
            ;

        if (!memcmp(inj.ins.bytes + j, opcode_blacklist[i].ins.bytes, opcode_blacklist[i].ins.length))
            return true;
    }
    return false;
}

void print_disassemble(insn_t ins)
{
    uint64_t address = (uintptr_t)aligned_buffer;
    uint8_t *code = ins.bytes;
    size_t code_size = MAX_INS_LENGTH;
    if (cs_disasm_iter(capstone_handle, (const uint8_t **)&code, &code_size, &address, capstone_insn))
    {
        expected_length = (int)(address - (uintptr_t)aligned_buffer);
        sync_fprintf(stdout, "\t%s %-45s (%02d)", capstone_insn->mnemonic, capstone_insn->op_str, expected_length);
    }
    else
    {
        expected_length = (int)(address - (uintptr_t)aligned_buffer);
        sync_fprintf(stdout, "\t%s %-45s (%02d)", "Unknown", "", expected_length);
    }
}

void print_result(insn_t ins)
{
    uint64_t address = (uintptr_t)aligned_buffer;
    uint8_t *code = ins.bytes;
    size_t code_size = MAX_INS_LENGTH;
    switch (config.out)
    {
    case TEXT:
        cs_disasm_iter(capstone_handle, (const uint8_t **)&code, &code_size, &address, capstone_insn);
        expected_length = (int)(address - (uintptr_t)aligned_buffer);
        sync_fprintf(stdout, " %s", expected_length == result.length ? " " : ".");
        sync_fprintf(stdout, "r: (%02d) ", result.length);
        if (result.signum == SIGILL)
            sync_fprintf(stdout, "sigill ");
        if (result.signum == SIGSEGV)
            sync_fprintf(stdout, "sigsegv");
        if (result.signum == SIGFPE)
            sync_fprintf(stdout, "sigfpe ");
        if (result.signum == SIGBUS)
            sync_fprintf(stdout, "sigbus ");
        if (result.signum == SIGTRAP)
            sync_fprintf(stdout, "sigtrap");
        sync_fprintf(stdout, " %3d ", result.si_code);

        sync_fprintf(stdout, "0x");
        for (int i = 0; i < MAX_INS_LENGTH; i++)
        {
            sync_fprintf(stdout, "%02x", ins.bytes[i]);
        }

        print_disassemble(ins);
        sync_fprintf(stdout, "\n");

        break;
    case RAW:
        if (cs_disasm_iter(capstone_handle, (const uint8_t **)&code, &code_size, &address, capstone_insn))
        {
            disas.length = (int)(address - (uintptr_t)aligned_buffer);
            disas.valid = 1;
        }
        else
        {
            disas.length = 0;
            disas.valid = 0;
        }
        sync_fwrite(&disas, 1, sizeof(disas), stdout);
        sync_fwrite(&result, 1, sizeof(result), stdout);
        sync_fwrite(inj.ins.bytes, 1, MAX_INS_LENGTH, stdout);
        sync_fwrite("\0", 1, 1, stdout); //aligning

        break;

    default:
        assert(0);
    }

    sync_fflush(stdout, false);
}

bool is_prefix(uint8_t x)
{
    return x == 0xf0 ||              //LOCK prefix
           x == 0xf2 ||              //REPNE/REPNZ prefix
           x == 0xf3 ||              //REP or REPE/REPZ prefix
           x == 0x2e ||              //CS segment override
           x == 0x36 ||              //SS segment override
           x == 0x3e ||              //DS segment override
           x == 0x26 ||              //ES segment override
           x == 0x64 ||              //FS segment override
           x == 0x65 ||              //GS segment override
           x == 0x2e ||              //Branch not taken
           x == 0x3e ||              //Branch taken
           x == 0x66 ||              //Operand-size override prefix
           x == 0x67 ||              //Address-size override prefix
           (x >= 0x40 && x <= 0x4f); //REX
}

int count_prefix()
{
    int count = 0;
    for (int i = 0; i < MAX_INS_LENGTH && is_prefix(inj.ins.bytes[i]); i++)
        count++;
    return count;
}

bool has_dup_prefix()
{
    int count[256] = {0};
    for (int i = 0; i < MAX_INS_LENGTH && is_prefix(inj.ins.bytes[i]); i++)
        count[inj.ins.bytes[i]]++;
    for (int i = 0; i < 256; i++)
    {
        if (count[i] > 1)
            return true;
    }
    return false;
}

bool has_prefix(uint8_t *prefix)
{
    bool flag = false;
    for (int i = 0; i < MAX_INS_LENGTH && is_prefix(inj.ins.bytes[i]); i++)
        if (inj.ins.bytes[0] == *prefix)
            flag = true;

    return flag;
}

bool next_instruction()
{
    if (result.length == 0)
        return true;
    if (result.length - 1 > inj.index && inj.last_len != result.length)
    {
        inj.index++;
        //inj.index = result.length - 1;
    }
    inj.last_len = result.length;

    inj.ins.bytes[inj.index]++;

    while (inj.index >= 0 && inj.ins.bytes[inj.index] == 0)
    {
        inj.index--;
        if (inj.index >= 0)
            inj.ins.bytes[inj.index]++;
        inj.last_len--;
    }

    if (blacklisted())
    {
        if (config.out == TEXT)
            print_result(inj.ins);
        return next_instruction();
    }

    int i = 0;
    while (prefix_blacklist[i].prefix)
    {
        if (has_prefix((uint8_t *)prefix_blacklist[i].prefix))
        {
            return next_instruction();
        }
        i++;
    }
    if (count_prefix() > config.max_prefix || (!config.allow_dup_prefix && has_dup_prefix()))
    {
        print_result(inj.ins);
        return next_instruction();
    }

    return inj.index >= 0;
}

int main(int argc, char **argv)
{
    int i;
    void *unaligned_buffer;

    assert(!pthread_mutex_init(output_mutex, NULL));

    unaligned_buffer = malloc(PAGE_SIZE * 3);
    aligned_buffer = (void *)(((uintptr_t)unaligned_buffer + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1)); //align the buffer on page

    //setup pages access protections
    assert(!mprotect(aligned_buffer, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    assert(!mprotect(aligned_buffer + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE));

    if (cs_open(CS_ARCH_X86, CS_MODE, &capstone_handle) != CS_ERR_OK)
        return -1;
    capstone_insn = cs_malloc(capstone_handle);

    while (next_instruction())
    {
        for (i = 1; i < MAX_INS_LENGTH; i++)
        {
            inject(i);

            if (result.addr != (uint32_t)(uintptr_t)(aligned_buffer + PAGE_SIZE)) //the fault was not due to the instruction being on the border
            {
                break;
            }
        }

        result.length = i;
        print_result(inj.ins);
    }

    sync_fflush(stdout, true);
    cs_free(capstone_insn, 1);
    cs_close(&capstone_handle);

    free(unaligned_buffer);

    pthread_mutex_destroy(output_mutex);

    return 0;
}
