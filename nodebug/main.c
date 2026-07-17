#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Rust scanner: continuously scans [start, end) for 0xCC (int3) */
extern long scan_loop(const char *start, const char *end, int interval_ms);
extern long scan(const char *start, const char *end);

/* ================================================================
 * Encrypted flag: HCTF{you_c4n7_br34k_m3}  (23 bytes)
 *
 * Encryption: XOR with rolling key [0xDE, 0xAD, 0xBE] (indices mod 3)
 * ================================================================ */

static unsigned char chunk1[8] = {
    0x96, 0xEE, 0xEA, 0x98, 0xD6, 0xC7, 0xB1, 0xD8
};

static unsigned char chunk2[8] = {
    0xE1, 0xAD, 0x79, 0xD0, 0xE9, 0xF2, 0xDC, 0xAC
};

static unsigned char chunk3[7] = {
    0x9E, 0x8A, 0xB5, 0xF2, 0xD3, 0xED, 0xD0
};

/* Key material — only first 3 bytes form the rolling XOR key;
   byte 0xEF is a red herring (DEADBEEF) */
static const unsigned char keybox[] = {
    0xDE, 0xAD, 0xBE, 0xEF
};

/* ----------------------------------------------------------------
 * Opaque predicates & control-flow obfuscation
 *
 * These macros inject x86-64 assembly that:
 *  - Perform arithmetic that always produces a known result
 *  - Use indirect jumps via computed addresses
 *  - Insert dead-code paths that static analysis cannot resolve
 *  - Consume RDTSC to pollute timing-based analysis
 * ---------------------------------------------------------------- */

#define OPAQUE_TRUE(name)                                   \
    do {                                                    \
        unsigned long _p;                                   \
        __asm__ volatile (                                  \
            "rdtsc\n\t"                                     \
            "shl $32, %%rdx\n\t"                            \
            "or %%rdx, %%rax\n\t"                           \
            "mov %%rax, %0\n\t"                             \
            "imul $0x41C64E6D, %0, %%rax\n\t"              \
            "add $0x3039, %%rax\n\t"                        \
            "and $1, %%rax\n\t"                             \
            "mov %%rax, %0\n\t"                             \
            : "=r"(_p) : : "rax", "rdx", "cc"              \
        );                                                  \
        if (_p) {                                           \
            __asm__ volatile ("nop\n\t" ::: "memory");      \
        } else {                                            \
            __asm__ volatile ("nop\n\t" ::: "memory");      \
        }                                                   \
    } while (0)

/* Indirect jump obfuscation: compute a target address and
   use it to confuse disassemblers / control-flow graphs */
#define JUMP_OBFUSCATE(label)                               \
    do {                                                    \
        unsigned long _jmp;                                 \
        __asm__ volatile (                                  \
            "lea %1(%%rip), %0\n\t"                         \
            : "=r"(_jmp) : "m"(label) : "memory"            \
        );                                                  \
        __asm__ volatile (                                  \
            "push %0\n\t"                                   \
            "ret\n\t"                                       \
            : : "r"(_jmp) : "memory"                        \
        );                                                  \
    } while (0)

/* Dead-code path: condition is always false, but compilers and
   static analysis tools cannot prove it at compile time.
   Uses numbered local labels (1f/1b) for reliable forward refs. */
#define DEAD_BRANCH(var)                                    \
    do {                                                    \
        unsigned long _v = (unsigned long)(var);             \
        __asm__ volatile (                                  \
            "bt $0, %0\n\t"                                 \
            "jc 1f\n\t"                                     \
            "1:\n\t"                                        \
            : "+r"(_v) : : "cc"                             \
        );                                                  \
    } while (0)

/* ----------------------------------------------------------------
 * Anti-debug guard functions with heavy asm obfuscation
 *
 * Each guard:
 *  1. Reads RDTSC (anti-timing-analysis)
 *  2. Evaluates opaque predicates (confuses CFG)
 *  3. Calls scan() on its own code region
 *  4. Uses indirect jumps (confuses disassemblers)
 *  5. Scans a WIDER region to catch breakpoints on nearby code
 * ---------------------------------------------------------------- */

/* Forward declarations */
static int guard_a(void);
static int guard_b(void);
static int guard_c(void);

__attribute__((noinline))
static int guard_a(void) {
    volatile unsigned long tsc_start, tsc_end;

    /* Read RDTSC — anti-timing: if single-stepping, gap will be huge */
    __asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                     : "=r"(tsc_start) : : "rax", "rdx");

    OPAQUE_TRUE(guard_a);

    /* Scan own code for int3 breakpoints */
    long r = scan((const char *)guard_a, (const char *)guard_b);

    /* Opaque predicate: (r+1)*(r+1) >= 0 is always true for integers,
       but static analysis cannot resolve this easily */
    volatile long _tmp = r + 1;
    __asm__ volatile (
        "imul %0, %0\n\t"
        "shr $63, %0\n\t"
        : "+r"(_tmp) : : "cc"
    );

    DEAD_BRANCH(r);

    /* Read RDTSC again — detect single-stepping via timing gap */
    __asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                     : "=r"(tsc_end) : : "rax", "rdx");

    /* If gap > 1000000 cycles, likely being traced */
    if (tsc_end - tsc_start > 1000000) {
        return -3;
    }

    return (int)r;
}

__attribute__((noinline))
static int guard_b(void) {
    volatile unsigned long tsc_start, tsc_end;

    __asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                     : "=r"(tsc_start) : : "rax", "rdx");

    OPAQUE_TRUE(guard_b);

    long r = scan((const char *)guard_b, (const char *)guard_c);

    /* Opaque predicate: compute x*(x-1), bit 0 is always 0 (product of
       consecutive integers is always even) — jump over nop if so */
    volatile long _ck = r;
    __asm__ volatile (
        "mov %0, %%rax\n\t"
        "dec %%rax\n\t"
        "imul %%rax, %%rax\n\t"
        "bt $0, %%rax\n\t"  /* CF = 0 always */
        "jnc 1f\n\t"
        "1:\n\t"
        : "+r"(_ck) : : "rax", "cc"
    );

    DEAD_BRANCH(r);

    __asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                     : "=r"(tsc_end) : : "rax", "rdx");

    if (tsc_end - tsc_start > 1000000) {
        return -3;
    }

    return (int)r;
}

__attribute__((noinline))
static int guard_c(void) {
    volatile unsigned long tsc_start, tsc_end;

    __asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                     : "=r"(tsc_start) : : "rax", "rdx");

    OPAQUE_TRUE(guard_c);

    long r = scan((const char *)guard_c, (const char *)guard_c + 1024);

    /* Opaque predicate using XOR properties: x ^ x == 0 always */
    volatile long _v = r;
    __asm__ volatile (
        "mov %0, %%rax\n\t"
        "xor %%rax, %%rax\n\t"  /* rax = 0 always */
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"            /* never taken */
        "1:\n\t"
        : "+r"(_v) : : "rax", "cc"
    );

    DEAD_BRANCH(r);

    __asm__ volatile ("rdtsc\n\tshl $32,%%rdx\n\tor %%rdx,%%rax\n\tmov %%rax,%0"
                     : "=r"(tsc_end) : : "rax", "rdx");

    if (tsc_end - tsc_start > 1000000) {
        return -3;
    }

    return (int)r;
}

/* ----------------------------------------------------------------
 * Decryption stages with asm obfuscation
 * ---------------------------------------------------------------- */

__attribute__((noinline))
static void stage_1(void) {
    int g = guard_a();

    /* Opaque: g is always < 0 when clean, so this xor-path is dead code */
    __asm__ volatile (
        "test %0, %0\n\t"
        "jns 1f\n\t"
        "jmp 2f\n\t"
        "1:\n\t"
        "2:\n\t"
        : "+r"(g) : : "cc"
    );

    if (g >= 0) {
        /* Breakpoint detected — corrupt data and bail */
        memset(chunk1, 'X', sizeof(chunk1));
        _exit(1);
    }

    for (int i = 0; i < 8; i++) {
        /* Inline the XOR with opaque wrapping */
        unsigned char k = keybox[i % 3];
        __asm__ volatile (
            "xor %1, %0\n\t"
            : "+r"(chunk1[i]) : "r"(k) : "cc"
        );
    }
}

__attribute__((noinline))
static void stage_2(void) {
    int g = guard_b();

    __asm__ volatile (
        "bt $0, %0\n\t"
        "jnc 1f\n\t"
        "1:\n\t"
        : "+r"(g) : : "cc"
    );

    if (g >= 0) {
        memset(chunk2, 'X', sizeof(chunk2));
        _exit(1);
    }

    for (int i = 0; i < 8; i++) {
        unsigned char k = keybox[(8 + i) % 3];
        __asm__ volatile (
            "xor %1, %0\n\t"
            : "+r"(chunk2[i]) : "r"(k) : "cc"
        );
    }
}

__attribute__((noinline))
static void stage_3(void) {
    int g = guard_c();

    /* Opaque: multiply by zero */
    volatile long _z = 0;
    __asm__ volatile (
        "imul $42, %0, %%rax\n\t"
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"
        "1:\n\t"
        : "+r"(_z) : : "rax", "cc"
    );

    if (g >= 0) {
        memset(chunk3, 'X', sizeof(chunk3));
        _exit(1);
    }

    for (int i = 0; i < 7; i++) {
        unsigned char k = keybox[(16 + i) % 3];
        __asm__ volatile (
            "xor %1, %0\n\t"
            : "+r"(chunk3[i]) : "r"(k) : "cc"
        );
    }
}

/* ----------------------------------------------------------------
 * Integrity check with asm obfuscation
 * ---------------------------------------------------------------- */

__attribute__((noinline))
static unsigned char checksum(void) {
    unsigned char h = 0x0F;
    unsigned char buf[23];
    memcpy(buf,     chunk1, 8);
    memcpy(buf + 8, chunk2, 8);
    memcpy(buf + 16, chunk3, 7);

    for (int i = 0; i < 23; i++) {
        __asm__ volatile (
            "xor %1, %0\n\t"
            : "+r"(h) : "r"(buf[i]) : "cc"
        );
    }

    /* Opaque: h is always in [0,255], so this branch is dead */
    __asm__ volatile (
        "cmp $0xFF, %0\n\t"
        "ja 1f\n\t"
        "1:\n\t"
        : "+r"(h) : : "cc"
    );

    return h;
}

/* ----------------------------------------------------------------
 * Main with indirect-jump obfuscation
 * ---------------------------------------------------------------- */

int main(void) {
    printf("[*] initializing...\n");

    /* Use a function pointer table to obscure the call graph */
    typedef void (*stage_fn)(void);
    stage_fn stages[3] = { stage_1, stage_2, stage_3 };

    for (int i = 0; i < 3; i++) {
        /* Indirect call through pointer — confuses simple CFG recovery */
        __asm__ volatile (
            "call *%0\n\t"
            : : "r"(stages[i]) : "memory"
        );
    }

    /* Verify prefix/suffix */
    if (chunk1[0] != 'H' || chunk1[1] != 'C' || chunk1[4] != '{') {
        puts("[-] wrong");
        return 1;
    }
    if (chunk3[6] != '}') {
        puts("[-] wrong");
        return 1;
    }

    unsigned char h = checksum();
    if (h != 0x00) {
        printf("[-] checksum failed (got 0x%02x)\n", h);
        printf("[-] chunk1: ", h);
        for (int i = 0; i < 8; i++) printf("%02x ", chunk1[i]);
        printf("\n[-] chunk2: ");
        for (int i = 0; i < 8; i++) printf("%02x ", chunk2[i]);
        printf("\n[-] chunk3: ");
        for (int i = 0; i < 7; i++) printf("%02x ", chunk3[i]);
        printf("\n");
        return 1;
    }

    printf("[+] Flag: %.8s%.8s%.7s\n", chunk1, chunk2, chunk3);
    return 0;
}
