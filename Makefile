CC=aarch64-linux-gnu-gcc
AR=aarch64-linux-gnu-gcc-ar
CFLAGS=-ggdb -std=gnu99 -O2 -pthread -Wall --save-temps
COMPILE=$(CC) $(CFLAGS)

dump_sys_regs: dump_sys_regs.c sregs.S
	$(COMPILE) dump_sys_regs.c sregs.S -o dump_sys_regs

clean:
	rm -rf *.o *.s *.i dump_sys_regs
