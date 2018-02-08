CC=aarch64-poky-linux-gcc
AR=aarch64-poky-linux-gcc-ar
CFLAGS=-ggdb -std=gnu99 -O2 -pthread -Wall --save-temps
COMPILE=$(CC) --sysroot=/tools/AGRreleases/yocto/jethro_11Jul2016/axxia-arm64-x9/tools/sysroots/aarch64-poky-linux $(CFLAGS)

dump_sys_regs: dump_sys_regs.c sregs.S
	$(COMPILE) dump_sys_regs.c sregs.S -o dump_sys_regs

clean:
	rm -rf *.o *.s *.i dump_sys_regs
