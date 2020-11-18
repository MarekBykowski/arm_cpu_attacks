GCC=aarch64-axxia-linux-gcc
AR=aarch64-axxia-linux-gcc-ar

CFLAGS=-ggdb -std=gnu99 -O2 -pthread -Wall -MD
#--save-temps 

#if applying mitigiation add MITIGATE towards the end of COMPILE
#MITIGATE=-DAPPLY_COUNTERPART

COMPILE=$(GCC) --sysroot=/tools/AGRreleases/yocto/morty/axxia_gen2_04apr2018/axxia-arm64-xlf/tools/sysroots/aarch64-axxia-linux $(CFLAGS) $(MITIGATE) 

all: dump_sys_regs

dump_sys_regs: dump_sys_regs.c sregs.S
	$(COMPILE) dump_sys_regs.c sregs.S -o dump_sys_regs

clean:
	rm -rf *.o *.s *.i dump_sys_regs 
