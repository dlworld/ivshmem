#
# file : Makefile
# desc : Build linux device driver and userspace sources for
#         test with the QEMU ivshmem PCI device
#

usr = ne_ivshmem_shm_guest_usr
krn = ne_ivshmem_ldd_basic

ifneq ($(KERNELRELEASE),)

obj-m := $(krn).o

else

KDIR ?= /lib/modules/$$(uname -r)/build

default:
        $(MAKE) -C $(KDIR) M=$$PWD modules
        $(CC) -Wall -O2 $(usr).c -o $(usr)

clean:
        $(MAKE) -C $(KDIR) M=$$PWD clean
        rm -f $(usr)

.PHONY : clean
endif
