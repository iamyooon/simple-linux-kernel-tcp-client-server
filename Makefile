obj-m += network_client.o
obj-m += network_server.o

ARCH		?= arm64
CROSS_COMPILE	?= aarch64-linux-gnu-
KERNEL_DIR	?= /home3/iamyooon/work/800.project/hpc_gdev_202x/src/kernel
PWD		?= $(shell pwd)

#echo "ARCH=$(ARCH)"
#echo "CROSS_COMPILE=$(CROSS_COMPILE)"
#echo "KERNEL_DIR= $(KERNEL_DIR)"
#echo "PWD=$(PWD)"

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

