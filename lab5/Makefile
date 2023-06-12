
obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB
root = ..
# all: kshram
# 	make -C ../dist/modulebuild M=$(PWD) modules

all: test
	make -C ../dist/modulebuild M=$(PWD) modules

test: test.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
# rm -f kshram
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
# cp kshram kshram.ko ../rootfs/modules
	cp test kshram.ko ../rootfs/modules
.PHONY: run

run : 
	
	$(shell sh run.sh)
	
	
# $(shell make zip)
# cd rootfs


#解壓縮
# unzip :

# 	bunzip2 -v rootfs.cpio.bz2
# 	cpio -idmv < rootfs.cpio   

#壓縮
# find .|cpio -o -H newc >rootfs.cpio
# tar -jcvf rootfs.cpio.bz2 rootfs.cpio 

# zip:
# 	find .| cpio -H newc -o|bzip2 >../dist/rootfs.cpio.bz2

# insmod ： 掛載 module
# lsmod ： 檢查目前 module 的狀態
# rmmod ：卸載 module
	
