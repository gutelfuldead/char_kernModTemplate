obj-m += template-driver.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
		gcc user.c -o test

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
		rm -f test
