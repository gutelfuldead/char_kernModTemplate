obj-m += template-driver.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
		gcc template-test.c -o template-test

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
		rm -f template-test
