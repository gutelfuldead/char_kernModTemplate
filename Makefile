obj-m := template-driver.o

all:
	$(MAKE) -C $(KDIR) SUBDIRS=`pwd` modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=`pwd` clean

modules_install:
	$(MAKE) -C $(KDIR) SUBDIRS=`pwd` modules_install
