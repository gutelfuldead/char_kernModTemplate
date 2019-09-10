===========================================
Character Driver /dev Kernel Module Example 
===========================================

This driver allows controlling of the ip core through,

1. devicetree
2. /sys/device/virtual
3. ioctls
4. read/write
5. poll

The driver will be mounted as ::

        /dev/templateDriver_0x<fpga mmap address>

Control through /sys/device/virtual
===================================

User can read and write registers and bit fields through the virtual sysfs
directory. For example ::

        $ pwd
        /sys/devices/virtual/templateDriver/templateDriver_0x43c00000/ip_registers
        $ ls -la
        total 0
        drwxr-xr-x    2 root     root             0 Jan  1 00:14 .
        drwxr-xr-x    4 root     root             0 Jan  1 00:00 ..
        -r--r--r--    1 root     root          4096 Jan  1 00:14 fpga_addr
        --w-------    1 root     root          4096 Jan  1 00:14 reset
        -rw-r--r--    1 root     root          4096 Jan  1 00:14 template_dts_entry
        $ cat fpga_addr
        0x43c00000
        $ echo 1 > reset

ioctl commands
==============

All ioctl commands can be viewed in ``template-driver.h``. Example code for
using the ioctls can be seen in ``apps/template-test.c``.


Device Tree Doc
===============

Template Driver Device Tree Doc

Required properties:
- compatible: Should be "usr,template-core"
- interrupt-names: Should be "interrupt"
- interrupt-parent: Should be <&intc>
- interrupts: Should contain interrupts lines.
- reg: Should contain registers location and length.
- usr,template-dts-entry: used to test grabbing data from devicetree in kmod

Example::

        template-core0: template-core@43c00000 {
                compatible = "usr,template-core";
                interrupt-names = "interrupt";
                interrupt-parent = <&intc>;
                interrupts = <0 29 4>;
                reg = <0x43c00000 0x10000>;
                usr,template-dts-entry = <400>;
        };
