===========================================
Character Driver /dev Kernel Module Example 
===========================================

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
