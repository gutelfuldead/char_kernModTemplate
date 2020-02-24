// SPDX-License-Identifier: GPL-2.0
/*
 * Template Character Driver for generic AXI4 IP Core
 *
 * Copyright (C) 2018 Jason Gutel
 *
 * Authors: Jason Gutel <jason.gutel@gmail.com>
 *
 */

/* ----------------------------
 *           includes
 * ----------------------------
 */
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/spinlock_types.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/param.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>

#include "template-driver.h"

/* ----------------------------
 *       driver parameters
 * ----------------------------
 */
#define DRIVER_NAME "templateDriver"
#define READ_BUF_SIZE 128U /* read buffer length in words */
#define WRITE_BUF_SIZE 128U /* write buffer length in words */

/* ----------------------------
 * Bit Ops
 * ----------------------------
 */
#define set_bit(bitNumber, dataValue) ((dataValue) |= (0x1 << (bitNumber)))
#define clear_bit(bitNumber, dataValue) ((dataValue) &= ~(0x1 << (bitNumber)))
#define flip_bit(bitNumber, dataValue)  ((dataValue) ^= (0x1 << (bitNumber)))
#define to_bool(x) (!(!(x)))
#define is_set(bitNumber, dataValue) to_bool((0x1 << (bitNumber)) & (dataValue))
#define is_clear(bitNumber, dataValue) (!is_set((bitNumber), (dataValue)))
#define assn_bit(bitNumber, dataValue, bitValue) ((bitValue) ? set_bit(bitNumber, dataValue) : clear_bit(bitNumber, dataValue))
#define read_mask(reg, mask, bitOffset, out) (out = (reg >> bitOffset) & mask)
#define set_mask(reg, reg_mask, bit_offset, write_val, out) do {\
	out = reg; \
	out &= ~(reg_mask << bit_offset); \
	out |= ((write_val & reg_mask) << bit_offset); \
	} while (0);

/* ----------------------------
 *           globals
 * ----------------------------
 */
static struct class *template_class; /* char device class */

/* ----------------------------
 *            types
 * ----------------------------
 */

struct template_driver {
	int irq; /* interrupt */
	struct resource *mem; /* physical memory */
	void __iomem *base_addr; /* kernel space memory */

	unsigned int template_dts_entry; /* example dts entry */

	uint32_t fpga_addr;
	struct device *dt_device; /* device created from the device tree */
	struct device *device; /* device associated with char_device */
	dev_t devt; /* our char device number */
	struct cdev char_device; /* our char device */
};

/* ----------------------------
 *   static function protos 
 * ----------------------------
 */
static void reset_ip_core(struct template_driver *template);
static void readModifyWrite(struct template_driver *template, uint32_t regOff, uint32_t value, uint32_t mask, uint32_t bit);

static void readModifyWrite(struct template_driver *template, uint32_t regOff, uint32_t value, uint32_t mask, uint32_t bit)
{
	unsigned int readVal;
	unsigned int outVal;

	readVal = 0;
	outVal  = 0;

	readVal = ioread32(template->base_addr + regOff);
	smi_set_mask(readVal, mask, bit, value, outVal);
	iowrite32(outVal, template->base_addr + regOff);
}

/* ----------------------------
 *         sysfs entries
 * ----------------------------
 */

static ssize_t sysfs_write(struct device *dev, const char *buf,
			   size_t count, unsigned int addr_offset,
               uint32_t mask, uint32_t bitOff)
{
	struct template_driver *template = dev_get_drvdata(dev);
	unsigned long tmp;
	int rc;

	rc = kstrtoul(buf, 0, &tmp);
	if (rc < 0)
		return rc;

	readModifyWrite(template, addr_offset, tmp, mask, bitOff);

	return count;
}

static ssize_t sysfs_read(struct device *dev, char *buf,
			  unsigned int addr_offset, uint32_t mask, uint32_t bitOff)
{
	struct template_driver *template = dev_get_drvdata(dev);
	unsigned int read_val;
	unsigned int len;
	unsigned int outVal;
	char tmp[32];

	read_val = ioread32(template->base_addr + addr_offset);
	read_mask(read_val, mask, bitOff, outVal);
	len =  snprintf(tmp, sizeof(tmp), "0x%x\n", outVal);
	memcpy(buf, tmp, len);

	return len;
}

static ssize_t fpga_addr_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct template_driver *template = dev_get_drvdata(dev);
	char tmp[32];
	unsigned int len;

	len = snprintf(tmp, sizeof(tmp),"0x%x\n", template->fpga_addr);
	memcpy(buf, tmp, len);
	return len;
}
static DEVICE_ATTR_RO(fpga_addr);

static ssize_t reset_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct template_driver *template = dev_get_drvdata(dev);
	reset_ip_core(template);
	return 1; /* return 1 so the "$ echo 1 > reset" command doesn't block */
}
static DEVICE_ATTR_WO(reset);

/*****************************************************************************
 * MODIFY START
 ****************************************************************************/
static ssize_t template_dts_entry_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	return sysfs_write(dev, buf, count, TEMPLATE_DTS_ENTRY_OFFSET, 0xffffffff, 0);
}

static ssize_t template_dts_entry_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	return sysfs_read(dev, buf, TEMPLATE_DTS_ENTRY_OFFSET, 0xffffffff, 0);
}

static DEVICE_ATTR_RW(template_dts_entry);

static struct attribute *template_attrs[] = {
	&dev_attr_fpga_addr.attr,
	&dev_attr_reset.attr,
	&dev_attr_template_dts_entry.attr,
	NULL,
};

/*****************************************************************************
 * MODIFY END
 ****************************************************************************/

static const struct attribute_group template_attrs_group = {
	.name = "ip_registers",
	.attrs = template_attrs,
};

/* ----------------------------
 *        implementation
 * ----------------------------
 */

static void reset_ip_core(struct template_driver *template)
{
	iowrite32(TEMPLATE_RESET_WORD, template->base_addr + TEMPLATE_STATUS_OFFSET);
}

static DEFINE_MUTEX(ioctl_lock);
static long template_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	long rc;
	void *__user arg_ptr;
	uint32_t temp_reg;
	struct template_kern_regInfo regInfo;
	struct template_driver *template = (struct template_driver *)f->private_data;

	if (mutex_lock_interruptible(&ioctl_lock))
		return -EINTR;

	// Coerce the arguement as a userspace pointer
	arg_ptr = (void __user *)arg;
	temp_reg = 0;

	// Verify that this IOCTL is intended for our device, and is in range
	if (_IOC_TYPE(cmd) != TEMPLATE_IOCTL_MAGIC) {
		dev_err(template->dt_device, "IOCTL command magic number does not match.\n");
		return -ENOTTY;
	} else if (_IOC_NR(cmd) >= TEMPLATE_NUM_IOCTLS) {
		dev_err(template->dt_device, "IOCTL command is out of range for this device.\n");
		return -ENOTTY;
	}

	// Perform the specified command
	switch (cmd) {
	case TEMPLATE_GET_REG:
		if (copy_from_user(&regInfo, arg_ptr, sizeof(regInfo))) {
			dev_err(template->dt_device, "unable to copy status reg to userspace\n");
			return -EFAULT;
		}
		regInfo.regVal = ioread32(template->base_addr + regInfo.regNo*4);
		if (copy_to_user(arg_ptr, &regInfo, sizeof(regInfo))) {
			dev_err(template->dt_device, "unable to copy status reg to userspace\n");
			return -EFAULT;
		}
		rc = 0;
		break;

        case TEMPLATE_SET_REG:
		if (copy_from_user(&regInfo, arg_ptr, sizeof(regInfo))) {
			dev_err(template->dt_device, "unable to copy status reg to userspace\n");
			return -EFAULT;
		}
		iowrite32(regInfo.regVal, template->base_addr + regInfo.regNo*4);
		rc = 0;
		break;

        case TEMPLATE_GET_FPGA_ADDR:
		temp_reg = template->fpga_addr;
		if (copy_to_user(arg_ptr, &temp_reg, sizeof(temp_reg))) {
			dev_err(template->dt_device, "unable to copy status reg to userspace\n");
			return -EFAULT;
		}
		rc = 0;
		break;

	case TEMPLATE_RESET_IP:
		reset_ip_core(template);
		break;

        case TEMPLATE_GET_DTS_VAL0:
		temp_reg = ioread32(template->base_addr + TEMPLATE_DTS_ENTRY_OFFSET);
		smi_read_mask(temp_reg, TEMPLATE_DTS_VAL0_MASK, TEMPLATE_DTS_VAL0_BIT, temp_reg_out);
		if (copy_to_user(arg_ptr, &temp_reg_out, sizeof(temp_reg_out))) {
			dev_err(template->dt_device, "unable to copy status reg to userspace\n");
			return -EFAULT;
		}
		rc = 0;
		break;

        case TEMPLATE_SET_DTS_VAL0:
		if (copy_from_user(&temp_reg, arg_ptr, sizeof(temp_reg))) {
			dev_err(template->dt_device, "unable to copy status reg to userspace\n");
			return -EFAULT;
		}
		readModifyWrite(template, TEMPLATE_DTS_ENTRY_OFFSET, temp_reg, TEMPLATE_DTS_VAL0_MASK, TEMPLATE_DTS_VAL0_BIT);
		rc = 0;
		break;

	default:
		return -ENOTTY;
	}

	mutex_unlock(&ioctl_lock);
	return rc;
}

static int template_close(struct inode *inod, struct file *f)
{
	f->private_data = NULL;
	return 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = template_open,
	.release = template_close,
	.unlocked_ioctl = template_ioctl
};

/* read named property from the device tree */
static int get_dts_property(struct template_driver *template,
			    char *name, unsigned int *var)
{
	int rc;

	rc = of_property_read_u32(template->dt_device->of_node, name, var);
	if (rc) {
		dev_err(template->dt_device, "couldn't read IP dts property '%s'",
			name);
		return rc;
	}
	dev_dbg(template->dt_device, "dts property '%s' = %u\n",
		name, *var);

	return 0;
}

static int template_probe(struct platform_device *pdev)
{
	struct resource *r_mem; /* IO mem resources */
	struct device *dev = &pdev->dev; /* OS device (from device tree) */
	struct template_driver *template = NULL;

	char device_name[64];

	int rc = 0; /* error return value */

	/* IP properties from device tree */
	unsigned int temp;

	/* ----------------------------
	 *     init wrapper device
	 * ----------------------------
	 */

	/* allocate device wrapper memory */
	template = devm_kmalloc(dev, sizeof(*template), GFP_KERNEL);
	if (!template)
		return -ENOMEM;

	dev_set_drvdata(dev, template);
	template->dt_device = dev;

	init_waitqueue_head(&template->read_queue);
	init_waitqueue_head(&template->write_queue);

	spin_lock_init(&template->read_queue_lock);
	spin_lock_init(&template->write_queue_lock);

	/* ----------------------------
	 *   init device memory space
	 * ----------------------------
	 */
	/* get iospace for the device */
	r_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r_mem) {
		dev_err(template->dt_device, "invalid address\n");
		rc = -ENODEV;
		goto err_initial;
	}

	template->mem = r_mem;

	/* request physical memory */
	if (!request_mem_region(template->mem->start, resource_size(template->mem),
				DRIVER_NAME)) {
		dev_err(template->dt_device,
			"couldn't lock memory region at 0x%pa\n",
			&template->mem->start);
		rc = -EBUSY;
		goto err_initial;
	}
	dev_dbg(template->dt_device, "got memory location [0x%pa - 0x%pa]\n",
		&template->mem->start, &template->mem->end);
	template->fpga_addr = template->mem->start;

	/* map physical memory to kernel virtual address space */
	template->base_addr = ioremap(template->mem->start, resource_size(template->mem));
	if (!template->base_addr) {
		dev_err(template->dt_device, "couldn't map physical memory\n");
		rc = -ENOMEM;
		goto err_mem;
	}
	dev_dbg(template->dt_device, "remapped memory to 0x%p\n", template->base_addr);

	/* ----------------------------
	 *          init IP
	 * ----------------------------
	 */
	/*****************************************************************************
	* MODIFY START
	****************************************************************************/
	/* retrieve device tree properties */
	rc = get_dts_property(template, "usr,template-dts-entry",
			      &temp);
	if (rc)
		goto err_unmap;

	/* check validity of device tree properties */
	if (temp > 64) { /* some error condition */
		dev_err(template->dt_device,
			"template-dts-entry=[%u] unsupported\n",
			temp);
		rc = -EIO;
		goto err_unmap;
	}
	template->template_dts_entry = temp;

	/*****************************************************************************
	* MODIFY END
	****************************************************************************/
	reset_ip_core(template);

	/* ----------------------------
	 *      init char device
	 * ----------------------------
	 */

	/* allocate device number */
	rc = alloc_chrdev_region(&template->devt, 0, 1, DRIVER_NAME);
	if (rc < 0)
		goto err_unmap;
	dev_dbg(template->dt_device, "allocated device number major %i minor %i\n",
		MAJOR(template->devt), MINOR(template->devt));

	/* create unique device name */
	snprintf(device_name, sizeof(device_name), "%s_%pa",
		 DRIVER_NAME, &template->mem->start);

	dev_dbg(template->dt_device, "device name [%s]\n", device_name);

	/* create driver file */
	template->device = device_create(template_class, NULL, template->devt,
				     NULL, device_name);
	if (IS_ERR(template->device)) {
		dev_err(template->dt_device,
			"couldn't create driver file\n");
		rc = PTR_ERR(template->device);
		goto err_chrdev_region;
	}
	dev_set_drvdata(template->device, template);

	/* create character device */
	cdev_init(&template->char_device, &fops);
	rc = cdev_add(&template->char_device, template->devt, 1);
	if (rc < 0) {
		dev_err(template->dt_device, "couldn't create character device\n");
		goto err_dev;
	}

	/* create sysfs entries */
	rc = sysfs_create_group(&template->device->kobj, &template_attrs_group);
	if (rc < 0) {
		dev_err(template->dt_device, "couldn't register sysfs group\n");
		goto err_cdev;
	}

	dev_info(template->dt_device, DRIVER_NAME " created at %pa mapped to 0x%pa, irq=%i, major=%i, minor=%i\n",
		 &template->mem->start, &template->base_addr, template->irq,
		 MAJOR(template->devt), MINOR(template->devt));

	/* initialize any start-up registers */
	iowrite32(template->template_dts_entry, template->base_addr + TEMPLATE_DTS_ENTRY_OFFSET);
	return 0;

err_cdev:
	cdev_del(&template->char_device);
err_dev:
	device_destroy(template_class, template->devt);
err_chrdev_region:
	unregister_chrdev_region(template->devt, 1);
err_unmap:
	iounmap(template->base_addr);
err_mem:
	release_mem_region(template->mem->start, resource_size(template->mem));
err_initial:
	dev_set_drvdata(dev, NULL);
	return rc;
}

static int template_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct template_driver *template = dev_get_drvdata(dev);

	sysfs_remove_group(&template->device->kobj, &template_attrs_group);
	cdev_del(&template->char_device);
	dev_set_drvdata(template->device, NULL);
	device_destroy(template_class, template->devt);
	unregister_chrdev_region(template->devt, 1);
	iounmap(template->base_addr);
	release_mem_region(template->mem->start, resource_size(template->mem));
	dev_set_drvdata(dev, NULL);
	return 0;
}

static const struct of_device_id template_of_match[] = {
	{ .compatible = "usr,template-core", },
	{},
};
MODULE_DEVICE_TABLE(of, template_of_match);

static struct platform_driver template_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table	= template_of_match,
	},
	.probe		= template_probe,
	.remove		= template_remove,
};

static int __init template_init(void)
{
	template_class = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(template_class))
		return PTR_ERR(template_class);
	return platform_driver_register(&template_driver);
}
module_init(template_init);

static void __exit template_exit(void)
{
	platform_driver_unregister(&template_driver);
	class_destroy(template_class);
}
module_exit(template_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jason Gutel jason.gutel@gmail.com>");
MODULE_DESCRIPTION("Template AXI4 Character Driver");
