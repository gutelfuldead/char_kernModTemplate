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
static int read_timeout = 1000; /* ms to wait before read() times out */
static int write_timeout = 1000; /* ms to wait before write() times out */
static DECLARE_WAIT_QUEUE_HEAD(template_read_wait);
static DECLARE_WAIT_QUEUE_HEAD(template_write_wait);

/* ----------------------------
 * module command-line arguments
 * ----------------------------
 */
module_param(read_timeout, int, 0444);
MODULE_PARM_DESC(read_timeout, "ms to wait before blocking read() timing out; set to -1 for no timeout");
module_param(write_timeout, int, 0444);
MODULE_PARM_DESC(write_timeout, "ms to wait before blocking write() timing out; set to -1 for no timeout");

/* ----------------------------
 *            types
 * ----------------------------
 */

struct template_driver {
	int irq; /* interrupt */
	struct resource *mem; /* physical memory */
	void __iomem *base_addr; /* kernel space memory */

	unsigned int template_dts_entry; /* example dts entry */

	wait_queue_head_t read_queue; /* wait queue for asynchronos read */
	spinlock_t read_queue_lock; /* lock for reading waitqueue */
	wait_queue_head_t write_queue; /* wait queue for asynchronos write */
	spinlock_t write_queue_lock; /* lock for writing waitqueue */
	unsigned int write_flags; /* write file flags */
	unsigned int read_flags; /* read file flags */

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
    return 0;
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

static unsigned int template_poll(struct file *file, poll_table *wait)
{
	unsigned int mask;
	struct template_driver *template = (struct template_driver *)file->private_data;
	unsigned int rdfo;
	unsigned int tdfv;
	mask = 0;

	poll_wait(file, &template_read_wait, wait);
	poll_wait(file, &template_write_wait, wait);

	rdfo = ioread32(template->base_addr + TEMPLATE_STATUS_OFFSET) & TEMPLATE_READ_READY_MASK;
	mask |= POLLIN | POLLRDNORM;

	tdfv = ioread32(template->base_addr + TEMPLATE_STATUS_OFFSET) & TEMPLATE_WRITE_READY_MASK;
	mask |= POLLOUT;

	return mask;
}

static DEFINE_MUTEX(ioctl_lock);
static long template_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    long rc;
    void *__user arg_ptr;
    uint32_t temp_reg;
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
        case TEMPLATE_READ_REG_STATUS:
            temp_reg = ioread32(template->base_addr + TEMPLATE_STATUS_OFFSET);
            if (copy_to_user(arg_ptr, &temp_reg, sizeof(temp_reg))) {
                dev_err(template->dt_device, "unable to copy status reg to userspace\n");
                return -EFAULT;
            }
            rc = 0;
            break;

        case TEMPLATE_WRITE_REG_STATUS:
            if (copy_from_user(&temp_reg, arg_ptr, sizeof(temp_reg))) {
                dev_err(template->dt_device, "unable to copy temp_struct from userspace\n");
                return -EFAULT;
            }
			iowrite32(temp_reg, template->base_addr + TEMPLATE_STATUS_OFFSET);
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

#ifdef TEMPLATE_INTERRUPT_ENABLE
static irqreturn_t template_irq(int irq, void *dw)
{
	struct template_driver *template = (struct template_driver *)dw;
    unsigned int pending_interrupts;

    do {
        pending_interrupts = ioread32(template->base_addr +
                          TEMPLATE_IER_OFFSET) &
                          ioread32(template->base_addr
                          + TEMPLATE_ISR_OFFSET);
        if (pending_interrupts & TEMPLATE_IRQ_EVENTA_MASK) {
            /* do something ... lets say read is ready! wakeup poll */

            /* wake the reader process if it is waiting */
            wake_up(&fifo->read_queue);
            wake_up_interruptible(&template_read_wait);

            /* clear interrupt */
            iowrite32(TEMPLATE_IRQ_EVENTA_MASK & IRQ_ALL_MASK,
                  template->base_addr + TEMPLATE_ISR_OFFSET);
        }
    } while (pending_interrupts);
    return IRQ_HANDLED;
}
#endif

/* reads a single packet from the template as dictated by the tlast signal */
static ssize_t template_read(struct file *f, char __user *buf,
			      size_t len, loff_t *off)
{
	struct template_driver *template = (struct template_driver *)f->private_data;
	size_t bytes_available;
	unsigned int words_available;
        unsigned int leftover;
	unsigned int copied;
	unsigned int copy;
	unsigned int i;
	int ret;
	u32 tmp_buf[READ_BUF_SIZE];

	if (template->read_flags & O_NONBLOCK) {
		/* opened in non-blocking mode
		 * return if there are no packets available
		 */
		if (!(ioread32(template->base_addr + TEMPLATE_STATUS_OFFSET) & TEMPLATE_READ_READY_MASK))
			return -EAGAIN;
	} else {
		/* opened in blocking mode
		 * wait for a packet available interrupt (or timeout)
		 * if nothing is currently available
		 */
		spin_lock_irq(&template->read_queue_lock);
		ret = wait_event_interruptible_lock_irq_timeout(
			template->read_queue,
			(ioread32(template->base_addr + TEMPLATE_STATUS_OFFSET) & TEMPLATE_READ_READY_MASK),
			template->read_queue_lock,
			(read_timeout >= 0) ? msecs_to_jiffies(read_timeout) :
				MAX_SCHEDULE_TIMEOUT);
		spin_unlock_irq(&template->read_queue_lock);
                wake_up_interruptible(&template_read_wait);

		if (ret == 0) {
			/* timeout occurred */
			dev_dbg(template->dt_device, "read timeout");
			return -EAGAIN;
		} else if (ret == -ERESTARTSYS) {
			/* signal received */
			return -ERESTARTSYS;
		} else if (ret < 0) {
			dev_err(template->dt_device, "wait_event_interruptible_timeout() error in read (ret=%i)\n",
				ret);
			return ret;
		}
	}

	bytes_available = ioread32(template->base_addr + TEMPLATE_READ_BYTES_OFFSET);
	if (!bytes_available) {
		dev_err(template->dt_device, "received a packet of length 0 - template core will be reset\n");
		reset_ip_core(template);
		return -EIO;
	}

	words_available = bytes_available/4;

	/* read data into an intermediate buffer, copying the contents
	 * to userspace when the buffer is full
	 */
	copied = 0;
	while (words_available > 0) {
		copy = min(words_available, READ_BUF_SIZE);

		for (i = 0; i < copy; i++) {
			tmp_buf[i] = ioread32(template->base_addr +
					     TEMPLATE_READ_OFFSET);
		}

		if (copy_to_user(buf + copied * sizeof(u32), tmp_buf,
				 copy * sizeof(u32))) {
			reset_ip_core(template);
			return -EFAULT;
		}

		copied += copy;
		words_available -= copy;
	}

    leftover = bytes_available % sizeof(u32);
    if (leftover) {
        tmp_buf[0] = ioread32(template->base_addr +
                              TEMPLATE_READ_OFFSET);

        if (copy_to_user(buf + copied * sizeof(u32), tmp_buf,
                     leftover)) {
            reset_ip_core(template);
            return -EFAULT;
        }
    }

	return bytes_available;
}

static ssize_t template_write(struct file *f, const char __user *buf,
			       size_t len, loff_t *off)
{
	struct template_driver *template = (struct template_driver *)f->private_data;
	unsigned int words_to_write;
	unsigned int copied;
        unsigned int copiedBytes;
	unsigned int copy;
	unsigned int i;
	int ret;
	u32 tmp_buf[WRITE_BUF_SIZE];
        int leftover;

	words_to_write = len / sizeof(u32);
        leftover = len % sizeof(u32);

	if (template->write_flags & O_NONBLOCK) {
		/* opened in non-blocking mode
		 * return if there is not enough room available in the template
		 */
		if (words_to_write > (ioread32(template->base_addr +
					      TEMPLATE_STATUS_OFFSET) & TEMPLATE_WRITE_READY_MASK)) {
			return -EAGAIN;
		}
	} else {
		/* opened in blocking mode */

		/* wait for an interrupt (or timeout) if there isn't
		 * currently enough room in the template
		 */
		spin_lock_irq(&template->write_queue_lock);
		ret = wait_event_interruptible_lock_irq_timeout(
			template->write_queue,
			(ioread32(template->base_addr + TEMPLATE_STATUS_OFFSET) & TEMPLATE_WRITE_READY_MASK),
			template->write_queue_lock,
			(write_timeout >= 0) ? msecs_to_jiffies(write_timeout) :
				MAX_SCHEDULE_TIMEOUT);
		spin_unlock_irq(&template->write_queue_lock);
                wake_up_interruptible(&template_write_wait);

		if (ret == 0) {
			/* timeout occurred */
			dev_dbg(template->dt_device, "write timeout\n");
			return -EAGAIN;
		} else if (ret == -ERESTARTSYS) {
			/* signal received */
			return -ERESTARTSYS;
		} else if (ret < 0) {
			/* unknown error */
			dev_err(template->dt_device,
				"wait_event_interruptible_timeout() error in write (ret=%i)\n",
				ret);
			return ret;
		}
	}

	/* write data from an intermediate buffer into the template IP, refilling
	 * the buffer with userspace data as needed
	 */
	copied = 0;
	while (words_to_write > 0) {
		copy = min(words_to_write, WRITE_BUF_SIZE);

		if (copy_from_user(tmp_buf, buf + copied * sizeof(u32),
				   copy * sizeof(u32))) {
			reset_ip_core(template);
			return -EFAULT;
		}

		for (i = 0; i < copy; i++)
			iowrite32(tmp_buf[i], template->base_addr +
				  TEMPLATE_WRITE_OFFSET);

		copied += copy;
		words_to_write -= copy;
	}

	if (leftover) {	
                if (copy_from_user(tmp_buf, buf + copied * sizeof(u32),
                                   leftover)) {
                        reset_ip_core(template);
                        return -EFAULT;
                }
                iowrite32(tmp_buf[0], template->base_addr +
                          TEMPLATE_WRITE_OFFSET);
        }

        /* write packet size to template */
	copiedBytes = (!!leftover) ? (copied*sizeof(u32)+leftover) : (copied*sizeof(u32));

    return (ssize_t)copiedBytes;
}

static int template_open(struct inode *inod, struct file *f)
{
	struct template_driver *template = (struct template_driver *)container_of(inod->i_cdev,
					struct template_driver, char_device);
	f->private_data = template;

	if (((f->f_flags & O_ACCMODE) == O_WRONLY) ||
	    ((f->f_flags & O_ACCMODE) == O_RDWR)) {
            template->write_flags = f->f_flags;
	}

	if (((f->f_flags & O_ACCMODE) == O_RDONLY) ||
	    ((f->f_flags & O_ACCMODE) == O_RDWR)) {
            template->read_flags = f->f_flags;
	}

	return 0;
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
	.read = template_read,
    .unlocked_ioctl = template_ioctl,
	.write = template_write,
	.poll = template_poll
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
#ifdef TEMPLATE_IRQ_ENABLED
	struct resource *r_irq; /* interrupt resources */
#endif
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
	 *    init device interrupts
	 * ----------------------------
	 */
#if TEMPLATE_IRQ_ENABLED
	/* get IRQ resource */
	r_irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!r_irq) {
		dev_err(template->dt_device, "no IRQ found for 0x%pa\n",
			&template->mem->start);
		rc = -EIO;
		goto err_unmap;
	}

	/* request IRQ */
	template->irq = r_irq->start;
	rc = request_irq(template->irq, &template_irq, 0, DRIVER_NAME, template);
	if (rc) {
		dev_err(template->dt_device, "couldn't allocate interrupt %i\n",
			template->irq);
		goto err_unmap;
	}
#endif

	/* ----------------------------
	 *      init char device
	 * ----------------------------
	 */

	/* allocate device number */
	rc = alloc_chrdev_region(&template->devt, 0, 1, DRIVER_NAME);
	if (rc < 0)
		goto err_irq;
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
err_irq:
#ifdef TEMPLATE_IRQ_ENABLED
	free_irq(template->irq, template);
#endif
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
#ifdef TEMPLATE_IRQ_ENABLED
	free_irq(template->irq, template);
#endif
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
	pr_info(DRIVER_NAME " driver loaded with parameters read_timeout = %i, write_timeout = %i\n",
		read_timeout, write_timeout);
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
