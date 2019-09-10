#ifndef TEMPLATE_DRIVER_h
#define TEMPLATE_DRIVER_h

#include <linux/ioctl.h>
/* #include "stdint.h" */

/* ----------------------------
 *     IP register offsets
 * ----------------------------
 */
#define TEMPLATE_ISR_OFFSET        0x00000000 /* irq status register */
#define TEMPLATE_IER_OFFSET        0x00000004 /* irq enable register */
#define TEMPLATE_STATUS_OFFSET     0x00000008
#define TEMPLATE_READ_BYTES_OFFSET 0x0000000C
#define TEMPLATE_WRITE_OFFSET      0x00000010
#define TEMPLATE_READ_OFFSET       0x00000014
#define TEMPLATE_DTS_ENTRY_OFFSET  0x00000018

/* ----------------------------
 * IP Register Mask
 * ----------------------------
 */
#define TEMPLATE_RESET_WORD 0xdeadbeef
#define TEMPLATE_READ_READY_MASK     1
#define TEMPLATE_WRITE_READY_MASK    2
#define TEMPLATE_IRQ_EVENTA_MASK     4

/* ----------------------------
 * IOCTLs
 * ----------------------------
 */
#define TEMPLATE_IOCTL_MAGIC 'Q'
#define TEMPLATE_NUM_IOCTLS 4

#define TEMPLATE_READ_REG_STATUS _IOR(TEMPLATE_IOCTL_MAGIC, 0, uint32_t)
#define TEMPLATE_WRITE_REG_STATUS _IOW(TEMPLATE_IOCTL_MAGIC,1,uint32_t)
#define TEMPLATE_RESET_IP _IO(TEMPLATE_IOCTL_MAGIC,2)
#define TEMPLATE_GET_FPGA_ADDR _IOR (TEMPLATE_IOCTL_MAGIC,3, uint32_t)

#endif /* TEMPLATE_DRIVER_h */
