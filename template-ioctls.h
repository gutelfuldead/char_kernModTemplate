#ifndef TEMPLATE_IOCTLS_H
#define TEMPLATE_IOCTLS_H

#include <linux/ioctl.h>
/* #include "stdint.h" */

#define TEMPLATE_IOCTL_MAGIC 'Q'
#define TEMPLATE_NUM_IOCTLS 3

struct temp_struct {
    uint32_t value;
    uint32_t regOff;
};

#define TEMPLATE_GET_STATUS_REG _IOR(TEMPLATE_IOCTL_MAGIC, 0, uint32_t)
#define TEMPLATE_RESET_IP _IO(TEMPLATE_IOCTL_MAGIC,1)
#define TEMPLATE_WRITE_REG _IOW(TEMPLATE_IOCTL_MAGIC,2,struct temp_struct)

#endif /* TEMPLATE_IOCTLS_H */
