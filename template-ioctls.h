#ifndef TEMPLATE_IOCTL_H
#define TEMPLATE_IOCTL_H

#define TEMPLATE_IOCTL_MAGIC 'Q'
#define TEMPLATE_NUM_IOCTLS 3

struct temp_struct {
    uint32_t value;
    uint32_t reg;
}

#define TEMPLATE_GET_STATUS_REG _IOR(TEMPLATE_IOCTL_MAGIC, 0, uint32_t)
#define TEMPLATE_RESET_IP _IO(TEMPLATE_IOCTL_MAGIC,1)
#define TEMPLATE_WRITE_REG(TEMPLATE_IOCTL_MAGIC,2,struct temp_struct)

#endif /* TEMPLATE_IOCTL_H */
