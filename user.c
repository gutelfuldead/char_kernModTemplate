#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "fcntl.h"
#include "string.h"
#include "errno.h"
#include "poll.h"
#include "template_ioctls.h"

static int fd;
static int temp_ioctl_demo();

int main(void)
{
    int rc;
    uint32_t sreg;
    struct temp_struct a;

    fd = open("/dev/template", O_RDWR|O_EXCL);
    if (fd < 0) {
        perror("Error opening /dev/template");
        return -1;
    }

    temp_ioctl_demo();

    return 0;
}

static int temp_ioctl_demo()
{
    int rc;
    struct temp_struct a;

    /* reset ip */
    rc = ioctl(fd, TEMPLATE_RESET_IP);
    if (rc) {
        perror("ioctl");
        return -1;
    }

    /* get status reg */
    rc = ioctl(fd, TEMPLATE_GET_STATUS_REG, &sreg);
    if (rc) {
        perror("ioctl");
        return -1;
    }

    /* write to random reg */
    a.value = 0xabcd0123;
    a.regOff = 32;
    rc = ioctl(fd, TEMPLATE_WRITE_REG, &a);
    if (rc) {
        perror("ioctl");
        return -1;
    }

    return 0;
}
