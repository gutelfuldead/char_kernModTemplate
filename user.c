#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "fcntl.h"
#include "string.h"
#include "errno.h"
#include "poll.h"
#include "template-driver.h"

static int fd;
static int reset_core(void);
static int read_status_reg(void);
static int write_status_reg(uint32_t val);

int main(void)
{
    int rc;

    fd = open("/dev/template", O_RDWR|O_EXCL);
    if (fd < 0) {
        perror("Error opening /dev/template");
        return -1;
    }

    printf("Read Status Reg...\n");
    rc = read_status_reg();
    if (rc) {
        close(fd);
        return -1;
    }

    printf("Write all 0's to status reg...\n");
    rc = write_status_reg(0);
    if (rc) {
        close(fd);
        return -1;
    }

    printf("Read Status Reg...\n");
    rc = read_status_reg();
    if (rc) {
        close(fd);
        return -1;
    }

    printf("Write all 1's to status reg...\n");
    rc = write_status_reg(0xffffffff);
    if (rc) {
        close(fd);
        return -1;
    }

    printf("Read Status Reg...\n");
    rc = read_status_reg();
    if (rc) {
        close(fd);
        return -1;
    }

    printf("reset core...\n");
    rc = reset_core();
    if (rc) {
        close(fd);
        return -1;
    }

    printf("Read Status Reg...\n");
    rc = read_status_reg();
    if (rc) {
        close(fd);
        return -1;
    }

    return 0;
}

static int reset_core(void)
{
    int rc;
    /* reset ip */
    rc = ioctl(fd, TEMPLATE_RESET_IP);
    if (rc) {
        perror("ioctl");
        return -1;
    }
    return 0;
}

static int read_status_reg(void)
{
    uint32_t sreg;
    int rc;
    /* get status reg */
    rc = ioctl(fd, TEMPLATE_READ_REG_STATUS, &sreg);
    if (rc) {
        perror("ioctl");
        return -1;
    }
    printf("Status Reg : 0x%08x\n",sreg);
    return 0;
}

static int write_status_reg(uint32_t val)
{
    int rc;
    /* write to status reg */
    rc = ioctl(fd, TEMPLATE_WRITE_REG_STATUS, &val);
    if (rc) {
        perror("ioctl");
        return -1;
    }
    return 0;
}
