#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "fcntl.h"
#include "string.h"
#include "errno.h"
#include "poll.h"
#include "template-driver.h"

#define DRIVER_NAME "/dev/templateDriver0"

static int fd;
static int reset_core(void);
static int read_status_reg(void);
static int write_status_reg(uint32_t val);
static int get_fpga_addr(void);

int main(int argc, char *argv[])
{
    int rc;
    char *device_file;

    if (argc == 1) {
        device_file = DRIVER_NAME;
        printf("Using default : %s\n",DRIVER_NAME);
    } else if (argc == 2) {
        device_file = argv[1];
        printf("Using : %s\n",device_file);
    } else {
        printf("Usage : %s %s\n",argv[0], DRIVER_NAME);
    }

    fd = open(device_file, O_RDWR|O_EXCL);
    if (fd < 0) {
        printf("Usage : %s %s\n",argv[0], DRIVER_NAME);
        perror("open");
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

static int get_fpga_addr(void)
{
    int rc;
    uint32_t addr;
    rc = ioctl(fd, TEMPLATE_GET_FPGA_ADDR, &addr);
    if (rc) {
        printf("failed to get status reg from ioctl %d\n",rc);
        return rc;
    }
    printf("FPGA Addr : 0x%x\n",addr);
    return 0;
}
