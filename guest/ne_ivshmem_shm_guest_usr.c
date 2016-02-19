/*
 * file : ne_ivshmem_shm_guest_usr.c
 * desc : a demo program that updates/reads the ivshmem POSIX SHM region
 *
 * Siro Mugabi, Copyright (c) nairobi-embedded.org, GPLv2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define prfmt(fmt) "%s:%d:: " fmt, __func__, __LINE__
#define prinfo(fmt, ...) printf(prfmt(fmt), ##__VA_ARGS__)
#define prerr(fmt, ...) fprintf(stderr, prfmt(fmt), ##__VA_ARGS__)

struct ivshmem_data {
    const char *filename;
    ssize_t filesize;
    enum {
        NE_IVSHMEM_READ,
        NE_IVSHMEM_WRITE,
    } ivshmem_op;
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-f SHMOBJ_NAME ] [-s SHMOBJ_SIZE] [-w USER_STRING] [-r]\n",
        prog);
    exit(EXIT_FAILURE);
}

static void bad_filesize(const char *prog)
{
    prerr("invalid filesize; specify value only in decimal or hex (with a leading \"0x\" or \"0X\")\n");
    usage(prog);
}

static void bad_filename(const char *prog)
{
    prerr("invalid filename; must not start with a '-'\n");
    usage(prog);
}

#define INVAL_HXFMT(s) \
        (s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))

static void do_getopt(int argc, char *const *argv, const char *opts,
                    struct ivshmem_data *ivd)
{
    int opt, inval_dec;
    unsigned int len;
    while ((opt = getopt(argc, argv, opts)) != -1) {
        switch (opt) {

        case 'h':
            usage(argv[0]);
            break;

        case 'w':
            ivd->ivshmem_op = NE_IVSHMEM_WRITE;
            break;

        case 'r':
            ivd->ivshmem_op = NE_IVSHMEM_READ;
            break;

        case 'f':
            if (optarg[0] == '-')
              bad_filename(argv[0]);
            ivd->filename = optarg;
            break;

        case 's':
            inval_dec = 0;
            /* accepting strictly decimal or hex values */
            if (sscanf(optarg, "%d%n", (int *)&ivd->filesize, &len) < 1 || 
                    len != strlen(optarg)) {    /* not base10? */
                inval_dec = 1;
                if (sscanf(optarg, "%x%n", (unsigned int *)&ivd->filesize, &len) < 1 ||
                        len != strlen(optarg)) {    /* not base16? */
                    bad_filesize(argv[0]);
                }
            }

            /* enforce leading "0x" or "0X" for non-decimal input
             * values to avoid ambiguity with octal */
            if (!inval_dec) {
                if (optarg[0] == '0')
                    bad_filesize(argv[0]);
            } else {
            if (INVAL_HXFMT(optarg))
                bad_filesize(argv[0]);
            }
            break;

        default:
            usage(argv[0]);
        }
    }
}

int main(int argc, char **argv)
{
    int fd;
    void *map = NULL;
    const char *opts = "hrwf:s:";
    const char *usrstrng = NULL, *filename = NULL;
    ssize_t filesize = 0;
    struct ivshmem_data ivd;

    ivd.filename = "/dev/ivshmem0"; /* default '/dev' node */
    ivd.filesize = 0x100000;    /* default mmio region size */
    ivd.ivshmem_op = NE_IVSHMEM_READ;   /* default op */

    do_getopt(argc, (char *const *)argv, opts, &ivd);

    filename = ivd.filename;
    filesize = ivd.filesize;

    if (ivd.ivshmem_op == NE_IVSHMEM_WRITE) {
        if (optind >= argc) {
            prerr("please specify string to write into mmio region\n");
            usage(argv[0]);
        }
        usrstrng = argv[optind];
    }
#ifdef DEBUG
    {
        printf("\nYou entered:\n\tfilename = \"%s\", filesize = %d, operation = %d, ",
                     filename, (int)filesize, ivd.ivshmem_op);
        if (ivd.ivshmem_op == NE_IVSHMEM_WRITE)
            printf("output_string = \"%s\"\n\n", usrstrng);
        else
            printf("\n\n");
    }
#endif

    if ((fd = open(filename, O_RDWR)) < 0) {
        prerr("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((map =
             mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
            0)) == (caddr_t) - 1) {
        fprintf(stderr, "%s\n", strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }

    switch (ivd.ivshmem_op) {
    case NE_IVSHMEM_READ:
        if (filesize)
            prinfo("read \"%s\"\n", (char *)map);
        break;

    case NE_IVSHMEM_WRITE:
        prinfo("writing \"%s\"\n", usrstrng);
        strcpy((char *)map, usrstrng);
        break;

    default:
        prinfo("no read/write operations performed\n");
    }

    if ((munmap(map, filesize)) < 0)
        prerr("WARNING: Failed to munmap \"%s\"\n", filename);

    close(fd);

    return 0;
}
