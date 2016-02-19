/*
 * file : ne_ivshmem_uio_usr.c
 * desc : a demo program that handles UIO interrupts and updates the ivshmem 
 *        POSIX SHM region with the IRQ count value
 *
 * Siro Mugabi, Copyright (c) nairobi-embedded.org, GPLv2
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <sys/mman.h>

#define prfmt(fmt) "%s:%d:: " fmt, __func__, __LINE__
#define prinfo(fmt, ...) printf(prfmt(fmt), ##__VA_ARGS__)
#define prerr(fmt, ...) fprintf(stderr, prfmt(fmt), ##__VA_ARGS__)

struct ivshmem_data {
    const char *filename;
    ssize_t filesize;
};

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-f UIO_DEV ] [-s UIO_MAP_SIZE] [-h]\n",
        prog);
    exit(EXIT_FAILURE);
}

static void bad_filesize(const char *prog)
{
    prerr
            ("invalid filesize; specify value only in decimal or hex (with a leading \"0x\" or \"0X\")\n");
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

        case 'f':
            if (optarg[0] == '-')
                bad_filename(argv[0]);
            ivd->filename = optarg;
            break;

        case 's':
            inval_dec = 0;
            /* accepting strictly decimal or hex values */
            if (sscanf(optarg, "%d%n", (int *)&ivd->filesize, &len) < 1 || len != strlen(optarg)) { /* not base10? */
                inval_dec = 1;
                if (sscanf(optarg, "%x%n", (unsigned int *)&ivd->filesize, &len) < 1 || len != strlen(optarg)) {    /* not base16? */
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

    int32_t fd;
    void *map = NULL;
    const char *opts = "hf:s:";
    const char *filename = NULL;
    ssize_t filesize = 0;
    struct ivshmem_data ivd;
    /* signals */
    sigset_t mask;
    int sfd, i;
    struct signalfd_siginfo fdsi;

    ivd.filename = "/dev/uio0"; /* default uio device */
    ivd.filesize = 0x100000;    /* default ivhsmem uio map1 size (1MB) */

    do_getopt(argc, (char *const *)argv, opts, &ivd);

    filesize = ivd.filesize;
    filename = ivd.filename;

    #ifdef DEBUG
    {
        printf("\nYou entered:\n\tfilename = \"%s\", filesize = %d ",
                     filename, (int)filesize);
        printf("\n\n");
    }
    #endif

    if ((fd = open(filename, O_RDWR)) < 0) {
        prerr("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((map =
             mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
            getpagesize())) == (caddr_t) - 1) {
        prerr("%s\n", strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* prepare for signal handling */
    sigemptyset(&mask);
    for (i = 1; i <= 20; i++)
        sigaddset(&mask, i);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        prerr("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((sfd = signalfd(-1, &mask, 0)) == -1) {
        prerr("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* prevent getting swapped out */
    mlockall(MCL_CURRENT | MCL_FUTURE);

    for (;;) {
        #define MAX_BUF 100
        char buf[MAX_BUF];
        int32_t count, maxfd;
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        FD_SET(sfd, &readfds);

        maxfd = 0;
        maxfd = fd > sfd ? fd : sfd;
        maxfd++;

        if ((select(maxfd, &readfds, NULL, NULL, NULL)) == -1) {
            prerr("select: %s\n", strerror(errno));
            goto cleanup;
        }

        /* signal handling */
        #define SIGFDINFO_SZ sizeof(struct signalfd_siginfo)
        if (FD_ISSET(sfd, &readfds)) {
            if ((read(sfd, &fdsi, SIGFDINFO_SZ)) != SIGFDINFO_SZ) {
                prerr("%s\n", strerror(errno));
                goto cleanup;
            }
            prinfo("Received signal %d. Quiting.\n",
                         fdsi.ssi_signo);
            goto cleanup;
        }

        /* uio interrupt handling */
        if (FD_ISSET(fd, &readfds)) {
            if ((read(fd, &count, sizeof(count))) !=
                    sizeof(int32_t)) {
                prerr("%s\n", strerror(errno));
                goto cleanup;
            }

            /* update ivshmem posix shm */
            snprintf(buf, MAX_BUF, "IRQ count : %d", count);
            prinfo("%s\n", strncpy((char *)map, buf, MAX_BUF));
        }

    }           /* for(;;) */

cleanup:
    munlockall();

    if (map)
        if ((munmap(map, filesize)) < 0)
            prerr("WARNING: Failed to munmap \"%s\"\n", filename);

    close(sfd);
    close(fd);
    exit(EXIT_SUCCESS);
}
