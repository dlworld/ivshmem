/*  
 *  file : ne_ivshmem_send_qeventfd.c
 *  desc : generates periodic irqs on a QEMU ivshmem device via an eventfd(2) file descriptor.
 *  
 *  notes: code based on ivshmem.c, qemu-char.c, qemu-socket.c, oslib-posix.c and osdep.c
 *  of qemu-1.0.1 (multiple open licenses)
 *
 *  Siro Mugabi, Copyright (c) nairobi-embedded.org
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
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

typedef struct {
    int fd;
    int msgfd;
} UNIXSockData;

static struct {
    long id, trgt_id;
    int fd, trgt_efd;
    int do_efd;
} Efd;

#define prfmt(fmt) "%s:%d:: " fmt, __func__, __LINE__
#define prinfo(fmt, ...) printf(prfmt(fmt), ##__VA_ARGS__)
#define prerr(fmt, ...) fprintf(stderr, prfmt(fmt), ##__VA_ARGS__);
#ifdef DDEBUG
#define prdebug(fmt, ...) printf(prfmt(fmt), ##__VA_ARGS__);
#else
#define prdebug(fmt, ...) do{}while(0)
#endif

static void reset_efd_trgt(void)
{
    Efd.trgt_id = Efd.trgt_efd = -EBADF;
    Efd.do_efd = 0;
}

static int tcp_get_msgfd(UNIXSockData * s)
{
    int fd = s->msgfd;
    s->msgfd = -1;
    return fd;
}

static void check_shm_size(int fd)
{
    struct stat buf;
    fstat(fd, &buf);
    prinfo("SHM size: %llu\n", (unsigned long long)buf.st_size);
}

static int process_server_msg(UNIXSockData * s, const uint8_t * buf, int flags)
{
    int msg_fd, tmp_fd;
    long msg_id;

    memcpy(&msg_id, buf, sizeof(long));
    tmp_fd = tcp_get_msgfd(s);
    prdebug("Processing msgID: %ld, flag: %d\n", msg_id, tmp_fd);

    /* (dis)connection notification */
    if (tmp_fd == -1) {
        if ((msg_id >= 0) && (Efd.id < 0)) {
            /* we just connected */
            prinfo("Our ID = %ld\n", msg_id);
            Efd.id = msg_id;
            return 0;
        } else {
            /* someone left the network */
            if (msg_id == Efd.trgt_id)
                reset_efd_trgt();

            prinfo("VM ID %ld just disconnected.\n", msg_id);
            return 0;
        }
    }

    msg_fd = dup(tmp_fd);
    if (msg_fd == -1) {
        prerr("Bad fd (%d) for eventfd received\n", msg_fd);
        return -1;
    }

    /* process ivshmem posix-shm info */
    if (msg_id == -1) {
        check_shm_size(msg_fd);
        return 0;
    }

    /* initialize target eventfd stuff */
    if (Efd.id != msg_id) {
        prinfo("Using fd %d for eventfd to VM ID %ld\n", msg_fd,
                     msg_id);
        Efd.trgt_efd = msg_fd;
        Efd.trgt_id = msg_id;
        Efd.do_efd = 1;
        return 0;
    } else {
        prinfo("Our eventfd fd %d\n", msg_fd);
        Efd.fd = msg_fd;
    }
    return 0;
}

static void unix_process_msgfd(UNIXSockData * s, struct msghdr *msg)
{
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        int fd;

        if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
                cmsg->cmsg_level != SOL_SOCKET
                || cmsg->cmsg_type != SCM_RIGHTS)
            continue;

        fd = *((int *)CMSG_DATA(cmsg));
        if (fd < 0)
            continue;

        if (s->msgfd != -1)
            close(s->msgfd);
        s->msgfd = fd;
    }
}

static ssize_t tcp_chr_recv(UNIXSockData * s, char *buf, size_t len)
{
    struct msghdr msg = { NULL, };
    struct iovec iov[1];
    union {
        struct cmsghdr cmsg;
        char control[CMSG_SPACE(sizeof(int))];
    } msg_control;
    ssize_t ret;

    iov[0].iov_base = buf;
    iov[0].iov_len = len;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &msg_control;
    msg.msg_controllen = sizeof(msg_control);
    ret = recvmsg(s->fd, &msg, 0);
    if (ret < 0)
        prerr("%s\n", strerror(errno));
    if (ret > 0)
        unix_process_msgfd(s, &msg);
    return ret;
}

static void set_cloexec(int fd)
{
    int f;
    f = fcntl(fd, F_GETFD);
    fcntl(fd, F_SETFD, f | FD_CLOEXEC);
    return;
}

static int unix_sock_connect(const char *path)
{
    struct sockaddr_un un;
    int sock;

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock >= 0)
        set_cloexec(sock);
    else {
        prerr("%s\n", strerror(errno));
        return -1;
    }

    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof(un.sun_path), "%s", path);
    if (connect(sock, (struct sockaddr *)&un, sizeof(un)) < 0) {
        prerr("%s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static void init_efd(void)
{
    Efd.id = Efd.fd = -EBADF;
    reset_efd_trgt();
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-f UNIX_SOCKET_PATH]\n", prog);
    exit(EXIT_FAILURE);
}

static void bad_filename(const char *prog)
{
    prerr("invalid filename; must not start with a '-'\n");
    usage(prog);
}

static void
do_getopt(int argc, char *const *argv, const char *opts, const char *path)
{
    int opt;

    while ((opt = getopt(argc, argv, opts)) != -1) {
        switch (opt) {

        case 'h':
            usage(argv[0]);
            break;

        case 'f':
            if (optarg[0] == '-')
                bad_filename(argv[0]);
            path = optarg;
            break;

        default:
            usage(argv[0]);
        }
    }
}

#define READ_BUF_LEN 4096
int main(int argc, const char *argv[])
{
    int fd = -1, ret = -1;
    UNIXSockData *s = NULL;
    const char *opts = "hf:";
    const char *path = "/tmp/ivshmem_socket";   /* default unix sock */
    /* signals */
    sigset_t mask;
    int sfd, i;
    struct signalfd_siginfo fdsi;

    do_getopt(argc, (char *const *)argv, opts, path);

    init_efd();
    if (!(s = malloc(sizeof(UNIXSockData)))) {
        prerr("%s\n", strerror(errno));
        exit(-1);
    }

    fd = unix_sock_connect(path);
    if (fd < 0)
        goto cleanup;

    s->fd = fd;
    s->msgfd = -1;

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

    for (;;) {

        uint8_t buf[READ_BUF_LEN];
        fd_set readfds;
        int max_fd, size, len = sizeof(buf);
        uint64_t u = 1;
        struct timeval tv;

        FD_ZERO(&readfds);
        FD_SET(sfd, &readfds);
        FD_SET(s->fd, &readfds);

        max_fd = 0;
        max_fd = s->fd > sfd ? s->fd : sfd;
        max_fd++;

        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if ((select(max_fd, &readfds, NULL, NULL, &tv)) == -1) {
            prerr("select: %s", strerror(errno));
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

        /* eventfd handling */
        if (FD_ISSET(s->fd, &readfds)) {
            if ((size = tcp_chr_recv(s, (void *)buf, len)) <= 0) {
                prerr("tcp_chr_recv error\n");
                goto cleanup;
            }

            ret = process_server_msg(s, buf, size);
            if (ret < 0) {
                prerr("process_server_read error\n");
                goto cleanup;
            }
        }

        if (Efd.do_efd) {
            prinfo("sending eventfd to VM ID %ld using fd = %d\n",
                         Efd.trgt_id, Efd.trgt_efd);
            ret = write(Efd.trgt_efd, &u, sizeof(uint64_t));
            if (ret != sizeof(uint64_t)) {
                prerr("%s\n", strerror(errno));
                goto cleanup;
            }
        }
    }           /* for(;;) */

cleanup:
    close(fd);
    if (s)
        free(s);

    exit(EXIT_SUCCESS);
}
