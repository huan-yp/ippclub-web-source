---
title: xv6 代码阅读
date: 2025-09-23 10:00:00
tags: 
- C++ 
- xv6
- OS	
categories: 科普
author: 苹果李子橘子
---

# 导言
这是关于 **MIT 6.828 xv6-RISCV** 的代码阅读笔记，全文将围绕以下并发，虚拟化，持久化，三部分展开(仿照《操作系统导论》的组织形式)，去代码中寻找并解释一些功能的关键工作流程

作者的知识水平有限，如果出现人类幻觉与胡说八道等情形，欢迎指正
# 并发

## 多进程运行
xv6-riscv 默认是一个运行在 qemu-riscv64 三核处理器上的教学用操作系统，最多支持8核处理器，具备有同时运行多个进程的能力。在 kernel/proc.h 中，我们可以看到其对一个 cpu 结构体的定义：
```c
struct cpu {
  struct proc *proc;          // 当前运行在该核心上的进程
  struct context context;     // 指向scheduler()函数的上下文结构体
  int noff;                   // 记录push_off()的调用次数
  int intena;                 // 记录push_off()前是否开中断
};
```
这里看似一个 cpu 只有指向一个进程的指针，但实际上，将 xv6 配置为单核启动也能实现多进程运行的效果，同一个进程也能被调度到不同的核心上去执行。在 kernel/proc.c 文件中，我们可以看到分配在内核栈上的进程控制块数组，其默认配置为最多支持64个进程同时运行,在 proc 结构体中，定义了一个进程所需要的所有基本信息:
```c
struct proc {
  struct spinlock lock;

  // p->lock must be held when using these:
  enum procstate state;        // Process state
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  int xstate;                  // Exit status to be returned to parent's wait
  int pid;                     // Process ID

  // wait_lock must be held when using this:
  struct proc *parent;         // Parent process

  // these are private to the process, so p->lock need not be held.
  uint64 kstack;               // Virtual address of kernel stack
  uint64 sz;                   // Size of process memory (bytes)
  pagetable_t pagetable;       // User page table
  struct trapframe *trapframe; // data page for trampoline.S
  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
};
```
在一个核心上支持多个进程的同时运行，需要支持这些进程之间的频繁切换，具体的，一个进程可能会在以下情况时让出cpu：

- 被中断打断，被迫让出 cpu 
- 调用 yield(), 主动让出 cpu
- 发起了阻塞性的系统调用，让出 cpu 以等待结果

进程的切换主要体现为对于 sched() 函数的调用，sched() 对于即将被让出的进程状态有着严格的要求，若不满足则会触发内核崩溃(xv6 对于错误的处理手段大多是直接引发内核崩溃)，随后，其会调用汇编函数 swtch() 保存当前上下文的值，切换至 cpu 中预置的 scheduler() 上下文,并在其中切换至一个新的进程运行

## 同步与互斥

### 互斥锁
即使在单核 cpu 上运行多个用户进程时，也有可能会出现数据竞态，或者程序在运行至不可被中断的关键代码时被中断打断，因此，需要使用互斥锁来对关键数据或者代码段进行保护。互斥锁的底层实现依赖于硬件提供的同步原语，这里不过多展开。
在即将进行对某个关键数据或者设备进行独占式访问时，进程会先使用 aqcuire() 来尝试获取独占权，在独占结束之后，通过 release() 释放。而为了防止中断的意外到来，可以使用 push_off() 和 pop_off() 两个配套函数来进行中断的开关操作，同时会记录操作的层数以避免中断的提前开启。

### 睡眠锁与唤醒机制

#### 睡眠
然而,一般的互斥锁被实现为自旋互斥锁,关键的独占性保证代码如下:
```c
 while(__sync_lock_test_and_set(&lk->locked, 1) != 0)
    ;
```
cpu 会在获取到独占权之前一直空转,在并发的常见应用场景：生产者与消费者模型当中，如果生产速率和消费速率之间差异显著，则必定会有一方因为等待而浪费了大量的 cpu 资源,为此，便出现了睡眠锁的使用，睡眠锁的基本机制为 sleep() 的调用，即，在拿到锁之后，确认没有待处理数据，就使得进程状态更新为 SLEEPING 释放锁并让出 cpu,节省了等待时的资源浪费。

在此之上，对自旋锁进一步封装得到了睡眠锁，结构体定义如下:
```c
struct sleeplock {
  uint locked;       // Is the lock held?
  struct spinlock lk; // spinlock protecting this sleep lock
  
  // For debugging:
  char *name;        // Name of lock.
  int pid;           // Process holding lock
};
```
其通过封装后的 aqcuiresleep() 函数和 releasesleep() 函数进行使用，关键点在于，如果获取不到锁，就会直接让进程进入睡眠状态

#### 唤醒
在生产者和消费者模型当中，如果使用睡眠锁，则必然会出现生产者准备好数据，需要通知消费者去处理的情况，这时候，必须要生产者去唤醒睡眠状态下的消费者,主要体现为对于 wakeup() 函数的调用,其会寻找当前 channel 上所有正在睡眠的线程，将进程状态改为唤醒,(似乎只会在内核态,如终端和文件读写，进行 sleep 和 wakeup，所以不会涉及虚存切换)


## 中断与异常

### 中断
xv6 中的中断主要分为时钟中断和外设中断，在中断到来时，CPU 可能处在不同的特权级
- S/U 模式异常：处于特权级的保护，用户进程无法访问到内核所使用的内存段，直接跳转至 kernelvec 会引发页错误，为此 xv6 中借助了跳板页实现，即 proc 结构体中的 trapframe 成员，在S/U模式下，中断到来时会首先跳转至跳板vec，在 usertrap 中，完成csr操作，虚存切换(必须有代码段被同时映射到内核空间和用户空间)和上下文保存等工作后再返回。
- M 模式异常: 再M模式下发生异常后，直接跳转至 kernelvec 函数，对应的 trap 只接收来自S mode的设备中断,否则直接内核崩溃
### 异常
- S/U模式发生异常会直接杀死异常来源的应用程序，M mode 异常直接崩溃

## 进程调度
- 调度逻辑很简单，把代码贴出来，不再赘述了
```c
  for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      if(p->state == RUNNABLE) {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;
        swtch(&c->context, &p->context);

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
        found = 1;
      }
```

# 虚拟化
虚拟化在操作系统里主要表现为，将有限的物理资源（CPU、内存、I/O、网络等）抽象为多个逻辑实例，让用户或应用认为自己独占该资源，而在XV6中，主要表现为CPU虚拟化，内存虚拟化和文件系统虚拟化，CPU虚拟化主要表现为进程线程的抽象和时间片轮转，在前一节介绍过了，而文件系统的虚拟化主要在持久化一节中讲解，本章还是主要围绕虚存展开。
## 虚存管理
### 初始化
除了最开始的 initcode.S 程序(直接在内核中分配虚存)，其他所有的程序最后都是通过kexec进行加载和内存初始化的(initcode.S 通过 exec 调用 init 程序，init 程序 fork 出所有其余进程)
```c
    printf("init: starting sh\n");
    pid = fork();
    if(pid < 0){
      printf("init: fork failed\n");
      exit(1);
    }
    if(pid == 0){
      exec("sh", argv);
      printf("init: exec sh failed\n");
      exit(1);
    }
```
具体来说,kexec 负责创建一个新的根页表，完成需要加载段的加载和数据映射(uvmalloc)以及必要的工具段，比如跳板页的映射，随后删除原进程的内存映射并释放所有物理内存。
```c
  proc_freepagetable(oldpagetable, oldsz);
```
而 kfork 则是会完全复制父进程的所有内存并建立映射，除了上下文中的a0被设定为0以在返回值上做出区分外，其余完全相同，知道使用 exec 被新进程覆盖,关键代码如下所示
```c
 // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;
```
### 虚存分配
当应用程序使用 malloc 申请内存的时候，如果程序当前的内存空间不足，malloc 就会发起 sbrk 的系统调用
```c
  if(p == freep)
      if((p = morecore(nunits)) == 0)
        return 0;
```
```c
static Header*
morecore(uint nu)
{
  char *p;
  Header *hp;

  if(nu < 4096)
    nu = 4096;
  p = sbrk(nu * sizeof(Header));
  if(p == SBRK_ERROR)
    return 0;
  hp = (Header*)p;
  hp->s.size = nu;
  free((void*)(hp + 1));
  return freep;
}
```
sys_sbrk最终会调用 uvmalloc 为用户空间分配更多的堆区内存,如果是 free,xv6的实现并没有内核层面的回收，也就是，单个应用程序的内存占用只会增大而不会缩小

## 特权级隔离
特权级隔离主要是硬件层面实现的工作，在RISCV架构中，主要使用三个特权级
- M mode 机器模式，权限最高的模式，可以访问和修改所有 CSR，并可执行所有特权指令
- S mode 超级用户模式，可以访问对S mode开放的CSR，可以处理用户态或是被M态委托的S态中断与异常，并且可以借助驱动使用设备
- U mode 只能执行用户级指令，访问被标记为用户可访问的虚拟内存

在硬件中，如果在执行某些特殊指令时处在了不符合的特权级，会从硬件层面产生异常

# 持久化
## 基本文件操作
### 从 fd 到 file
当用户空间发起对某个 fd 的读写时，底层会表现为 sys_read 或者 sys_write,在真正对文件进行读写之前，内核会去从对应进程控制块中断 ofile 数组中查询 fd 对应的 file 对象,然后对这个 file 对象执行对应的操作，比如 pipewrite, writei, 或者devsw.write();
### 管道，设备与磁盘
在文件操作中，有一种思想叫做 "一切皆文件"。正如上文所说，对设备和管道的访问也被抽象为了文件操作，而真正意义上的磁盘文件是被标记为 inode 的 file 对象，设备对应的devsw 回调函数会在内核驱动初始化时被注册，目前 xv6 只支持串口设备，但是为其添加内核驱动应该是较为简单的事情。
### 文件系统
在不需要持久化的前提下，可以修改 xv6 的代码使其使用 ramdisk,ramdisk 的二进制内容和 fs.img 是完全相同的，也就是说，文件系统实际上就是通过特殊排列以赋予文件，目录等语义的一种协议，具体来说，我们可以在 mkfs/mkfs.c 中看到文件系统的构造方式, 这里不在详细说明.
这里开始讲解严格意义上的磁盘文件读写
#### file 
在 file.c 中，我们可以看到如下代码
```c
struct {
  struct spinlock lock;
  struct file file[NFILE];
} ftable;
```
其定义了一个 ftable 全局变量，应用程序通过向 ftable 申请一个空闲(ref == 0)的 file 块，注册对应的文件描述符，并且根据文件类型的差异进行相应的初始化工作，从而获得对应文件的使用权。

#### inode
而如果申请的文件类型是 磁盘文件或者设备文件，则 file 结构体中的 inode* 成员会被注册，inode 是类 Unix 文件系统中用于描述文件元数据核心数据结构。它本质上是一个记录文件属性和磁盘数据块位置的节点，inode 存放在磁盘上的的 inode 表中，但是在 xv6 系统中，我们在内存中也存放了 inode 的备份以便于访问，其存放在 itable 中，被设置为最多允许存在50个活跃 inode，其定义如下:
```c
struct {
  struct spinlock lock;
  struct inode inode[NINODE];
} itable;
```
以打开在 itable 中从未注册过的某个文件为例，首先看到 sys_open 函数
```c
uint64
sys_open(void)
{
  char path[MAXPATH];
  int fd, omode;
  struct file *f;
  struct inode *ip;
  int n;

  argint(1, &omode);
  if((n = argstr(0, path, MAXPATH)) < 0)
    return -1;

  begin_op();

  if(omode & O_CREATE){
    ip = create(path, T_FILE, 0, 0);
    if(ip == 0){
      end_op();
      return -1;
    }
  } else {
    if((ip = namei(path)) == 0){
      end_op();
      return -1;
    }
    ilock(ip);
    if(ip->type == T_DIR && omode != O_RDONLY){
      iunlockput(ip);
      end_op();
      return -1;
    }
  }

  if(ip->type == T_DEVICE && (ip->major < 0 || ip->major >= NDEV)){
    iunlockput(ip);
    end_op();
    return -1;
  }

  if((f = filealloc()) == 0 || (fd = fdalloc(f)) < 0){
    if(f)
      fileclose(f);
    iunlockput(ip);
    end_op();
    return -1;
  }

  if(ip->type == T_DEVICE){
    f->type = FD_DEVICE;
    f->major = ip->major;
  } else {
    f->type = FD_INODE;
    f->off = 0;
  }
  f->ip = ip;
  f->readable = !(omode & O_WRONLY);
  f->writable = (omode & O_WRONLY) || (omode & O_RDWR);

  if((omode & O_TRUNC) && ip->type == T_FILE){
    itrunc(ip);
  }

  iunlock(ip);
  end_op();

  return fd;
}
```
若在打开模式中置位了CREATE位，则会调用 create 函数，其会判断上级目录是否存在，以及传入的文件是否存在，若不存在，则会调用ialloc分配新的 inode 并且利用 iupdate 同步硬盘中的数据，若不是 create，则直接查找对应文件的inode,最后是调用 iget 从内存 inode 缓存里取出一个 inode，如果缓存没有，就分配一个空槽位并初始化，但不从磁盘加载 inode 内容,真正完成对磁盘内容的更新是在 ilock 中进行的，在此之后，就可以利用这个 inode 来实现对于磁盘的操作了, 以读文件为例， 调用链为 sys_read->fileread->readi->bread ，从 readi 开始，直接涉及了对于 inode 的操作，readi函数如下所示:
```c
int
readi(struct inode *ip, int user_dst, uint64 dst, uint off, uint n)
{
  uint tot, m;
  struct buf *bp;

  if(off > ip->size || off + n < off)
    return 0;
  if(off + n > ip->size)
    n = ip->size - off;

  for(tot=0; tot<n; tot+=m, off+=m, dst+=m){
    uint addr = bmap(ip, off/BSIZE);
    if(addr == 0)
      break;
    bp = bread(ip->dev, addr);
    m = min(n - tot, BSIZE - off%BSIZE);
    if(either_copyout(user_dst, dst, bp->data + (off % BSIZE), m) == -1) {
      brelse(bp);
      tot = -1;
      break;
    }
    brelse(bp);
  }
  return tot;
}
```
代码的关键部分在于，通过bmap函数获取到硬盘所在区域的块编号，随后通过bread函数，从对应块读取整块的数据至内存中的buf并返回，通过either_copyout函数复制到函数调用者提供的缓冲区。
#### 引用计数
在 xv6 文件系统的实现中，file 结构体和 inode 结构体都有自己的 ref 成员，file结构体的 ref 指向的是对于持有该file对象的应用程序，共有几个文件描述符指向该 file 对象，而 inode 结构体的 ref 指向的是有几个 file 指向该 inode。具体来说，其特殊性体现在引用计数归零时的特殊操作，若关闭一个文件描述符时，其所对应的 file ref 归零，则关闭回收该 file 对象，若 file 对象关闭时，inode 结构体的 ref 也归零，并且文件的链接数也归零，则会在磁盘中删除该文件，因为再也没有手段来访问到该文件了。
#### 超级块
超级块是整个存放整个文件系统元信息的地方，从 fsinit 函数开始，其会被常驻地加载到内存当中，作为一个 superblock 结构体。
```c
struct superblock {
  uint magic;        // Must be FSMAGIC
  uint size;         // Size of file system image (blocks)
  uint nblocks;      // Number of data blocks
  uint ninodes;      // Number of inodes.
  uint nlog;         // Number of log blocks
  uint logstart;     // Block number of first log block
  uint inodestart;   // Block number of first inode block
  uint bmapstart;    // Block number of first free map block
};
```
一切对于文件系统的操作都需要从超级块中提供的元信息开始，就以 balloc 函数为例，其代码如下:
```c
static uint
balloc(uint dev)
{
  int b, bi, m;
  struct buf *bp;

  bp = 0;
  for(b = 0; b < sb.size; b += BPB){
    bp = bread(dev, BBLOCK(b, sb));
    for(bi = 0; bi < BPB && b + bi < sb.size; bi++){
      m = 1 << (bi % 8);
      if((bp->data[bi/8] & m) == 0){  // Is block free?
        bp->data[bi/8] |= m;  // Mark block in use.
        log_write(bp);
        brelse(bp);
        bzero(dev, b + bi);
        return b + bi;
      }
    }
    brelse(bp);
  }
  printf("balloc: out of blocks\n");
  return 0;
}
```
这个函数的作用是分配一个被清零的磁盘块，其逻辑是，遍历读取磁盘中所有的位图块，逐块校验其中有没有空闲块，如果有，则返回其块号，若没有，则返回0，表示磁盘空间用尽。
## 日志与崩溃一致性

### 日志
在日常对于电脑的使用当中，电脑的关闭有时并不是正常关机，有充分的时间让系统完成资源的清理和硬件的关闭操作，而是直接断电，此时，磁盘的读写会被强行中断，此时可能会出现部分更新或者状态不一致等问题，造成数据丢失或者读取垃圾数据，所以，需要通过日志来维护文件系统的崩溃一致性，一次事务要么全部完成，要么全部失败，不存在部分完成的情况。

在文件系统的初始化中，我们也可以看到日志系统的初始化:
```c
void
fsinit(int dev) {
  readsb(dev, &sb);
  if(sb.magic != FSMAGIC)
    panic("invalid file system");
  initlog(dev, &sb);
  ireclaim(dev);
}
```
日志的定义如下所示
```c
struct log {
  struct spinlock lock;
  int start;
  int outstanding; // how many FS sys calls are executing.
  int committing;  // in commit(), please wait.
  int dev;
  struct logheader lh;
};
struct log log;
```
#### 日志的提交流程
为了保证程序的崩溃一致性，对于磁盘的写入与磁盘的读取并不相同，具体来说，在 writei 函数中，并没有直接写入磁盘当中，而是表现为调用了一个 log_write ,具体来说，其会在内存中的 log 块中注册被修改的块号，同时为对应的buff增加引用计数避免被回收,而在磁盘操作结束，调用end_op()时，如果此时磁盘完全空闲，则会进行日志的commit工作，完整流程如下:
```c
static void
commit()
{
  if (log.lh.n > 0) {
    write_log();     // Write modified blocks from cache to log
    write_head();    // Write header to disk -- the real commit
    install_trans(0); // Now install writes to home locations
    log.lh.n = 0;
    write_head();    // Erase the transaction from the log
  }
}
```
首先，write_log函数将log中被标记为修改的磁盘块真正写入磁盘中的日志区域，write_head函数则将日志头写入磁盘，当write_head函数被执行完成的时候，便真正标记着这个写入事务执行完成，随后install_trans将日志区域的数据写入磁盘，写入完成后，重置磁盘中的日志头。至此，一次磁盘写入完全完成。
#### 重放
如上所示，一次磁盘写入的完成与否取决于 commit 函数中第一个 write_head 函数是否完成，如果 write_head 函数没有执行完成，则写入全部未完成，如果其已经执行完成，则写入被认为全部完成。由于现代磁盘保证单个块写入的原子性，所以不用担心 write_head 的写入被打断，若在write_head执行之后断电，操作系统在启动时会进行日志的重放操作，彻底完成写入。
```c
static void
recover_from_log(void)
{
  read_head();
  install_trans(1); // if committed, copy from log to disk
  log.lh.n = 0;
  write_head(); // clear the log
}

```

