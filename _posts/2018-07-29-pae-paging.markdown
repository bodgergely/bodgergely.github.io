---
layout: post
title:  "PAE Paging - Memory mapping on x86"
date:   2018-07-19 02:36:41 +0100
categories: jekyll update
---

## Intro

I needed to delve a bit deeper into x86(64) paging as the challange on [pwnable.kr](pwnable.kr) 
in the Hacker's Secret category named **sotmmu** is asking for it.

## Challange

Busybox machine running kernel 3.7.1.
You only have a very bare bone environment, no gcc nor gdb just a minimal set of UNIX tools plus the kernel 
with a buggy page walker module inserted :)

The msot obvious bug is that we have a format string vulerability, there is a printk(userspace_addr).
We control the user space addr that gets passed in. On the stack we have the first four bytes of the 
paging structure that holds the pte entries so we can overwrite to those 4 bytes using "%n" specifier.
The 3.7.1 kernel still has "%n", the number of chars "to be written/were to be written" printf feature in
printk!

Now at this moment I am still thinking quite hard how this could be exploited as I just seem to have control
over the first entry in this pte array. If I just could overwrite the a text page phisycal mapping with a physical
address that I know holds my custom shellcode to raise my priviliges I would be golden. But 
I am quite limited as the only candidate address that I can reach directly and could be useful based on
the busybox memory mappings is virtual 0x82000000 as it could hold text memory. But I am not so lucky and it does 
not seem to hold physical frame.


This kernel uses  PAE which is for 32 bit x86 Intel processors to extend the physical addresses from 32 bits to 52 bits.

(Intel Software Developer's Manual - Systems Programming Guide - Chapter 4.)


## PAE

In PAE we have 3 levels of linear address translation. The first 2 bits identify 4 possible entries, the next 9 bits
identify the entry in the second struture pointed to by the previous entry.
Then comes the 3rd 9 bits which again indexes into the 3rd stucture pointed to by the second structure's chosen entry.
At this point we either have a frame mapped onto the virtual address or not. If yes the remaining 12 bits is the offset in the frame.

The above is the standard case when a frame is 4096 bytes long (12 bits identify it). It is possible to have larger (2MB) so called 
hugepages. In this case we need 22 bits for the offset so we have only 10 bits to identify the correct frame.
There is trade off between having larger pages vs smaller pages since the granularity affects greatly systems performance
and we might prefer one or the other depending on our requirements.


Please consult the Intel's manual Chapter 4 Paging for a detailed description.


- CR0.PG = 1
- CR4.PAE = 1
- IA32_EFER>LME = 0

linear 32 bit   ===>    physical 52 bit

- 4 PDPTE registers pointing to 4 structures

### PDPTE registers

    CR3 references the base of a 32 byte page-directory-pointer table. 
    CR3 registers 31:5 bits define the actual address to this table. The other bits are ignored.

    PDPTE register:
        - 52:12 bits define the address to the page directory referenced by this table pointer

### Linear translation with PAE paging

CR3 -> PDPTE -> PDE -> PTE -> PT (4KB pages)
CR3 -> PDPTE -> PDE -> PT (2MB pages)

PAE paging may map linear addresses to either **4KB** or to **2MB** pages.

Bits 31:30 of the linear address select a PDPTE register this is the **PDPTEi** where i is the value of 31:30 bits.
These 2 bits control access to a 1 Gigabyte region of memory of the linear address space. If the P flag(bit 0) 
of PDPTEi is 0 the processor just ignores the bits 63:1 and there is no mapping for the 1 GB region controlled by
PDPTEi. A reference using a linear address in this region causes a page-fault exception.

If the P flag is 1 -> the 4 KB page directory (aligned) is located at the physical address specified by by bits
51:12  of the PDPTEi. A page directory contains 512, 8 byte long entries. 

The **PDE**'s physial address is specified with the below method: (commbination of PDPTEi and the linear address)
    - Bits 51:12 are from PDPTEi
    - Bits 11:3  are bits 29:21 of the linear address
    - Bits 2:0   are 0.

Each PDE controls accessto a 2MB region of the linear address space.

A PDE can map a 2MB page or 512  4KB pages which depends on the PS flag (bit 7) of the PDE.

   - PS == 1 then PDE maps a 2MB page
        **Final physical address** is computed: 
            - Bits 51:21 from PDE
            - Bits 20:0 from the original linear address
   
   - PS == 0 then a 4KB page table is located at the physical address specified by
            bits 51:12 of the PDE. A page table has 512, 8 byte entries, **PTE**s
    
        A PTE is selected from this page table by the below method:
            
            - Bits 51:12 are from the PDE
            - Bits 11:3 are bits 20:12 of the linear address
            - Bits 2:0 are 0

Every PTE maps a 4KB page (because PTE is identified by bits 31:12 of the linear address)

        Final address at this point is calculated:
            
            - Bits 51:12 from the PTE
            - Bits 11:0  from the original linear address

If the P flag (bit 0) of the PDE or the PTE is 0 or if the PDE or PTE sets any reserved bit then the entry is 
used neither to reference another paging structure entry nor map a page. A reference to such linear address would cause
a page-fault exception.

The following bits are reserved with PAE paging:

    If the P flag (bit 0) of a PDE or a PTE is 1, bits 62:MAXPHYADDR are reserved.

    If the P flag and the PS flag (bit 7) of a PDE are both 1, bits 20:13 are reserved.

    If IA32_EFER.NXE = 0 and the P flag of a PDE or a PTE is 1, the XD flag (bit 63) is reserved.

    If the PAT is not supported:
        — If the P flag of a PTE is 1, bit 7 is reserved.
        — If the P flag and the PS flag of a PDE are both 1, bit 12 is reserved.


All the above information is taken from the Intel Software Developer's manual (chapter 4, Paging)


## Implementation

We can create a linux kernel module to walk the process's page table structures.

include/linux/mm_types.h    --> for the mm_struct
arch/x86/include/asm/pgtable_types.h  --> for the pgd_t
arch/x86/include/asm/pgtable-3level_types --> pgdval_t

You can access the current process:

{% highlight c %}
struct task_struct* proc = current;      // current is macro ; calls get_current()
struct mm_struct*   mm   = proc->mm;     
pgd_t*              pgd  = mm->pgd;      // should point to the table containing the 4 entries of pgd entries
{% endhighlight %}

{% highlight c %}
typedef struct { pgdval_t pgd;  } pgd_t;
typedef u64	pgdval_t;
{% endhighlight %}



    

{% highlight c %}
static u64 mmu_walk_pae(u32 vaddr)
{
    struct task_struct* proc = current;
    struct mm_struct* mm = proc->mm;
    pgd_t* pdpte_table = mm->pgd;
    
    // PDPTE selection
    // virt addr bits 31:30 select the PDPTEi
    u32 pdpte_index = (vaddr & 0xC0000000) >> 30;
    u32 pdpte = *(u32*)(pdpte_table + pdpte_index*8);
    // inspect the P flag (bit 0)
    if(!(pdpte & 0x1)) {
        printk("PDPTE%u not a mapping\n", pdpte_index);
        return NULL;
    }
    u32* pde_addr = get_pde_addr(pdpte, vaddr);
    u32  pde = *pde_addr;
    if(!(pde & 0x1)) {
        printk("PDE: %p contains: %x is not a mapping.\n", pde_addr, pde);
    }
    if(pde & 0x80) {
        printk("PDE: %p contain : %x is mapping a 2MB page.\n", pde_addr, pde);
        return (pde & 0x000fffffffe00000) | (vaddr & 0x001fffff);
    }

    u32 pte_table_addr = (pde & 0xfffff000) + 0xc0000000;
    u32 pte_index = ((vaddr & 0x1ff000) >> 12);
    u64* pte_addr = (u64*)(pte_table_addr + (pte_index * 8));
    u64  pte = *pte_addr;
    if(!(pte & 0x1)) {
        printk("PTE not a mapping, PTE table start: %x, index: %x, pte_addr: %p, pte: %llx", 
                                    pte_table_addr, pte_index, pte_addr, pte);
        return NULL;
    }

    // final physical
    return (pte & 0x000ffffffffff000) | (vaddr & 0xfff);

}


{% endhighlight %}

