# WeensyOS

## Introduction and Motivation:
Virtual memory is a component of the operating system that helps the OS safely run multiple applications atop the same physical memory (the computer's RAM). Each process receives its own virtual memory address space, and these virtual addresses are mapped to specific physical addresses. This gives the process an illusion of a contiguous memory space in which only its data exists.

The operating system kernel is the core program of the OS that runs with full machine privilege to manage processes and their associated virtual memories. The main goals of the kernel are to fairly share machine resources among processes, and provide convenient and safe access to the hardware while protecting the OS from malicious programs.

Almost all modern operating systems use virtual memory. In order to implement full virtual memory with complete and correct memory isolation, this program implements interaction with page tables, kernel and user memory spaces, processes, and virtual and physical memories. In principle, WeensyOS can run an any computer with an x86-64 architecture. However, this program is run in QEMU.

## Overview:
WeensyOS is a miniature operating system that implements process memory isolation, virtual memory, and various system calls. 

<img width="736" alt="Screenshot 2023-06-24 at 3 40 20 PM" src="https://github.com/PatrickLi2021/WeensyOS/assets/50870866/e38c066c-2823-4c87-8677-0d344693e662">

## Memory System Layout:
The WeensyOS memory system layout is described by the following constants:

- `KERNEL_START_ADDR`: Represents the start of kernel code. Equivalent to `0x40000`.
- `KERNEL_STACK_TOP`: Represents the top of the kernel stack (the kernel stack is one page long). Equivalent to `0x80000`.
- `CONSOLE_ADDR`: CGA console memory, equivalent to `0xB8000`. Values written to this page get printed in the terminal. All processes have read/write to this page.
- `PROC_START_ADDR`: Represents the start of application code. Applications should not be able to access memory below this value, except for the single page of console memory.
- `MEMSIZE_PHYSICAL`: The size of physical memory (`0x200000` or `2 MB`). WeensyOS does not support physical addresses greater than or equal to `MEMSIZE_PHYSICAL`.
- `MEMSIZE_VIRTUAL`:  The size of virtual memory (`0x300000` or `3 MB`). WeensyOS does not support virtual addresses greater than or equal to this value.
- `PAGESIZE`: The size of a memory page, which is equivalent to 4096 (`1 << 12`)
  
<img width="674" alt="Screenshot 2023-06-24 at 3 18 56 PM" src="https://github.com/PatrickLi2021/WeensyOS/assets/50870866/abcd9286-acb2-478a-8f14-0fb016368238">

## Relevant Files:

- `kernel.hh`: Declares constants and function headers for the kernel. Some of these kernel functions are implemented in `kernel.cc` (while others are in `k-hardware.cc`)
- `kernel.cc`: The core of the kernel program
- `u-lib.hh`: User-space library with system call specifications and implementations. The user-space processes can call functions in this file.
- `k-vmiter.hh`: Defines iterators for x86-64 page tables. The `vmiter` enumerates virtual memory mappings, while `ptiter` visits individual page table pages.

<img width="668" alt="Screenshot 2023-06-24 at 3 21 23 PM" src="https://github.com/PatrickLi2021/WeensyOS/assets/50870866/46c39e7e-a423-47e8-9161-5211c4eac9da">

## Key Features:
- **Kernel Isolation:** Kernel memory is inaccessible from userspace processes
- **Process Isolation:** Process isolation was implemented by giving each process its own independent page table. This makes it so that each process only has permission to access its own pages. This is done by first allocating a new, initially-empty page table for the process and then copying the mappings from the kernel pagetable into this new page table using a `vmiter`. This ensures that the required kernel mappings are present in the new page table. After that, we ensure that any page that belongs to the process is mapped as user-accessible.
- **Virtual Page Allocation:** All process data is allocated using `kalloc` rather than direct access to an internal `pages` array that stores each page's information.
- **Overlapping Virtual Address Spaces**: Each process uses the same virtual addresses for different physical memory. In other words, each process's stack grows down starting at `MEMSIZE_VIRTUAL`.
- **Fork System Call:** Creates a new child process by duplicating the calling parent process. The form system call appears to return twice, one to each process - it returns 0 to the child process, and it returns the child's process ID to the parent process. This functionality was implemented by copying the process data in every application page shared by the two processes. Each virtual address in the old page table is examined and whenever the parent process has a user-accessible page at virtual addres _V_, fork allocates a new physical page _P_, copies the data from the parent's page into _P_ using `memcpy`, and maps page _P_ at address _V_ in the child process's page table.
- **Shared Read-Only Memory:** Shares read-only pages between processes rather than copying them over. It does so by incrementing the reference counts of pages being shared between processes.
- **Exit:** A system call that allows the current process to free its memory and resources and exit cleanly and gracefully.

## Code:
Available upon request (patrick_li@brown.edu or patrickli2021@gmail.com)
