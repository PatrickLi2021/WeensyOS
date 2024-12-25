#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[NPROC];             // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state
//    Information about physical page with address `pa` is stored in
//    `pages[pa / PAGESIZE]`. In the handout code, each `pages` entry
//    holds an `refcount` member, which is 0 for free pages.
//    You can change this as you see fit.

pageinfo pages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel(const char* command) {
    // Initialize hardware.
    init_hardware();
    log_printf("Starting WeensyOS\n");

    // Initialize timer interrupt.
    ticks = 1;
    init_timer(HZ);

    // Clear screen.
    console_clear();

    // (re-)Initialize the kernel page table.
    for (vmiter it(kernel_pagetable); it.va() < MEMSIZE_PHYSICAL; it += PAGESIZE) {
        // Allow CGA console memory to be accessible to applications
        if (it.va() == CONSOLE_ADDR) {
            it.map(it.va(), PTE_P | PTE_U | PTE_W);
        }
        // Mark all userspace memory as present, writable, and accessible to userspace
        else if (it.va() >= PROC_START_ADDR) {
            it.map(it.va(), PTE_P | PTE_W | PTE_U);
        }
        // Mark kernel memory as present and writable
        else if (it.va() != 0) {
            it.map(it.va(), PTE_P | PTE_W);
        } 
        else {
            // nullptr is inaccessible even to the kernel
            it.map(it.va(), 0);
        }
    }

    // Set up process descriptors.
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (command && program_loader(command).present()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // Switch to the first process using run().
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel memory allocator. Allocates `sz` contiguous bytes and
//    returns a pointer to the allocated memory (the physical address of
//    the newly allocated memory), or `nullptr` on failure.
//
//    The returned memory is initialized to 0xCC, which corresponds to
//    the x86 instruction `int3` (this may help you debug). You can
//    reset it to something more useful.
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The stencil code returns the next allocatable free page it can find,
//    but it never reuses pages or supports freeing memory (you'll have to
//    change this at some point).

static uintptr_t next_alloc_pa;

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }
    next_alloc_pa = 0;
    while (next_alloc_pa < MEMSIZE_PHYSICAL) {
        uintptr_t pa = next_alloc_pa;
        next_alloc_pa += PAGESIZE;

        if (allocatable_physical_address(pa) && !pages[pa / PAGESIZE].used()) {
            pages[pa / PAGESIZE].refcount = 1;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
        pa += PAGESIZE;
    }
    return nullptr;
}

// kfree(kptr)
//    Frees `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.
//    kfree takes in a physical address and "frees" memory at that physical address

void kfree(void* kptr) {
    // Checks if kptr is the nullptr (it doesn't point to a valid page)
    if (kptr == nullptr) {
        return;
    }
    // If the kptr is valid, then decrement its refcount by 1
    else if (pages[(uintptr_t) kptr / PAGESIZE].refcount > 0) {
        pages[(uintptr_t) kptr / PAGESIZE].refcount -= 1;
    }
}

// process_setup(pid, program_name)
//    Loads application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    // Initialize this process's page table
    x86_64_pagetable* process_pt = (x86_64_pagetable*) kalloc(PAGESIZE);
    // Ensures that the page table is empty
    memset(process_pt, 0, PAGESIZE);
    vmiter dest_iter(process_pt, 0);
    // Copy mappings from kernel_pagetable into the empty page table
    for (vmiter it(kernel_pagetable, 0); it.va() < PROC_START_ADDR; it += PAGESIZE) {
        dest_iter.try_map(it.pa(), it.perm());
        dest_iter += PAGESIZE;
    }
    ptable[pid].pagetable = process_pt;

    // Initialize `program_loader`.
    // The `program_loader` is an iterator that visits segments of executables.
    program_loader loader(program_name);

    // Using the loader, we're going to start loading segments of the program binary into memory
    // (recall that an executable has code/text segment, data segment, etc).

    // First, for each segment of the program, we allocate page(s) of memory.
    for (loader.reset(); loader.present(); ++loader) {
        for (uintptr_t a = round_down(loader.va(), PAGESIZE);
             a < loader.va() + loader.size();
             a += PAGESIZE) {
            
            // Create a new segment vmiter using the page table that was previously created
            vmiter segment(process_pt, a);

            // Allocates memory for a new page
            x86_64_page* seg_page = (x86_64_page*) kalloc(PAGESIZE);
            if (seg_page != nullptr) {
                memset(seg_page, 0, PAGESIZE);
                int status = segment.try_map(seg_page, PTE_P | PTE_W * loader.writable() | PTE_U);
                if (status < 0) {
                    kfree(seg_page);
                }
            }

            // `a` is the virtual address of the current segment's page.
            // assert(!pages[a / PAGESIZE].used());
            // Read the description on the `pages` array if you're confused about what it is.
            // Here, we're directly getting the page that has the same physical address as the
            // virtual address `a`, and claiming that page by incrementing its reference count
            // (you will have to change this later).
            // pages[a / PAGESIZE].refcount = 1;
        }
    }

    // We now copy instructions and data into memory that we just allocated.
    for (loader.reset(); loader.present(); ++loader) {
        // Move dest_iter to the virtual address associated with this seg page
        dest_iter.find(loader.va());
        memset((void*) dest_iter.pa(), 0, loader.size());
        memcpy((void*) dest_iter.pa(), loader.data(), loader.data_size());
    }

    // Set %rip and mark the entry point of the code.
    ptable[pid].regs.reg_rip = loader.entry();

    // We also need to allocate a page for the stack (this is the virtual address?)
    uintptr_t stack_addr = PROC_START_ADDR + PROC_SIZE * pid - PAGESIZE;

    // Allocate a physical address for the stack page using kalloc()
    x86_64_page* stack_page = (x86_64_page*) kalloc(PAGESIZE);
    if (stack_page != nullptr) {
        memset(stack_page, 0, PAGESIZE);
        vmiter stack(process_pt, MEMSIZE_VIRTUAL - PAGESIZE);   
        int status = stack.try_map(stack_page, PTE_P | PTE_W | PTE_U);
        if (status < 0) {
            kfree(stack_page);
        }
    }
    // assert(!pages[stack_addr / PAGESIZE].used());
    // Again, we're using the physical page that has the same address as the `stack_addr` to
    // maintain the one-to-one mapping between physical and virtual memory (you will have to change
    // this later).
    // pages[stack_addr / PAGESIZE].refcount = 1;
    // Set %rsp to the start of the stack.
    ptable[pid].regs.reg_rsp = MEMSIZE_VIRTUAL;

    // Finally, mark the process as runnable.
    ptable[pid].state = P_RUNNABLE;
}

// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//    You should *not* have to edit this function.
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (see
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception(). This way, the process can be resumed right where
//    it left off before the exception. The pushed registers are popped and
//    restored before returning to the process (see k-exception.S).
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PFERR_USER)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, regs->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_BROKEN;
        break;
    }

    default:
        panic("Unexpected exception %d!\n", regs->reg_intno);

    }

    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value, if any, is returned to the user process in `%rax`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

// Headers for helper functions used by syscall.
int syscall_page_alloc(uintptr_t addr);
pid_t syscall_fork();
void syscall_exit();

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();

    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        panic(nullptr); // does not return

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule(); // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return syscall_fork();

    case SYSCALL_EXIT:
        syscall_exit();
        schedule(); // does not return

    default:
        panic("Unexpected system call %ld!\n", regs->reg_rax);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Helper function that handles the SYSCALL_PAGE_ALLOC system call.
//    This function implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the stencil code, it does not - you will
//    have to change this).

int syscall_page_alloc(uintptr_t addr) {
    // assert(!pages[addr / PAGESIZE].used());
    // If the requested address is within kernel memory or reserved, then return -1
    if (addr < PROC_START_ADDR || addr % 4096 != 0 || addr >= MEMSIZE_VIRTUAL) {
        return -1;
    }
    // Currently we're simply using the physical page that has the same address
    // as `addr` (which is a virtual address).
    vmiter heap_it(current->pagetable, addr);
    x86_64_page* heap_page = (x86_64_page*) kalloc(PAGESIZE);
    if (heap_page == nullptr) {
        return -1;
    }
    int status = heap_it.try_map(heap_page, PTE_P | PTE_W | PTE_U);
    if (status < 0) {
        kfree(heap_page);
        return -1;
    }
    // pages[addr / PAGESIZE].refcount = 1;
    memset((void*) heap_page, 0, PAGESIZE);
    return 0;
}

// Helper for syscall_exit
void exit_helper(pid_t pid) {
    // Free the pages that are stored inside the page table
    for(vmiter it2(ptable[pid].pagetable, PROC_START_ADDR); it2.va() < MEMSIZE_VIRTUAL; it2 += PAGESIZE) {
        if (it2.user() && it2.va() != CONSOLE_ADDR) {
            kfree((void*) it2.pa());
        }
    }
    // Frees the page tables
    for(ptiter it1(ptable[pid].pagetable); it1.active(); it1.next()) {
        kfree((void*)it1.pa());
    }
    kfree(ptable[pid].pagetable);
}

// syscall_fork()
//    Handles the SYSCALL_FORK system call. This function
//    implements the specification for `sys_fork` in `u-lib.hh`.
//    When fork fails, we want to free the child. fork fails when all 16 processes are filled and we try
//    call fork (i.e. no free ptable slot. This means that we didn't allocate anything and there's no need to free).
//    If there's not enough memory for another process, then we also can't fork. This happens when a kalloc fails. We 
//    then want to call syscall_exit on the child here. The last and most subtle one is mapping to a page table. When 
//    try_map fails, we don't simply want to call syscall_exit on the child. We also want to free the physical 
//    address returned by kalloc and then exit the child

pid_t syscall_fork() {
    // Loop until we find a free process slot
    int i = 1;
    while (ptable[i].state != P_FREE) {
        i++;
        // All process slots are filled and there is no free process slot
        if (i >= 16) {
            return -1;
        }
    }
    // Once a free slot is found, we allocate memory for a page table copy
    ptable[i].pagetable = (x86_64_pagetable*) kalloc(PAGESIZE);
    // Checks if there isn't enough free memory to successfully complete sys_fork call
    if (ptable[i].pagetable == nullptr) {
        return -1;
    }
    memset(ptable[i].pagetable, 0, PAGESIZE);
    
    for (vmiter it(current->pagetable, 0); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        
        // Checks if the parent process has a user-accessible page at virtual address V and the 
        // address does NOT equal the console address
        if (it.user() && it.va() != CONSOLE_ADDR && it.writable()) {
            // Allocate a new physical page and copy the data from the parent's page into this page
            x86_64_page* new_phys_page = (x86_64_page*) kalloc(PAGESIZE);
            // Checks if there isn't enough free memory to successfully complete a sys_fork call
            if (new_phys_page == nullptr) {
                exit_helper(ptable[i].pid);
                return -1;
            }
            memcpy(new_phys_page, (x86_64_page*) it.pa(), PAGESIZE);
            // Map the current virtual address to the child process's page table
            vmiter child_vmiter(ptable[i].pagetable, it.va());
            int status = child_vmiter.try_map(new_phys_page, it.perm());
            if (status < 0) {
                exit_helper(ptable[i].pid);
                kfree((void*) new_phys_page);
                return -1;
            }
        } 
        // Checks if the page at virtual address V is NOT user-accessible or writable
        else {
            vmiter vm1(ptable[i].pagetable, it.va());
            int status = vm1.try_map(it.pa(), it.perm());
            if (status < 0) {
                exit_helper(ptable[i].pid);
                kfree((void*) ptable[i].pagetable);
                return -1;
            }
            if (it.user() && !it.writable()) {
                pages[it.pa() / PAGESIZE].refcount += 1;
            }
        }
    }
    ptable[i].pid = i;
    ptable[i].state = P_RUNNABLE;
    ptable[i].regs = current->regs;
    ptable[i].regs.reg_rax = 0;
    current->regs.reg_rax = i;
    return i;
    // panic("Unexpected system call %ld!\n", SYSCALL_FORK);
}

// syscall_exit()
//    Handles the SYSCALL_EXIT system call. This function
//    implements the specification for `sys_exit` in `u-lib.hh`.
void syscall_exit() {
    exit_helper(current->pid);
    // Mark the current process as free
    current->state = P_FREE;
}

// schedule
//    Picks the next process to run and then run it.
//    If there are no runnable processes, spins forever.
//    You should *not* have to edit this function.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % NPROC;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("%u\n", spins);
        }
    }
}


// run(p)
//    Runs process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.
//    You should *not* have to edit this function.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draws a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.
//    You should *not* have to edit this function.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % NPROC;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < NPROC; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % NPROC;
        }
    }

    extern void console_memviewer(proc* vmp);
    console_memviewer(p);
}
