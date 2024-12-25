Project 4 - WeensyOS
====================

<!-- TODO: Fill this out. -->

## Design Overview:
For the WeensyOS project, I didn’t really make any interesting design decisions. I think the only thing that is probably worth mentioning is that for Step 7, when I am using `vmiter` and `ptiter` to enumerate and iterate through the relevant pages, I put that functionality inside of a helper method called `exit_helper(pid_t pid)` that essentially did that work for me. Then anytime in `syscall_fork()` where I needed to free any memory that was allocated for the child process before memory ran out, I would call that helper method. Another design decision that I made was in `syscall_fork()`. I separated my cases based on whether certain memory was writable and/or usable.


## Collaborators:
Andrew Yang, Angela Li

## Extra Credit Attempted:
No

## How long did it take to complete WeensyOS?
15 hours

<!-- Enter an approximate number of hours that you spent actively working on the project. -->
