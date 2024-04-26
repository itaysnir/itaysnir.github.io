---
layout: post
title:  "Pwn College - Program Interaction"
date:   2024-04-26 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This is the very first module within pwn-college. \ The module deals with common ways to interact with linux processes, which are mandatory for binary exploitation.

This page contains solutions for selected challenges, some of them are actually pretty interesting. 

## Connection

```bash
ssh -v hacker@dojo.pwn.college
```

## Challenge 5

```bash
echo ilgyfizp > /tmp/qsvkql
./embryoio_level5 < /tmp/qsvkql
```

## Challenge 7 

Run binary without any env variables.

```bash
env -i ./embryoio_level7
```

## Challenge 15

First, issue `ipython` to enter the interactive session. 

```python
from pwn import *
p = process(['/challenge/embryoio_level15'])
data = p.read()
print(data)
```

## Challenge 22

```python
#!/usr/bin/python

from pwn import *
import subprocess

p = subprocess.Popen('/challenge/embryoio_level22', stdout=subprocess.PIPE)
stdout, stderr = p.communicate()
print(stdout)
```

## Challenge 27 

```python
#!/usr/bin/python

from pwn import *
import subprocess

fd = open('/tmp/btxtnc', 'w')
p = subprocess.Popen('/challenge/embryoio_level27', stdout=fd)
p.wait(timeout=3)
```

## Challenge 29

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>


char* new_argv[] = {"/home/hacker/a", NULL};
char* new_envp[] = {NULL};

void pwncollege()
{
        printf("Ahoy sir\n");
        return;
}

int main()
{
        printf("Executing C exploit\n");
        pid_t pid = fork();
        if (pid == 0)
        {
                printf("Hello from child!\n");
                execve("/challenge/embryoio_level29", new_argv, new_envp);
        }
        else
        {
                printf("Hello from parent! child pid: %d\n", pid);
                wait(0);
        }
        return 0;
}
```

## Challenge 34

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>


char* new_argv[] = {"/home/hacker/a", "qbzvqfcqfo",NULL};
char* new_envp[] = {"yaqxjf=lhyehkxglc", NULL};
const char* open_file = "/tmp/plwkwg";

void pwncollege()
{
        printf("Ahoy sir\n");
        return;
}

int main()
{
        printf("Executing C exploit\n");
        int crap_fd = open(open_file, O_CREAT | O_RDWR, S_IWUSR | S_IRUSR);
        pid_t pid = fork();
        if (pid == 0)
        {
                dup2(crap_fd, STDOUT_FILENO);
                printf("Hello from child!\n");
                close(crap_fd);
                execve("/challenge/embryoio_level34", new_argv, new_envp);
        }
        else
        {
                printf("Hello from parent! child pid: %d\n", pid);
                wait(0);
                sleep(2);
                int read_fd = open(open_file,O_RDWR, S_IRUSR);
                char flag[100] = {0};
                read(read_fd, flag, 100);
                printf("FLAG: %s", flag);
        }
        return 0;
}
```


## Challenge 40

Makes cat to read from stdin, and the pipe transfers it to the program’s stdin (without -, pipe is closed too soon):

```bash
cat - | ./embryoio_level40
```

## Challenge 41

The trick here is to press CTRL+D after inserting the input! \
CTRL+D sends an EOF (not signal), which means ‘flush the input i’ve typed so far'. 

This is NOT a signal, but is implemented as a read of length 0 by the TTY driver. Its corresponding character is 0x04. 

## Challenge 48

```python
from pwn import *
p1 = process('/bin/cat')
p2 = process('/challenge/embryoio_level48', stdout = p1.stdin)
p1.read()
```

## Challenge 52

```python
from pwn import *
p1 = process('/bin/cat', stdout=PIPE)
p1.sendline('hslxhekd')
p2 = process('/challenge/embryoio_level52', stdin = p1.stdout)
p2.recv()
```

## Challenge 53

Really tricky, same as above but with `rev`. \
I just copied `cat`, and renamed it to be `rev`. \
Not sure whats the intended solution.

## Challenge 54

```python
#!/usr/bin/python

from pwn import *
import subprocess as sp

p2 = sp.Popen('/challenge/embryoio_level54', stdout = sp.PIPE)
p1 = sp.Popen('/bin/cat', stdin = p2.stdout)
stdout, stderr = p1.communicate()
print(stdout)
```

## Challenge 60

Rule of thumb - when redirecting read / write end of a pipe to stdin / stdout (via dup2()), BOTH ends of the pipe must be closed - for both child and parent!

This article is very informative: [c-pipes][c-pipes].

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>


struct subprocess
{
        pid_t pid;
        int stdin;
        int stdout;
        int stderr;
};


void mk_pipe(int fds[2])
{
        if (pipe(fds) == -1)
        {
                perror("Could not create pipe");
                exit(1);
        }
}

void mv_fd(int fd1, int fd2)
{
        dup2(fd1, fd2);
        close(fd1);
}

pid_t call(char* argv[], char* envp[], struct subprocess *p)
{
        int child_in[2];
        int child_out[2];
        int child_err[2];
        mk_pipe(child_in);
        mk_pipe(child_out);
        mk_pipe(child_err);
        pid_t pid = fork();
        if (pid == 0)
        {
                close(0); // check if able to switch to STDIN_FILENO
                close(1);
                close(2);
                close(child_in[1]);
                close(child_out[0]);
                close(child_err[0]);
                mv_fd(child_in[0], 0);
                mv_fd(child_out[1], 1);
                mv_fd(child_err[1], 2);
                printf("Hello from child\n");
                execve("/challenge/embryoio_level60", argv, envp);
        }
        else
        {
                close(child_in[0]);
                close(child_out[1]);
                close(child_err[1]);
                p->pid = pid;
                p->stdin = child_in[1];
                p->stdout = child_out[0];
                p->stderr = child_err[0];
                wait(0);
                return pid;
        }
}

char* new_argv[] = {"/home/hacker/bash", "qbzvqfcqfo",NULL};
char* new_envp[] = {NULL};
const char* open_file = "/tmp/plwkwg";

void pwncollege()
{
        printf("Ahoy sir\n");
        return;
}

int main()
{
        printf("Executing C exploit\n");
        //int crap_fd = open(open_file, O_CREAT | O_RDWR, S_IWUSR | S_IRUSR);
        struct subprocess* new_p = (struct subprocess *) malloc(sizeof(struct subprocess));
        call(new_argv, new_envp, new_p);
        char my_buffer[4096] = {0};
        read(new_p->stdout, my_buffer, 4096);
        write(STDOUT_FILENO, my_buffer, 4096);
        return 0;
}
```

## Challenge 64

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

char* new_argv[] = {"/usr/bin/rev", NULL};
char* new_envp[] = {NULL};

const char* open_file = "/tmp/plwkwg";

int pipefd[2];

void pwncollege()
{
        printf("Ahoy sir\n");
        return;
}


int main()
{
        printf("Executing C exploit\n");
        if (pipe(pipefd) == -1)
        {
                perror("pipe");
                exit(1);
        }

        pid_t pid = fork();

        if (pid == 0)
        {
                pid_t pid_2 = fork();
                if (pid_2 != 0 )  /* Child proc */
                {
                        printf("Hello from child!\n");

                        close(pipefd[1]);  // close write end of the pipe
                        close(STDIN_FILENO);
                        dup2(pipefd[0], STDIN_FILENO);
                        close(pipefd[0]);

                        execve("/challenge/embryoio_level64", new_argv, new_envp);
                        //execve("/home/hacker/rev", new_argv, new_envp);
                }

                else  /* Very Child proc */
                {
                        printf("Hello from very child!\n");
                        close(pipefd[0]);  // close read end of the pipe
                        close(STDOUT_FILENO);
                        dup2(pipefd[1], STDOUT_FILENO);  // move stdout to be the write end of the pipe
                        close(pipefd[1]);

                        execve("/usr/bin/cat", new_argv, new_envp);
                        //execve("/challenge/embryoio_level64", new_argv, new_envp);
                }
        }

        else
        {
                printf("Hello from parent! child pid: %d\n", pid);

                waitpid(pid, 0, 0);
        }

        return 0;
}
```

## Challenge 66

```bash
find . -exec '{}' \;
```

## Challenge 67

`-quit` option stops processing other paths from the CLI.

```bash
find . -exec '{}' jkqlfouqfb \; -quit
```

## Challenge 69

Checks of bash script are performed on parent. \
The child process (C binary) is switched to the requested binary. \
So simply write an executable of execve(/embryoio), and execute it from a bash script. 

## Challenge 73

Execute child proc within a different directory:

```bash
(cd /tmp/fpyqct && exec /challenge/embryoio_level73)
```

The brackets allows execution of a subshell. \
`&&` is conditional, causes execution of child only if first command succeeded. 

Note the usage of `exec` is mandatory - to replace the whole memory view of the process. \
Without it, 3 processes are acctually spawned (parent, subshell, and subshell fork to embryoio).  

## Challenge 88

```bash
(exec -a /tmp/ztbbgg /challenge/$HOSTNAME)
```

Note - built in bash commands run in the context of parent process, that is why brackets are required!

## Challenge 90

Make a FIFO, and redirect it to `stdin` in Terminal 1:

```bash
/challenge/$HOSTNAME < ~/itay_fifo
```

On Terminal 2, send data to the FIFO:

```bash
echo kcjqhdpt > itay_fifo
```

## Challenge 93

Interactive FIFO. 

```bash
/challenge/$HOSTNAME < ~/itay_fifo > ~/itay_fifo_2
cat > itay_fifo # allows interactive input
cat itay_fifo_2 # read output
```

## Challenge 94

Write C binary, and call:

```c
dup2(STDIN_FILENO, 321)
```

## Challenge 97

```bash
kill -SIGHUP $PID
```

## Challenge 107

```python
from pwn import *
import os, sys
from glob import glob

os.dup2(sys.stdin.fileno(), 74)
p = process("/challenge/embryoio_level107", close_fds=False)
p.interactive()
```

## Challenge 108

```python
from pwn import *
import os, sys

p = process("/challenge/embryoio_level108", close_fds=False)
p.stderr.write(bytes('siqattux\n','ascii'))
p.interactive()
```

It is good to know that input can be read from stdout and stderr, and written to `stdin` (by the program). \
0, 1 and 2 file descriptors are all pointing towards the same file, which is the `/dev/pts/<num>` character device file. 

## Challenge 109

The solution is identical to the above. \
This is extremely cool, as now the input is read from `stdout`. \
The reason is described above. 

## Challenge 125

`expect` seems natural for this challenge, however it isn't present within the machine. 

```python
from pwn import *
import os, sys
import time


def itay_parse():
    for line in sys.stdin:
        sys.stdout.write(line)


def solve():
    print("opening second file")

    file_2 = open("/home/hacker/itay_file_2", 'r')
    data = file_2.readlines()[-1].split('for:')[1][1:]
    result = eval(data)
    print(result)

    file_2.close()
    time.sleep(2)

def main():
    while True:
        solve()

if __name__ == '__main__':
    main()
```

## Challenge 126

Make `itay.sh` as a bash script that just launches the challenge regulary. \
Then, the following code solves the challenge:

```python
from pwn import *

def solve_chall(p):
    p.readuntil('for: ')
    data = p.read()
    result = str(eval(data))
    print(result)
    p.sendline(result)
    return

p = process(["/usr/bin/bash", "/home/hacker/itay.sh"])
for i in range(500):
    solve_chall(p)

print('going interactive')
p.interactive()
```

## Challenge 128

Important notice - `/bin/sh`'s kill and `/bin/bash`'s kill are different! \
The default shell being popped up is `sh`, so arguments are sent accordingly. 

```python
from pwn import *
import time
import re
import os
import subprocess

def solve_chall(p):
    p.recv()
    time.sleep(0.1)
    data = str(p.recvuntil("']"))

    pid = re.findall(r'(PID\s[1-9]+)', data)[0].split()[1]
    signals = re.findall(r'SIG.*\'', data)[0].split()

    print('Got signals: ')
    print(signals)

    i = 0
    for sig in signals:
        i += 1
        if i != 500:
            sig = str(sig[:-2])
        else:
            sig = str(sig[:-1])
        if sig[0] == '\'':
            sig = sig[1:]
        sig = sig[3:]  # need to send it on /bin/sh format, NOT /bin/bash!!

        print("New signal: ", sig)
        command = 'kill -s {} {}'.format(sig, pid)
        subprocess.Popen(command, shell=True)
        ans = p.recv()
        print(ans)

    p.interactive()
    return

p = process(["/usr/bin/bash", "/home/hacker/itay.sh"])
solve_chall(p)
```

## Challenge 129

Add `stdin=PIPE, stdout=PIPE` to chall 126 code.

[c-pipes]: https://jameshfisher.com/2017/02/17/how-do-i-call-a-program-in-c-with-pipes/
