# pwnable.kr_syscall
\#pwnable \#kernel exploit 

###syscall.c
```cpp
// adding a new system call : sys_upper

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>

#define SYS_CALL_TABLE		0x8000e348		// manually configure this address!!
#define NR_SYS_UNUSED		223

//Pointers to re-mapped writable pages
unsigned int** sct;

asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}

static int __init initmodule(void ){
	sct = (unsigned int**)SYS_CALL_TABLE;
	sct[NR_SYS_UNUSED] = sys_upper;
	printk("sys_upper(number : 223) is added\n");
	return 0;
}

static void __exit exitmodule(void ){
	return;
}

module_init( initmodule );
module_exit( exitmodule );

```

This is the kernel exploit problem!  We can find the line "sys_upper(number : 223) is added". It means that *module_init( initmodule );* was done successfully. 

There is a simple vulnerability in the given source code, "syscall.c". 
If the in[i] value is not between 0x61~0x7a, out[i] can be overwritten with in[i]. Both out[i] and in[i] are adjustable as the attacker likes. The vulnerability is attributed to this block without any boundary check!
```cpp
else{
			out[i] = in[i];
		}
```
In kernel exploit, if we want to escalate to root, this should be conducted. 
>commit_creds(prepare_kernel_cred(0));

This is similar to setuid(0).

If we change any syscall function to commit_creds and prepare_kernel_cred, we can escalate to root! Those syscall functions need only one argument. Therefore, we will choose the syscall functions need only one argument, which are stime(25) and time(13)

The address of prepare_kernel_cred and commit_creds can be found in /proc/kallsyms. Also, the syscall number can be found in /usr/include/arm-linux-gnueabihf/asm/unistd.h.

We will overwrite stime function with the address of commit_creds and time function with the address of prepare_kernel_creds. Unfortunately, the last byte of the address of commit_creds(0x6c) is between 0x61~0x7a. Therefore, we have to overwrite 0x8003f560(commit_creds) with meaningless instructions like *mov r1,r1 (\x01\x10\xa0\xe1)* and overwrite stime function with the address of *commit_creds-12*. So that the function commit_creds will start with meaningless 12bytes. 

After calling syscall(25(syscall(13,0)), we will escalate to root!
Done!
