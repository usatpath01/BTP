#Kernel Installation

1. Fully update your operating system.
```
sudo apt update && sudo apt upgrade -y
```
2. Download and install the essential packages to compile kernels.
```
sudo apt install build-essential libncurses-dev libssl-dev libelf-dev bison flex -y

```

3. Clean up your installed packages.
```
sudo apt clean && sudo apt autoremove -y
```

4. Download kernel version 5.8.1 source code.
```
wget -P ~/ https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.8.1.tar.xz
```

5. Unpack the tarball you just downloaded to your home folder.
```
tar -xvf ~/linux-5.8.1.tar.xz -C ~/

```

#CREATION

1. Change your working directory to the root directory of the recently unpacked source code.
```
cd ~/linux-5.8.1/
```

2. Create the home directory of your system call.
Decide a name for your system call, and keep it consistent from this point onwards. I have chosen identity.
```
mkdir identity
```

3. Create a C file for your system call.
```
nano identity/identity.c
```

4. Copy the code from kernel_programming/identity/identity.c (git repositry) to the identity.c in your system.

5. Create a Makefile for your system call.
```
nano identity/Makefile
```
Write the following code in it.
```
obj-y := identity.o
```
6. Replace the kernel makefile with the Makefile in kernel_programming (git repositry).

7. Replace include/linux/syscalls.h in your system with the syscall.h present in kernel_programming in git repo.

8. Replace arch/x86/entry/syscalls/syscall_64.tbl in your system with syscall_64.tbl present in kernel_programming in git repo.


#Installation

1. Configure the kernel
```
make menuconfig
```
Make no changes to keep it in default settings.
Save and exit

Note : Only need to do this step one time only. No need to redo while compiling kernel code again.

2. Compile kernel code
```
make ARCH=$(arch) -j$(nproc)
```

3. Prepare the installer of the kernel
```
sudo make modules_install ARCH=$(arch) -j$(nproc)
```

4. Install the kernel
```
sudo make install ARCH=$(arch) -j$(nproc)
```

5. sudo update-grub

6. Reboot the System

#Checking

1. Make a directory named "apache2" in var/log directory

2. Check the new system call by running test.c provided int git repo
```
gcc test.c
```
3. Run it
```
./a.out
```

4. Check if date and pid are appended to the string in var/log/apache2/lol.txt in your system.

#Replacing Write syscall

Note: First do testing on "identity" syscall before modifying write syscall

1. Replace linux-5.8.1/fs/read_write.c in your system with kernel_programming/read_write.c to make write system call working.

2. Recompile the kernel (follow Installation steps 2-6)

3. Check write system call by writing a C-programm.

Note: You have to add code in 
'''SYSCALL_DEFINE3(write, unsigned int, fd, const char \_\_user *, buf, size_t, count)''' function in read_write.c to modify it furhter.