## SSTIC 2021 Challenge Writeup

This repository hosts the files for my solution to the [SSTIC 2021 challenge](https://www.sstic.org/2021/challenge/). The corresponding writeup can be found on my website: https://www.robertxiao.ca/hacking/sstic-2021/.

## Files

- `README.md`: This readme
- `writeup.md`: Original Markdown source for the writeup
- `images/`: Images and diagrams for the writeup
- `files/`: Files and materials used in my solution
    - `DRM/`: Contents of `DRM.zip` exfiltrated from the stage 2 machine, containing the publicly-accessible components of the DRM solution
        - `DRM_server.tar.gz`: Runnable system image for the DRM key server
        - `Readme`: Message from `Trou` explaining the DRM solution
        - `libchall_plugin.so`: VLC plugin for accessing the DRM system
    - `stage1/`: Stage 1 solution files
        - `tshark-extract.sh`: Script to dump the pcap as JSON
        - `build-imgs.py`: Script to reconstruct disk images out of the pcap
    - `stage2/`: Stage 2 solution files
        - `chall/`: Original files extracted from the pcap disk image
            - `A..Mazing.exe`: Vulnerable Windows binary running on a remote server
            - `Readme.md`: A readme describing the maze challenge
            - `env.txt`: Text file describing the Windows server environment under which the binary runs
            - `flag.jpg`: The flag for stage 1
        - `A..Mazing.exe.{c,h}`: IDA decompilation of the Windows binary
        - `makeleak.py`: The first stage of the exploit, which makes a "leaker" maze that can be used to leak a heap address
        - `exploit.py`: The second stage of the exploit, which exploits several bugs to pop a shell on the server
    - `stage3/`: Stage 3 solution files
        - `libchall_plugin.so.{c,h}`: IDA decompilation of the VLC plugin
        - `guest.so`: Sample `guest.so` downloaded from the media server
        - `guest-test.c`: A C program to test the exported functionality of `guest.so`
        - `guest-dump.c`: A C program to dump the decrypted VM bytecode out of `guest.so` into `guest.vm`
        - `disas.py`: First disassembler, which produces an assembly-like syntax, used to understand the VM program
        - `interp-disas.py`: Second disassembler, which uses a Python syntax to permit easy simulation and tampering of the program
        - `interp.txt`: Sample output of the second disassembler
        - `interp-test.py`: A test harness which just emulates the VM using the second disassembler's output
        - `interp-encrypt.py`: A program which uses the targeted modification described in the writeup to encrypt data with arbitrary perms, thereby breaking the whitebox scheme
    - `stage4/`: Stage 4 solution files
        - `service.{c,h}`: IDA decompilation of the keyserver service binary
        - `pwcheck.prog`: Extracted custom ISA machine code for the keyserver's password check
        - `testprog.py`: A script for interactive online experimentation with the custom ISA
        - `disas.py`: Disassembler for the custom ISA developed through reverse-engineering the ISA
        - `disas.txt`: Disassembly for the password check program
        - `solvepw.py`: Solver for the password check to generate the expected password
        - `pw.bin`: The password that passes the keyserver's password check
        - `rce.py`: A script for sending the password and a binary program to achieve remote code execution on the keyserver
        - `prog.c`: A program for execution on the keyserver that dumps out all accessible DRM keys
    - `stage5/`: Stage 5 solution files
        - `sstic.ko.{c,h}`: IDA decompilation of the keyserver kernel driver
        - `poc{1,2,3,4}.c`: Various in-progress "proofs of concept" for the kernel exploit which demonstrate progressively more interesting behaviour
        - `exploit.c`: The final kernel exploit which gains full shellcode execution in the kernel and dumps out all remaining DRM keys
        - `shellcode.s`: The shellcode used in the exploit which flips off the DRM device's debug flag and escalates to root
        - `decrypt.py`: The final decryption script which downloads and decrypts all of the media files from the media server. This was progressively amended throughout the solve with keys as they were discovered.

## Organizer's Materials

The SSTIC organizers have open-sourced all of the components of the challenge. You can find the relevant repositories here:

- [offline](https://github.com/challengeSSTIC2021/offline): All the files necessary to host your own instance of the challenge
- [Step2_challenge](https://github.com/challengeSSTIC2021/Step2_challenge): The source code for the stage 2 Windows challenge
- [appjaillauncher-rs](https://github.com/challengeSSTIC2021/appjaillauncher-rs): The modified AppJailLauncher which ran the stage 2 Windows challenge
- [wb](https://github.com/challengeSSTIC2021/wb): The media server service for stages 3-5, including the whitebox crypto generator for stage 3
- [service](https://github.com/challengeSSTIC2021/service): The keyserver service for stages 3-5
- [qemu](https://github.com/challengeSSTIC2021/qemu): The modified qemu implementing the SSTIC hardware device for stages 3-5
