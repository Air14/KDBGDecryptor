# KDBGDecryptor
A simple example how to decrypt kernel debugger data block with two different methods:

1. By calling KdDecodeBlockData 
2. By copying encrypted kdbg struct from memory and then decrypting it with KiWaitNever and KiWaitAlways (more stealthy)

This sample was tested on Windows 20H2 (build 19042)