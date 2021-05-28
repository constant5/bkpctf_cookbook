# bkpctf_cookbook


These are the steps to reproduce heap overflow exploit detaile by LiveOverflow in the three part series:
Video write-up:

 * Part 1 - Reverse Engineering the binary - https://www.youtube.com/watch?v=f1wp6wza8ZI
 * Part 2 - Leaking heap and libc address - https://www.youtube.com/watch?v=dnHuZLySS6g
 * Part 3 - Creating an arbitrary write - House of Force - https://www.youtube.com/watch?v=PISoSH8KGVI

 The cookbook binary is found at: https://drive.google.com/file/d/1cu-UrL9GTc_toGKwnv0Nk-vI99oiMv0Q/view?usp=sharing

 You can DM me if you want access. 

 For debugging I set up the cookbook program to run as a service to run on my Ubuntu VM simply by using socat with the local ip:

$ socat TCP-LISTEN:6666,reuseaddr,fork EXEC:"./cookbook"

Then its easy to connect to the service from another terminal using netcat:

$ nc 127.0.0.1 6666

From here you can debug the running cookbook program using gdb:

$ gdb --pid=`pidof cookbook` cookbook

For additional debugging info you can add the GDB plugin - pwndbg - https://github.com/pwndbg/pwndbg.git

For diassembly of the binary files I used IDA Free from https://hex-rays.com/


