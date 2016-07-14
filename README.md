Linux System Administrator/DevOps Interview Questions
====================================================

A collection of linux sysadmin/devops interview questions. Feel free to contribute via pull requests, issues or email messages.


## <a name='toc'>Table of Contents</a>

  1. [Contributors](#contributors)
  1. [General Questions](#general)
  1. [Simple Linux Questions](#simple)
  1. [Medium Linux Questions](#medium)
  1. [Hard Linux Questions](#hard)
  1. [Expert Linux Questions](#expert)
  1. [Networking Questions](#network)
  1. [MySQL Questions](#mysql)
  1. [DevOps Questions](#devop)
  1. [Fun Questions](#fun)
  1. [Demo Time](#demo)
  1. [Other Great References](#references)


####[[⬆]](#toc) <a name='contributors'>Contributors:</a>

* [moregeek](https://github.com/moregeek)
* [typhonius](https://github.com/typhonius)
* [schumar](https://github.com/schumar)
* [negesti](https://github.com/negesti)
* peter
* [andreashappe](https://github.com/andreashappe)
* [quatrix](https://github.com/quatrix)
* [biyanisuraj](https://github.com/biyanisuraj)
* [pedroguima](https://github.com/pedroguima)
* Ben


####[[⬆]](#toc) <a name='general'>General Questions:</a>

* What did you learn yesterday/this week?
* Talk about your preferred development/administration environment. (OS, Editor, Browsers, Tools etc.)
* Tell me about the last major Linux project you finished.
* Tell me about the biggest mistake you've made in [some recent time period] and how you would do it differently today. What did you learn from this experience?
* Why we must choose you?
* What function does DNS play on a network?
* What is HTTP?
* What is an HTTP proxy and how does it work?
* Describe briefly how HTTPS works.
* What is SMTP? Give the basic scenario of how a mail message is delivered via SMTP.
* What is RAID? What is RAID0, RAID1, RAID5, RAID10?
* What is a level 0 backup? What is an incremental backup?
* Describe the general file system hierarchy of a Linux system.


####[[⬆]](#toc) <a name='simple'>Simple Linux Questions:</a>

* What is the name and the UID of the administrator user?
 * `root uid->0`
* How to list all files, including hidden ones, in a directory?
 * `ls -a`
* What is the Unix/Linux command to remove a directory and its contents?
 * `rm -rf`
* Which command will show you free/used memory? Does free memory exist on Linux?
 * `free; Don't confuse free memory with unused memory. Free memory, in the unix world is a page of physical memory that has no logical data mapped to it. Unused memory does have some data mapped to it, but it is currently not in active use by a running process. [Link](http://serverfault.com/questions/9442/why-does-red-hat-linux-report-less-free-memory-on-the-system-than-is-actually-av)`
* How to search for the string "my konfi is the best" in files of a directory recursively?
 * `grep -R "my konfi is the best" file_or_directory`
* How to connect to a remote server or what is SSH?
 * `telnet or ssh; SSH is Secure Shell`
* How to get all environment variables and how can you use them?
 * `printenv or env; use $VARIABLE`
* I get "command not found" when I run ```ifconfig -a```. What can be wrong?
 * `The path of ifconfig(/sbin) is not in your PATH`
* What happens if I type TAB-TAB?
 * `You will get a list of all available cmds in your PATH`
* What command will show the available disk space on the Unix/Linux system?
 * `df`
* What commands do you know that can be used to check DNS records?
 * `dig or nslookup`
* What Unix/Linux commands will alter a files ownership, files permissions?
 * `chown, chmod`
* What does ```chmod +x FILENAME```do?
 * `add execution permission to FILENAME`
* What does the permission 0750 on a file mean?
 * `user rwx; group rx; others none`
* What does the permission 0750 on a directory mean?
 * `user rw and go into; group r and go into; others none`
* How to add a new system user without login permissions?
 * `give user with /bin/false shell`
* How to add/remove a group from a user?
 * `add: usermod -a -G groupname user; remove: gpasswd -d user groupname`
* What is a bash alias?
 * `nothing more than a keyboard shortcut, or abbreviation`
* How do you set the mail address of the root/a user?
 * `put mail address in your .forward file`
* What does CTRL-c do?
 * `kill a process with the signal SIGINT`
* What is in /etc/services?
 * `associate human friendly name to machine friendly port`
* How to redirect STDOUT and STDERR in bash? (> /dev/null 2>&1) 
 * `> is STDOUT, 2> is STDERR`
* What is the difference between UNIX and Linux.
 * `Linux is a UNIX clone and free software; UNIX is not free, and was created by AT&T Bell Labs.`
* What is the difference between Telnet and SSH?
 * `SSH encryptes the communication, Telnet not.`
* Explain the three load averages and what do they indicate.
 * `last 1 min, 5mins, and 15mins`
* Can you name a lower-case letter that is not a valid option for GNU ```ls```?
 * `-y`


####[[⬆]](#toc) <a name='medium'>Medium Linux Questions:</a>

* What do the following commands do and how would you use them?
 * ```tee``` `read from standard input and write to files and standard output; use case: watching some (log)output and writing to a file`
 * ```awk``` `pattern scanning and processing language; use case: I want 2nd column of the output`
 * ```tr``` `Translate, squeeze, and/or delete characters from standard input, writing to standard output; use case: upper case to lower case`
 * ```cut``` `Print selected parts of lines from each FILE to standard output. use case: similar to awk` 
 * ```tac``` `Last line first out`
 * ```curl``` `a tool to transfer data from or to a server, using a lot of protocols, like HTTP, HTTPS, FTP etc; use case: cmdline HTTP test tool`
 * ```wget``` `a tool for download of file from web`
 * ```watch``` `execute a program periodically and output to the screen; use case: watch the system load`
 * ```head``` `output the first lines of the file; use case: check the first lines of logfile`
 * ```tail``` `print the last lines of the file to standard output; use case: continously watch the logfile`
* What does an ```&``` after a command do?
 * `If a command is terminated by the control operator &, the shell executes the command in the background in a subshell. The shell does not wait for the command to finish, and the return status is 0.`
* What does ```& disown``` after a command do?
 * `run the previous cmd in subshell, and run disown immediately`
* What is a packet filter and how does it work?
 * `a piece of software built into kernel which looks the header of packets and decide the fates of the packet. DROP, ACCEPT and so on`
* What is Virtual Memory?
 * `using disk as an extension of RAM so that usable memory grows correspondly; combined size of physical memory and swap space is the amount of VM available.`
* What is swap and what is it used for?
 * `when program requires more memory, the kernel swaps out less used pages to swap and give program more memory which it needs immediately.`
* What is an A record, an NS record, a PTR record, a CNAME record, an MX record?
 * `A stands for address(domain->IP), NS for nameserver, PTR opposite of A (IP->domain), CNAME for Canonical Name, MX for mail exchange`
* Are there any other RRs and what are they used for?
 * `AAAA for IPV6, TXT for human readable text record`
* What is a Split-Horizon DNS?
 * `base on the source of query, give different dns answers. For example: same domain can give two answers given external or internal networking conditions`
* What is the sticky bit?
 * `when the sticky bit of directory is set, in this directory, only the file's owner, dir's owner or root can delete or rename it. Without it, any users can do; For example: the sticky bit is normally enabled on /tmp; use chmod +t or chmod -t`
* What does the immutable bit do to a file?
 * `a file with immutable bit can NOT be modified/renamed/deleted and no hard/soft link can be created; only root user can add immutable bit, for example: chattr +i/-i filename and lsattr filename`
* What is the difference between hardlinks and symlinks? What happens when you remove the source to a symlink/hardlink?
 * `hardlink and file points to the same inode; soft link points to a different inode(->datablock). That datablock points to the file. When there is no inode pointing to the datablock, the datablock will be removed by the VFS.`
* What is an inode and what fields are stored in an inode?
 * `inode is index node, which is a data structure which represents to the file system object. Each inode stores the attributes and disk block location(s) of the filesystem object's data.`
* How to force/trigger a file system check on next reboot?
 * `touch /forcefsck or shutdown -F -r now`
* What is SNMP and what is it used for?
 * `Simple Network Management Protocol; used for collecting and organizing info about managed devices on IP networks and for modifying that info to change device behavior.`
* What is a runlevel and how to get the current runlevel?
 * `a state of init and the whole system that defines what system services are operatings; 0 halt, 1 single user mode, 2 local multiuser without networking, 3 with networking, 4 not used, 5 full multiuser with networking and X, 6 Reboot; runlevel cmd for giving you the current runlevel`
* What is SSH port forwarding?
 * `create a secure connection between local machine and remote server, through which services can be relayed.`
* What is the difference between local and remote port forwarding?
 * `http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot; so basically local creating a tunnel for client -> server, remote creating a tunnel for client <- server.`
* What are the steps to add a user to a system without using useradd/adduser?
 * `edit /etc/passwd; edit /etc/group; create home dir; setup password by passwd cmd`
* What is MAJOR and MINOR numbers of special files?
 * `MAJOR number identifies the driver associates with the device, i.e /dev/null to driver 1; MINOR number is used by the kernel to determine exactly which device is being referred to. i.e. a direct pointer to your dvice from the kernel`
* Describe the mknod command and when you'd use it.
 * `make block or character special files; create a named pipe. one process reads from it, another writes to it.`
* Describe a scenario when you get a "filesystem is full" error, but 'df' shows there is free space.
 * `out of inodes`
* Describe a scenario when deleting a file, but 'df' not showing the space being freed.
 * `space will not be freed if the files are still opened. use lsof | grep deleted to find the open deleted files`
* Describe how 'ps' works.
 * `ps works by reading from proc file system. check "strace -e open ps"`
* What happens to a child process that dies and has no parent process to wait for it and what’s bad about this?
 * `it becomes zombie process; and it's not possible to kill it; it must be waited on by its parent process; Killing the parent process will solve it`
* Explain briefly each one of the process states.
 * `R: Running, D: uninterruptible sleep (wait IO), S: interruptible sleep(waiting for event to complete), Z: defunct/zombie, T: stopped `
* How to know which process listens on a specific port?
 * `netstat -anp | grep LISTEN`
* What is a zombie process and what could be the cause of it?
 * `a child process dies, but no parent process waits for it.`
* You run a bash script and you want to see its output on your terminal and save it to a file at the same time. How could you do it?
 * `program | tee filename`
* Explain what echo "1" > /proc/sys/net/ipv4/ip_forward does.
 * `enable ip forwarding on the host`
* Describe briefly the steps you need to take in order to create and install a valid certificate for the site https://foo.example.com.
 * `create private key, generate csr request file, send to CA, get the signed valid cert and install in the apache server. cert with intermediate cert and priv key`
* Can you have several HTTPS virtual hosts sharing the same IP?
 * `Yes, as long as the server supports SNI (server name indication)`
* What is a wildcard certificate?
 * `a certificate can be used for all subdomains, i.e \*.google.com`
* Which Linux file types do you know?
 * `regular files, directories, block file, pipe, character device files, symbolic links, socket files`
* What is the difference between a process and a thread? And parent and child processes after a fork system call?
 * `threads of same process run in a shared memory space; while processes run in separated memory spaces.; fork creates a new process as child of the caller(parent) process (or duplicates the current process). They run in the separate memory space.`
* What is the difference between exec and fork?
 * `exec replaces the memory space with a new program.`
* What is "nohup" used for?
 * `when run a program in the shell, it forks a new process. When parent shell exits, the forked process will be killed too. nohup is used for telling the process to ignore SIGHUP.`
* What is the difference between these two commands?
 * ```myvar=hello``` `non-exported var is NOT available to other programs`
 * ```export myvar=hello``` `exported var is available to other programs`
* How many NTP servers would you configure in your local ntp.conf?
 * `if more than NTP server is required, then use four to avoid 'falseticker'`
* What does the column 'reach' mean in ```ntpq -p``` output?
 * #TODO
* You need to upgrade kernel at 100-1000 servers, how you would do this?
 * use some centralized configuration software, like puppet or cfengine.
* How can you get Host, Channel, ID, LUN of SCSI disk?
 * ```cat /proc/scsi/scsi```
* How can you limit process memory usage?
 * `use Linux control group, i.e. 500M for virtual memory, 5000M for swap`
 * ``` cgcreate -g memory:/myGroup
echo $(( 500 * 1024 * 1024 )) > /sys/fs/cgroup/memory/myGroup/memory.limit_in_bytes
echo $(( 5000 * 1024 * 1024 )) > /sys/fs/cgroup/memory/myGroup/memory.memsw.limit_in_bytes ```
 * ``` cgexec -g memory:myGroup your_program ```
* What is bash quick substitution/caret replace(^x^y)?
 * `take the last cmd and replace x with y, run it again`
* Do you know of any alternative shells? If so, have you used any?
 * `ZSH, fish shell, but I'm not using other shells so often`
* What is a tarpipe (or, how would you go about copying everything, including hardlinks and special files, from one server to another)?
 * `tar preserves hardlinks`
 * ``` tar -cf - . | ssh remote_server "tar -xpf -" ```

####[[⬆]](#toc) <a name='hard'>Hard Linux Questions:</a>

* What is a tunnel and how you can bypass a http proxy?
 * `SSH tunnel between your local machine and a remote server, using port forwarding to bypass http proxy or NAT`
* What is the difference between IDS and IPS?
 * `IDS->LOG vs IPS->LOG/DROP`
* What shortcuts do you use on a regular basis?
 * `Ctrl-d, Ctrl-z, <tab>, Ctrl-c, <middlebutton>`
* What is the Linux Standard Base?
 * `It's a joint project by several Linux distributions to standardize the software system structure, including filesystem hierarchy`
* What is an atomic operation?
 * `atomic operation provides instructions that execute atomically without interruption. It's never possible for two atomic operations to occur on the same variable concurrently. so not possible for the increments to race.`
* Your freshly configured http server is not running after a restart, what can you do?
 * `check logs, in rc levels ...`
* What kind of keys are in ~/.ssh/authorized_keys and what it is this file used for?
 * `public key in this file, the file is for key-auth`
* I've added my public ssh key into authorized_keys but I'm still getting a password prompt, what can be wrong?
 * `permission on the file should be 400`
* Did you ever create RPM's, DEB's or solaris pkg's?
 * #TODO
* What does ```:(){ :|:& };:``` do on your system?
 * `forkbomb`
* How do you catch a Linux signal on a script?
 * `in bash ``` trap [commands] [signals]``` `
* Can you catch a SIGKILL?
 * `No`
* What's happening when the Linux kernel is starting the OOM killer and how does it choose which process to kill first?
 * `The kernel maintains *oom_score* for each of the processes. ``` cat /proc/pid/oom_score ``` The higher the value, is likelihood of getting killed by OOM killer in an OOM situation.`
* Describe the linux boot process with as much detail as possible, starting from when the system is powered on and ending when you get a prompt.
 * `#TODO`
* What's a chroot jail?
 * ` http://unix.stackexchange.com/questions/105/chroot-jail-what-is-it-and-how-do-i-use-it
A chroot jail is a way to isolate a process from the rest of the system. It should only be used for processes that don't run as root, as root users can break out of the jail very easily.

The idea is that you create a directory tree where you copy or link in all the system files needed for a process to run. You then use the chroot system call to change the root directory to be at the base of this new tree and start the process running in that chroot'd environment. Since it can't actually reference paths outside the modified root, it can't maliciously read or write to those locations.

On Linux, using a bind mounts is a great way to populate the chroot tree. Using that, you can pull in folders like /lib and /usr/lib while not pulling in /user, for example. Just bind the directory trees you want to directories you create in the jail directory.`
* When trying to umount a directory it says it's busy, how to find out which PID holds the directory?
 * `lsof PATH or fuser PATH to find the running process.`
* What's LD_PRELOAD and when it's used
 * `That object will be loaded before any other shared objects, in order to overwrite some selected functions.`
* You ran a binary and nothing happened. How would you debug this?
 * `use strace to figure out what's going on.`
* What are cgroups? Can you specify a scenario where you could use them?
 * `control groups, allow you to allocate resources (CPU, memory, bandwidth) among user-defined groups of tasks running on a system.`


####[[⬆]](#toc) <a name='expert'>Expert Linux Questions:</a>

* A running process gets ```EAGAIN: Resource temporarily unavailable``` on reading a socket. How can you close this bad socket/file descriptor without killing the process?
 * `#TODO`


####[[⬆]](#toc) <a name='network'>Networking Questions:</a>

* What is localhost and why would ```ping localhost``` fail?
* What is the similarity between "ping" & "traceroute" ? How is traceroute able to find the hops.
* What is the command used to show all open ports and/or socket connections on a machine?
* Is 300.168.0.123 a valid IPv4 address?
* Which IP ranges/subnets are "private" or "non-routable" (RFC 1918)?
* What is a VLAN?
* What is ARP and what is it used for?
* What is the difference between TCP and UDP?
* What is the purpose of a default gateway?
* What is command used to show the routing table on a Linux box?
* A TCP connection on a network can be uniquely defined by 4 things. What are those things?
* When a client running a web browser connects to a web server, what is the source port and what is the destination port of the connection?
* How do you add an IPv6 address to a specific interface?
* You have added an IPv4 and IPv6 address to interface eth0. A ping to the v4 address is working but a ping to the v6 address gives yout the response ```sendmsg: operation not permitted```. What could be wrong?
* What is SNAT and when should it be used?
* Explain how could you ssh login into a Linux system that DROPs all new incoming packets using a SSH tunnel.
* How do you stop a DDoS attack?
* How can you see content of an ip packet?
* What is IPoAC (RFC 1149)?


####[[⬆]](#toc) <a name='mysql'>MySQL questions:</a>

* How do you create a user?
* How do you provide privileges to a user?
* What is the difference between a "left" and a "right" join?
* Explain briefly the differences between InnoDB and MyISAM.
* Describe briefly the steps you need to follow in order to create a simple master/slave cluster.
* Why should you run "mysql_secure_installation" after installing MySQL?
* How do you check which jobs are running?


####[[⬆]](#toc) <a name='devop'>DevOps Questions:</a>

* Can you describe your workflow when you create a script?
* What is GIT?
* What is a dynamically/statically linked file?
* What does "./configure && make && make install" do?
* What is puppet/chef/ansible used for?
* What is Nagios/Zenoss/NewRelic used for?
* What is the difference between Containers and VMs?
* How do you create a new postgres user?
* What is a virtual IP address? What is a cluster?
* How do you print all strings of printable characters present in a file?
* How do you find shared library dependencies?
* What is Automake and Autoconf?
* ./configure shows an error that libfoobar is missing on your system, how could you fix this, what could be wrong?
* What are the advantages/disadvantages of script vs compiled program?
* What's the relationship between continuous delivery and DevOps?
* What are the important aspects of a system of continuous integration and deployment?

####[[⬆]](#toc) <a name='fun'>Fun Questions:</a>

* A careless sysadmin executes the following command: ```chmod 444 /bin/chmod ``` - what do you do to fix this?
* I've lost my root password, what can I do?
* I've rebooted a remote server but after 10 minutes I'm still not able to ssh into it, what can be wrong?
* If you were stuck on a desert island with only 5 command-line utilities, which would you choose?
* You come across a random computer and it appears to be a command console for the universe. What is the first thing you type?
* Tell me about a creative way that you've used SSH?
* You have deleted by error a running script, what could you do to restore it?
* What will happen on 19 January 2038?


####[[⬆]](#toc) <a name='demo'>Demo Time:</a>

* Unpack test.tar.gz without man pages or google.
* Remove all "*.pyc" files from testdir recursively?
* Search for "my konfu is the best" in all *.py files.
* Replace the occurrence of "my konfu is the best" with "I'm a linux jedi master" in all *.txt files.
* Test if port 443 on a machine with IP address X.X.X.X is reachable.
* Get http://myinternal.webserver.local/test.html via telnet.
* How to send an email without a mail client, just on the command line?
* Write a ```get_prim``` method in python/perl/bash/pseudo.
* Find all files which have been accessed within the last 30 days.
* Explain the following command ```(date ; ps -ef | awk '{print $1}' | sort | uniq | wc -l ) >> Activity.log```
* Write a script to list all the differences between two directories.
* In a log file with contents as ```<TIME> : [MESSAGE] : [ERROR_NO] - Human readable text``` display summary/count of specific error numbers that occurred every hour or a specific hour.


####[[⬆]](#toc) <a name='references'>Other Great References:</a>

Some questions are 'borrowed' from other great references like:

* https://github.com/darcyclarke/Front-end-Developer-Interview-Questions
* https://github.com/kylejohnson/linux-sysadmin-interview-questions/blob/master/test.md
* https://github.com/gurmeet1109/docgurmeet/tree/master/InterviewQuestionsSamples
* http://slideshare.net/kavyasri790693/linux-admin-interview-questions
* https://github.com/gurmeet1109/docgurmeet/tree/master/InterviewQuestionsSamples
* https://github.com/kylejohnson/linux-sysadmin-interview-questions/blob/master/test.md
