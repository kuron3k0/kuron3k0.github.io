---
layout:     post
title:      "内网Mysql代理浅析"
subtitle:   ""
date:       2020-7-7 14:14:00
author:     "kuron3k0"
header-img: "img/post-bg-alitrip.jpg"
tags:
    - RedTeam 
---

最近看到TX的一篇[红蓝对抗的文章](https://mp.weixin.qq.com/s/OGiDm3IHBP3_g0AOIHGCKA)，其中提到了Mssql代理，遂联想到Mysql应该也是一样的原理。于是网上一顿乱搜，不过只找到一篇[老外的博客](https://x-c3ll.github.io/posts/Pivoting-MySQL-Proxy/)，下面就来大概讲讲具体的利用。


### 0x00 使用场景

在渗透测试中，由于防火墙的原因，目标主机可能只开放了某一个业务端口，其余反连和直连的端口被全部禁用了，借用[mssqlproxy](https://github.com/blackarrowsec/mssqlproxy)的一个图，很好的呈现了这种场景。
![](/img/in-post/mysqlproxy/scenario.png)

这个时候我们虽然可以利用UDF执行命令，但是十分不方便，于是就有了下面的说法。

### 0x01 原理

关键原理就是UDF和Socket Reuse。Mysql UDF各位师傅应该都很熟悉，这里就不详细讲了；而Socket Reuse，虽然我是第一次听说，但其实很早就有相关的概念了：
> Socket-reuse shellcode is used to bypass firewalls. Usually, shellcode and exploit developers and users provide "bindshell" and "connect-back" shellcodes. Both of these require a permissive firewall to some extent or another. However, because sockets are treated as re-usable or dynamic file descriptors by most operating systems, it is possible to examine existing socket connections, therefore one can simply bind a shell to the socket that the exploit shellcode came from.

具体可以看下[这篇文章](https://nets.ec/Shellcode/Socket-reuse)


### 0x02 踩坑过程

一开始想着跑跑代码能用就行了，毕竟也不是很难的技术，原理也比较简单，但我就是自带用不了别人poc的属性，死活跑不起来，没办法，只能自己调代码了。


来看下关键代码逻辑，先看攻击端，首先连接Mysql数据库，然后进入proxy_init函数，传参是3，其实就是我们连接数据库的那个socket的fd，012是标准输入输出那些
![](/img/in-post/mysqlproxy/connect.png)

执行已经加载好的UDF函数，并读取服务端返回的一个特定字符串，确定服务端代码已经执行，跳出循环，`select_fd[0]`即数据库链接fd
![](/img/in-post/mysqlproxy/execudf.png)

在本地监听任意可用的端口，这里用了`1337`,`select_fd[1]`是我们用`proxychains`连接时产生的fd
![](/img/in-post/mysqlproxy/listen.png)

后面就是上面提到的这两个fd循环读取和写数据了。

感觉没什么问题，因为客户端的代码是可以跑起来的，也能成功执行服务端的函数，执行`proxychains ssh root@127.0.0.1`，抓个包验证一下(不熟悉socks5的师傅可以看看[这个](https://segmentfault.com/a/1190000020174099))，客户端先发送了`05 01 00`，`05`是版本号，`01`是支持的认证方式总数，后面就是认证方式，`00`即`NOAUTH`
![](/img/in-post/mysqlproxy/invite.png)

服务端返回`05 00`，同样`05`是版本号，`00`是服务端选择的认证方式
![](/img/in-post/mysqlproxy/authrsp.png)

至此认证是已经完成了的，然后就是客户端发送命令`05 01 00 01 7f 00 00 01 00 16`，各字节含义如下：
![](/img/in-post/mysqlproxy/cmd.png)

- `05` 版本号
- `01` CONNECT命令
- `00` 保留字段
- `01` 地址类型为IPv4
- `7f 00 00 01` IP地址127.0.0.1
- `00 16` 端口号22

发现服务端一直没有`PSH ACK`的回应，于是客户端发了FIN结束连接，所以问题在服务端

客户端执行`select do_carracha('a');`之后，服务端用getpeername遍历所有fd，通过ip匹配上我们的连接，并fork出一个子进程，执行payload
![](/img/in-post/mysqlproxy/doca.png)

最终子进程执行了worker函数，fd就是客户端的数据库连接，红框中的socks5_invitation和socks5_auth分别对应了客户端发的`05 01 00`和服务端发的`05 00`
![](/img/in-post/mysqlproxy/worker.png)

所以为什么socks5_command这里出了问题？原来的代码读了`05 01 00 01 7f 00 00 01 00 16`的前4个字节
![](/img/in-post/mysqlproxy/precmd.png)

然后判断第4个字节是否`01`，但是判断socks命令类型不应该是判断第2个字节吗......虽然结果是一样的，这里就假设是对的
![](/img/in-post/mysqlproxy/ip1.png)
![](/img/in-post/mysqlproxy/ip2.png)

所以应该是服务端读的问题了，于是尝试了好多种方式打印command，但是写文件不知道为什么写不了，用gethostbyname发到dnslog也发不出去，system也执行不了命令，可能是权限的原因？不过也没有深究了，因为虽然写不了文件，但是文件是可以创建的，把command拼到文件名即可。

最后发现是command前面多了一个`00`......所以是socks5_invitation这里读少了一个字节，擦，那作者是怎么跑成功的......
![](/img/in-post/mysqlproxy/haha.png)

所以就把上面那里读少的字节读完，就可以跑了，启动代理
![](/img/in-post/mysqlproxy/runproxy.png)

成功连接
![](/img/in-post/mysqlproxy/shell.png)


### 0x03 Reference

- [https://mp.weixin.qq.com/s/OGiDm3IHBP3_g0AOIHGCKA]()
- [https://x-c3ll.github.io/posts/Pivoting-MySQL-Proxy/]()
- [https://github.com/blackarrowsec/mssqlproxy]()
- [https://segmentfault.com/a/1190000020174099]()
- [https://nets.ec/Shellcode/Socket-reuse]()

