---
layout:     post
title:      "Padding Oracle Attack 备忘录"
subtitle:   ""
date:       2019-12-21 14:14:00
author:     "kuron3k0"
header-img: "img/post-bg-alitrip.jpg"
tags:
    - Crypto
---

最近Shiro出了Padding Oracle的漏洞，听说了这么久，终于在现实世界看到这种攻击，本想好好分析下，但是还是太懒了，然后就不了了之了哈哈哈。等到今天虎哥跟我们分享了Padding Oracle之后，我就刚好趁还记得收藏一下做个备忘，每次看完都要忘一遍。。


### 0x00 漏洞利用条件

先把漏洞利用条件说清楚一下，首先是会有这么一个类似的场景，服务端加密了一些凭据信息，把它作为我们的cookie，这个时候我们带cookie访问的话，是`会触发服务端的解密操作`，然后第二点也是最关键的一点，`服务器会对解密时的密码错误和Padding错误有不同响应`，比如Padding错了的话，会返回500，密码错误的话，会返回200，并提示密码错误。


### 0x01 漏洞分析

这种攻击说到底就是CBC的加密方式导致的。CBC就是分组加密，比如下图，明文分成等长的三块，最后一块不够长的话，就会进行`Padding`，补到够为止，然后还有IV（初始向量）和key（加密密钥），都跟块长度一样。首先IV和第一块明文异或，然后用key加密，加密算法是什么就不重要了，得到第一块密文，然后把这块密文作为下一个块的IV，一直重复这个过程到加密完成。
![](/img/in-post/Padding-Oracle/cbc-encrypt.png)


这里说下上面提到的这个漏洞的关键——Padding。PKCS#5是一种常见的Padding，像下图第一个例子，缺少5个字节，所以补5个0x05；第二个例子，缺少2个字节，就补2个0x02；以此类推，如果刚刚好不用补的话，就在后面补一个块长度的字节数，如第四个例子。
![](/img/in-post/Padding-Oracle/padding.png)


Padding Oracle有两种攻击方式，第一种是破解密文，第二种是伪造密文，而两种攻击方式都依赖于我们提交给服务器的密文块解密出来的中间值，从图中可以看到，无论IV是什么，只要key和密文不变，这个中间值是不会改变的。
![](/img/in-post/Padding-Oracle/intermidiate_value.png)


首先破解密文，我们是逐块破解，而且破解顺序是随意的，因为每一块密文的IV我们都知道，只要中间值破解出来了，跟IV异或后即可得到明文。


那这个中间值怎么破解呢，比如我们的密文是AAAAAAAABBBBBBBBCCCCCCCC：

1. 分成三块：AAAAAAAA、BBBBBBBB、CCCCCCCC
2. 把第一块发到服务器去破解：`http://server/check?cipher=00000000AAAAAAAA`
3.  枚举IV的第一位，00000001，00000002，0000000X，IV会跟中间值进行异或得到明文，直到服务器没有返回Padding错误。（不用在意密文不一样，关注解密出来的结果就行了）
    ![](/img/in-post/Padding-Oracle/enum1.png)
    ![](/img/in-post/Padding-Oracle/enum2.png)
那么解密出来没有错误的情况其实有两种（虎哥牛逼），一种是`0xN	0xN	0xN	0xN	0xN	0xN	0xN	0x01`，前面的结果不重要，最后一位是`0x01`即可 ，另一种是`0x08	0x08	0x08	0x08	0x08	0x08	0x08	0x08`，如下图例子3、4，都是正确的Padding。
    ![](/img/in-post/Padding-Oracle/padding.png)
这个时候就要判断第二位是不是0x08，给服务端发送`http://server/check?cipher=000000YXAAAAAAAA`，X是刚才已经试出来的使Padding没错的字节，Y是与刚才不同的字节，如果这时候Padding没有错，证明第二位是对Padding没有影响的，因为第二种情况需要所有位置都是`0x08`，所以是刚才的结果是第一种情况。
    ![](/img/in-post/Padding-Oracle/enum3.png)
4. 这时我们知道了解密出来的明文第一位是`0x01`，也知道了IV——0000000X的第一位`X`，那我们把X和0x01异或之后就得到了AAAAAAAA解密后中间值的第一位
5. 然后我们调整`X`，使`X`异或中间值第一位的结果为`0x02`，然后枚举IV的第二位`Y`，发到服务器解密`http://server/check?cipher=000000YXAAAAAAAA`，而不会出现Padding错误的情况，只有当解密结果为`0xN	0xN	0xN	0xN	0xN	0xN	0x02	0x02
`即第一第二位都为0x02的时候
    ![](/img/in-post/Padding-Oracle/enum4.png)
    ![](/img/in-post/Padding-Oracle/enum5.png)
6. 以此类推，把中间值算出来后，与正确的IV异或，即可得到明文


然后我们来看看伪造密文，其实是大同小异。之前看到一篇文章就是写到这里，然后说：
> 伪造密文是一样步骤，你们仔细想想是不是这样？

.......大哥，我就想看怎么伪造啊，那啥都脱了你给我看这个= =。果然还是自己动手丰衣足食，纠结了好久之后终于想明白了。

借用彬神说的场景，有一个任意文件读取的URL，但是filename是AES-CBC-128加密的，现在我想构造/etc/passwd的密文，Padding后分成两块，像这样：
    ![](/img/in-post/Padding-Oracle/passwd.png)

跟解密不一样，伪造密文需要从最后一块开始。因为如果你从第一块开始的话，你通过调整IV得到了第一块明文`/etc/pas`的密文，这个时候第二块的IV（第一块的密文）也就确定了，无法改变，只能调第二块的密文得到我们想要的明文结果（是这样吧？应该没有想错，有的话请大佬斧正）。

来伪造密文：

1. 随意选八个字节，没错就是任意选，然后用前面的方法确定这个密文解密出来的中间值，然后跟`s w d 0x05 0x05 0x05 0x05 0x05`异或，得到第二块的IV，也就是第一块密文
    ![](/img/in-post/Padding-Oracle/fake1.png)
2. 然后同样的，枚举第一块的IV，利用Padding Oracle得到第一块密文的中间值，把这个中间值和`/etc/pas`异或，得到第一块的IV，至此，密文伪造完成


这里还有虎哥提到的[一篇可以用Padding Oracle破解加密密钥的文章](https://blog.gdssecurity.com/labs/2015/10/26/exploiting-padding-oracle-to-gain-encryption-keys.html)，有点吓人，不过其实条件也比较苛刻，需要IV和key一样以及第一块明文已知或容易猜解，有兴趣的大佬可以看一下。

Shiro RCE的洞就是在这个攻击的基础上套上反序列化，就不再分析了。






### 0x02 Reference

-   [https://blog.gdssecurity.com/labs/2015/10/26/exploiting-padding-oracle-to-gain-encryption-keys.html](https://blog.gdssecurity.com/labs/2015/10/26/exploiting-padding-oracle-to-gain-encryption-keys.html)
- [http://blog.zhaojie.me/2010/10/padding-oracle-attack-in-detail.html](http://blog.zhaojie.me/2010/10/padding-oracle-attack-in-detail.html)
- [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)

