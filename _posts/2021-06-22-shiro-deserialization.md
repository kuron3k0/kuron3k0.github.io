---
layout:     post
title:      "Shiro反序列化漏洞学习"
subtitle:   ""
date:       2021-06-11 20:13:14
author:     "kuron3k0"
header-img: "img/post-bg-2015.jpg"
tags:
    - Java
---

前面把shiro近期的权限绕过漏洞过了一下，现在把反序列化的也搞一搞

## CVE-2016-4437(ver < 1.2.5)
对比1.2.4和1.2.5代码的区别，把默认的AES加密秘钥删掉了
![](/img/in-post/shiro-deserialize/1.png)

这里用urldns来反序列化，用默认的秘钥加密一下
```python
from Crypto.Cipher import AES
import base64
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:
    def __init__( self, key ):
        """
        Requires hex encoded param as a key
        """
        self.key = key

    def encrypt( self, raw ):
        """
        Returns hex encoded encrypted value!
        """
        raw = pad(raw)
        iv = Random.new().read(AES.block_size);
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        """
        Requires hex encoded param to decrypt
        """
        enc = enc.decode("hex")
        iv = enc[:16]
        enc= enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc))

if __name__== "__main__":
    key = base64.b64decode('kPH+bIxk5D2deZiIxcaaaA==')
    with open('shiro_urldns','rb') as f:
        s=f.read()
    encryptor = AESCipher(key)
    plaintext = encryptor.encrypt(s)
    print("%s" % plaintext)

```

放到rememberMe的cookie中
![](/img/in-post/shiro-deserialize/3.png)

反序列化成功
![](/img/in-post/shiro-deserialize/2.png)

过程挺简单，先是从AbstractShiroFilter开始，调用createSubject函数创建Subject
![](/img/in-post/shiro-deserialize/4.png)

后面会到`CookieRememberMeManager`，base64解码
![](/img/in-post/shiro-deserialize/6.png)

cookie名在初始化的时候指定为`rememberMe`
![](/img/in-post/shiro-deserialize/5.png)

用默认秘钥进行AES解密
![](/img/in-post/shiro-deserialize/7.png)

最后readObject反序列化
![](/img/in-post/shiro-deserialize/8.png)


## CVE-2019-12422(ver < 1.4.2)

这个洞反序列化的过程和上面的并无不同，关键就是通过padding oracle把我们想要的密文构造出来就行了

密文伪造之前分析过，具体可以看一下[以前的文章](https://kuron3k0.github.io/2019/12/21/Padding-Oracle-Attack/)

具体伪造流程：
1. 首先选取需要加密的明文M，按16字节（一块的大小）分成n块，最后一块不够16字节的话，用padding补好
2. 从最后一块开始，选取16个随机字节作为密文，在前面拼上iv（需要我们自己枚举，最开始可设为全0），发到服务器做解密，根据服务器反馈判断解密出来的padding是否正确；解密有一个中间值是不会变的，我们要做的就是枚举iv，算出这个中间值：先调整iv最后一位，使得解密出来的中间值与iv异或后最后一位是0x01，成功后即会得到padding为正确的反馈，然后这个时候中间值最后一位已经知道，将iv最后一位调整为与中间值最后一位异或后是0x02的值，并按照最后一位的方法开始枚举iv倒数第二位，直到16位都完成
3. 最终和我们的明文异或，就得到了上一块的密文
4. 对每一块明文，重复上面的过程，最终得到完整密文

这个时候可能会有个问题，第二步如果枚举iv最后一位的时候，解密后的倒数第二位已经是0x02（只是在枚举iv最后一位，倒数第二位是固定的），那么padding成功的反馈实际上是因为两个0x02（我们以为是一个0x01）。举个例子：iv最后一位是`11111110`，中间值最后一位`11111100`，异或为`00000010`（即为2），但是我们以为是`00000001`，所以中间值最后一位我们就认为是`11111110 xor 00000001 = 11111111`，枚举iv倒数第二位时， 就会把iv最后一位设置为`11111101（11111111 xor 11111101 = 00000010）`，但实际上真实的值异或出来应该是`11111101 xor 11111100 = 00000011（3）`，只有当倒数第三位是3才会有padding正确的反馈，不然的话遍历完256种情况也不会成功

鉴于这种情况，最好的做法是得到padding成功的反馈后，调整iv的前一位，如果还是反馈正确，那就没问题，不然的话需要调整一下iv的当前位

回到shiro这里，我们需要找到反馈padding是否正确的地方。容易发现`convertBytesToPrincipals`函数中如果padding不对会抛出异常
![](/img/in-post/shiro-deserialize/9.png)
![](/img/in-post/shiro-deserialize/10.png)

最终会返回http头：`Set-Cookie: rememberMe=deleteMe`
![](/img/in-post/shiro-deserialize/11.png)

于是开始伪造密文，先从最后一块密文`C[n]`开始，把`rememberMe=base64(iv + C[n])`发到服务器，结果发现枚举了一轮，一直都是返回`deleteMe`？

看了一下发现后台发现是反序列化出错，因为我们随机选的密文解出来肯定不是一个类的序列化字节码，反序列化会出错因此也会进到异常分支，输出`deleteMe`
![](/img/in-post/shiro-deserialize/12.png)

所以我们需要一个正常的`rememberMe Cookie`，保证反序列化成功，这样才能过这个地方。但是又有一个问题，这个时候我们的伪造密文只能appand到加密后的字节码后面，有一个前缀在，那iv不是固定了吗？如果要枚举iv的话，会变成这种形式：`iv1 + encryptedCookie + iv2 + 我们选的随机密文`，这样应该不能解密成功？

尝试了一下用秘钥加密了`123`，两段单独的加密扔给服务器解析，看看是什么情况
![](/img/in-post/shiro-deserialize/13.png)

两个`123`都解出来了，之前还是脑子抽筋了，第二个iv是什么都不影响解密，因为最后一块的解密是用第二块iv来做异或的，中间的乱码就是把iv当做密文解密，然后中间值与`123\r\r\r\r\r\r\r\r\r\r\r\r\r`异或得出的结果，对解密没有影响
![](/img/in-post/shiro-deserialize/14.png)

因此只需要按照正常padding oracle进行即可，只是多了一个前缀，这里参考了[inspiringz大佬的脚本](https://github.com/inspiringz/Shiro-721/blob/master/exp2_%E6%89%8B%E5%B7%A5%E5%AE%9E%E7%8E%B0/shiro_oracle_padding.py)，我在这个基础上检查了上面提到的问题，具体代码看[这里](https://github.com/kuron3k0/shiro_padding_oracle/blob/main/shiro_oracle_padding.py#L50)
![](/img/in-post/shiro-deserialize/17.png)


运行脚本，得到payload
![](/img/in-post/shiro-deserialize/16.png)

burp发包，反序列化成功
![](/img/in-post/shiro-deserialize/18.png)

## 参考
- [https://github.com/apache/shiro/compare/shiro-root-1.2.4%E2%80%A6shiro-root-1.2.5](https://github.com/apache/shiro/compare/shiro-root-1.2.4%E2%80%A6shiro-root-1.2.5)
- [https://github.com/apache/shiro/commit/a8018783373ff5e5210225069c9919e071597d5e](https://github.com/apache/shiro/commit/a8018783373ff5e5210225069c9919e071597d5e)
- [https://github.com/inspiringz/Shiro-721/blob/master/exp2_%E6%89%8B%E5%B7%A5%E5%AE%9E%E7%8E%B0/shiro_oracle_padding.py](https://github.com/inspiringz/Shiro-721/blob/master/exp2_%E6%89%8B%E5%B7%A5%E5%AE%9E%E7%8E%B0/shiro_oracle_padding.py)