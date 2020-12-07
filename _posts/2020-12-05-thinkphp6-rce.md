---
layout:     post
title:      "Thinkphp 6 任意文件写入漏洞"
subtitle:   ""
date:       2020-12-05 10:40:00
author:     "kuron3k0"
header-img: "img/home-bg-geek.jpg"
tags:
    - PHP
    - 漏洞分析
---

## 环境搭建
直接用composer安装
```cmd
D:\tools\xampp\htdocs\thinkphp>php composer config -g repo.packagist composer https://mirrors.aliyun.com/composer/
```
```cmd
D:\tools\xampp\htdocs\thinkphp>php composer create-project topthink/think think6
```
下下来是最新的6.0.5版本，在comoposer.json改成有漏洞的版本然后update
![](/img/in-post/thinkphp6.0.1/version.png)
```cmd
D:\tools\xampp\htdocs\thinkphp\think6>php ../composer update
```
打开session
![](/img/in-post/thinkphp6.0.1/sessioninit.png)

修改一下控制器
![](/img/in-post/thinkphp6.0.1/test.png)


## 漏洞利用
其实就是session名没有校验，直接拼接到文件名中导致的跨目录写文件
![](/img/in-post/thinkphp6.0.1/exp.png)

## 漏洞分析
配vscode+xdebug调试环境整了好久，最后用了这个配置才行(本地调试)
![](/img/in-post/thinkphp6.0.1/6.png)

在index.php的最后下断点
![](/img/in-post/thinkphp6.0.1/7.png)

调用中间件的end函数
![](/img/in-post/thinkphp6.0.1/8.png)
![](/img/in-post/thinkphp6.0.1/9.png)

SessionInit中间件调用session的save函数
![](/img/in-post/thinkphp6.0.1/10.png)

但是session其实没有save函数，触发__call魔术方法，调用驱动的save函数
![](/img/in-post/thinkphp6.0.1/11.png)

一直追溯到Store类
![](/img/in-post/thinkphp6.0.1/12.png)
![](/img/in-post/thinkphp6.0.1/13.png)

Store->save中调用了write，sessionId通过getId获取，data是类属性
![](/img/in-post/thinkphp6.0.1/14.png)

跟进write看看是怎么做的，调用了getFilename，然后writeFile写文件
![](/img/in-post/thinkphp6.0.1/16.png)

很明显就是这里实现了路径穿越，还帮忙建目录了
![](/img/in-post/thinkphp6.0.1/17.png)

很直接的调用了file_put_contents
![](/img/in-post/thinkphp6.0.1/18.png)

然后再来看看路径(sessionId)和数据(data)是怎么传进来的，首先setId方法会对$this->id赋值，注意sessionId需要长度为32，不然会被md5处理
![](/img/in-post/thinkphp6.0.1/15.png)

这次从index.php的开头下断点，进入到runWithRequest，这里调用中间件的pipeline，类似servlet的filter一样，链式调用每个中间件的handle函数
![](/img/in-post/thinkphp6.0.1/19.png)

SessionInit的handle函数中，从cookie里取出了我们的PHPSESSID值，调用了上面的Store类中的setId方法
![](/img/in-post/thinkphp6.0.1/20.png)

然后data就是在控制器中调用`session("demo",$_GET['c']);`的时候，进入Store类的set方法，即`$this->data[$name] = $value;`
![](/img/in-post/thinkphp6.0.1/21.png)

Arr::set的第一个参数，传的是实参
![](/img/in-post/thinkphp6.0.1/22.png)


## 参考
[https://xz.aliyun.com/t/8546](https://xz.aliyun.com/t/8546)
