---
layout:     post
title:      "OAuth安全学习——RCE篇（CVE-2016-4977 && CVE-2018-1260）"
subtitle:   ""
date:       2021-01-18 10:40:00
author:     "kuron3k0"
header-img: "img/home-bg-o.jpg"
tags:
    - OAuth
    - Web
---

上一篇文章主要是OAuth流程上的一些漏洞，然后本文就是对历史上的OAuth的RCE漏洞进行分析学习

## 漏洞简介
OAuth在处理异常的时候，调用了SpelView导致表达式注入

## 环境搭建
下载`http://secalert.net/research/cve-2016-4977.zip`，用idea导入maven项目，在`WhitelabelErrorEndpoint`和`OAuth2Exception`下个断点
![](/img/in-post/oauth-security-rce1/1.png)

![](/img/in-post/oauth-security-rce1/2.png)

## CVE-2016-4977
访问`http://127.0.0.1:8080/oauth/authorize?response_type=token&client_id=acme&redirect_uri=${999-1}`，因为这里uri有问题，直接进入`OAuth2Exception`，错误信息为`invalid redirect：${999-1}……`
![](/img/in-post/oauth-security-rce1/3.png)

生成`ModelAndView`对象，forward到`/oauth/error`
![](/img/in-post/oauth-security-rce1/4.png)

`DispatcherServlet`做分发
![](/img/in-post/oauth-security-rce1/5.png)

其中提取`错误信息的model对象`，写入request的attribute
![](/img/in-post/oauth-security-rce1/6.png)

`/oauth/error`这里从request中取出了error，并得到详细信息，然后生成新的MV对象，View是`SpelView`，model是详细错误信息
![](/img/in-post/oauth-security-rce1/7.png)

第一次渲染`SpelView`，发现`${errorSummary}`，然后进入`resolvePlaceholder`函数
![](/img/in-post/oauth-security-rce1/8.png)

`errorSummary`就是我们错误的详细信息，EL解析完即可得到我们的恶意payload
![](/img/in-post/oauth-security-rce1/9.png)

这里判断如果解析完的值不为空的话，递归调用`parseStringValue`函数
![](/img/in-post/oauth-security-rce1/10.png)

得到`999-1`，表达式解析完得到`998`
![](/img/in-post/oauth-security-rce1/11.png)

最后是正常的调用，弹出计算器
![](/img/in-post/oauth-security-rce1/12.png)

## CVE-2018-1260
其实跟上一个漏洞是一样的表达式注入，只是在不同地方

全局搜一下`SpelView`，可以发现在`/oauth/confirm_access`中还有一个调用点
![](/img/in-post/oauth-security-rce1/13.png)

访问`http://127.0.0.1:8080/oauth/authorize?response_type=code&client_id=acme&redirect_uri=http://localhost&scope=%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22calc.exe%22%29%7D`，来到`validateScope`函数，这里需要client的scope设为空，不然会过不了
![](/img/in-post/oauth-security-rce1/14.png)

跳转到`/oauth/confirm_access`
![](/img/in-post/oauth-security-rce1/15.png)

取出model中的scope拼进`template`中
![](/img/in-post/oauth-security-rce1/16.png)

用`template`生成一个`SpelView`对象，然后后面就跟之前一样了
![](/img/in-post/oauth-security-rce1/17.png)

## 参考
- [https://paper.seebug.org/70/](https://paper.seebug.org/70/)
- [https://github.com/spring-projects/spring-security-oauth/](https://github.com/spring-projects/spring-security-oauth/)
