---
layout:     post
title:      "Shiro权限绕过历史漏洞学习"
subtitle:   ""
date:       2021-06-11 20:13:14
author:     "kuron3k0"
header-img: "img/post-bg-2015.jpg"
tags:
    - Java
---



## 0x00 Shiro简介
Apache Shiro™是一个强大且易用的Java安全框架,能够用于身份验证、授权、加密和会话管理。Shiro拥有易于理解的API,您可以快速、轻松地获得任何应用程序——从最小的移动应用程序到最大的网络和企业应用程序。

## 0x01 搭环境
先起一个spring boot，然后装好依赖
```java
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.4.0</version>
</dependency>
```

几个简单的controller
```java
@PostMapping("/doLogin")
public void doLogin(String username, String password) {
    Subject subject = SecurityUtils.getSubject();
    try {
        subject.login(new UsernamePasswordToken(username, password));
        System.out.println("登录成功!");
    } catch (AuthenticationException e) {
        e.printStackTrace();
        System.out.println("登录失败!");
    }
}

@ResponseBody
@RequestMapping(value="/admin/cmd", method= RequestMethod.GET)
public  String admin(){
    return "in admin panel";
}
```


配置也比较简单，新建一个继承`AuthorizingRealm`的类，其中重载的`doGetAuthenticationInfo`函数认证用的，这里插了一个账号进去；而`doGetAuthorizationInfo`则是授权用的
```java
class MyRealm extends AuthorizingRealm {

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }


    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        if("xxxxx".equals(username)){
            return new SimpleAuthenticationInfo(username, "yyyyy", getName());
        }
        return null;
    }
}
```

然后生成三个bean，一个是刚才的`MyRealm`；一个是设置了`MyRealm`的`DefaultWebSecurityManager`；最后是`ShiroFilterFactoryBean`，注意`setFilterChainDefinitionMap`设置的map包含了需要认证的url，用`authc`标记，可匿名访问则是`anon`。其中`/*`只匹配下一段url，而`/**`匹配后面所有的url
```java
@Configuration
class ShiroConfig {
    @Bean
    MyRealm myRealm(){
        return new MyRealm();
    }

    @Bean
    public DefaultWebSecurityManager manager(){
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(myRealm());
        return manager;
    }

    @Bean
    public ShiroFilterFactoryBean filterFactoryBean(){
        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(manager());
        factoryBean.setUnauthorizedUrl("/dologin");
        factoryBean.setLoginUrl("/dologin");
        Map<String, String> map = new HashMap<>();
        map.put("/dologin", "anon");
        map.put("/admin/*", "authc");
        factoryBean.setFilterChainDefinitionMap(map);
        return factoryBean;

    }

}
```

## CVE-2020-1957(ver < 1.5.2)
### 漏洞分析

正常访问/admin/cmd，会跳转到/doLogin
![](/img/in-post/shiro-bypass-vuln/1.png)

url后面加上斜杠，成功绕过
![](/img/in-post/shiro-bypass-vuln/2.png)


要实现绕过，就要让shiro匹配不上url，即`getChain`函数需要返回`null`、`pathMatches`函数一直返回`false`
![](/img/in-post/shiro-bypass-vuln/3.png)

跟进`pathMatches`，最后到达`AntPathMatcher`的`doMatch`函数，函数对`/admin/cmd/`以及shiro配置的路径`/admin/*`做了分词操作，admin匹配了admin，cmd匹配了*，最后到了如下代码

```java
if (pathIdxStart > pathIdxEnd) {
    if (pattIdxStart > pattIdxEnd) {
        return pattern.endsWith(this.pathSeparator) ? path.endsWith(this.pathSeparator) : !path.endsWith(this.pathSeparator);
```
`pathIdxEnd`和`pattIdxEnd`分别是`/admin/cmd/`和`/admin/*`根据斜杠split后的数组长度，`pathIdxStart`和`pattIdxStart`每遍历一段就加一，因为是正常遍历，且都匹配上了，所以最终会进到这个分支，因为pattern不是以`/`结尾的，所以函数的返回就是`!path.endsWith(this.pathSeparator)`，但是因为我们手动添加了一个`/`在后面，所以最终返回了`false`，实现了绕过


## CVE-2020-11989(ver < 1.5.3)
先说一个坑，spring boot的版本太高也是利用不了的。。因为`UrlPathHelper`的`getPathWithinServletMapping`函数中，由于从`getPathWithinApplication`获取路径的时候存在分号，所以导致`context-path`（即`/shiro`）无法删掉，低版本最终会返回`servletPath`，而高版本是不会返回的，因此导致后续匹配不上Controller的url，最终返回404
![](/img/in-post/shiro-bypass-vuln/4.png)

### 漏洞分析

第一种绕过方式：

正常访问跳转到登录页面
![](/img/in-post/shiro-bypass-vuln/5.png)

在前面添加分号即可绕过
![](/img/in-post/shiro-bypass-vuln/6.png)

这种比较简单，因为会把分号后面的内容全部去掉，因此只返回了`/`，匹配不上shiro设置的限制，从而导致绕过
![](/img/in-post/shiro-bypass-vuln/7.png)


第二种绕过方式：
新建一个controller
```java
@ResponseBody
@RequestMapping(value="/user/{index}", method= RequestMethod.GET)
public String user(@PathVariable String index){
    return "i am user"+ index.toString() + "!";
}
```

正常访问跳转到登录页面
![](/img/in-post/shiro-bypass-vuln/8.png)

把带斜杠的字符串双重编码后，绕过成功
![](/img/in-post/shiro-bypass-vuln/9.png)

url进来的时候，`getPathInfo`会做一次解码。对于request做解码的函数，可以参考一下[mi1k7ea大佬的这篇文章](https://xz.aliyun.com/t/7544)
![](/img/in-post/shiro-bypass-vuln/10.png)

然后shiro在`decodeAndCleanUriString`函数会自己再做一次解码
![](/img/in-post/shiro-bypass-vuln/11.png)

这里对shiro的pattern和url都做了分割，可以看到url比pattern多了一个值
![](/img/in-post/shiro-bypass-vuln/12.png)

遍历匹配
![](/img/in-post/shiro-bypass-vuln/13.png)

url比pattern长，所以`pathIdxStart`指针是没指到最后一个值的，导致最后返回false，从而绕过
![](/img/in-post/shiro-bypass-vuln/14.png)


## CVE-2020-13933(ver < 1.6.0)
### 漏洞分析

先复现一下

正常访问，跳转登录
![](/img/in-post/shiro-bypass-vuln/15.png)

加上url编码的分号，绕过成功
![](/img/in-post/shiro-bypass-vuln/16.png)


先看看shiro怎么取的url，取了servletpath和pathinfo拼起来，然后去掉分号后面的内容
```java
public static String getPathWithinApplication(HttpServletRequest request) {
    return normalize(removeSemicolon(getServletPath(request) + getPathInfo(request)));
}
```

最终调用的是request的`getServletPath`和`getPathInfo`，但是request的`getServletPath`和`getPathInfo`是会做url解码的
![](/img/in-post/shiro-bypass-vuln/17.png)


所以最终会把`%3b`解码后，去掉后面的内容，`/user`自然与`/user/*`匹配不上
![](/img/in-post/shiro-bypass-vuln/18.png)


## CVE-2020-17523(ver < 1.7.1)
### 漏洞分析

正常访问，跳转到登录页面
![](/img/in-post/shiro-bypass-vuln/20.png)

换成`%20`成功绕过
![](/img/in-post/shiro-bypass-vuln/19.png)

来看一下shiro是怎么解析url的，先解码成`/user/ `
![](/img/in-post/shiro-bypass-vuln/21.png)

然后会分别对shiro的pattern和url用斜杠进行分割，但是shiro分割逻辑存在问题，对`/user/ `分割的时候，分成了`user`和空格，并会对其进行trim操作，所以我们的空格就被过滤掉了，然后因为`token.length() <= 0`的值为true，这个空格就没有被加到数组中
![](/img/in-post/shiro-bypass-vuln/22.png)

很明显看到分割出来的两个数组长度是不一样的，从而完成绕过
![](/img/in-post/shiro-bypass-vuln/23.png)

而spring不会把空格去掉，匹配上正确的控制器
![](/img/in-post/shiro-bypass-vuln/24.png)

## 参考
- [https://segmentfault.com/a/1190000019440231](https://segmentfault.com/a/1190000019440231)
- [https://www.anquanke.com/post/id/240033](https://www.anquanke.com/post/id/240033)
- [https://shiro.apache.org/security-reports.html](https://shiro.apache.org/security-reports.html)
- [https://xz.aliyun.com/t/7544](https://xz.aliyun.com/t/7544)