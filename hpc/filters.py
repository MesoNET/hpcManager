# -*- coding: utf-8 -*-
""" HPC filters' operators and combinations functions

This module provides filters operators for attributes like regex 
comparison (=), not (!=). It also provides a reverse polish notation 
function to build complexe filters combination.
"""

from typing import Optional
from re import compile, IGNORECASE
from itertools import chain
import hpc.generics
import operator
from cilogger.cilogger import ccilogger  # , ftrace
log = ccilogger(__name__)
# log.setLevel("TRACE")

# @ftrace
def comparison_operator_check(f_value: any) -> str:
    """ This function check if a comparison_operator value provided in 
    filter is valid or not

    :param any f_value: Anything

    :return: Empty string if f_value is a string or a number
    """
    if isinstance(f_value, str):
        return ""
    elif isinstance(f_value, int) or isinstance(f_value, float):
        return ""
    else:
        return "Must be a string or a number (int or float)"

# @ftrace
def inferior_operator(value: any, f_value: any) -> bool:
    """ This operator compares value to a filter value given by filter and 
    return true if value is inferior to filter value. By example, 10 is 
    inferior to 20 and "20B" is inferior to "20A". If one of value or 
    f_value is a string, a lexical comparison is done. String comparison 
    is python's string comparison. If both f_value and value are numbers 
    then number comparison is done.

    :param any value: An attribute value
    :param any f_value: A string or an int

    :return: True if value is inferior to f_value
    """
    
    try:
        converted_value = int(value)
        converted_f_value = int(f_value)
        log.debug(
            f"[int] Is {converted_value} < {converted_f_value} ? "
            f"= {converted_value < converted_f_value}"
        )
        return converted_value < converted_f_value
    except (TypeError, ValueError):
        try:
            converted_value = float(value)
            converted_f_value = float(f_value)
            log.debug(
                f"[float] Is {converted_value} < {converted_f_value} ? "
                f"= {converted_value < converted_f_value}"
            )
            return converted_value < converted_f_value
        except (TypeError, ValueError):
            if value is None:
                value = ''
            if f_value is None:
                f_value = ''
            log.debug(f"[str] Is {value} < {f_value} ? = {value < f_value}")
            return value < f_value

# @ftrace
def superior_operator(value: any, f_value: any) -> bool:
    """ This operator compares value to a filter value given by filter and 
    return true if value is inferior to filter value. By example, 20 is 
    superior to 10 and "20A" is superior to "20B". If one of value or f_value 
    is a string, a lexical comparison i done. String comparison is python's 
    string comparison. If both f_value and value are numbers then number 
    comparison is done.

    :param any value: An attribute value
    :param any f_value: A string or an int

    :return: True if value is superior to f_value
    """
    
    try:
        converted_value = int(value)
        converted_f_value = int(f_value)
        log.debug(
            f"[int] Is {converted_value} > {converted_f_value} ? "
            f"= {converted_value > converted_f_value}"
        )
        return converted_value > converted_f_value
    except (TypeError, ValueError):
        try:
            converted_value = float(value)
            converted_f_value = float(f_value)
            log.debug(
                f"[float] Is {converted_value} > {converted_f_value} ? "
                f"= {converted_value > converted_f_value}"
            )
            return converted_value > converted_f_value
        except (TypeError, ValueError):
            if value is None:
                value = ''
            if f_value is None:
                f_value = ''
            log.debug(f"[str] Is {value} > {f_value} ? = {value > f_value}")
            return value > f_value

# @ftrace
def regex_operator_check(f_value: any) -> str:
    """ This function check if a regex_operator value provided in filter is 
    valid or not

    :param any f_value: Anything

    :return: Empty string if f_value is a string and is a valid regex else 
             an error message to display
    """
    try: 
        compile(f"{f_value}", IGNORECASE)
    except Exception:
        return "Must be a valid regex"
    return ""

# @ftrace
def regex_operator(value: any, f_value: any) -> bool:
    """ This operator compares an attribute value to a regular expression 
    given by filter. The comparison is case incensitive. Value is evaluate as 
    a string no matter its type.

    :param any value: An attribute value
    :param any f_value: A regex string

    :return: True if value matches filter else False (ignore case)
    """
    if value is None:
        f_regex = compile(f"{f_value}", IGNORECASE)
        r = f_regex.search("")
        # log.trace(
        #     f"Applying operator '{value}' =~ '{f_regex.pattern}' "
        #     f"=> {r} [{r is not None}]"
        # )
    else:
        f_regex = compile(f"{f_value}", IGNORECASE)
        r = f_regex.search(f"{value}")
        # log.trace(
        #     f"Applying operator '{value}' =~ '{f_regex.pattern}' "
        #     f"=> {r} [{r is not None}]"
        # )
    return r is not None

# @ftrace
def not_regex_operator(value: any, f_value: any) -> bool:
    """ This operator compares an attribute value to a regular expression 
    given by filter. The comparison is case incensitive. Value is evaluate 
    as a string no matter its type. If match found return false.

    :param any value: An attribute value
    :param any f_value: A regex string

    :return: True if value does not match filter else False (ignore case)
    """
    if value is None:
        f_regex = compile(f"{f_value}", IGNORECASE)
        r = f_regex.search("")
        # log.trace(
        #     f"Applying operator '{value}' !~ '{f_regex.pattern}' "
        #     f"=> {r} [{r is None}]"
        # )
    else:
        f_regex = compile(f"{f_value}", IGNORECASE)
        r = f_regex.search(f"{value}")
        # log.trace(
        #     f"Applying operator '{value}' !~ '{f_regex.pattern}' "
        #     f"=> {r} [{r is None}]"
        # )
    return r is None

# @ftrace
def search_operator_check(f_value: any) -> str:
    """ This function check if a search_operator value provided in filter is 
    valid or not.

    :param any f_value: Anything

    :return: Empty string if f_value is a string and is a valid search filter 
             as key<value else an error message to display
    """
    try:
        f_value_regex = compile(r'^(?P<not>!?)(?P<k>[^<]+)<(?P<v>.*)$')
        m = f_value_regex.match(f_value)
        if m:
            value = m.group('v')
            # log.trace(
            #     f"Found key '{m.group('k')}' and value '{value}' "
            #     f"for search filter."
            # )
            compile(f"{value}", IGNORECASE)
        else:
          return "Must be '[!]key<[regex]'"  
    except Exception:
        return "'[!]key<[regex]'"
    return ""

# @ftrace
def search_operator(value: any, f_value: any) -> bool:
    """ This operator search in a list of dict or in GenericObjects
     
    depending of [module\_]attribute attribute type means :
      * [module\_]attribute@k< : means is k in list if [module\_]attribute 
                                is a list
      * [module\_]attribute@k<v : means is k with value v in dict or in 
                                 genericObjects if [module\_]attribute is a dict or a genericObjects

    if expression begins with '!' mean return true if key not in list or dict    
    
    :param any value: An attribute value
    :param any f_value: A search list/dict filter key<value

    :return: True if value match filter else False
    """
    r = None
    f_value_regex = compile(r'^(?P<not>!?)(?P<k>[^<]+)<(?P<v>.*)$')
    m = f_value_regex.match(f_value)
    invert = False
    k = None
    v = None
    if m:
        if m.group('not') == '!':
            invert = True
        k = m.group('k')
        v = m.group('v')
    else:
        raise RuntimeError(
            "Something bad appends in search filter operator"
        )

    if isinstance(value, dict):
        # log.trace(
        #     f"Found a dict in value '{value}', looking for key '{k}' ..."
        # )
        if k == '*':
            # log.trace(
            #     f"Searching in all keys '{list(value.keys())}' "
            #     f"with value {v}"
            # )
            f_regex = compile(f"{v}", IGNORECASE)
            if invert:
                return(all([
                    f_regex.search(f"{value[key]}") is None 
                    for key in value.keys()
                ]))
            else:
                return(any([
                    f_regex.search(f"{value[key]}") is not None 
                    for key in value.keys()
                ]))
        elif k in value:
            # log.trace(f"Found key '{k}' with value {value[k]}")
            f_regex = compile(f"{v}", IGNORECASE)
            r = f_regex.search(f"{value[k]}")
            # log.trace(
            #     f"Applying operator '{value}' @ '{k}' < '{f_regex.pattern}' "
            #     f"=> {r} [{r is not None}]"
            # ) 
    elif isinstance(value, hpc.generics.GenericObjects) and \
         all([isinstance(item, hpc.generics.GenericObject) for item in value]):
        for item in value:
            log.trace(f"Parsing object {item} from list")
            attr = getattr(item,k,None)
            if attr is not None:
                log.trace(f"Found attribute {k} in object with value : {type(attr).__name__}<{attr}>")
                if isinstance(attr, list):
                    r = v in attr
                    log.trace(
                        f"Applying operator '{value}' @ '{k}' < '{v}' "
                        f"=> {r} [{r is not None}]"
                    ) 
                else:
                    f_regex = compile(f"{v}", IGNORECASE)
                    r = f_regex.search(f"{attr}")
                    log.trace(
                        f"Applying operator '{value}' @ '{k}' < '{f_regex.pattern}' "
                        f"=> {r} [{r is not None}]"
                    ) 

        #log.critical(f"Filter on Object list is not implemented")

    elif isinstance(value, list) and \
         all([isinstance(item, str) or isinstance(item, int) or 
             isinstance(item, float) 
             for item in value
         ]):
        if k in value:
            r = True
        log.trace(
            f"Applying operator '{value}' @ '{k}' (is '{k}' in '{value}' ?)"
            f"=> {r} [{r is not None}]"
        ) 
    if invert:
        return r is None
    else:
        return r is not None

# @ftrace
def count_operator_check(f_value: any) -> str:
    """ This function check if a count_operator value provided in filter is 
    valid or not.

    :param any f_value: Anything

    :return: Empty string if f_value is a string and is a valid search filter 
             else an error message to display
    """
    try:
        # log.trace(f"Checking count operator provided : {f_value}")
        f_value_regex = compile(r'^(?P<operator>\=\=|\<|\<\=|\>|\>\=|)(?P<count>[0-9]+)$')

        m = f_value_regex.match(f_value)
        
        if not m:
            return "Must be # followed by one operator "\
                   "between >, >=, <, <=, == "\
                   "followed by a number (Exemple : #>=3)"
    except Exception:
        return "Must be # followed by one operator "\
               "between >, >=, <, <=, == "\
               "followed by a number (Exemple : #>=3)"
    return ""

# @ftrace
def count_operator(value: any, f_value: any) -> bool:
    """ This operator count values in list or in GenericObjects or keys in dict
    an compare to number provided
        
    :param any value: An attribute value
    :param any f_value: A search list/dict filter key<value

    :return: True if value match filter else False
    """
    r = None
    operator_map = {
        '<': operator.lt,
        '<=': operator.le,
        '==': operator.eq,
        '!=': operator.ne,
        '>=': operator.ge,
        '>': operator.gt
    }
    c_operator_regex = compile(r'^(?P<operator>\=\=|\<|\<\=|\>|\>\=|)(?P<count>[0-9]+)$')
    m = c_operator_regex.match(f_value)
    if m:
        c_operator = m.group('operator')
        c_count = int(m.group('count'))
        log.trace(f"Operator : {c_operator} ({str(operator_map[c_operator])}, Count : {c_count})")
    
        if isinstance(value, dict):
            log.trace(f"Value : {value}, Length : {len(value.keys)}")
            return operator_map[c_operator](len(value.keys), c_count)
        elif isinstance(value, hpc.generics.GenericObjects) and \
            all([isinstance(item, hpc.generics.GenericObject) for item in value]):
            log.trace(f"Value : {value}, Length : {value.len()}")
            return operator_map[c_operator](value.len(), c_count)
        elif isinstance(value, list) and \
            all([isinstance(item, str) or isinstance(item, int) or 
                isinstance(item, float) 
                for item in value
            ]):
            log.trace(f"Value : {value}, Length : {len(value)}")
            return operator_map[c_operator](len(value), c_count)
        elif value is None:
            log.trace(f"Value : {None} (means []), Length : 0")
            return operator_map[c_operator](0, c_count)
        else:
            log.trace(f"Value : {value} (means 1 item), Length : 1")
            return operator_map[c_operator](1, c_count)
        
    return r is not None

""" Operator declaration   
"""
filter_operators = {
    '=': {
        'name': "regex",
        'check': regex_operator_check,
        'function': regex_operator
    },
    '!': {
        'name': "not regex",
        'check': regex_operator_check,
        'function': not_regex_operator
    },
    '<': {
        'name': "inferior",
        'check': comparison_operator_check,
        'function': inferior_operator
    },
    '>': {
        'name': "superior",
        'check': comparison_operator_check,
        'function': superior_operator
    },
    '@': {
        # [module_]attribute@k< means is k in list if [module_]attribute is a list
        # [module_]attribute@k<v means is k with value v in dict or in genericObjects if [module_]attribute is a dict or a genericObjects
        'name': "search",
        'check': search_operator_check,
        'function': search_operator
    },
    '#': {
        # [module_]attribute#>0 if [module_]attribute is a list or a GenericObjects means len(list) > 0
        # [module_]attribute#>0 if [module_]attribute is a dict means len(dict.keys()) > 0
        # Possible values : #>, #>=, #<, #<=, #=
        'name': "count",
        'check': count_operator_check,
        'function': count_operator
    }
}

""" Reverse polish notation available operators   
"""
rpn_operators = {
    "and": lambda op1, op2: op1 and op2,
    "or": lambda op1, op2: op1 or op2,
}

# @ftrace
def rpn(f_results: list) -> bool:
    """ Evaluate a list of filter results with reverse polish notation syntax

    .. note:: Filter result list example:

           [True, True, "or", False, "and"]

    :param list f_results: A list of filter results
    :return: True or False according to the evatuation of the expression

    :raise ArithmeticError: If the list is not a valid rpn expression (not 
                            enough operand before operator)
    :raise ArithmeticError: If the list is not a valid rpn expression (not 
                            enough operator)
    :raise TypeError: If filter results or not booleans
    """
    rpn_stack = []
    for token in f_results:
        if token in rpn_operators:
            # log.trace(
            #     f"RPN : Evaluating token '{token}' as an operator with "
            #     f"current stack {rpn_stack} ..."
            # )
            if len(rpn_stack) > 1:
                oprd1 = rpn_stack.pop()
                oprd2 = rpn_stack.pop()
                r = rpn_operators[token](oprd1, oprd2)
                # log.trace(
                #     f"Popping last two operand '{oprd1}' and '{oprd2}' and "
                #     f"push result '{r}' to stack"
                # )
                rpn_stack.append(r)
            else: 
                raise ArithmeticError(
                    "Filters combination is not a valid RPN expression (not "
                    "enough operand before operator)"
                )
        else:
            # log.trace(
            #     f"RPN : Evaluating token '{token}' as an operand with "
            #     f"current stack {rpn_stack} ..."
            # )
            if isinstance(token, bool):
                # log.trace(f"Pushing operand '{token}' to stack")
                rpn_stack.append(token)
            else:
                raise TypeError("Filters results must be booleans")

    if len(rpn_stack) == 1:
        return rpn_stack.pop()
    else:
        raise ArithmeticError(
            "Filters combination is not a valid RPN expression (not enough "
            "operator)"
        )
            

# @ftrace
def predefined_filters_help_format(predefined: dict, object_type: str, module: str = "hpc") -> str:
    """ Format filter help for an object

    An filter help is formatted as below :

    .. code-block:: python

        "    * **<filtername>**: <filter help>\\n"

    :param dict predefined: Predefined filters
    :param str object_type: Object type "user" or "group"
    :param str module: Module name
    :return: A formatted help string for filters
    """
    return "\n".join([
        f"    * {f_name:30}: {f_data['help']}" 
        for f_name, f_data in predefined[object_type].items() 
        if (('module' not in f_data and module == 'hpc') or 
            ('module' in f_data and f_data['module'] == module))
    ])


# @ftrace
def predefined_filters_expand(
            predefined: dict, object_type: str, opt_filters: list,
            module: str = "hpc"
        ) -> list:
    """ Expand predefined filters from a list of filter for an object type

    if a filter is a predefined filter i.e. "predefined=MyFilter", all filters 
    in predefined filters are append to filter list. If it is not a predefined 
    filter it is just append to filter list.

    :param str object_type: Object type "user" or "group"
    :param list opt_filters: A list of filter given by command line
    :param str module: Module name in which this filter is valid. "hpc" module 
                       by default.

    :return: A list of all filters with predefined filters replaced by
             real filters

    :raise ValueError: If predefined filter name is not found in predefined 
                       filters for the given object
    :raise alueError: If no predefined filters for this object is available
    """
    if opt_filters:
        filters = []
        attributes = []
        predefined_filter_regex = compile(r'^(predefined|pf)=(?P<name>.+)$')
        for f in opt_filters:
            mfilter = predefined_filter_regex.match(f)
            if mfilter:
                name = mfilter.group("name")
                log.trace(f"Expanding filters name '{name}'...")
                pf = [
                    fname for fname, fdata in predefined[object_type].items()
                    if (('module' not in fdata and module == 'hpc') or 
                        ('module' in fdata and fdata['module'] == module))
                ] 
                log.debug(
                    f"Looking in module '{module}' for predefined filter list {pf} in object "
                    f"'{object_type}' with name '{name}'"
                )
                if object_type in predefined:
                    if name in predefined[object_type] and \
                       (('module' not in predefined[object_type][name] and module == 'hpc') or 
                       ('module' in predefined[object_type][name] and predefined[object_type][name]['module'] == module)):
                        filters += predefined[object_type][name]['filters']
                        attributes += predefined[object_type][name]['attributes']
                    else:
                        raise ValueError(
                            f"Bad predefined filter value '{name}'. "
                            f"Predefined filters must be one of {pf}"
                        )
                else:
                    raise ValueError(
                        f"No predefined filters for object '{object_type}' "
                        f"is available"
                    )
                
            else:
                filters.append(f)
        if attributes:
            formated_filters = "' '".join(filters)
            log.debug(f"Predefined Attrs : {' '.join(attributes)}")
            log.debug(f"Predefined Filters : '{formated_filters}'")
            return (attributes, filters)
        else:
            if not module == 'hpc' :
                attributes = predefined[object_type][f'{module.title()}{object_type.title()}s']['attributes']
            else:
                attributes = predefined[object_type][f'All{object_type.title()}s']['attributes']
            log.debug(
                f"Predefined (defaults attrs): ( Attrs={attributes}, "
                f"Filters={filters} )"
            )
            return (attributes, filters)
    else:
        if not module == 'hpc' :
            attributes = predefined[object_type][f'{module.title()}{object_type.title()}s']['attributes']
        else:
            attributes = predefined[object_type][f'All{object_type.title()}s']['attributes']
        log.debug(
            f"Predefined (defaults filters): ( Attrs={attributes}, "
            f"Filters={[]} )"
        )
        return (attributes, [])