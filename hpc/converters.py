# -*- coding: utf-8 -*-
import hpc.utils
import hpc.generics
from cilogger.cilogger import ccilogger #, ftrace

log = ccilogger(__name__)

# @ftrace
def convert(attribute: str, value: any) -> tuple:
    """ Function that convert a value according to convert rules
    
    rules:

      * if attribute name is titled and value is a string return a titled 
        value
      * if value is a list and is empty and return an empty string
      * if value is a string return a safe string with the ssafe function

    :param str attribute: An attribute
    :param any value: An attribute value

    :return: A tuple containing attribute lowered and a converted value 
             according to matching rules
    """
    # Rule 1
    if attribute.istitle() and isinstance(value, str):
        value = value.title()

    # Rule 2
    if isinstance(value, list) and not value:
        value = ""
  
    if issubclass(type(value), hpc.generics.GenericObjects):
        if not value:
            value = ""
        else:
            value = [{str(a): str(getattr(o,a,None)) for a in o.attrs()} for o in value]

    # Rule 3
    if isinstance(value, str):
        value = hpc.utils.ssafe(value)
    
    if value is None:
        value = ""

    return (attribute.lower(), value)