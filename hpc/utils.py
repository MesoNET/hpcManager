# -*- coding: utf-8 -*-
""" Common useful functions for all modules
"""
from argparse import ArgumentParser
from ctypes import c_char
from subprocess import run as sp_run, PIPE
from json import dumps
from re import compile
from requests import post, get
from typing import Optional, List, Tuple
from unicodedata import normalize
from string import ascii_letters, digits
from importlib import import_module
from cilogger.cilogger import ccilogger, rootlogger # , ftrace
from threading import Thread
from hashlib import md5, sha512
from pathlib import Path
from os import environ
from getpass import getuser
from config.config import config
import ldap
import io

log = ccilogger(__name__)
#log.setLevel("TRACE")


class ThreadSafe(Thread):
    """ Custom Thread class implementation to handle exceptions raised in 
    child threads

        Add an attribute "exception" to standard class. Default to None and 
        set to child's Exception if raised.
    """
    def __init__(
            self, group=None, target=None, name=None, args=(), kwargs={}, 
            daemon=None
        ):
        super().__init__(
            group=group, target=target, name=name, args=args, 
            kwargs=kwargs, daemon=daemon
        )
        self.exception = None

    def run(self):
        try:
            Thread.run(self)
        except Exception as e:
            self.exception = e


# @ftrace
def load_config(mname) -> dict:
        """ Internal helper function used to load configuration once when 
        first object is created.

        It searchs in hpc.config to find a module with current module name 
        and if found and contains a config variable. If config variable is 
        a dict then it sets ___config__ class attribute with else sets an 
        empty dict and emit a warning.

        :raise TypeError: If config variable found in config module is not a 
                          dict
        :raise AttributeError: If module has no config variable defined inside
        """

        default_config = {}
        config_prefix = "config"
        module_name = mname.split(".")[-1]

        # log.trace(f"Found module name '{module_name}'")
        module_config = f"{config_prefix}.config{module_name.lower().title()}"

        try:
            # log.trace(
            #      f"Try to load config module '{module_config}'"
            # )
            config = import_module(module_config)
            if hasattr(config, "config"):
                if isinstance(config.config, dict):
                    # log.trace(f"Found config : {config.config}")
                    return config.config
                else:
                    raise TypeError(
                        f"Config variable found in config module "
                        f"'{module_config}' is not a dict "
                        f"({type(config.config)})")
            else:
                raise AttributeError(
                    f"Module '{module_config}' has no config variable defined "
                    f"inside"
                )
        
        except ModuleNotFoundError as e:
            if rootlogger.isEnabledFor(rootlogger.TRACE):
                log.error(e)
            log.warning(f"Module '{module_config}' not found, using defaults")
            return default_config

# @ftrace
def register_attributes(attribute_list: List[dict], meta: bool=False) -> dict:
    """ This function parse and check an attributes list and return a dict 
    needed for register attributes when deriving an GenericObject class

    :param List[dict] attribute_list: List of attributes
    :param bool meta: If attribute_list is a list of meta attributes
    :return: A dict contraining ready to register attributes when deriving 
             an GenericObject class

    Attribute list format :

    .. code-block:: python

        [{
            "name": <name>, "category": "<category>" ,
            "type": <type>, "default": <default>, "help": "<help>"
        }]

    """
    attributes = {
        "standard": [],
        "extended": []
    }

    if meta:
        alist = [
            {
                "name": m['name'], 
                "category": "standard", 
                "type": m['type'],
                "default": None,
                "help": m['help']
            } 
            for m in attribute_list
        ]
    else:
        alist = attribute_list

    log.trace(f"Registering attributes : {alist}")
    reserved_attributes_names = ["all", "std", "ext", "int"]
    for a in alist:
        mandatory_attrs_len = len(
            set(a.keys()).difference([
                "name", "category", "type", "default", "help"
            ])
        )
        if mandatory_attrs_len == 0:
            registered_attrs = [
                a['name'] for lattribute in attributes.values() 
                for a in lattribute if lattribute
            ]
            if a["name"] in registered_attrs:
                raise KeyError(f"Attribute '{a}' already registered")
            elif a["name"] in reserved_attributes_names:
                raise KeyError(
                    f"Attribute '{a}' use a reserved word as "
                    f"name ({reserved_attributes_names})"
                )
            else:
                if a["category"] in attributes:
                    attributes[a["category"]].append({
                        "name": a["name"], "type": a["type"], 
                        "default": a["default"], "help": a["help"]
                    })
                    # log.trace(f"Registring attribute {a['name']}")
                else:
                    raise NotImplementedError(
                        f"Unknown attribute category '{a['category']}' "
                        f"(must be one of {[c for c in attributes]})."
                    )
        else:
            s = set(a.keys()).difference([
                "name", "category", "type", "default", "help"
            ])
            raise KeyError(
                f"Missing keys {[i for i in s]} in attribute definition"
            )

    #log.trace(f"Registered attributes : {attributes}")
    return attributes

# @ftrace
def build_callable(
    action: str, command: str=None, label: str=None, check: str=None, 
    doit: str=False, predefined_parents: Optional[List[str]]=None,
    required_attributes: list=[], optional_attributes: list=[],
    additional_arguments: Optional[List[ArgumentParser]]=None,
    examples: List[tuple]=[]):
    """ Helper for building callable. See register_callables for more 
    informations on callable attributes
    """

    return {
        "action": action,
        "command": command,
        "label": label,
        "check": check,
        "doit": doit,
        "predefined_parents": predefined_parents,
        "required_attributes": required_attributes,
        "optional_attributes": optional_attributes,
        "additional_arguments": additional_arguments,
        "examples": examples
    }


# @ftrace
def register_callables(clist: List[dict], adict: dict) -> List:
    """ This function parse and check module callable list and return the list 
    

    :param List[dict] alist: List of callables
    :param dict adict: Object's attributes
    :return: The list of callable unmodified
  
    Callable list format :

    .. code-block:: python

        [{
            "action": <action name>,
            "command": <command name or None>,
            "label": <Command label used for displaying help>,
            "check": presence|absence,
            "doit": <undo method name>,
            "predefined_parents": <list of predefined parent parser>,
            "required_attributes": <list of required attributes>,
            "optional_attributes": <list of optional attributes>,
            "additional_arguments": <list of ArgumentParser>,
            "examples": <list of tuple (Example label, Example description) 
                        to be added in epilog examples>,
        }]

      * **check** : Check for object presence or absence in object list before 
                    doing anything. Check is done with object keys.

    """
    
    # Check if callable is a list of dict
    if not(
            isinstance(clist, list) \
            and all([isinstance(c, dict) for c in clist])
          ):
        raise TypeError("Callables must be a list of dict")

    
    # Check callables attributes
    l_err = []
    callables_attrs = [
        "action", "command", "label", "check", "doit", "predefined_parents", 
        "required_attributes", "optional_attributes",
        "additional_arguments", "examples"
    ]
    predefined_parents = ["continue_on_failure"]
    checks = ["absence", "presence"]
   
    for c in clist:
        if not all([k in c for k in callables_attrs]):
            l_missing = [f"{k}" for k in callables_attrs if k not in c]
            l_err.append(
                f"Some callables attributes are missing for action "
                f"'{c['action']}' and "
                f"command '{c['command']}' : '{', '.join(l_missing)}'"
            )
    if l_err :
        for e in l_err:
            log.fatal(e)
        raise ValueError("Some callables attributes are missing")

    # Check if actions with no commands are a string and unique
    l_actions = [c['action'] for c in clist]
    if all([isinstance(a, str) for a in l_actions]):
        l_actions_nc = [c['action'] for c in clist if c['command'] is None]
        if not (len(l_actions_nc) == len(set(l_actions_nc))):
            l_err = set(
                [f"{a}" for a in l_actions_nc if l_actions_nc.count(a) > 1]
            )
            raise ValueError(
                f"Some actions with no command in callables are not "
                f"unique : '{', '.join(l_err)}'"
            )
    else:
        l_err = [f'{a}' for a in l_actions if not isinstance(a,str)]
        raise TypeError(
            f"Some actions in callables are not strings : '{', '.join(l_err)}'"
        )

    # Check if command list is a string or None and unique inside action
    for a in l_actions:
        l_commands = [c['command'] for c in clist if a == c['action']]
        log.trace(f"Commands : {l_commands}")
        if all([cmd is None or isinstance(cmd, str) for cmd in l_commands]):
            if not (len(l_commands) == len(set(l_commands))):
                l_err = set([
                    f"{cmd}" for cmd in l_commands if l_commands.count(cmd) > 1
                ])
                raise ValueError(
                    f"Some commands in callables action '{a}' are not "
                    f"unique : '{', '.join(l_err)}'"
                )
        else:
            l_err = [
                f'{cmd}' 
                for cmd in l_commands 
                if not(cmd is None or isinstance(a, str))
            ]
            raise TypeError(
                f"Some commands in callables action '{a}' are not strings or "
                f"None: '{', '.join(l_err)}'"
            )
            
    for c in clist:
        # Check populate action
        if not(
            c['check'] is None 
            or (
                isinstance(c['check'], str) 
                and c['check'] in checks
            )
        ):
            raise TypeError(
                f"Check callables action '{c['action']}' and command "
                f"'{c['command']}' is not None or a string or is not one of "
                f"[{', '.join(checks)}])"
            )

        # Check if required attributes is a list of string and in standard or 
        # extended attributes
        standard_attrs = [a['name'] for a in adict['standard']]     
        log.trace(f"Standards attributes : {standard_attrs}")
        if not(len(c['required_attributes']) == len(set(c['required_attributes']))):
            l_err = set([
                f"{attr}" 
                for attr in c['required_attributes'] 
                if c['required_attributes'].count(attr) > 1
            ])
            raise TypeError(
                f"Some requires attributes in callable action '{c['action']}' "
                f"and command '{c['command']}' are not unique : '{', '.join(l_err)}'"
            )
        if not(all([attr in standard_attrs for attr in c['required_attributes']])):
            l_err = [
                f'{attr}' 
                for attr in c['required_attributes'] 
                if not attr in standard_attrs
            ]
            raise TypeError(
                f"Some requires attributes in callable action '{c['action']}' "
                f"and command '{c['command']}' are not defined in "
                f"module : '{', '.join(l_err)}'"
            )

        # Check if optional if attributes is a list of string and in standard or 
        # extended attributes
        all_attrs = [
            a['name'] for a in adict['standard']] + [a['name'] 
            for a in adict['extended']
        ]
        if not (len(c['optional_attributes']) == len(set(c['optional_attributes']))):
            l_err = set([
                f"{attr}" 
                for attr in c['optional_attributes'] 
                if c['optional_attributes'].count(attr) > 1
            ])
            raise TypeError(
                f"Some optionals attributes in callable action '{c['action']}' "
                f"and command '{c['command']}' are not unique : '{', '.join(l_err)}'"
            )
        if not(all([attr in all_attrs for attr in c['optional_attributes']])):
            l_err = [
                f'{attr}' 
                for attr in c['optional_attributes'] 
                if not attr in all_attrs
            ]
            raise TypeError(
                f"Some optionals attributes in callable action '{c['action']}' "
                f"and command '{c['command']}' are not defined in "
                f"module : '{', '.join(l_err)}'"
            )
        
        if not(
            c['additional_arguments'] is None or (
                isinstance(c['additional_arguments'], list) and
                all([isinstance(aa, ArgumentParser) for aa in c['additional_arguments']])
            )
        ):
            raise TypeError(
                f"Additionnal arguments in callables action '{c['action']}' and command "
                f"'{c['command']}' is not None or a list of ArgumentParser ({c['additional_arguments']})"
            )

        if not(
            c['examples'] is None or (
                isinstance(c['examples'], list) and
                all([isinstance(t, tuple) for t in c['examples']]) and
                all([
                    isinstance(l, str) and isinstance(d, str) 
                    for (l,d) in [t for t in c['examples']]
                ])
            )
        ):
            raise TypeError(
                f"Examples in callables action '{c['action']}' and command "
                f"'{c['command']}' is not None or a list of string "
                f"tuple (List[Tuple[str,str]])"
            )

    # TODO: Check if callable has a corresponding method in module : Possible ?

    if l_err :
        for e in l_err:
            log.fatal(e)
        raise ValueError("Failed to register callables")
    return clist

# @ftrace
def to_parser(arg: str, **kwargs) -> ArgumentParser:
    """ Helper to create Argument parser from raw add_argmument definition

    :param str arg: add_argmument name or flags
    :param kwargs: all add_argmument parameters
    """

    custom_parser = ArgumentParser(
        add_help=False
    )
    custom_parser.add_argument(
        arg, **kwargs
    )
    return custom_parser


# @ftrace
def attributes_to_docstring(attributes: dict) -> str:
    """ Generate attributes docstring for an object

    :param dict attributes: List of attributes
    :return: Attributes in doctring format
    """
    sdoc = []
    for category, attrs in attributes.items():
        sdoc += [f"    **{category.title()} attributes :**"] + \
                ["\n".join(
                    [f"    :param {a['type']} {a['name']}: {a['help']} (default : {a['default']})"
                     for a in attrs]
                )]

    return "\n" + "\n\n".join(sdoc) + "\n"


# @ftrace
def help_format(dhelp: dict) -> str:
    """ Format attributes help for an object

    An attribute help is formatted as below :

    .. code-block:: python

        "    * **<attribute name>**: <attribute help>\\n"

    :param dict dhelp: dict of all object's attributes help
    :return: A formatted attribute help string
    """
    return "\n".join([
        "\n".join([f"      * {sa:12}   - {sh}" for sa, sh in h])
        if isinstance(h, list) 
        else f"    * {a:14}: {h}"
        for a, h in dhelp
    ])

# @ftrace
def check_module_config(config: dict) -> bool:
    """ This function check if module configuration is present in both user 
    and group declaration

    :param dict config: Module configuration's dict
    :return: True if module configuration are present in both user and group
             declaration
    """

    log.trace(f"Checking configuration {config} ...")
    if "modules" in config:
        if "group" in config["modules"]:
            if "user" in config["modules"]:
                mgroup = [m["name"] for m in config["modules"]["group"]]
                muser = [m["name"] for m in config["modules"]["user"]]
                log.trace(f"Group modules : {mgroup}")
                log.trace(f"User modules : {muser}")
                return(
                    set(mgroup) == set(muser)
                )
            else:
                log.fatal("No user module configuration found")     
        else:
            log.fatal("No group module configuration found")     
    else:
        log.fatal("No module configuration found")
    
    return False

# ftrace
def get_current_module_config(script_name: str) -> dict:
    """ This function retrieve a module configuration, from script name

    :param str script_name: Module name
    :param dict config: Modules configuration's dict
    :return: Module configuration
    """

    log.trace(f"Script name : {script_name}")
    
    module_regex = compile(
        r'^(?P<meta_module>[a-z]+)(?P<module>[A-Z][a-z]+)Manager.py$'
    )
    module_match = module_regex.match(Path(script_name).name)

    if  module_match:
        mm_name = module_match.group('meta_module')
        log.trace(f"Meta module '{mm_name}' found")
        config = load_config(mm_name)
        log.trace(f"Meta module config: '{config}'")
        module_list = []
        if check_module_config(config):
            module_list = list(set([
                m["name"].lower()
                for mtype, modules in config["modules"].items() 
                for m in modules
            ]))
        else :
            log.fatal(f"Bad module configuration in configHpc ...")
            exit()

        m_name = module_match.group('module').lower()
        m_filters = None
        if m_name in module_list :
            log.trace(f"Module '{m_name}' found")
            m_filters = import_module(f"config.config{m_name.title()}Filters")
            
        else: 
            log.fatal(
                f"Module '{m_name}' detected but not available"
            )
            exit()
    else:
        log.fatal(
            f"Unable to parse modules from script "
            f"name '{Path(script_name).name}' ..."
        )
        exit()

    return({
        "name": m_name,
        "filters": getattr(m_filters, "predefined"),
        "objects": {
            "group": next(iter(
                [m for m in config["modules"]["group"] if m["name"] == m_name]), None
            )
            ,
            "user": next(iter(
                [m for m in config["modules"]["user"] if m["name"] == m_name]), None
            )
        }
    })

def get_current_meta_module_config(script_name: str) -> dict:
    """ This function retrieve a meta module configuration, from script name

    :param str script_name: Module name
    :return: A dict containing type and list type of meta module objects
    """

    log.trace(f"Script name : {script_name}")
    meta_module_regex = compile(r'^(?P<meta_module>[a-z]*)Manager.py$')
    meta_module_match = meta_module_regex.match(Path(script_name).name)

    load_meta_module = None
    if meta_module_match:
        mm_name = meta_module_match.group('meta_module')
        log.trace(f"Module '{mm_name}' found")
        module = import_module(f"hpc.{mm_name}")
        mfilters = import_module(f"config.config{mm_name.title()}Filters")
        meta_module = {
            "name": mm_name,
            "filters": getattr(mfilters, "predefined"),
            "group": {
                "type": getattr(module, f"{mm_name.title()}Group"),
                "list": getattr(module, f"{mm_name.title()}Groups")
            },
            "user": {
                "type": getattr(module, f"{mm_name.title()}User"),
                "list": getattr(module, f"{mm_name.title()}Users")
            }
        }
    else:
        log.fatal(
            f"Unable to find module from script "
            f"name '{Path(script_name).name}' ..."
        )
        exit()

    #return(meta_module_config)
    return meta_module

# @ftrace
def run(command: str, exit_codes: List[int]=[0]) -> list:
    """ Run a system command

    :param str command: Full command line with options to execute
    :param  Optional[List[int]] exit_codes: List of exit codes to consider 
                                            as ok
    :return: List of string for each line in the output

    :raise RuntimeError: If command fails
    """
    log.trace(f"< '{command}'")
    p = sp_run(command, stdout=PIPE, stderr=PIPE, shell=True)
    if p.returncode in exit_codes:
        for line in p.stdout.decode().rstrip().split('\n'):
            if line == '':
                log.trace("> Success !")
            else:
                log.trace(f"> {line.strip()}")
        return p.stdout.decode().splitlines()
    else:
        for line in p.stdout.decode().rstrip().split('\n'):
            if not line == '':
                log.debug(f"> {line.strip()}")
        for line in p.stderr.decode().rstrip().split('\n'):
            log.debug(f"> {line.strip()}")
        raise RuntimeError(
            f"Unable to execute command '{command}' "
            f"({p.stderr.decode().rstrip()})."
        )

# @ftrace
def runs(commands: List[Tuple[str,Optional[List[int]]]]) -> list:
    """ Run multiple system command in sequence

    :param commands: List of full command lines with options to execute
    :return: List of string for each line in the output
    """
    result = []
    cmds = [(c[0], c[1]) if isinstance(c,tuple) else (c,[0]) for c in commands]
    for command, exit_codes in cmds:
        if command is not None:
            result += run(command, exit_codes)
    return result

# @ftrace
def pplist(data: any, n:int=3) -> str:
    """ Pretty print long dict or list data with first and last N entries.

    Example :

    .. code-block:: python
    
        d = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]
        x = sjon(d)
        '["a", "b", "c", ..., "i", "j", "k"]'
    
    """
    if isinstance(data, list):
        if len(data) > n * 2:
            # log.trace(f"First {n} entries : {jdata[:n]}")
            # log.trace(f"Last {n} entries : {jdata[-n:]}")
            return f"[{', '.join([f'{e}' for e in data[:n]])}, " \
                   f"..., {', '.join([f'{e}' for e in data[-n:]])}]"
        else:
            return data 
    elif isinstance(data, dict):
        if len(list(data)) > n * 2:
            return \
                f"[{', '.join([f'{k}: {data[k]}' for k in list(data)[:n]])}, " \
                f"..., {', '.join([f'{k}: {data[k]}' for k in list(data)[-n:]])}]"
        else:
            return data 
    else:
        return data

# @ftrace
def api_call(
        url: str, data: dict, auth: tuple, headers: dict, 
        rtype: str = "POST", rscode: list = [200], doit=True
    ):
    """ Wrapper for requests.post to post request API.

    :param str url: API url
    :param dict data: Data for querying API
    :param tuple auth: user and password tuple for authenticate against API
    :param dict headers: Additional requests headers
    :param str rtype: API request type 'POST' or 'GET' (default to "POST")
    :param list rscode: API response status code list (default to 200)
    :param bool doit: Really make API call else just return curl command line 
                      (default to True)
    :return: json data API response

    :raise RuntimeError: If status code in API response is not 200
    :raise NotImplementedError: If request type is not implemented
    """
    curl_headers = ""
    curl_headers = ' '.join([f'-H "{h}: {v}"' for h, v in headers.items()])
    curl_datas = ""
    if rtype == "POST":
        curl_datas = f"-X POST -d '{dumps(data)}'"
    
    if doit:
        if rtype == "POST":
            r = post(url, data=dumps(data), auth=auth, headers=headers)    
        elif rtype == "GET":
            r = get(url, auth=auth, headers=headers)
        else:
            raise NotImplementedError(
                f"Request type '{rtype}' is not implemented"
            )

        log.debug(
            f"CLI (Doit={doit}): {config['binary']['curl']} "
            f"{config['default-curl-options']} {curl_headers} {curl_datas} "
            f"{url}"
        )
        log.debug(f"Requested url ({rtype}): {url}")
        log.debug(f"Request real url : {r.url}")
        log.trace(f"Request headers : {r.request.headers}")
        log.debug(f"Request data : {r.request.body}")
        log.debug(f"Request response status : {r.status_code}")

        if r.status_code in rscode :
            log.trace(f"Request apparent encoding : {r.apparent_encoding}")
            log.trace(f"Request encoding : {r.encoding}")
            log.trace(f"Request response headers : {r.headers}")
            # log.debug(
            #     f"Request [{r.request.body}] response raw data : {r.content}"
            # )
            log.trace(f"Request [{r.request.body}] response data : {r.json()}")
            log.debug(
                f"Request [{r.request.body}] response "
                f"data : {pplist(r.json())}"
            )
            return r.json()
        else:
            log.trace(f"Request apparent encoding : {r.apparent_encoding}")
            log.trace(f"Request encoding : {r.encoding}")
            log.trace(f"Request response headers : {r.headers}")
            log.trace(
                f"Request [{r.request.body}] response raw data : {r.content}"
            )
            log.debug(
                f"Request [{r.request.body}] response raw data : "
                f"{pplist(r.content.splitlines())}"
            )
            raise RuntimeError(
                f"Bad api post response status '{r.status_code}'"
            )
    else:
        return f"{config['binary']['curl']} {config['default-curl-options']} {curl_headers} {curl_datas} {url}"




# @ftrace
def ssafe(s: any) -> str:
    """ Replace all specials chars in a string including accents

    :param any s: A string
    :return: The string with all specials char replaced
    """
    sanitized_s=s.replace('"',' ').replace("'",' ')

    return normalize('NFD', str(sanitized_s)).encode('ascii', 'ignore').decode("utf-8")


# @ftrace
def ssafelower(s: any) -> str:
    """ Replace all specials chars in a string including accents and lower 
    the string

    :param any s: A string
    :return: The string with all specials char replaced and lowered
    """
    return ssafe(s).lower()


# @ftrace
def loginsafe(login: str) -> str:
    """ Remove all non ascii letters

    :param str login: An oid with unwanted chars
    :return: An oid with only ascii letters
    """
    return ''.join([c for c in login if c in ascii_letters or c in digits])

def fingerprint(s: str) -> str:
    """This function perform a fingerprint on a string. It first do a 
    sha512sum and then a md5sum to reduce fingerprint length

    :param str s: String to fingerprint
    :return: A fingerprint

    .. todo:: Use SHA3-512
    """
    s_sha512sum = sha512(s.encode()).hexdigest()
    s_fingerprint = md5(s_sha512sum.encode()).hexdigest()
    return s_fingerprint

def get_effective_user_name() -> str:
    """ This function returns effective user login name 

    :return: effective user login name
    """
   
    if 'SUDO_USER' in environ:
        return(environ['SUDO_USER'])
    else:
        return(getuser())

def removesuffix(string: str, suffix: str) -> str:
    """ Before we use python 3.9
    https://peps.python.org/pep-0616/
    """
    # suffix='' should not call self[:-0].
    if suffix and string.endswith(suffix):
        return string[:-len(suffix)]
    else:
        return string[:]

def is_number(n: str):
    """ Check if string is an number
    """
    try:
        float(n)
    except ValueError:
        return False
    else:
        return float(n).is_integer()
    
def gidnumber_from_name(group_name: str, config: dict):
    #ldap.set_option()
    # ldaplogs=io.StringIO()
    # ldap_handler = ldap.initialize(
    #     uri = config['uri'], trace_level=0, trace_file=ldaplogs
    # )
    # r = ldap_handler.search_s(
    #     base=config['group']['ou'],
    #     scope=ldap.SCOPE_ONELEVEL,
    #     filterstr=f"(&(objectClass=*)(cn={group_name}))",
    #     attrlist=["gidNumber"]
    # )
    # log.debug(f"Result : {r} ({next(iter(r))[1]})")
    r = ldap_call(
        uri=config['uri'],
        base=config['group']['ou'],
        scope=ldap.SCOPE_ONELEVEL,
        filterstr=f"(&(objectClass=*)(cn={group_name}))",
        attrlist=["gidNumber"]
    )
    if len(r) == 1:
        log.debug(f"[{group_name}] => R : {r[0]} ({int(next(iter(r[0]['gidNumber']),'unkown_gidNumber').decode())})")
        pgroupid = int(next(iter(r[0]['gidNumber']),'unkown_gidNumber').decode())
        return pgroupid
    # else:
    #     raise ValueError(f"Ldap group name must match exactly one ldap entry (matched {len(r)})")
    return None
def name_from_gidnumber(gidnumber: str, config: dict):
    r = ldap_call(
        uri=config['uri'],
        base=config['group']['ou'],
        scope=ldap.SCOPE_ONELEVEL,
        filterstr=f"(&(objectClass=*)(gidNumber={gidnumber}))",
        attrlist=["cn"]
    )
    if len(r) == 1:
        log.debug(f"[{gidnumber}] => R : {r[0]} ({str(next(iter(r[0]['cn']),'unkown_gidNumber').decode())})")
        name = str(next(iter(r[0]['cn']),'unkown_gidNumber').decode())
        return name
    # else:
    #     raise ValueError(f"Ldap group name must match exactly one ldap entry (matched {len(r)})")
    return None
    
def ldap_call(uri, base, scope, filterstr, attrlist, doit=True):
    #ldap.set_option()
    ldaplogs=io.StringIO()
    ldap_handler = ldap.initialize(
        uri = uri, trace_level=0, trace_file=ldaplogs
    )
    r = ldap_handler.search_s(
        base=base, scope=scope, filterstr=filterstr, attrlist=attrlist
    )
    
    scope2str = {
        ldap.SCOPE_BASE: "base", 
        ldap.SCOPE_ONELEVEL: "one", 
        ldap.SCOPE_SUBTREE: "sub"
    }

    log.debug(
            f"CLI (Doit={doit}): {config['binary']['ldapsearch']} "
            f"{config['default-ldapsearch-options']} -H {uri} -b '{base}' "
            f"-s {scope2str[scope]} '{filterstr}' {(' ').join(attrlist)}"
        )
    log.debug(f"Ldap raw results : {r}")
    entries = [entry for _, entry in r]
    log.debug(f"Ldap entries : {entries}")
    return entries