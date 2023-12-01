# -*- coding: utf-8 -*-
""" Module for managing generic object and objects list

"""

import hpc.filters
from sys import modules
from abc import ABC
from json import load, dumps, dump, JSONEncoder, JSONDecoder
from copy import deepcopy
from typing import Callable, Optional, List, Union
from pathlib import Path
from typing import List
from re import A, compile, IGNORECASE
from config.configHooks import hooks
from hpc.utils import ssafe
from hpc.converters import convert
from itertools import chain
from textwrap import shorten
from cilogger.cilogger import ccilogger  # , ctrace
log = ccilogger(__name__)


# @ctrace
class JSONObjectEncoder(JSONEncoder):
    """ Custom JSON Object encoder class

    This class provides the default method for saving GenericObject.

    It adds a "__type__" key to object keys found in "obj.__dict__".

    This key is use for loading object to instantiate the appropriate 
    object (__type__ == ClassName).

    .. todo:: Use obj.attrs to get sane attribute list
    """
    def default(self, obj: object) -> dict:
        try:
            result = {'__type__': obj.__class__.__name__}
            attr_list_std = {
                o: v for o, v in obj.__dict__.items() 
                if o.startswith('_standard_')
            }
            attr_list_internal = {
                o: v for o, v in obj.__dict__.items() 
                if o.startswith('_internal_')
            }
            result.update({
                (o.replace('_standard_', '', 1) 
                if o.startswith('_standard_') else o): v
                for o, v in attr_list_std.items()
            })
            result.update({
                (o.replace('_internal_', '', 1) 
                if o.startswith('_internal_') else o): v
                for o, v in attr_list_internal.items()
            })
            self.__log__.trace(
                f"Found attribute list '{result.keys()}' for object '{obj}'"
            )
            return result
        except AttributeError:
            return JSONEncoder.default(self, obj)

    def __repr__(self):
        return '<{}>'.format(self.__class__.__name__)

    @property
    def __log__(self):
        """ Internal attibute providing a way to log inside class
        """
        return ccilogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )


# @ctrace
class JSONObjectDecoder(JSONDecoder):
    """ Custom JSON Object decoder class

    This class provides the default method for loading json file containing 
    GenericObject into a GenericObject instance.

    The "__type__" key is use to instantiate the appropriate 
    object (__type__ == ClassName).

    It looks in current "__package__" location un try all classes definitions 
    in all modules in this folder.

    .. todo:: Improve performance
    """
    def __init__(self):
        super().__init__(object_hook=self.default)

    def default(self, obj: dict) -> object:
        if '__type__' in obj:
            otype = obj.pop('__type__')
            # self.__log__.trace('Obj: {}'.format(obj))
            lpackage = [
                f"{__package__}.{m}" for m in dir(modules[__package__]) 
                if not m.startswith('__')
            ]
            # self.__log__.trace(
            #     f"Found package list '{lpackage}' in '{__package__}'"
            # )
            for module in lpackage:
                try:
                    # self.__log__.trace(
                    #     f"Trying object class '{otype}' in "
                    #     f"module '{module}' ..."
                    # )
                    cls = getattr(modules[module], otype)
                    return cls(**obj)
                except AttributeError:
                    pass
        else:
            return obj

    def __repr__(self):
        return f"<{self.__class__.__name__}>"
    
    @property
    def __log__(self):
        """ Internal attibute providing a way to log inside class
        """
        return ccilogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )


# @ctrace
class GenericObject(ABC):
    """ Abstract class for managing generic objects

    All generic objects can be load from json and save to json. Its 
    parse \\**kwargs and use the private method "_assign" to assign 
    attributes values.

    Attributes are registered when deriving a class. Attributes are defined 
    as a dict :

    .. code-block:: python

        {
            "<category>": [{
                "name": <name>, "type": <type>, 
                "default": <default>, "help": <help>
            }]
        }

    Attributes definition :

      * **name**: Attribute short name.
      * **category**: Attribute category (standard means set at creation 
                      time, extended are attributes set with a custom function 
                      once object is created).
      * **type**: Atttribute type.
      * **default** : Attribute default value if not set at creation time 
                      (Default value must be None or type of attribute type).
      * **help**: Attribute docstring (Can be used for displaying help)

    A helper function :py:func:`~.hpc.utils.register_attributes` is provided 
    in :py:mod:`~.hpc.utils` module to parse and check attributes list to 
    avoid mistakes

    Methods can be registered to be visible in standalone module manager as 
    an action with attributes as arguments and additionnal non attributes 
    arguments. Methods are defined as a list fo dict :
    
    .. code-block:: python
    
        [
            {
                "method": "<method name>",
                "label": "<action help message>",
                "required_attributes": ["<attribute name>", ...],
                "optional_attributes": ["<attribute name>", ...],
                "additional_arguments": [
                    {
                        "names": ("<argument name>", ...),
                        "alias": "<argument alias>"
                        "argparse_argument": { 
                            "help" : "Help message"
                            ... 
                        } 
                    }
                ],
            }
        ]

    Callable definition :
      * **method** : Positional argument name to add do standalone module 
                     manager. A method with this name must exist in class 
                     in order to be visible.
      * **label** : "Description of method action"
      * **required_attributes** : Required module attributes that must be 
                                  filled in for the method to work
      * **optional_attributes** : Module attributes that may be 
                                  filled
      * **additional_arguments** : Additional optional arguments (in the 
                                   argparse meaning) that will be visible for 
                                   the method action. "names" are defined as 
                                   tuples (names without -- or - will be 
                                   prefixed by -- or -). "alias" is defined as a 
                                   name if mapping has to be done beetween 
                                   modules. "argparse_argument" is an argparse
                                   definition given to the add_argument method 
                                   as unpacked dict.
                                   
    Generic object class derivation example  :

    .. code-block:: python

        from hpc.utils import register_attributes
        class MyObject(GenericObject):
            attributes = register_attributes([{
                "name": "login", "category": "standard", 
                "type": str, "default": None, "help": "User login"
            },{
                "name": "group", "category": "extended", 
                "type": str, "default": None, "help": "User group name"
            },{
                "name": "uid", "category": "standard", 
                "type": int, "default": None, "help": "User id"
            }])
            callables = [{
                "method": "create",
                "label": "Create a generic object"
                "required_attributes": ["login"],
                "optional_attributes": ["group", "uid"],
                "additional_arguments": [{
                    "names": ("-v", "--verbose"),
                    "alias": "verbose",
                    "argparse_argument": { 
                        "help" : "Increase verbosity"
                        "required": False,
                        "action": "store_true",
                        "default": False
                    } 
                }]
            }]
            pass

    :raise AttributeError: if attribute given by \\**kwargs does not exists 
                           in the object

    .. todo:: Add attribute check function to check more than type
    """
    __config__ = None
    
    attributes = {
        "standard": [],
        "extended": []
    }
    callables = []

    def __init__(self, **kwargs):
        self._create_attributes()
        self.assign(**kwargs)

    @property
    def config(self):
        """ Object configuration
        """
        return self.__class__.__config__

    @property
    def mname(self) -> str:
        """ Module name
        """
        return self.__module__.split(".")[-1].lower()

    @property
    def otype(self) -> str:
        """ Object class name
        """
        return self.__class__.__name__

    @classmethod
    def attrs(cls) -> list:
        """ Function that returns standard attribute short name

        :return: Standard attributes short names
        """
        return [a["name"] for a in cls.attributes['standard'] if "name" in a]

    @classmethod
    def attribute(cls, aname:str) -> dict:
        """ Return attribute dict

        :param str aname: Name of the attribute definition to retrieve
        :return: A dict containing attribute definition

        :raise AttributeError if attribute does not exists
        """
        d_attribute = next(iter([
            a for a in cls.attributes['standard'] + cls.attributes['extended']
            if 'name' in a and a['name'] == aname
        ]), None)
        if d_attribute is None:
            raise AttributeError(
                f"Attribute '{aname}' does not exists in object '{cls.otype}' "
                f"in module '{cls.mname}'"
            )
        else:   
            return d_attribute


    @classmethod
    def actions(cls, command: Optional[bool] = None, names=False) -> list:
        """ Function that returns a list of actions. If command is 
        false, only actions with no command will be retreived. If true only 
        actions with commands will be retreived. If names is True, returns 
        only action's names

        
        :param Optional[bool] command: Retreive actions with commands (None 
                                       by default, mean all actions)
        :param bool names: Retreive only actions names (False by default)

        :return: Actions name list
        """
        l_actions = []
        if command is None:
            l_actions = [m for m in cls.callables]
        else:
            if command:
                l_actions = [m for m in cls.callables if m["command"] is not None]
            else:
                l_actions = [m for m in cls.callables if m["command"] is None]
        
        #log.trace(f"Actions : {l_actions}")
        if names:
            return list(dict.fromkeys([a['action'] for a in l_actions]))
        else:
            return l_actions
            
    
    @classmethod
    def action(cls, action: str, command: Optional[str] = None) -> Optional[dict]:
        """ Function that returns a dict containing action attributes if 
        action exists else None. By default retreives action with no command.
        If command is provided, retreive action with this command name. 

        :param str action: Retreive actions with name <action>
        :param Optional[str] command: Retreive actions with command name <command> 
                                      (None by default)

        :return: Action attributes or None if action does not exists
        """
        return next(
            iter([
                m for m in cls.callables 
                if m["action"] == action and m["command"] == command
            ]), 
            None
        )
    
    @classmethod
    def commands(cls, action: str, names=False) -> dict:
        """ Function that returns a list of commands available for an action 

        :param str action: Retreive commands with action name <action>
        :param bool names: Retreive only commands names (False by default)
        :return: Methods name list
        """
        l_commands = [
            m for m in cls.callables 
            if m["action"] == action and m['command'] is not None
        ]
        if names:
            return list(dict.fromkeys([c['command'] for c in l_commands]))
        else:
            return l_commands


    def command(cls, action: str, command: str) -> Optional[dict]:
        """ Function that returns a dict containing command attributes if 
        action exists and command else None. 

        :param str action: Retreive actions with name <action>
        :param str command: Retreive actions with command name <command>

        :return: Command attributes or None if action or command does not exists
        """
        return next(
            iter([
                m for m in cls.callables 
                if m["action"] == action 
                and m["command"] is not None 
                and m["command"] == command
            ]), 
            None
        )


    @classmethod
    def atypes(cls) -> dict:
        """ Function that returns a dict containing attributes name and 
        type for all standard attributes

        :return: A dict containing attributes name and type for all attributes
        """
        return {
            a["name"]: a["type"] 
            for a in cls.attributes['standard'] if "name" in a
        }

    @classmethod
    def attrs_ext(cls):
        """ Function that returns extended attribute short name

            :return: Extended attributes short names
        """
        return [a["name"] for a in cls.attributes['extended'] if "name" in a]

    @classmethod
    def help(cls) -> List[tuple]:
        """ Function that returns a list of tuple with attribute and help 
        string. For extended attributes, attribute help is suffixed 
        by " (extended))".

        :return: A list of tuple (attribute, help)
        
        :raise NotImplementedError: If attribute category is unknown

        """
        dhelp = []
        
        for c, attrs in cls.attributes.items():
            for a in attrs:
                if c == 'standard':
                    if issubclass(a['type'], GenericObjects):
                        dhelp.append((a["name"], f"{a['help']} (Object list)"))
                        dhelp.append((a, a['type'].otype().help()))
                    else:
                        dhelp.append((a["name"], a["help"]))
                elif c == 'extended':
                    dhelp.append((a["name"], f"{a['help']} (extended)"))
                else: 
                    raise NotImplementedError(
                        f"Attribute category '{c}' is unknown"
                    )
                  
        return dhelp
    
    def dattrs(self) -> dict:
        """ Return object standard attributes as a dict. if an attribute is a 
        GenericObjects it is converted to a list of dict

        :return: A dict containing standard attribute name as key
        """
        return {
            a: getattr(self, a, None).dattrs() 
            if isinstance(getattr(self, a, None), GenericObjects) 
            else getattr(self, a, None) 
            for a in self.attrs() + self.attrs_ext()
        }          

    @classmethod
    def to_filters(cls, filter_options: list) -> list:
        """ Function that parses and return filters from command line option 

        It parses and converts '--filter module_attribute="value"' in a 
        tuple (rpn operator, obj_attribute, operator, regex_value) and raises error if filter option 
        can not be parsed.

        :param list filter_options: An array of command line filter options
        :return: a set of tuples (obj_attribute, value_regex)

        :raise ValueError: if attribute is not a standalone attribute or a 
                           module_attribute
        :raise ValueError: if module_attribute not in available module's 
                           attribute list
        :raise ValueError: if filter syntax does not follow the 
                           scheme <module_attribute>=<regex>
        """
        filters = []
        operators_regex = '|'.join(hpc.filters.filter_operators.keys())
        rpn_operators_regex = '|'.join(hpc.filters.rpn_operators.keys())
        if filter_options:
            filter_regex = compile(
                r'^(?P<attribute>.+?)'
                r'(?P<operator>(' + operators_regex + r'))'
                r'(?P<value>.*)$|'
                r'^(?P<rpn>'+ rpn_operators_regex + r')$'
            )
            for f in filter_options:
                log.trace(f"Analysing filter '{f}' ...")
                mfilter = filter_regex.match(f)
                if mfilter:
                    rpn_op = mfilter.group("rpn")
                    log.trace(f"RPN filter '{rpn_op}' ...")
                    if rpn_op is None:
                        operator = mfilter.group("operator")
                        value = mfilter.group("value")
                        attribute = mfilter.group("attribute")
                        attrs = attribute.split('_', 1)
                        if len(attrs) == 2:
                            all_attributes = [
                                f"{module}_{a}" 
                                for module, o in cls.atypes().items() 
                                for a in o.attrs() + o.attrs_ext()
                            ]
                        elif len(attrs) == 1:
                            all_attributes = [
                                f"{a}" for a in cls.attrs() + cls.attrs_ext()
                            ]
                        else:
                            raise ValueError(
                                f"Bad filter attribute '{attribute}'. Object "
                                f"attribute must be one of a standalone "
                                f"attribute or a module_attribute"
                            ) 
                        if attribute not in all_attributes:
                            raise ValueError(
                                f"Bad filter attribute '{attribute}'. Object "
                                f"attribute must be one of {all_attributes}"
                            )
                        
                        operator_check = hpc.filters.filter_operators[operator]['check'](value)
                        if len(operator_check) > 0:
                            raise ValueError(
                                    f"Bad filter value '{f}' for {hpc.filters.filter_operators[operator]['name']} ({operator}) "
                                    f"operator . {operator_check}"
                            ) 
                        log.trace(
                            f"Parsed filter '{(None, attribute, operator ,value)}' ..."
                        )
                        filters.append((None, attribute, operator ,value))
                    else:
                        filters.append((rpn_op, None, None ,None))
                else:
                    raise ValueError(
                            f"Bad filter syntax '{f}'. Syntax must be "
                            f"'(<attribute>({operators_regex})<value>)"
                            f"|({rpn_operators_regex})'"
                    )
                ops = [
                    rpn_op for rpn_op, attr, op, value in filters 
                    if rpn_op in hpc.filters.rpn_operators
                ]
                

            if len(ops) > 0:
                rpn_filters = [
                    rpn_op 
                    if rpn_op in hpc.filters.rpn_operators else True 
                    for rpn_op, attr, op, value in filters
                ]
                log.trace(f"Found RPN expression : {rpn_filters}")
                # Evaluate if rpn expression is correct
                try:
                    hpc.filters.rpn(rpn_filters)
                except Exception as e:
                    raise ValueError(e)

        return filters

    def filter(self, o_filter: tuple):
        """ Method that check if this object match filter. Comparison are 
        done with filter operator.

        :param tuple o_filter: A filter tuple.
        :return: True if this object match filter else false

        :raise NotImplementedError: If filter operator does not exists.

        .. note:: Filter tuple example:

           (<attribute>, <filter operator>, <value>")
        
        """
        (f_attribute, f_operator, f_value) = o_filter
        value = getattr(self, f_attribute, None)

        # Generic hook : replace all attribute name surround by braket by 
        # its value
        
        # Check if we have hooks for this filter
        # self.__log__.trace(
        #     f"Looking for hook '({self.mname}, {f_attribute})' on "
        #     f"filter value '{f_value}' ..."
        # )
        if self.mname in hooks and \
           f_attribute in hooks[self.mname] and \
           f_value in hooks[self.mname][f_attribute]:
            hook = hooks[self.mname][f_attribute][f_value](self)
            self.__log__.trace(
                f"Applying hook '({self.mname}, {f_attribute})' on filter "
                f"value '{f_value}' : {hook}"
            )
            f_value = hook
        
        # apply filter operator
        if f_operator in hpc.filters.filter_operators:
            return hpc.filters.filter_operators[f_operator]['function'](
                value, f_value
            )
        else:
            raise NotImplementedError(
                f"This filter operator is not supported {f_operator}"
            )

    def fdattrs(self, attrs: List[str], flat: Optional[str]=None) -> dict:
        """ Return a dict {attrs: value, ...} containing only wanted attrs for 
        this object

        :param List[str] attrs: Wanted attributes name list
        :param Optional[str] flat: The name of the attribute to expand or 
                                   None if no expand is wanted

        :return: A dict with wanted attributes and values ready to use 
                 with csv.DictReader
        """
        
        l = []
        r = self.dattrs()
        if flat is None:
            # self.__log__.trace(f"Add record : {r}")
            l.append(dict(convert(a, r[a]) for a in attrs))
        else:
            # self.__log__.debug(f"Expanding attribute '{flat}'")
            for entry in r[flat]:
                # self.__log__.debug(entry)
                nr = {}
                for a in attrs:
                    if a == flat:
                        nr.update({a: entry})
                    else:
                        nr.update({a: r[a]})
                {convert(a, entry) if a == flat else r[a] for a in attrs}
                # self.__log__.trace(f"Add record : {nr}")
                l.append(nr)          

        # self.__log__.debug(f"l = {l}")
        return l

    def assign(self, **kwargs):
        """ Assign \\**kwargs arguments to the corresponding object 
        attribute if exists.

        \\**Kwargs arguments are assigned by attribute name.

        :param dict \\**kwargs: \\**Kwargs dict passed to the __init__ function

        :raise AttributeError: if Object attribute does not exists
        """
        for attribute, value in kwargs.items():
            # self.__log__.trace(
            #     f"Parsing attribute '{attribute}' with value '{value}'"
            # )

            # Force private attribute use
            if attribute in self.__class__.attrs():
                attribute = f"_standard_{attribute}"
            if attribute in self.__class__.attrs_ext():
                attribute = f"_extended_{attribute}"
            if hasattr(self, attribute):
                # Force setter use
                # self.__log__.trace(
                #     f"Found attribute '{attribute}' with value '{value}'"
                # )
                if attribute.startswith('_standard_'):
                    attribute = attribute.replace('_standard_', '', 1)
                if attribute.startswith('_extended_'):
                    attribute = attribute.replace('_extended_', '', 1)
                setattr(self, attribute, value)
            else:
                raise NameError(
                    f"No attribute '{attribute}' found in object '{self}'"
                )

    def from_dict(self, attrs_dict: dict, required_attrs=None, optional_attrs=None):
        """ This method create a GenericObject from a dictionnay containing 
        attribute names and values for all standard attributes. 

        The best way to use this method is to call HpcModuleManager width all 
        standard modules attributes save the output in a csv file and read 
        this file with csv.Dictreader()

        .. code-block:: python

            objs = GenericObjects()
            csv_obj_data = DictReader("/path/to/csv_file", delimiter=':')
            for obj_data in csv_obj_data:
                o = GenericObject()
                o.from_dict(obj_data)
                objs.add(o)

        :param dict attrs_dict: A dictionnay containing attribute names and 
                                values for all standard attributes

        :raise RuntimeError: If csv string value can not be converted to 
                             module real value type
        :raise ValueError: If dict key is not a valid module attribute
        """
        attrs = {}

        for attr, atype in self.atypes().items():
            require = None
            if required_attrs and attr in required_attrs:
                require = True
            elif optional_attrs and attr in optional_attrs:
                require = False
            else:
                require = None

            attrs.update({
                attr : {
                    'type': atype,
                    'value': None,
                    'required': require,
                    'set': False,
                }
            })

        # Pas fini fini, pas assez de controles
        for key, value in attrs_dict.items():
            attrs[key]['value'] = value
            attrs[key]['set'] = True

        # TODO : 
        attrs_set = {
            a : not (adata['required'] is not None and adata['required'] and not adata['set'])
            for a, adata in attrs.items()
        }
        # print(list(attrs_set.values()))
        self.__log__.debug(
            f"Attributes set : '{attrs_set}' ([{','.join(f'{v}' for v in list(attrs_set.values()))}])"
        )
        if all(list(attrs_set.values())):
            self.__log__.debug(f"Creating object '{self.otype}' ...")

            # Assigning attribute value and convert it first if needed
            for attr, adata in attrs.items():
                if isinstance(adata['value'], adata['type']):
                    self.__log__.debug(
                        f"Found correct value '{adata['value']}' "
                        f"({type(adata['value'])}) for attribute '{attr}' ..."
                    )
                else:
                    self.__log__.debug(
                        f"Converting value '{adata['value']}' "
                        f"({type(adata['value'])}) in "
                        f"'{adata['type']}' for attribute '{attr}' ..."
                    )
                    if adata['value'] is not None:
                        try:
                            if adata['type'] is int:
                                if adata['value']:
                                    d = adata['type'](adata['value'])
                                    attrs[attr]['value'] = d
                                else:
                                    attrs[attr]['value'] = None
                            elif adata['type'] is list:
                                if adata['value'] == '':
                                    attrs[attr]['value'] = []
                                else:
                                    l = adata['value'].split(',')
                                    attrs[attr]['value'] = l
                            elif issubclass(adata['type'], GenericObjects):
                                attrs[attr]['value'] = adata['type']()
                                if isinstance(adata['value'],list):
                                    l = adata['value'].split(',')
                                    attrs[attr]['value'].add(l)
                            elif adata['type'] is Path:
                                attrs[attr]['value'] = adata['type'](adata['value'])
                            elif adata['type'] is bool:
                                attrs[attr]['value'] = adata['type'](adata['value'])

                            self.__log__.debug(
                                f"Converted value '{adata['value']}' "
                                f"({type(adata['value'])}) in "
                                f"'{adata['type']}' : "
                                f"{attrs[attr]['value']} ({type(attrs[attr]['value'])})"
                            )
                        except Exception as e:
                            raise RuntimeError(
                                f"Unable to convert value '{adata['value']}' "
                                f"({type(adata['value'])}) in "
                                f"'{adata['type']}' for "
                                f"attribute '{attr}'"
                            )
                    else:
                        self.__log__.debug(
                                f"No Conversion for value '{adata['value']}' "
                                f"({type(adata['value'])}) in "
                                f"'{adata['type']}'"
                            )
                        
            ok_attrs = {a:d['value'] for a, d in attrs.items()}
            self.__log__.trace(f"Assigning attrs {ok_attrs} to object '{self.otype}' ...")
            self.__init__(**ok_attrs)
        else:
            raise AttributeError(
               f"All required attributes must be set. Attribute(s) "
               f"'{', '.join([a for a, v in attrs_set.items() if not v])}' "
               f"must be set."
            )

    def call(
            self, command: str, undo: Optional[str]=None, 
            doit: Optional[bool]=False, stop_on_failure=True, 
            **kwargs
        ):
        """Call method name called "command".

        :param str command: Method to call
        :param Optional[str] undo: Method to call if command execution 
                                   fails, defaults to None
        :param Optional[bool] doit: Really do command else just print what 
                                    should be done, defaults to False
        :param bool stop_on_failure: Raise if command execution fails, 
                                     defaults to True
        
        :raises RuntimeError: If command execution fails and stop_on_failure 
                              flag is enable
        """
        run_mode = doit
        done_commands = []
        todo_commands = []
        undo_commands = []
        run_result = []
        
        args = [f"{k}={type(v).__name__}<{v}>" for k,v in kwargs.items()]
        self.__log__.debug(
            f"Calling command '{command}' of '{self}' (Doit={run_mode}, {', '.join(args)})..."
        )
        try:
            if doit is None: 
                run_result.append(getattr(self, command)(**kwargs))
            else:
                run_result.append(getattr(self, command)(doit=run_mode, **kwargs))
                done_commands.append(getattr(self, command)(doit=False, **kwargs))
                if undo is not None:
                    self.__log__.debug(
                        f"Calling undo command '{undo}' of '{self}' (Doit={run_mode}, {', '.join(args)})..."
                    )
                    undo_commands.append(getattr(self, undo)(doit=False, **kwargs))
        except RuntimeError as e:
            run_mode = False
            todo_commands.append((getattr(self, command)(doit=False, **kwargs),e))

        if todo_commands:
            self.__log__.debug(
                f"Failure in '{self}' command '{command}' call"
            )      
            for c in list(chain.from_iterable(done_commands)):
                if doit:
                    self.__log__.info(f"  {c} : [OK]")
                else:
                    self.__log__.info(f"  {c} : [DRY-RUN]")
            for commands, e in todo_commands:
                self.__log__.error(f"  +> {e}")
                for c in commands:
                    self.__log__.error(f"  | {c} : [FAILED]")
            self.__log__.info('Undo changes :')
            for c in list(chain.from_iterable(undo_commands)):
                self.__log__.info(f"  {c}")
            if not undo_commands:
                self.__log__.info(f"  None")
            if stop_on_failure:
                # raise RuntimeError(
                #     f"Unable to execute command '{command}' on {self.otype} "
                #     f"'{self}'"
                # )
                self.__log__.debug(
                    f"Unable to execute command '{command}' on {self.otype} "
                    f"'{self}'"
                )
        else:
            for c in list(chain.from_iterable(done_commands)):
                if doit:
                    self.__log__.debug(f"  {c} : [OK]")
                else:
                    self.__log__.info(f"  {c} : [DRY-RUN]")
        return(run_result)


    @staticmethod
    def _internal_create_getx(attribute:str, category:str) -> Callable:
        """ Internal helper function to create dynamic getter

        :param str attribute: Short attribute name
        :param str category: Attribute category

        :return: A getter function on specified attribute
        """

        def getx(self):
            return getattr(self, f"_{category}_{attribute['name']}")

        return getx

    @staticmethod
    def _internal_create_setx(attribute: str, category:str) -> Callable:
        """ Internal helper function to create dynamic setter

        :param str attribute: Short attribute name
        :param str category: Attribute category

        :return: A setter function on specified attribute
        """

        def setx(self, value):
            if value is None or isinstance(value, attribute["type"]):
                setattr(
                    self, f"_{category}_{attribute['name']}", deepcopy(value)
                )
            else:
                raise TypeError(
                    f"Bad attribute value type '{value}' ({type(value)}) for "
                    f"attribute '{attribute['name']}' (Type must "
                    f"be '{attribute['type']}')")

        return setx

    def _create_attributes(self):
        """ Internal helper function to create dynamic attribute property 
        from class attributes list
        """
        for category, alist in self.__class__.attributes.items():
            for a in alist:
                g = self._internal_create_getx(a, category)
                s = self._internal_create_setx(a, category)

                # self.__log__.trace(
                #     f"Set default value '{a['default']}' "
                #     f"({type(a['default'])}) for "
                #     f"attribute '{a['name']}'"
                # )

                setattr(
                    self.__class__, a['name'], 
                    property(fget=g, fset=s, doc=a["help"])
                )
                setattr(self, f"{a['name']}", deepcopy(a["default"]))

    def __str__(self):
        attrs = [
            shorten(str(getattr(self, a, None)), width=10, placeholder='..') 
            for a in self.attrs() 
            if not getattr(self, a, None) == self.__class__.attribute(a)['default']
        ]
        attrs_ext = [
            shorten(str(getattr(self, a, None)), width=10, placeholder='..') 
            for a in self.attrs_ext() 
            if not getattr(self, a, None) == self.__class__.attribute(a)['default']
        ]
        return(
            f"<{', '.join(attrs)}, "
            f"[{', '.join(attrs_ext)}]>"
        )

    @property
    def __log__(self):
        """ Internal attibute providing a way to log inside class
        """
        return ccilogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )

# @ctrace
class GenericObjects(ABC):
    """ Abstract class for managing generic objects list

    List can be load from json file and save to json file. You can add indexes
    to speedup object's access. When derivating this class, to add a new index 
    you must override "__init__", "add" and "delete" methods.

    Example :

    .. code-block:: python

        class MyObject(GenericObject):
            attributes = register_attributes([{
                "name": "login", "category": "standard", 
                "type": str, "default": None, "help": "Attribute 1"
            }, {
                "name": "group", "category": "extended", 
                "type": str, "default": None, "help": "Attribute 2"
            }, {
                "name": "uid", "category": "standard", "type": int, 
                "default": None, "help": "Attribute 3"
            }])
            pass

        class MyObjects(GenericObjects):
            def __init__(self, **kwargs):
                self._register_index(index_name="logins", multiple=False)
                self._register_index(index_name="groups", multiple=True)
                super().__init__(**kwargs)

            def add(self, obj: 'MyObject'):
                super().add(obj)
                self._add_to_logins(obj.login, obj)
                self._add_to_groups(obj.group, obj)

            def delete(self, obj: 'MyObject'):
                super().delete(obj)
                self._delete_from_logins(obj.login, obj)
                self._delete_from_groups(obj.group, obj)

            pass

    You can retrieve full index or just a key in the index with dynamically 
    created methods:

      * **get_<index name>() -> dict**: 
          To get the content off all keys in the index
      * **get_by_<index name>(<index key>) -> Union[object, object list]**: 
          To get the content of one key in an index
    """
    __config__ = None

    def __init__(
            self, objs: Union[GenericObject, list, 'GenericObjects'] = None, 
            **kwargs
        ):

        self._objects: List[GenericObject] = []
        if objs is not None:
            if isinstance(objs, GenericObject):
                self.add(objs)
            elif isinstance(objs, GenericObjects) or isinstance(objs, list):
                self.adds(objs)
            else:
                raise TypeError(
                    f"Must be a GenericObject, a list or a "
                    f"GenericObjects ({type(objs)})"
                )
        if kwargs:
            self.__log__.warning(
                "Param **kwargs are not use in GenericObjects instantiation."
            )

    @property
    def config(self):
        """ Object configuration
        """
        return self.__class__.__config__

    def get(self) -> List[GenericObject]:
        """ Get the object list

        :return: Objects list
        """
        return self._objects

    def len(self) -> int:
        """ Get the object list length

        :return: Object list length
        """
        return len(self._objects)

    def get_by_value(
            self, attr: str, value: any
        ) -> Optional['GenericObjects']:
        """ Get all objects from the list with attribute name and attribute 
        value

        :param str attr: Attribute name
        :param any value: Attribute value

        :return: Generic objects list for object with attribute name and 
                 attribute value or None if no match
        """
        objs = [
            obj for obj in self 
            if hasattr(obj, attr) and getattr(obj, attr) == value
        ]
        if objs:
            return self.__class__(objs=objs)
        else:
            return None

    def add(self, obj: GenericObject):
        """ Add an object to the objects list

        :param GenericObject obj: Object to add object to the list

        :raise KeyError: If object is already in object list
        :raise TypeError: If object is not a GenericObject or derived from 
                          GenericObject
        """
        if isinstance(obj, GenericObject):
            if obj in self._objects:
                raise KeyError(f"Object '{obj}' is already in object list")
            else:
                self._objects.append(obj)
        else:
            raise TypeError(
                f"Object obj must be a GenericObject or derived from "
                f"GenericObject ({type(obj)})"
            )

    def delete(self, obj: GenericObject):
        """ Delete an object to the objects list

        :param GenericObject obj: Object to delete from the list

        :raise KeyError: If object is not in object list
        :raise TypeError: If object is not string or a GenericObject or 
                          derived from GenericObject
        """
        if isinstance(obj, GenericObject):
            if obj in self._objects:
                self._objects.remove(obj)
            else:
                raise KeyError(f"Object '{obj}' is not in object list")
        else:
            raise TypeError(
                f"Object obj must be a string or a GenericObject "
                f"or derived from GenericObject ({type(obj)})"
            )

    def adds(self, lobj: Union[List, 'GenericObjects']):
        """ Add an object list to the objects list

        :param Union[List, 'GenericObjects'] lobj: Object list of GenericObject
                                                   or GenericObjects to add to 
                                                   the list

        :raise ValueError: if object list to add is not a list of 
                           GenericObject or a GenericObjects
        """

        if isinstance(lobj, list) or isinstance(lobj, GenericObjects):
            [self.add(obj) for obj in lobj]
        else:
            raise TypeError(
                f"Must be a list of GenericObject or GenericObjects, can't "
                f"add '{lobj}'"
            )

    def deletes(self, lobj: Union[List, 'GenericObjects']):
        """ Remove an object list from the objects list

        :param Union[List, 'GenericObjects'] lobj: Object list or 
                                                   GenericObjects to remove 
                                                   from the list

        :raise ValueError: if object list to delete is None
        :raise ValueError: if object list to delete is not a list of 
                           GenericObject or a GenericObjects
        """
        if isinstance(lobj, list) or isinstance(lobj, GenericObjects):
            for obj in lobj:
                self.delete(obj)
        else:
            raise TypeError(
                f"Must be a list of GenericObject or GenericObjects, "
                f"can't delete '{lobj}'"
            )
    
    def dattrs(self) -> list:
        """ Return a list of object standard attributes as a dict.

        :return: A list containing all object as a dict
        """
        return [o.dattrs() for o in self._objects]

    def fdattrs(
            self, attrs: List[str], flat: Optional[str]=None
        ) -> List[dict]:
        """ Return a list of dict {attrs: value, ...} containing only wanted 
        attrs for all objects in the list

        :param List[str] attrs: Wanted attributes name list
        :return: A list of dict with wanted attributes and values
        """
        fields = []
        if flat is None:
            for obj in self:
                fields += obj.fdattrs(attrs)
        else:
            for obj in self:
                fields += obj.fdattrs(attrs, flat)

        return fields
    
    def save(self, objects_file: Path, fmt: Optional[str] = None):
        """ Save all objects from the list in a json file

        :param Path objects_file: Json file full path to save objects list
        :param Optional[str] fmt: Json format style can be "compact" or "log". 
                                  Default to pretty print with indent=2.
        """
        with open(objects_file.as_posix(), 'w') as objects_fh:
            if fmt == "log":
                o_dump = ",\n".join([
                    " {}".format(dumps(
                            obj, cls=JSONObjectEncoder, indent=None, 
                            sort_keys=False, ensure_ascii=False
                    )) for obj in self._objects
                ])
                objects_fh.write(f"[\n{o_dump}\n]\n")
            elif fmt == "compact":
                dump(
                    self._objects, cls=JSONObjectEncoder, fp=objects_fh, 
                    indent=None, sort_keys=False, ensure_ascii=False
                )
            else:
                dump(
                    self._objects, cls=JSONObjectEncoder, fp=objects_fh, 
                    indent=2, sort_keys=False, ensure_ascii=False
                )

    def filters(self, filters: List[tuple]):
        """ Retrieves objects matching filters. Comparison are done with 
        filter operator and value and are case insensitive.

        :param List[tuple] filters: A filter tuple list.

        :return: Generic object matching filters

        .. note:: Filter tuple example:

           (<attribute>, <join operator>, <filter operator>, <value>")

        Join operator is and (&) by default. The other join operator is or (|).

        """
        fgo = GenericObjects()
        for obj in self:
            result = False
            f_results = []
            for f in filters:
                # self.__log__.debug(f"Applying filter {f} ...")
                (f_rpn, f_attribute, f_operator, f_value) = f
                if f_rpn is None:
                    attrs = obj.attrs() + obj.attrs_ext()
                    generic_hook_regex = compile(
                            r'\[(' + '|'.join(attrs) + r')\]'
                        )
                    for m in generic_hook_regex.findall(f_value):
                        if m in attrs:
                            generic_hook_subregex = compile(r'\[' + m + r'\]')
                            n_value = f"{getattr(obj, m, None)}"
                            f_value = generic_hook_subregex.sub(
                                ssafe(n_value), f_value, 1
                            )
                    f_results.append(
                        obj.filter((f_attribute, f_operator, f_value))
                    )
                else:
                    # rpn is not None
                    f_results.append(f_rpn)
            if len([
                    rpn_op for rpn_op, attr, op, value in filters 
                    if rpn_op in hpc.filters.rpn_operators
                ]) > 0:
                # self.__log__.debug(f"RPN : {f_results} = {result}")
                result = hpc.filters.rpn(f_results)
            else: 
                # No operator all filters are evaluated with "and" operator
                result = all(f_results)
                # self.__log__.debug(f"Filter (&) : {f_results} = {result}")
                
            if result:
                fgo.add(obj)
        return fgo

    def load(self, objects_file: Path):
        """ Load all objects into the list from a json file

        :param Path objects_file: Json file full path to load objects list from
        """
        with open(objects_file.as_posix(), 'r') as objects_fh:
            self.adds(load(objects_fh, cls=JSONObjectDecoder))

    def _register_index(self, index_name: str, multiple: bool = False):
        """ Register an index to search object in list by key

        :param str index_name: Name of the index to add
        :param bool multiple: True if a key can refer to a list of object 
                              (False by default)
        """
        def get_index_by_key(key):
            return self._get_by_index(f"_index_{index_name}", key)

        def get_index():
            return self._get_index(f"_index_{index_name}")

        def add_to_index(key, value):
            self._add_to_index(f"_index_{index_name}", key, value, multiple)

        def delete_from_index(key, value):
            self._delete_from_index(f"_index_{index_name}", key, value, multiple)

        setattr(self, f"_index_{index_name}", {})
        setattr(self, f"_add_to_{index_name}", add_to_index)
        setattr(self, f"_delete_from_{index_name}", delete_from_index)
        setattr(self, f"get_{index_name}", get_index)
        setattr(self, f"get_by_{index_name}", get_index_by_key)

    def _add_to_index(
            self, index: str, key: Union[int, str], 
            obj: GenericObject, multiple: bool = False
        ):
        """ Add an object into to an index indexed by a key

        :param str index: The name of the index
        :param Union[int, str] key: The key inside the index to add object to
        :param GenericObject obj: The object to set or to add to the index key
        :param bool multiple: True if a key can refer to a list of object 
                              (False by default)

        :raise ValueError: if index name is not defined as an attribute
        :raise ValueError: if a key refers to a single object (multiple=False) 
                           and key is already refers to an object
        """
        if hasattr(self, index):
            idx = getattr(self, index)
            if idx is None:
                idx = {}
            if key in idx:
                if multiple:
                    if obj in idx[key]:
                        raise ValueError(
                            f"Object '{obj}' is already indexed, somthing "
                            f"goes wrong."
                        )
                    else:
                        # self.__log__.trace(f"Append obj '{obj}' to key '{key}' in index '{index}'")
                        idx[key].append(obj)
                else:
                    raise ValueError(
                        f"Key index '{key}' in index '{index}' is not "
                        f"multiple and is already linked with "
                        f"object '{idx[key]}'"
                    )
            else:
                if multiple:
                    # self.__log__.trace(
                    #     f"Append obj '{obj}' to key '{key}' in "
                    #     f"index '{index}' (first obj)"
                    # )
                    idx.update({key: [obj]})
                else:
                    # self.__log__.trace(
                    #     f"Add obj '{obj}' to key '{key}' in index '{index}'"
                    # )
                    idx.update({key: obj})
            setattr(self, index, idx)
        else:
            raise ValueError(f"No index '{index}' defined")

    def _delete_from_index(
            self, index: str, key: Union[int, str], 
            obj: GenericObject, multiple: bool = False
        ):
        """ Remove an object from an index indexed by a key

        :param str index: The name of the index
        :param Union[int, str] key: The key inside the index to remove 
                                    object from
        :param GenericObject obj: The object to remove from the index key or 
                                  the index key list
        :param bool multiple: True if a key can refer to a list of object 
                              (False by default)

        :raise ValueError: if index name is not defined as an attribute
        :raise ValueError: if object to remove can not be fount in index key 
                           or index key list
        """
        if hasattr(self, index):
            idx = getattr(self, index)
            if idx is None:
                raise ValueError(f"Index '{index}' is not set")
            else:
                if key in idx:
                    if multiple:
                        if obj in idx[key]:
                            idx[key].remove(obj)
                        else:
                            raise ValueError(
                                f"Object '{obj}' is not indexed, somthing "
                                f"goes wrong."
                            )
                        if not idx[key]:
                            idx.pop(key)
                    else:
                        idx.pop(key)
                    setattr(self, index, idx)
                else:
                    raise ValueError(
                        f"Key '{key}' is not in index, somthing goes wrong."
                    )
        else:
            raise ValueError(f"No index '{index}' defined.")

    def _get_by_index(
            self, index: str, key: str
        ) -> Optional[Union['GenericObjects', List['GenericObjects']]]:
        """ Get all objects from the list from the index

        :param str index: Index name
        :param str key: Index key

        :return: None if key is not found else Objects list for objects 
                 in index if it's a multiple index else only one Object
        """
        if hasattr(self, index):
            idx = getattr(self, index)
            if idx is None:
                raise ValueError(f"Index '{index}' is not set")
            else:
                # self.__log__.trace(
                #     f"Looking for key '{key}' in index '{idx}' ..."
                # )
                if key in idx:
                    if isinstance(idx[key], list):
                        return self.__class__(objs=idx[key])
                    else:
                        return idx[key]
                else:
                    return None

    def _get_index(self, index: str) -> Optional[dict]:
        """ Get all objects from the list from the index

        :param str index: Index name

        :return: Index
        """
        if hasattr(self, index):
            idx = getattr(self, index)
            if idx is None:
                raise ValueError(f"Index '{index}' is not set")
            else:
                return idx
        else:
            raise ValueError(f"No index '{index}' defined.")

    @property
    def __log__(self):
        """ Internal attibute providing a way to log inside class
        """
        return ccilogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )

    def __iter__(self):
        return self._objects.__iter__()

    def __next__(self):
        return self.__iter__().__next__()

    def __repr__(self):
        return f"<{self.__class__.__name__}>"
