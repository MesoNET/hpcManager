# -*- coding: utf-8 -*-
""" Module for managing meta users and groups
"""
from hpc.generics import GenericObjects, GenericObject
from hpc.utils import ssafe, ThreadSafe, removesuffix
from hpc.converters import convert
from itertools import chain
from typing import KeysView, List, Optional
from hpc.filters import filter_operators, rpn_operators, rpn
from sys import modules
from re import compile, escape
from pathlib import Path
import copy
from cilogger.cilogger import ccilogger  # , ctrace
log = ccilogger(__name__)

# @ctrace
class MetaGroup(GenericObject):
    """
    Meta group
    """
    _config__ = None
    attributes = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __str__(self) -> str:
        oids = [
            f"{None}"
            if getattr(self, m['name'], None) is None 
            else '_'.join([
                f"{getattr(getattr(self, m['name'], None), key, None)}"
                for key in m['keys']
            ])
            for m in self.config['modules']['user']
        ]
        return f"[{self.otype}]<{','.join(oids)}>"
    
    def modules(self, method):
        """ Function that return a dict {name: module object} for all module 
        which is an object and has a method called method

        :param str method: The method name to search for in modules
        """
        return {
            a:getattr(self, a)
            for a in self.attrs() 
            if getattr(self, a) is not None 
            and callable(getattr(getattr(self, a), method, None))
        }
    
    def from_dict(self, group_dict: dict):
        """ This method create an metaGroup from a dictionnay containing 
        attribute names and values for all modules.

        The best way to use this method is to call MetaManager with all 
        standard modules attributes save the output in a csv file and read 
        this file with csv.Dictreader()

        .. code-block:: python

            objs = MetaGroups()
            csv_obj_data = DictReader("/path/to/csv_file", delimiter=':')
            for obj_data in csv_obj_data:
                o = MetaGroup()
                o.from_dict(obj_data)
                objs.add(o)

        :param dict group_dict: A dictionnay containing attribute names and 
                                values for all modules

        :raise RuntimeError: If csv string value can not be converted to 
                             module real value type
        :raise ValueError: If dict key is not a valid module attribute
        """
        lmodules = {}
        for m in self.config['modules']['group']:
            lmodules.update({
                m['name']: {
                    'type': m['type'],
                    'attrs': {}
                }
            })

        for key, value in group_dict.items():
            (m_name, attr) = key.split('_')
            lmodules[m_name]['attrs'].update({attr: value})

        self.__log__.debug(f"Module dict : {lmodules}")

        for module, mdata in lmodules.items():
            self.__log__.debug(f"Creating object '{module}' ...")
            mobj = mdata['type']()
            attrs = {k:v for k,v in mdata['attrs'].items() if k in mobj.attrs()}
            mobj.from_dict(attrs)
            setattr(self, module, mobj)
            
    def call(
            self, command: str, undo: Optional[str]=None, 
            doit: Optional[bool]=False, stop_on_failure=True
        ):
        """Call method name called "command" on each meta modules if method
        exists in module.

        :param str command: Module method to call
        :param Optional[str] undo: Module method to call if command execution 
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
        for name, m in self.modules(command).items():
            self.__log__.debug(
                f"Calling command '{command}' of meta group '{self}' in "
                f"module {name} (Doit={run_mode})..."
            )
            try:
                if doit is None: 
                    run_result.append(getattr(m, command)())
                else:
                    run_result.append(getattr(m, command)(doit=run_mode))
                    done_commands.append(getattr(m, command)(doit=False))
                    if undo is not None:
                        undo_commands.append(getattr(m, undo)(doit=False))
            except RuntimeError as e:
                run_mode = False
                todo_commands.append((getattr(m, command)(doit=False),e))

        if todo_commands:
            self.__log__.error(
                f"Failure in meta group '{self}' command '{command}' call"
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
                raise RuntimeError(
                    f"Unable to execute command '{command}' on meta "
                    f"group '{self}'")
        else:
            for c in list(chain.from_iterable(done_commands)):
                if doit:
                    self.__log__.debug(f"  {c} : [OK]")
                else:
                    self.__log__.info(f"  {c} : [DRY-RUN]")
        return(run_result)

    def fdattrs(self, attrs: List[str]) -> List[dict]:
        """ Return a dict {attrs: value, ...} containing only wanted attrs 
        for this object

        :param List[str] attrs: Wanted attributes
        
        :return: A dict with wanted attributes and values
        """
        r = {}
        
        for a in attrs:
            a_type, a_name = a.split("_", 1)

            value = getattr(getattr(self, a_type), a_name.lower(), '')
            #self.__log__.trace(f"Raw value for '{a_name}' : {value}")
            ac, vc = convert(f"{a_name}", value)

            r.update({f"{a_type}_{ac}": vc})
 
        #self.__log__.trace(f"Add record : {r}")
        return [r]

# @ctrace
class MetaGroups(GenericObjects):
    """
    List of MetaGroup objects.
    """
    __config__ = None
    def __init__(self, **kwargs):
        self._keys = {
            m['name']: m['keys']
            for m in self.config['modules']['group']
        }
        self._register_index(index_name="ids",multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: MetaGroup):
        super().add(obj)
        current_id = next(iter([
            "_".join([
                getattr(getattr(obj,name),k) for k in keys
            ]) for name, keys in self._keys.items() 
            if getattr(obj,name) is not None
        ]), None)
        self._add_to_ids(current_id, obj)

    def delete(self, obj: MetaGroup):
        super().delete(obj)
        current_id = next(iter([
            "_".join([
                getattr(getattr(obj,name),k) for k in keys
            ]) for name, keys in self._keys.items() 
            if getattr(obj,name) is not None
        ]), None)
        self._delete_from_ids(current_id, obj)
    
    def generate_missing(self):
        """ Generate missing atttributes values for a module if those 
        attributes in modules has generators defined in configuration
        """
        # Obj key
        for m in [
                mod for mod in self.config['modules']['group'] 
                if 'generators' in mod
            ]:
            self.__log__.trace(
                f"Generate missing attributes for module '{m['name']}' ..."
            )
            for obj in [
                    o  for o in self.get() 
                    if getattr(o, m['name'], None) is None
                ]:
                attrs = {
                    a.replace(f"{m['name']}_",''): generator(self.get(), obj) 
                    for a, generator in m['generators'].items() 
                    if a.replace(f"{m['name']}_",'') in 
                       list(set(m['keys'] + m['type'].attrs() + m['type'].attrs_ext()))
                }
                self.__log__.trace(
                    f"Generated missing attributes for module '{m['name']}' : {attrs}"
                )
                # We remove generated attributes if key is None
                if all([attrs[k] is not None for k in m['keys']]):
                    m_obj = m['type'](**attrs)
                    setattr(obj, m['name'], m_obj)
                else:
                    self.__log__.trace(
                        f"Cleaned generated missing attributes for module "
                        f"'{m['name']}' : No key for this module where "
                        f"generated ({[(k,attrs[k]) for k in m['keys']]})"
                    )

    def merge(self, name: str, objs: GenericObjects):
        """ Merge module according to module's merging key defined in 
        configuration

        :param str name: Module name
        :param GenericObjects objs: A list of objects

        :raise RuntimeError: If module can not be identified by key in 
                             MetaGroup object
        """
        self.__log__.trace(f"Merging module '{name}' ...")
        self.__log__.trace(self)
        for obj in objs:
            # Getting modules's keys
            okey = "_".join(
                [getattr(obj,k) for k in self._keys[name]]
            )
            if okey in self.get_ids():
                mobj = getattr(self.get_by_ids(okey), name, "Module Not Found")
                if mobj == "Module Not Found":
                    raise RuntimeError(
                        f"Unable to find module '{name}' in MetaGroup object "
                        f"identified by key '{okey}'"
                    )
                else:
                    setattr(self.get_by_ids(okey), name, obj) 
            else:
                m_obj = getattr(
                    modules[self.__class__.__module__],
                    removesuffix(self.__class__.__name__, 's')
                )
                o = {name: obj}
                self.add(m_obj(**o))

    def populate(self):
        """ Call populate methods for all defined module in configuration
        """
        lmodules = {}
        threads = []
        for m in self.config['modules']['group']:
            objs = m['list']()
            lmodules.update({m['name']: objs})
            threads.append(ThreadSafe(target=objs.populate))

        # Paralelize populate
        [t.start() for t in threads]
        [t.join() for t in threads]

        for e in [t.exception for t in threads if t.exception is not None]:
            raise e

        # Merge results
        [self.merge(name, objs) for name, objs in lmodules.items()]

    def filters(self, filters: List[tuple]) -> 'MetaGroups':
        """ Retrieves objects matching filters. Comparison are done with 
        filter operator and value and are case insensitive.

        :param List[tuple] filters: A filter tuple list.
        
        :return: Meta group matching filters

        :raise NotImplementedError: If filter operator is not supported

        .. note:: Filter tuple example:

           (<meta attribute>_<module attribute>, <operator>, <value>)

        """
        m_objs = getattr(
            modules[self.__class__.__module__],
            self.__class__.__name__
        )
        fgmeta = m_objs()
        for obj in self:
            result = False
            f_results = []
            for f in filters:
                (f_rpn, f_attribute, f_operator, f_value) = f
                if f_rpn is None:
                    a_type, a_name = f_attribute.split("_", 1)
                    objtmp = getattr(obj, a_type, None)
                    # self.__log__.debug(
                    #     f"Applying filter {f} on {objtmp} ..."
                    # )
                    if objtmp is None:
                        if f_operator in filter_operators:
                            f_results.append(
                                filter_operators[f_operator]['function'](
                                    "", f_value
                                )
                            )
                        else:
                            raise NotImplementedError(
                                f"This filter operator is not "
                                f"supported {f_operator}"
                            )
                    else:
                        # Generic hook : replace all attribute name surround 
                        # by braket by its value
                        attrs = [
                            f"{module}_{a}" 
                            for module, o in obj.atypes().items() 
                            for a in o.attrs() + o.attrs_ext()
                        ]

                        generic_hook_regex = compile(
                            r'\[(' + '|'.join(attrs) + r')\]'
                        )

                        for m in generic_hook_regex.findall(f_value):
                            if m in attrs:
                                av_type, av_name = m.split("_", 1)
                                # self.__log__.trace(
                                #     f"Looking for meta generic hook "
                                #     f"'([{m}])' on filter value '{f_value}' "
                                #     f"in attrs list {attrs}..."
                                # )
                                n_value = f"{getattr(getattr(obj, av_type, None), av_name, None)}"
                                # self.__log__.trace(
                                #     f"Looking for meta generic hook '({m})' "
                                #     f"on filter value '{f_value}' in module "
                                #     f"{av_type} and attribute {av_name} : "
                                #     f"{n_value} in "
                                #     f"({getattr(obj, av_type, None)})"
                                # )
                                
                                generic_hook_subregex = compile(
                                    r'\[' + m + r'\]'
                                )
                                f_value = generic_hook_subregex.sub(
                                    escape(ssafe(n_value)), f_value, 1
                                )

                        f_results.append(
                            objtmp.filter((a_name, f_operator, f_value))
                        )
                else:
                    # rpn is not None
                    f_results.append(f_rpn)

            if len([
                    rpn_op for rpn_op, attr, op, value in filters 
                    if rpn_op in rpn_operators
                ]) > 0:
                # self.__log__.debug(f"RPN : {f_results} = {result}")
                result = rpn(f_results)
            else: 
                # No operator all filters are evaluated with "and" operator
                result = all(f_results)
                # self.__log__.debug(f"Filter (&) : {f_results} = {result}")
                
            if result:
                fgmeta.add(obj)
        return fgmeta

# @ctrace
class MetaUser(GenericObject):
    """
    Meta user

    A MetaUser is a user that has a unix account and a slurm account
    """
    __config__ = None
    attributes = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __str__(self) -> str:
        oids = [
            f"{None}"
            if getattr(self, m['name'], None) is None 
            else '_'.join([
                f"{getattr(getattr(self, m['name'], None), key, None)}"
                for key in m['keys']
            ])
            for m in self.config['modules']['user']
        ]
        return f"[{self.otype}]<{','.join(oids)}>"

    def modules(self, method, revert_order=False):
        """ Function that return a dict {name: module object} for all module 
        which is an object and has a method called method

        :param str method: The method name to search for in modules
        """
        if revert_order:
            return {
                a:getattr(self, a)
                for a in self.attrs()[::-1]
                if getattr(self, a) is not None 
                and callable(getattr(getattr(self, a), method, None))
            }
        else:
            return {
                a:getattr(self, a)
                for a in self.attrs() 
                if getattr(self, a) is not None 
                and callable(getattr(getattr(self, a), method, None))
            }
    
    def from_dict(self, user_dict: dict):
        """ This method create an metaUser from a dictionnay containing 
        attribute names and values for all modules.

        The best way to use this method is to call MetaManager width all 
        standard modules attributes save the output in a csv file and read 
        this file with csv.Dictreader()

        .. code-block:: python

            objs = MetaUsers()
            csv_obj_data = DictReader("/path/to/csv_file", delimiter=':')
            for obj_data in csv_obj_data:
                o = MetaUser()
                o.from_dict(obj_data)
                objs.add(o)

        :param dict user_dict: A dictionnay containing attribute names and 
                               values for all modules

        :raise RuntimeError: If csv string value can not be converted to 
                             module real value type
        :raise ValueError: If dict key is not a valid module attribute
        """
        lmodules = {}
        for m in self.config['modules']['user']:
            lmodules.update({
                m['name']: {
                    'type': m['type'],
                    'attrs': {}
                }
            })

        for key, value in user_dict.items():
            (m_name, attr) = key.split('_')
            lmodules[m_name]['attrs'].update({attr: value})

        self.__log__.debug(f"Module dict : {lmodules}")

        for module, mdata in lmodules.items():
            self.__log__.debug(f"Creating object '{module}' ...")
            mobj = mdata['type']()
            attrs = {k:v for k,v in mdata['attrs'].items() if k in mobj.attrs()}
            mobj.from_dict(attrs)
            setattr(self, module, mobj)
  
    def call(
            self, command: str, undo: Optional[str]=None, 
            doit: Optional[bool]=False, stop_on_failure=True,
            revert_order=False
        ):
        """Call method name called "command" on each meta modules if method
        exists in module.

        :param str command: Module method to call
        :param Optional[str] undo: Module method to call if command execution 
                                   fails, defaults to None
        :param Optional[bool] doit: Really do command else just print what 
                                    should be done, defaults to False
        :param bool stop_on_failure: Raise if command execution fails, 
                                     defaults to True
        :param bool revert_order: Revert module order (for delete commands)
        
        :raises RuntimeError: If command execution fails and stop_on_failure 
                              flag is enable
        """
        run_mode = doit
        done_commands = []
        todo_commands = []
        undo_commands = []
        run_result = []
        for name, m in self.modules(command,revert_order=revert_order).items():
            self.__log__.debug(
                f"Calling command '{command}' of meta user '{self}' in "
                f"module {name} (Doit={run_mode})..."
            )
            try:
                if doit is None: 
                    run_result.append(getattr(m, command)())
                else:
                    run_result.append(getattr(m, command)(doit=run_mode))
                    done_commands.append(getattr(m, command)(doit=False))
                    if undo is not None:
                        undo_commands.append(getattr(m, undo)(doit=False))
            except RuntimeError as e:
                run_mode = False
                todo_commands.append((getattr(m, command)(doit=False),e))

        if todo_commands:
            self.__log__.error(
                f"Failure in meta user '{self}' command '{command}' call"
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
                #     f"Unable to execute command '{command}' "
                #     f"on meta user '{self}'"
                # )
                self.__log__.error(
                    f"Unable to execute command '{command}' "
                    f"on meta user '{self}'"
                )
                exit(2)
        else:
            for c in list(chain.from_iterable(done_commands)):
                if doit:
                    self.__log__.debug(f"  {c} : [OK]")
                else:
                    self.__log__.info(f"  {c} : [DRY-RUN]")
        return(run_result)

    def fdattrs(self, attrs: List[str]) -> List[dict]:
        """ Return a dict {attrs: value, ...} containing only wanted attrs 
        for this object

        :param attrs: Wanted attributes
        
        :return: A dict with wanted attributes and values
        """
        r = {}
        for a in attrs:
            a_type, a_name = a.split("_", 1)

            value = getattr(getattr(self, a_type), a_name.lower(), '')
            ac, vc = convert(f"{a_name}", value)
            
            r.update({f"{a_type}_{ac}": vc})
 
        # self.__log__.trace(f"Add record : {r}")
        return [r]


# @ctrace
class MetaUsers(GenericObjects):
    """
    List of MetaUser objects.
    """
    __config__ = None
    def __init__(self, **kwargs):
        self._keys = {
            m['name']: m['keys'] 
            for m in self.config['modules']['user']
        }
        self._register_index(index_name="ids",multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: MetaUser):
        super().add(obj)
        self.__log__.trace(
                f"Add obj '{obj}' ..."
            )
        self.__log__.trace(
                f"Current Id keys'{[getattr(obj, name) for name, keys in self._keys.items() if getattr(obj, name) is not None]}' ..."
            )
        for name, keys in self._keys.items():
            if getattr(obj, name) is not None:
                for k in keys:
                    self.__log__.trace(f"Current Ids [{name}/{k}]: {getattr(getattr(obj, name), k)}")
       
        current_id = next(iter([
            '_'.join([getattr(getattr(obj, name), k) for k in keys]) 
            for name, keys in self._keys.items() 
            if getattr(obj, name) is not None
        ]), None)
        self._add_to_ids(current_id, obj)

    def delete(self, obj: MetaUser):
        super().delete(obj)
        current_id = next(iter([
            "_".join([
                getattr(getattr(obj,name),k) for k in keys
            ]) for name, keys in self._keys.items() 
            if getattr(obj, name) is not None
        ]), None)
        self._delete_from_ids(current_id, obj)

    def generate_missing(self):
        """ Generate missing atttributes values for a module if those 
        attributes in modules has generators defined in configuration
        """
        for m in [
                mod for mod in self.config['modules']['user'] 
                if 'generators' in mod
            ]:
            self.__log__.trace(
                f"Generate missing attributes for module '{m['name']}' ..."
            )
            for obj in [
                    o  for o in self.get() 
                    if getattr(o, m['name'], None) is None
                ]:
                attrs = {
                    a.replace(f"{m['name']}_",''): generator(self.get(), obj) 
                    for a, generator in m['generators'].items() 
                    if a.replace(f"{m['name']}_",'') in 
                       m['type'].attrs() + m['type'].attrs_ext()
                }
                m_obj = m['type'](**attrs)
                setattr(obj, m['name'], m_obj)
    
    def merge(self, name, objs):
        """ Merge module according to module's merging key defined in 
        configuration

        :param str name: Module name
        :param GenericObjects objs: A list of objects

        :raise RuntimeError: If module can not be identified by key in 
                             MetaUser object
        """
        # Obj key
        self.__log__.trace(f"Merging module '{name}' ...")
        for obj in objs:
            okey = "_".join(
                [getattr(obj,k) for k in self._keys[name]]
            )
            if okey in self.get_ids():
                mobj = getattr(self.get_by_ids(okey), name, "Module Not Found")
                if mobj == "Module Not Found":
                    raise RuntimeError(
                        f"Unable to find module '{name}' in MetaUser object "
                        f"identified by key '{okey}'"
                    )
                else:
                    setattr(self.get_by_ids(okey), name, obj) 
            else:
                m_obj = getattr(
                    modules[self.__class__.__module__],
                    removesuffix(self.__class__.__name__, 's')
                )
                o = {name: obj}
                self.add(m_obj(**o))

    def populate(self):
        """ Call populate methods for all defined module in configuration
        """
        lmodules = {}
        threads = []
        for m in self.config['modules']['user']:
            objs = m['list']()
            lmodules.update({m['name']: objs})
            threads.append(ThreadSafe(target=objs.populate))

        # Paralelize populate
        [t.start() for t in threads]
        [t.join() for t in threads]

        for e in [t.exception for t in threads if t.exception is not None]:
            raise e

        # Merge results
        [self.merge(name, objs) for name, objs in lmodules.items()]

    def filters(self, filters: List[tuple]) -> 'MetaUsers':
        """ Retrieves objects matching filters. Comparison are done with 
        filter operator and value and are case insensitive.

        :param List[tuple] filters: A filter tuple list.
        
        :return: Meta user matching filters

        :raise NotImplementedError: If filter operator is not supported

        .. note:: Filter tuple example:

           <meta attribute>_<module attribute>, <operator>, <value>")

        """
        m_objs = getattr(
            modules[self.__class__.__module__],
            self.__class__.__name__
        )
        fumeta = m_objs()
        for obj in self:
            result = False
            f_results = []
            for f in filters:
                (f_rpn, f_attribute, f_operator, f_value) = f
                if f_rpn is None:
                    a_type, a_name = f_attribute.split("_", 1)
                    objtmp = getattr(obj, a_type, None)
                    # self.__log__.debug(
                    #     f"Applying filter {f} on {objtmp} ..."
                    # )
                    if objtmp is None:
                        if f_operator in filter_operators:
                            f_results.append(
                                filter_operators[f_operator]['function'](
                                    "", f_value
                                )
                            )
                        else:
                            raise NotImplementedError(
                                f"This filter operator is not "
                                f"supported {f_operator}")
                    else:
                        # Generic hook : replace all attribute name surround 
                        # by braket by its value
                        attrs = [
                            f"{module}_{a}" 
                            for module, o in obj.atypes().items() 
                            for a in o.attrs() + o.attrs_ext()
                        ]
    
                        generic_hook_regex = compile(
                            r'\[(' + '|'.join(attrs) + r')\]'
                        )
                        for m in generic_hook_regex.findall(f_value):
                            if m in attrs:
                                av_type, av_name = m.split("_", 1)
                                # self.__log__.trace(
                                #     f"Looking for meta generic hook "
                                #     f"'([{m}])' on filter value '{f_value}' "
                                #     f"in attrs list {attrs}..."
                                # )
                                n_value = f"{getattr(getattr(obj, av_type, None), av_name, None)}"
                                # self.__log__.trace(
                                #     f"Looking for meta generic hook '({m})' "
                                #     f"on filter value '{f_value}' in module "
                                #     f"{av_type} and attribute {av_name} : "
                                #     f"{n_value} in "
                                #     f"({getattr(obj, av_type, None)})"
                                # )
                                
                                generic_hook_subregex = compile(
                                    r'\[' + m + r'\]'
                                )
                                f_value = generic_hook_subregex.sub(
                                    escape(ssafe(n_value)), f_value, 1
                                )
                                # self.__log__.trace(
                                #     f"Looking for meta generic hook '({m})' "
                                #     f"on filter value '{f_value}' in module "
                                #     f"{av_type} and attribute {av_name} : "
                                #     f"{n_value} => '{f_value}'"
                                # )
                        f_results.append(
                            objtmp.filter((a_name, f_operator, f_value))
                        )
                else:
                    # rpn is not None
                    # FIXME implement rpn
                    f_results.append(f_rpn)

            if len([
                    rpn_op for rpn_op, attr, op, value in filters 
                    if rpn_op in rpn_operators
                ]) > 0:
                # self.__log__.debug(f"RPN : {f_results} = {result}")
                result = rpn(f_results)
            else: 
                # No operator all filters are evaluated with "and" operator
                result = all(f_results)
                # self.__log__.debug(f"Filter (&) : {f_results} = {result}")
                
            if result:
                fumeta.add(obj)
        return fumeta
        