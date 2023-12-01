# -*- coding: utf-8 -*-

# pylint: disable=no-member
# pylint: disable=E1101

""" Module for managing hpc history for users and groups
"""
from hpc.generics import GenericObjects, GenericObject
from pathlib import Path
from typing import List, Optional
from config.config import config
import copy
from config.configManager import continue_on_failure_parser
from hpc.utils import (
    runs, register_attributes, register_callables, attributes_to_docstring, 
    load_config, get_effective_user_name, to_parser, build_callable
)
import re
from itertools import chain
from sys import stdout
from datetime import datetime
from cilogger.cilogger import ccilogger  # , ctrace

log = ccilogger(__name__)


# @ctrace
class HistoryLog(GenericObject):
    """
    History log entry.
    """
    attributes = register_attributes([{
        "name": "ts", "category": "standard", "type": str, 
        "default": None, "help": "History log timestamp",
    }, {
        "name": "action", "category": "standard", "type": str,
        "default": None, "help": "History log action",
    }, { 
        "name": "user", "category": "standard","type": str,
        "default": None, "help": "History log user",
    }, {
        "name": "tags", "category": "standard", "type": list, "default": [],
        "help": f"History log tags",
    }, {
        "name": "message", "category": "standard", "type": str,
        "default": None, "help": f"History log message",
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this group a generated group"
    }])
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_str(self):
        return(
            f"<{', '.join([str(getattr(self, a, None)) for a in self.attrs()])}>"
        )


# @ctrace
class HistoryLogs(GenericObjects):
    """
    List of history log objects.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @staticmethod
    def otype() -> GenericObject:
        return HistoryLog


# @ctrace
class HistoryGroup(GenericObject):
    """
    HistoryGroup object class.
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes([{
        "name": "group", "category": "standard", "type": str,
        "default": None, "help": "History group name",
    }, {
        "name": "musers", "category": "extended", "type": list,
        "default": [], "help": "List of user names members of the group",
    }, {
        "name": "logs", "category": "standard", "type": HistoryLogs,
        "default": HistoryLogs(), "help": "List of group history logs",
    }, {
        "name": "category", "category": "extended", "type": str,
        "default": None,
        "help": f"Group category ({', '.join(config['category'])})",
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this group a generated group"
    }])
    callables = register_callables([
        build_callable(
            action="list",      
            examples=[(
                "List logs for group 'p99099'", 
                "--attribute group category logs --filter 'group=^p99099$'"
            ),(
                "List logs for group 'p99099' and displays them on log per line", 
                "--attribute group category logs --filter 'group=^p99099$' --flat logs"
            )]),
        build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["group"]),
        build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["group"]),
        build_callable(
            action="add", 
            command="log",
            check="presence",
            doit=True,
            predefined_parents=["continue_on_failure"],
            label="Add new history entry to group",
            required_attributes=["group"],
            additional_arguments=[
                continue_on_failure_parser,
                to_parser("--action", 
                    dest=f"add_log_additional_arguments_action", 
                    metavar=f"<action>",
                    type=str, required=True,
                    help=f"Log message action"
                ),
                to_parser("--tag", 
                    dest=f"add_log_additional_arguments_tag", 
                    metavar=f"<tag>",
                    action="append",
                    default=[["group"]],
                    type=str,
                    required=False, nargs="*",
                    help=f"Log message tag to add (can be use multiple times to add multiples tags). 'group' tag is added by default"
                ),
                to_parser("--message", 
                    dest=f"add_log_additional_arguments_message", 
                    metavar=f"<message>",
                    type=str, required=True,
                    help=f"Log message to add"
                ),
                to_parser("--predefined", 
                    dest=f"add_log_additional_arguments_predefined", 
                    action='store_true',
                    required=False,
                    help=f"Use a predefined message"
                )
            ]),
        build_callable(
            action="remove",
            command="log",
            check="presence",
            doit=True,
            predefined_parents=["continue_on_failure"],
            label="Remove history entry from group history",
            required_attributes=["group"],
            additional_arguments=[
                continue_on_failure_parser,
                to_parser("--ts", 
                    dest=f"remove_log_additional_arguments_ts", 
                    metavar=f"<timestamp>",
                    type=str, required=True,
                    help=f"Log message timestamp"
                ),
            ])
    ], attributes)
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._define_category()

    def _define_category(self):
        """Define a category from a list of categories defined in config

        :raise RuntimeError: If a category can not be define

        FIXME: Use gramc project type instead when available in gramc API
        """
        defined_category = None
        default_category = None
        for category, data in self.config["global"]["category"].items():
            if data["regex"] is None:
                default_category = category
            else:
                category_regex = re.compile(r"{}".format(data["regex"]))
                if category_regex.match(str(self._standard_group)):
                    defined_category = category

        if defined_category is None:
            defined_category = default_category

        if defined_category is None:
            raise RuntimeError(
                f"Category can not be define for group '{self._standard_group}' from configured "
                f"categories '{[c for c in self.config['global']['category']]}' "
            )
        else:
            self._extended_category = defined_category
    
    @property
    def history_folder(self):
        """ Group history folder full path
        """
        if self._standard_group is None or not isinstance(self._standard_group, str):
            raise ValueError(
                f"History group name '{self._standard_group}' is not valid"
            )
        else:
            history_folder = Path(self.config["historyRootPath"]).joinpath(
                self._standard_group
            )
            return history_folder

    @property
    def history_file(self):
        """ Group history file full path
        """
        return self.history_folder.joinpath(self.config["historyGroupFileName"])

    def create(self, doit: bool = False) -> Optional[List[str]]:
        """Create a group history

        :param bool doit: If True really creates history group file on system 
                          else just return the command as a string
                          
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        :raise RuntimeError: If history group name is not set
        
        """

        history_users_folder = self.history_folder.joinpath(
            self.config["historyUsersFolder"]
        )
        history_owner = f"{self.config['historyFolderOwner']}:{self.config['historyFolderGroupOwner']}"
        history_file_owner = f"{self.config['historyFileOwner']}:{self.config['historyFileGroupOwner']}"
        commands = [
            f"{self.config['global']['binary']['mkdir']} {self.history_folder}",
            f"{self.config['global']['binary']['chown']} {history_owner} {self.history_folder}",
            f"{self.config['global']['binary']['chmod']} {self.config['historyFolderRights']} {self.history_folder}",
            f"{self.config['global']['binary']['mkdir']} {history_users_folder}",
            f"{self.config['global']['binary']['chown']} {history_owner} {history_users_folder}",
            f"{self.config['global']['binary']['chmod']} {self.config['historyFolderRights']} {history_users_folder}",
            f"{self.config['global']['binary']['touch']} {self.history_file}",
            f"{self.config['global']['binary']['chown']} {history_file_owner} {self.history_file}",
            f"{self.config['global']['binary']['chmod']} {self.config['historyFileRights']} {self.history_file}",
        ]
        hl = HistoryLog(
            ts=datetime.now().isoformat(),
            action="create",
            user=get_effective_user_name(),
            tags=["history", "group"],
            message=f"Création de l'historique du groupe '{self._standard_group}'",
        )
        if doit:
            runs(commands)
            self.__log__.debug(f"Add history entry '{hl}'")
            self.logs.add(hl)                
            self.logs.save(self.history_file, fmt="log")
            return f"Success to create history for group '{self._standard_group}'"
        else:
            return commands + [
                f"Add history entry '{hl}' to file '{self.history_file}'"
            ]
    
    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """Delete a group history

        :param bool doit: If True really deletes history group file on 
                          system else just return the command as a string

        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        :raise RuntimeError: If history group name is not set

        """

        ts=datetime.now().isoformat()
        hl = HistoryLog(
            ts=datetime.now().isoformat(),
            action="delete",
            user=get_effective_user_name(),
            tags=["history", "group"],
            message=f"Suppression de l'historique du groupe '{self._standard_group}'.",
        )
        history_archive_file = f"{self.config['historyArchiveRootPath']}/{self._standard_group}-{self.history_file.name}-{ts}"
        history_users_folder = self.history_folder.joinpath(
            self.config["historyUsersFolder"]
        )
        commands = [
            f"{self.config['global']['binary']['rmdir']} {history_users_folder}",
            f"{self.config['global']['binary']['mv']} {self.history_file} {history_archive_file}",
            f"{self.config['global']['binary']['rmdir']} {self.history_folder}",
        ]
        if doit:
            self.logs.add(hl)
            self.__log__.debug(f"Add history entry '{hl}'")
            self.logs.save(self.history_file, fmt="log")
            runs(commands)
            return f"Succes to delete history group '{self._standard_group}'"
        else:
            return [f"Delete history entry '{hl}'"] + commands

    def add_log(self, action: str, tag: List[str], message: str, predefined: bool=False, doit: bool = False) -> Optional[List[str]]:
        """Add new log entry for group history

        :param str action:  The log entry action 
        :param List[str] tag: Tags to be added to the log entry
        :param str message: The message to add to the log entry
        :param bool predefined: If it is a predefined message. In this case 
                                message and tags are ignored and a method called 'action' 
                                must exists (False by default), 
        
        :param bool doit: If True really add new log entry to history group file 
                          on system else just return which log line would be added
                          and in which file (False by default)
        
        :return: None if doit is True and no raise else just return what should 
                 be done as string array (one action per element)

        :raise ValueError: if predefined and no class method name 'action'
        :raise RuntimeError: If command fails
        """

        if predefined:
            am = getattr(self, action, None)
            if am is None:
                raise ValueError(
                    f"Predefined log entry '{action}' does not exists."
                )
            else:
                am()
        else:
            hl = HistoryLog(
                ts=datetime.now().isoformat(),
                action=action,
                user=get_effective_user_name(),
                tags=list(set(chain.from_iterable(tag))),
                message=message,
            )
            self.__log__.debug(
                f"Add history entry '{hl}' to file '{self.history_file}'"
            )
            
        if doit:
            self.logs.add(hl)
            self.logs.save(self.history_file, fmt="log")
            return f"Log entry {hl.to_str()} added"
        else:
            return [f"Add log entry {hl.to_str()}"]


    def remove_log(self, ts: str, doit: bool = False) -> Optional[List[str]]:
        """Remove the oldest log entry for group history matching timestamp 'ts'

        :param str ts:  Timestamp of the log entry
        :param bool doit: If True really add new log entry to history group file 
                          on system else just return which log line would be added
                          and in which file (False by default)
        
        :return: None if doit is True and no raise else just return what should 
                 be done as string array (one action per element)

        :raise ValueError: if message with timestamp 'ts' can not be found in 
                           log file
        """
        if doit:
            self.logs = HistoryLogs()
            self.logs.load(self.history_file)
            log.debug(f"History ({ts}) : {[(l.ts,l.message) for l in self.logs]}")
            hl = next(iter(self.logs.filters(
                [(None, 'ts', '=', f'^{ts}$')]
            )), None)
            if hl is not None:
                self.logs.delete(hl)
                self.logs.save(self.history_file, fmt="log")
                self.__log__.debug(
                    f"Removing history entry '{hl.to_str()}' from "
                    f"file '{self.history_file}'"
                )
                return f"Log entry '{hl.to_str()}' removed"
            else:
                raise ValueError(
                    f"Unable to find log message with timestamp '{ts}' in "
                    f"file '{self.history_file}'."
                )
        else:
            return [
                f"Remove log entry with timestamp '{ts}'"
            ]


# @ctrace
class HistoryGroups(GenericObjects):
    """
    List of HistoryGroup objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="groups", multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: HistoryGroup):
        super().add(obj)
        self._add_to_groups(obj.group, obj)

    def delete(self, obj: HistoryGroup):
        super().delete(obj)
        self._delete_from_groups(obj.group, obj)

    def populate(self, groups: Optional[List[str]] = None):
        """Populate group history for all groups from history files. Populate all groups by default.

        :param Optional[List[str]] groups: List of group name to retrieve.
                                           None means all groups.

        :raise RuntimeError: if a group in group list is not found.
        """
        if (
            groups is None
            or isinstance(groups, list)
            and all([isinstance(g, str) for g in groups])
        ):
            if groups is None:
                search_groups = None
            else:
                search_groups = groups
        else:
            raise ValueError("Group list must be None or a list of group name")

        for folder in [
            gf
            for gf in Path(self.config["historyRootPath"]).iterdir()
            if search_groups is None or gf in search_groups
        ]:
            group = folder.name
            musers = [
                uf.name
                for uf in folder.joinpath(self.config["historyUsersFolder"]).iterdir()
            ]
            hlf = folder.joinpath(self.config["historyGroupFileName"])
            hls = HistoryLogs()
            #self.__log__.trace(f"Loading log file '{hlf}' for group '{group}' ...")
            hls.load(hlf)
            #self.__log__.trace(f"Logs : ")
            #[self.__log__.trace(f"  {l.to_str()}") for l in hls]
            self.add(HistoryGroup(group=group, musers=musers, logs=copy.deepcopy(hls)))

        self.__log__.debug(
            f"Found {self.len()} groups '{self.get_groups()}' in history groups (asked for '{groups}')"
        )
        self.__log__.trace(
            f"Found {self.len()} groups '{[l.to_str() for g, go in self.get_groups().items() for l in go.logs]}' in history groups (asked for '{groups}')"
        )
        if groups is not None and not self.len() == len(groups):
            raise RuntimeError(
                f"Groups '{[g for g in groups if g not in self.get_groups()]}' not found in "
                f"history groups."
            )


# @ctrace
class HistoryUser(GenericObject):
    """
    HistoryUser object class
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes(
        [
            {
                "name": "login",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "History user login name",
            },
            {
                "name": "pgroup",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "User history primary group name",
            },
            {
                "name": "logs",
                "category": "standard",
                "type": HistoryLogs,
                "default": HistoryLogs(),
                "help": "List of user history logs",
            },
            {
                "name": "category",
                "category": "extended",
                "type": str,
                "default": None,
                "help": f"User group category ({', '.join(config['category'])})",
            }, {
                "name": "generated", "category": "extended", "type": bool, 
                "default": False, "help": f"Is this user a generated user"
            }
        ]
    )
    callables = register_callables([
        build_callable(
            action="list",
            examples=[(
                "List logs for user with login 'toto'", 
                "--attribute login pgroup category logs --filter 'login=^toto$'"
            ),(
                "List logs for user with login 'toto' and displays them one line per log", 
                "--attribute login pgroup category logs --filter 'login=^toto$' --flat logs"
            )]),
        build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["pgroup", "login"]),
        build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["pgroup", "login"]),
        build_callable(
            action="add",
            command="log",
            check="presence",
            doit=True,
            predefined_parents=["continue_on_failure"],
            label="Add new history entry to user",
            required_attributes=["pgroup", "login"],
            additional_arguments=[
                continue_on_failure_parser,
                to_parser("--action", 
                    dest=f"add_log_additional_arguments_action", 
                    metavar=f"<action>",
                    type=str, required=True,
                    help=f"Log message action"
                ),
                to_parser("--tag", 
                    dest=f"add_log_additional_arguments_tag", 
                    metavar=f"<tag>",
                    action="append",
                    default=[["user"]],
                    type=str,
                    required=False, nargs="*",
                    help=f"Log message tag to add (can be use multiple times to add multiples tags). 'user' tag is added by default"
                ),
                to_parser("--message", 
                    dest=f"add_log_additional_arguments_message", 
                    metavar=f"<message>",
                    type=str, required=True,
                    help=f"Log message to add"
                ),
                to_parser("--predefined", 
                    dest=f"add_log_additional_arguments_predefined", 
                    action='store_true',
                    required=False,
                    help=f"Use a predefined message"
                )
            ]),
        build_callable(
            action="remove",
            command="log",
            check="presence",
            doit=True,
            predefined_parents=["continue_on_failure"],
            label="Remove history entry from user history",
            required_attributes=["pgroup", "login"],
            additional_arguments=[
                continue_on_failure_parser,
                to_parser("--ts", 
                    dest=f"remove_log_additional_arguments_ts", 
                    metavar=f"<timestamp>",
                    type=str, required=True,
                    help=f"Log message timestamp"
                ),
            ])
    ], attributes)
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
       
    @property
    def history_folder(self):
        """ User history folder full path
        """
        if self._standard_pgroup is None or not isinstance(self._standard_pgroup, str):
            raise ValueError(
                f"History group name '{self._standard_pgroup}' is not valid"
            )
        elif self._standard_login is None or not isinstance(self._standard_login, str):
            raise RuntimeError(
                f"You must set a valid history user login name ({self.login})"
            )
        else:
            history_folder = Path(self.config["historyRootPath"]).joinpath(
                self._standard_pgroup,
                self.config["historyUsersFolder"],
                self._standard_login,
            )
            return history_folder
    
    @property
    def history_archive_folder(self):
        """ User history archive folder full path
        """
        if self._standard_pgroup is None or not isinstance(self._standard_pgroup, str):
            raise ValueError(
                f"History group name '{self._standard_pgroup}' is not valid"
            )
        elif self._standard_login is None or not isinstance(self._standard_login, str):
            raise RuntimeError(
                f"You must set a valid history user login name ({self.login})"
            )
        else:
            history_folder = Path(self.config["historyArchiveRootPath"]).joinpath(
                self._standard_pgroup,
                self.config["historyUsersFolder"],
                self._standard_login,
            )
            return history_folder

    @property
    def history_file(self):
        """ User history file full path
        """
        return self.history_folder.joinpath(self.config["historyUserFileName"])

    def create(self, doit: bool = False) -> Optional[List[str]]:
        """Create a user history

        :param bool doit: If True really creates history user file on system else just return the command as a string
        :return: None if doit is True and no raise else just return commands that should be done as string array

        :raise RuntimeError If history group folder does not exist
        :raise RuntimeError If history users folder does not exist
        """
        if not self.history_folder.parent.parent.exists() :
            raise RuntimeError(f"History group folder '{self.history_folder.parent.parent}' does not exist.")

        if not self.history_folder.parent.exists() :
            raise RuntimeError(f"History users folder '{self.history_folder.parent}' does not exist.")

        history_owner = f"{self.config['historyFolderOwner']}:{self.config['historyFolderGroupOwner']}"
        history_file_owner = f"{self.config['historyFileOwner']}:{self.config['historyFileGroupOwner']}"
        commands = [
            f"{self.config['global']['binary']['mkdir']} {self.history_folder}",
            f"{self.config['global']['binary']['chown']} {history_owner} {self.history_folder}",
            f"{self.config['global']['binary']['chmod']} {self.config['historyFolderRights']} {self.history_folder}",
            f"{self.config['global']['binary']['touch']} {self.history_file}",
            f"{self.config['global']['binary']['chown']} {history_file_owner} {self.history_file}",
            f"{self.config['global']['binary']['chmod']} {self.config['historyFileRights']} {self.history_file}",
        ]
        hl = HistoryLog(
            ts=datetime.now().isoformat(),
            action="create",
            user=get_effective_user_name(),
            tags=["history", "user"],
            message=f"Création de l'historique de l'utilisateur '{self._standard_login}' "
            f"dans le groupe '{self._standard_pgroup}'",
        )
        if doit:
            runs(commands)
            
            self.__log__.debug(f"Add history entry '{hl}'")
            self.logs.add(hl)                    
            
            self.logs.save(self.history_file, fmt="log")
            return f"Succes to create history for user '{self._standard_login}'"
        else:
            return commands + [f"Add history entry '{hl}'"]

    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """Delete a user history

        :param bool doit: If True really deletes history user file on system 
                          else just return the command as a string
        :return: A success string message or None if doit is True and no raise 
                 else just return commands that should be done as string array

        :raise RuntimeError: If command fails
        """
        ts=datetime.now().isoformat()
        hl = HistoryLog(
            ts=datetime.now().isoformat(),
            action="delete",
            user=get_effective_user_name(),
            tags=["history", "user"],
            message=f"Suppression de l'historique de l'utilisateur '{self._standard_login}' "
            f"dans le groupe '{self._standard_pgroup}'",
        )
        history_archive_file = f"{self.config['historyArchiveRootPath']}/{self._standard_pgroup}-{self._standard_login}-{self.history_file.name}-{ts}"
        commands = [
            f"{self.config['global']['binary']['mv']} {self.history_file} {history_archive_file}",
            f"{self.config['global']['binary']['rmdir']} {self.history_folder}",
        ]
        if doit:
            self.logs.add(hl)
            self.__log__.debug(f"Add history entry '{hl}'")
            try:
                self.logs.save(self.history_file, fmt="log")
            except FileNotFoundError as e:
                raise RuntimeError(e)
            runs(commands)
            return f"Succes to delete history for user '{self._standard_login}'"
        else:
            return [f"Delete history entry '{hl}'"] + commands
    
    def add_log(self, action: str, tag: List[str], message: str, predefined: bool=False, doit: bool = False) -> Optional[List[str]]:
        """Add new log entry for group history

        :param str action:  The log entry action 
        :param List[str] tag: Tags to be added to the log entry
        :param str message: The message to add to the log entry
        :param bool predefined: If it is a predefined message. In this case 
                                message and tags are ignored and a method called 'action' 
                                must exists (False by default), 
        
        :param bool doit: If True really add new log entry to history group file 
                          on system else just return which log line would be added
                          and in which file (False by default)
        
        :return: None if doit is True and no raise else just return what should 
                 be done as string array (one action per element)

        :raise ValueError: if predefined and no class method name 'action'
        :raise RuntimeError: If command fails
        """

        if predefined:
            am = getattr(self, action, None)
            if am is None:
                raise ValueError(
                    f"Predefined log entry '{action}' does not exists."
                )
            else:
                am()
        else:
            hl = HistoryLog(
                ts=datetime.now().isoformat(),
                action=action,
                user=get_effective_user_name(),
                tags=list(set(chain.from_iterable(tag))),
                message=message,
            )
            self.__log__.debug(
                f"Add history entry '{hl}' to file '{self.history_file}'"
            )
            
        if doit:
            self.logs.add(hl)
            self.logs.save(self.history_file, fmt="log")
            return f"Log entry {hl.to_str()} added"
        else:
            return [f"Add log entry {hl.to_str()}"]


    def remove_log(self, ts: str, doit: bool = False) -> Optional[List[str]]:
        """Remove the oldest log entry for group history matching timestamp 'ts'

        :param str ts:  Timestamp of the log entry
        :param bool doit: If True really add new log entry to history group file 
                          on system else just return which log line would be added
                          and in which file (False by default)
        
        :return: None if doit is True and no raise else just return what should 
                 be done as string array (one action per element)

        :raise ValueError: if message with timestamp 'ts' can not be found in 
                           log file
        """
        if doit:
            self.logs = HistoryLogs()
            self.logs.load(self.history_file)
            log.debug(f"History ({ts}) : {[(l.ts,l.message) for l in self.logs]}")
            hl = next(iter(self.logs.filters(
                [(None, 'ts', '=', f'^{ts}$')]
            )), None)
            if hl is not None:
                self.logs.delete(hl)
                self.logs.save(self.history_file, fmt="log")
                self.__log__.debug(
                    f"Removing history entry '{hl.to_str()}' from "
                    f"file '{self.history_file}'"
                )
                return f"Log entry '{hl.to_str()}' removed"
            else:
                raise ValueError(
                    f"Unable to find log message with timestamp '{ts}' in "
                    f"file '{self.history_file}'."
                )
        else:
            return [
                f"Log entry with timestamp '{ts}' removed"
            ]


# @ctrace
class HistoryUsers(GenericObjects):
    """
    List of HistoryUsers objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="logins", multiple=False)
        self._register_index(index_name="pgroups", multiple=True)
        super().__init__(**kwargs)

    def add(self, obj: HistoryUser):
        super().add(obj)
        self._add_to_logins(obj.login, obj)
        self._add_to_pgroups(obj.pgroup, obj)

    def delete(self, obj: HistoryUser):
        super().delete(obj)
        self._delete_from_logins(obj.login, obj)
        self._delete_from_pgroups(obj.pgroup, obj)

    def populate(self, users: Optional[List[str]] = None):
        """Populate user history for all users from history files. Populate all 
        users by default.

        :param Optional[List[str]] users: List of user login name to retrieve.
                                          None means all users.

        :raise ValueError: If group list must is not None or a list of group name
        :raise RuntimeError: if a user in user list is not found.
        """
        if (
            users is None
            or isinstance(users, list)
            and all([isinstance(g, str) for g in users])
        ):
            if users is None:
                search_users = None
            else:
                search_users = users
        else:
            raise ValueError("Group list must be None or a list of group name")

        hgs = HistoryGroups()
        hgs.populate()

        for folder in [
                uf
                for gf in Path(self.config["historyRootPath"]).iterdir() 
                if gf.joinpath(self.config["historyUsersFolder"]).exists()
                for uf in gf.joinpath(self.config["historyUsersFolder"]).iterdir()
                if search_users is None or uf in search_users
            ]:
            login = folder.name
            pgroup = folder.parent.parent.name
            category = hgs.get_by_groups(pgroup).category
            self.__log__.trace(
                f"Parsing history file path and found user login '{login}' in "
                f"group '{pgroup}'"
            )
            hlf = folder.joinpath(self.config["historyUserFileName"])
            hls = HistoryLogs()
            hls.load(hlf)
            # for l in hls:
            #     self.__log__.trace(
            #         f"Loaded logs for user login '{login}' : '{l}'"
            #     )
            self.add(
                HistoryUser(
                    login=login, pgroup=pgroup, category=category, logs=hls
                )
            )

        self.__log__.debug(
            f"Found {self.len()} users '{self.get_logins()}' in users history "
            f"(asked for '{users}')"
        )

        if users is not None and not self.len() == len(users):
            raise RuntimeError(
                f"Users '{[u for u in users if u not in self.get_logins()]}' "
                f"not found in users history."
            )