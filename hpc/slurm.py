# -*- coding: utf-8 -*-
""" Module for managing slurm users and groups
"""
from hpc.generics import GenericObjects, GenericObject
from typing import List, Optional
from hpc.utils import (
    run, runs, register_attributes, attributes_to_docstring, 
    load_config, pplist
)
import hpc.utils
from csv import DictReader
from re import compile
from config.config import config
from cilogger.cilogger import ccilogger  # , ctrace
log = ccilogger(__name__)


# @ctrace
class SlurmAccount(GenericObject):
    """
    Slurm account

    .. seealso::
       * `Slurm sacctmgr man page`_ for more information on slurm account 
         attributes
    .. _Slurm sacctmgr man page: https://slurm.schedmd.com/sacctmgr.html
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes([{
        "name": "account", "category": "standard", "type": str, 
        "default": None, "help": "Slurm account name"
    }, {
        "name": "descr", "category": "standard", "type": str, 
        "default": None, "help": "Slurm account description"
    }, {
        "name": "org", "category": "standard", "type": str, 
        "default": None, "help": "Slurm account organization"
    }, {
        "name": "category", "category": "extended", "type": str, 
        "default": None, 
        "help": f"Slurm account category ({', '.join(config['category'])})"
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this account a generated account"
    }])
    callables = hpc.utils.register_callables([
        hpc.utils.build_callable(
            action="list",      
            examples=[(
                "List account for all slurm accounts in 'mesonet' category", 
                "--attribute account --filter 'category=^mesonet$'"
        )]),
        hpc.utils.build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["account"]
        ),
        hpc.utils.build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["account"]
        )
    ], attributes)
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._define_category()

    def _define_category(self):
        """ Define a category from a list of categories defined in config

        :raise RuntimeError: If a category can not be define

        FIXME: Use gramc project type instead when available in gramc API
        """
        defined_category = None
        default_category = None
        for category, data in self.config['global']['category'].items():
            if data['regex'] is None:
                default_category = category
            else:
                category_regex = compile(r"{}".format(data['regex']))
                if category_regex.match(str(self._standard_account)):
                    defined_category = category

        if defined_category is None:
            defined_category = default_category

        if defined_category is None:
            raise RuntimeError(
                f"Category can not be define for group "
                f"'{self._standard_account}' from configured "
                f"categories "
                f"'{[c for c in self.config['global']['category']]}' "
            )
        else:
            self._extended_category = defined_category

    def create(self, doit: bool = False) -> Optional[List[str]]:
        """ Create a slurm account with the 'sacctmgr add account' command

        :param bool doit: If True really creates slurm account else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        opts = ['']
        if self._standard_descr is not None and not self._standard_descr == '':
            opts.append('descr="{}"'.format(self.descr))

        if self._standard_org is not None and not self._standard_org == '':
            opts.append('org="{}"'.format(self.org))

        commands = [
            f"{self.config['binary']['sacctmgr']} -i add account "
            f"name='{self._standard_account}'{' '.join(opts)}"
        ]

        if doit:
            runs(commands)
            return None
        else:
            return commands

    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """ Delete a slurm account with the 'sacctmgr delete account' command

        :param bool doit: If True really deletes slurm account else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return command 
                 what should be done as string
        """
        commands = [
            f"{self.config['binary']['sacctmgr']} -i delete account "
            f"name='{self._standard_account}'"
        ]

        if doit:
            runs(commands)
            return None
        else:
            return commands


# @ctrace
class SlurmAccounts(GenericObjects):
    """
    List of slurmAccount objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="accounts", multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: SlurmAccount):
        """ Add a SlurmAccount object to the list

        :param SlurmAccount obj: A SlurmAccount object
        """
        super().add(obj)
        self._add_to_accounts(obj.account, obj)

    def delete(self, obj: SlurmAccount):
        """ Remove a SlurmAccount object from the list

        :param SlurmAccount obj: A SlurmAccount object
        """
        super().delete(obj)
        self._delete_from_accounts(obj.account, obj)

    def populate(self, accounts: Optional[List[str]] = None):
        """ Populate slurm account list (sacctmgr list account command). 
        Populate all slurm accounts by default.

        :param Optional[List[str]] accounts: List of slurm account names to 
                                             retrieve. None means all accounts.

        :raise RuntimeError: if an account in accounts list is not found.
        """
        if accounts is None or \
           isinstance(accounts, list) and \
           all([isinstance(a, str) for a in accounts]):
            if accounts is None:
                search_std_accounts = ""
            else:
                account_list = ",".join([f'"{a}"' for a in accounts])
                search_std_accounts = f" Names={account_list}"
            command = f"{self.config['binary']['sacctmgr']} -n -P " \
                      f"list account{search_std_accounts}"

            output = run(command)
            cdata = DictReader(
                output, fieldnames=['account', 'descr', 'org'],
                delimiter="|"
            )

            self.__log__.trace("Found row : '{}'".format(cdata))
            self.__log__.trace("Populate command : '{}'".format(command))
            self.adds([
                SlurmAccount(
                    account=str(d['account']), descr=str(d['descr']), 
                    org=str(d['org'])
                ) for d in cdata 
                if accounts is None or str(d['account']) in accounts
            ])

            self.__log__.trace(
                f"Found accounts '{self.get_accounts()}' in slurm accounts "
                "(asked for '{accounts}'"
            )
            self.__log__.debug(
                f"Found accounts '{pplist(self.get_accounts())}' in slurm "
                "accounts (asked for '{accounts}'"
            )

            if accounts is not None and not self.len() == len(accounts):
                account_list = [
                    a for a in accounts if a not in self.get_accounts()
                ]
                raise RuntimeError(
                    f"Accounts '{account_list}' not found in slurm accounts."
                )
        else:
            raise ValueError("Account list must be None or a list of account")


# @ctrace
class SlurmUser(GenericObject):
    """
    Slurm user

    .. seealso::
       * `Slurm sacctmgr man page`_ for more information on slurm user 
         attributes
    .. _Slurm sacctmgr man page: https://slurm.schedmd.com/sacctmgr.html
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes([{
        "name": "user", "category": "standard", "type": str, 
        "default": None, "help": "Slurm user name"
    }, {
        "name": "account", "category": "standard", "type": str, 
        "default": None, "help": "Slurm user's account name"
    }, {
        "name": "admin", "category": "standard", "type": bool, 
        "default": False, "help": "Slurm administrator user"
    }, {
        "name": "category", "category": "extended", "type": str, 
        "default": None, 
        "help": f"Account category ({', '.join(config['category'])})"
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this user a generated user"
    }])
    callables = hpc.utils.register_callables([
        hpc.utils.build_callable(
            action="list",      
            examples=[(
                "List slurm users in surm account 'm23099'", 
                "--attribute user category --filter 'group=^m23099$'"
            )]),
        hpc.utils.build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["account", "user"]
        ),
        hpc.utils.build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["account", "user"]
        )
    ], attributes)
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._define_category()

    def _define_category(self):
        """ Define a category from a list of categories defined in config

        :raise RuntimeError: If a category can not be define

        FIXME: Use gramc project type instead when available in gramc API
        """
        defined_category = None
        default_category = None
        for category, data in self.config['global']['category'].items():
            if data['regex'] is None:
                default_category = category
            else:
                category_regex = compile(r"{}".format(data['regex']))
                if category_regex.match(str(self._standard_account)):
                    defined_category = category

        if defined_category is None:
            defined_category = default_category

        if defined_category is None:
            raise RuntimeError(
                f"Category can not be define for group "
                f"'{self._standard_user}' from configured categories "
                f"'{[c for c in self.config['global']['category']]}' "
            )
        else:
            self._extended_category = defined_category

    def _set_default_association(self) -> list:
        """ Generate command list for setting default association for a slurm 
        user

        :return: A list of command for setting default association for a slurm 
                 user
        """
        commands = []
        for p, jdata in self.config['partitions'].items():
            set_value = ' '.join([
                f'"{option}={next(iter([f"{k}={v}" for k,v in value.items()]))}"'
                if isinstance(value, dict)
                else f'"{option}={value}"'
                for option, value in jdata['association']['default'].items()
                
            ])
            commands.append(
                f"{self.config['binary']['sacctmgr']} -i modify user "
                f"'{self._standard_user}' where partition='{p}' "
                f"set {set_value}"
            )

        return commands

    def create(self, doit: bool = False) -> Optional[List[str]]:
        """ Create a slurm user with the sacctmgr command

        :param bool doit: If True really creates slurm user else just return 
                          the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        partitions = ','.join([p for p in self.config['partitions']])
        if self.config['qos']:
            qos = f" qos='{','.join(self.config['qos'])}'"
        commands = [
            f"{self.config['binary']['sacctmgr']} -i add user "
            f"name='{self._standard_user}' defaultaccount="
            f"'{self._standard_account}' partition='{partitions}'{qos}"
        ]
        commands.extend(self._set_default_association())
        if doit:
            runs(commands)
            
            return None
        else:
            return commands

    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """ Delete a slurm user with the sacctmgr command

        :param bool doit: If True really deletes slurm user else just return 
                          the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        commands = [
            f"{self.config['binary']['sacctmgr']} -i delete user "
            f"name='{self._standard_user}'"
        ]
        if doit:
            runs(commands)
            return None
        else:
            return commands

    def activity_details(self) -> Optional[List[str]]:
        """ Display user jobs for a slurm user on the system.

        :return: list of dict containing nonde name and process informations 
                 for this user on all login nodes. Process informations 
                 fields are set in activity configuration key
        """
        jdata = self.activity()
        if len(jdata) > 0:
            if len(list(jdata)) > 0:
                sfieds = ' '.join([
                    f"{r:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}" 
                    for r in self.config['activity']
                ])
                self.__log__.info(f"  {sfieds}")
                for j in jdata:
                    sdata = ' '.join([
                        f"{v:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}" 
                        for r, v in j.items()
                    ])
                    self.__log__.info(f"  {sdata}")
        return jdata               

    def activity(self) -> Optional[List[str]]:
        """ Find user jobs for a slurm user on the system.

        :return: list of dict containing nonde name and process informations 
                 for this user on all login nodes. Process informations 
                 fields are set in activity configuration key

        :raise RuntimeError: If activity configuration si not valid
        """
        sactivity = '","'.join([
            c['abrv'] for a, c in self.config['activity'].items()
        ])
        command = f"{self.config['binary']['squeue']} -h " \
                  f"-u {self._standard_user} " \
                  f'-o "{sactivity}"'

        if isinstance(self.config['activity'], dict) and \
           len(self.config['activity']) > 0:
            self.__log__.debug(f"  {command}")
            output = list(set(run(command)))
            jdata = list(DictReader(
                output, fieldnames=[a for a in self.config['activity']]
            ))
            if len(list(jdata)) > 0:
                sfieds = ' '.join([
                    f"{r:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}" 
                    for r in self.config['activity']
                ])
                self.__log__.debug(f"  {sfieds}")
                for j in jdata:
                    sdata = ' '.join([
                        f"{v:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}" 
                        for r, v in j.items()
                    ])
                    self.__log__.debug(f"  {sdata}")

                self.__log__.warning(
                    f"User has {len(list(jdata))} remaining jobs on cluster"
                )
            return jdata
        else:
            raise ValueError(
                "Slurm configuration key 'activity' must be an array "
                "containing at least one ps field name"
            )
    
    def lock(self, doit: bool = False) -> Optional[List[str]]:
        """ Lock a slurm user with the sacctmgr command. Set MaxJobs to 0.

        :param bool doit: If True really lock slurm user else just return the 
                          command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        commands = []
        for p in self.config['partitions']:
            commands.append(
                f"{self.config['binary']['sacctmgr']} -i modify " \
                f"user '{self._standard_user}' " \
                f"where partition='{p}' set maxjobs=0 MaxSubmit=0"
            )
        if doit:
            runs(commands)
            return None
        else:
            return commands
    
    def unlock(self, doit: bool = False) -> Optional[List[str]]:
        """ Unlock a slurm user with the sacctmgr command. Set MaxJobs to -1.

        :param bool doit: If True really unlock slurm user else just return the command as a string
        :return: None if doit is True and no raise else just return commands that should be done as string array

        :raise RuntimeError: If command fails
        """
        commands = []
        for p in self.config['partitions']:
            commands.append(
                f"{self.config['binary']['sacctmgr']} -i modify " \
                f"user '{self._standard_user}' " \
                f"where partition='{p}' set maxjobs=-1 MaxSubmit=-1"
            )

        if doit:
            runs(commands)
            return None
        else:
            return commands

    def killall(self, doit: bool = False) -> Optional[List[str]]:
        """ Cancel all slurm user's jobs with the scancel command.

        :param bool doit: If True really cancel all slurm user's jobs else 
                          just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If user is root
        """
        if self._standard_user == 'root':
            raise RuntimeError("You can't cancel root jobs with this method")
        commands = [
            f"{self.config['binary']['scancel']} -u '{self._standard_user}'"
        ]
        if doit:
            runs(commands)
            return None
        else:
            return commands

# @ctrace
class SlurmUsers(GenericObjects):
    """
    List of SlurmUser objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="users", multiple=False)
        self._register_index(index_name="accounts", multiple=True)
        super().__init__(**kwargs)

    def add(self, obj: SlurmUser):
        """ Add a SlurmUser object to the list

        :param SlurmUser obj: A SlurmUser object
        """
        super().add(obj)
        self._add_to_users(obj.user, obj)
        self._add_to_accounts(obj.account, obj)

    def delete(self, obj: SlurmUser):
        """ Remove a SlurmUser object from the list

        :param SlurmUser obj: A SlurmUser object
        """
        super().delete(obj)
        self._delete_from_users(obj.user, obj)
        self._delete_from_accounts(obj.account, obj)

    @staticmethod
    def to_admin(value: str):
        """ Convert slurm administrator string to boolean

        :param str value: A string to parse 
        :return: True if it's an slurm administratior string else False
        """
        if isinstance(value, str):
            if value == "Administrator" or value == "Admin":
                return True
            else:
                return False

    def populate(
            self, accounts: Optional[List[str]] = None, 
            users: Optional[List[str]] = None
        ):
        """ Populate slurm user list (sacctmgr list user command). Populate 
        all slurm users by default.

        :param Optional[List[str]] accounts: List of account name to retrieve 
                                             user from. None means no filter on
                                             account name.
        :param Optional[List[str]] users: List of user name to retrieve. None 
                                          means no filter on user name.

        :raise RuntimeError: if a user in users list is not found.
        """
        if users is None or \
           isinstance(accounts, list) and \
           all([isinstance(a, str) for a in accounts]) or \
           isinstance(users, list) and \
           all([isinstance(u, str) for u in users]):
            if users is None:
                search_users = ""
            else:
                search_users = " names={}".format(",".join(
                    [f'"{u}"' for u in users]
                ))

            if accounts is None:
                search_std_accounts = ""
            else:
                search_std_accounts = " defaultaccount={}".format(
                    ",".join([f'"{a}"' for a in accounts]
                ))

            command = f"{self.config['binary']['sacctmgr']} -n -P " \
                      f"list user{search_std_accounts}{search_users}"

            output = run(command)
            cdata = DictReader(
                output, fieldnames=['name', 'default-account', 'admin'],
                delimiter="|"
            )

            self.__log__.trace("Found row : '{}'".format(cdata))
            self.__log__.trace("Populate command : '{}'".format(command))
            self.adds([
                SlurmUser(
                    user=str(d['name']), account=str(d['default-account']),
                    admin=self.to_admin(str(d['admin']))
                ) for d in cdata if users is None or str(d['name']) in users
            ])

            self.__log__.trace(
                f"Found users '{self.get_users()}' in slurm users (asked for "
                f"users '{users}' and accounts '{accounts}')"
            )
            self.__log__.debug(
                f"Found users '{pplist(self.get_users())}' in slurm users "
                "(asked for users '{users}' and accounts '{accounts}')"
            )

            if users is not None and not self.len() == len(users):
                user_list = [
                    u for u in users
                    if u not in self.get_users() and 
                       u not in [item.gid for item in self.get()]
                ]
                raise RuntimeError(
                    f"Users '{user_list}' not found in slurm users."
                )
        else:
            raise ValueError("User list must be None or a list uid or name")