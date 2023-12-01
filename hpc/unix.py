# -*- coding: utf-8 -*-
""" Module for managing unix users and groups
"""
from hpc.generics import GenericObjects, GenericObject
from pathlib import Path
from typing import List, Optional
from config.config import config
from hpc.utils import (
    runs, run, ssafelower, register_attributes, 
    attributes_to_docstring, load_config, pplist
)
import hpc.utils
from hpc.generators import (
    encrypted_password_generator, real_root_path_generator
)
from datetime import date
from csv import DictReader
from re import compile, split
from cilogger.cilogger import ccilogger  # , ctrace
log = ccilogger(__name__)


# @ctrace
class UnixGroup(GenericObject):
    """
    Unix group. Standards attributes are those in /etc/group file.
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes([{
        "name": "group", "category": "standard", "type": str, 
        "default": None, "help": "Unix group name"
    }, {
        "name": "password", "category": "standard", "type": str, 
        "default": None, "help": "Unix group password"
    }, {
        "name": "gid", "category": "standard", "type": int, 
        "default": None, "help": "Unix group gid"
    }, {
        "name": "musers", "category": "standard", "type": list, 
        "default": [],
        "help": "List of user names of users who are members of the group"
    }, {
        "name": "category", "category": "extended", "type": str, 
        "default": None,
        "help": f"Group category ({', '.join(config['category'])})"
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this group a generated group"
    }])
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
                if category_regex.match(str(self._standard_group)):
                    defined_category = category

        if defined_category is None:
            defined_category = default_category

        if defined_category is None:
            raise RuntimeError(
                f"Category can not be define for group "
                f"'{self._standard_group}' from configured "
                f"categories "
                f"'{[c for c in self.config['global']['category']]}' "
            )
        else:
            self._extended_category = defined_category

    def create(self, doit: bool = False) -> Optional[List[str]]:
        """ Create a unix group on the system with the groupadd command

        :param bool doit: If True really creates group on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        real_root_path = real_root_path_generator(
            self.config['global']['homeRootRealPaths'], self._standard_gid
        )
        real_path = real_root_path.joinpath(f"{self._standard_group}")
        relative_path = Path(
            self.config['global']['homeRootPath']
        ).joinpath(f"{self._standard_group}")
        optcommands = []
        if not real_path == relative_path :
            optcommands = [
                f"{self.config['global']['binary']['ln']} "
                f"-s {real_path} {relative_path}"
            ]

        commands = [
            f"{self.config['binary']['groupadd']} "
            f"-g {self._standard_gid} {self._standard_group}",
            f"{self.config['global']['binary']['update-cache']}",
            f"{self.config['global']['binary']['mkdir']} {real_path}",
            f"{self.config['global']['binary']['chmod']} {self.config['group']['folderRights']} {real_path}",
            f"{self.config['global']['binary']['chown']} {self.config['group']['folderOwner']} {self._standard_group} {real_path}"
        ] + optcommands
    
        if doit:
            runs(commands)
            return None
        else:
            return commands

    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """ Delete a unix group on the system with the groupdel command

        :param bool doit: If True really deletes group on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If user members not empty or user primary 
                             members not empty
        """
        
        relative_path = Path(
            self.config['global']['homeRootPath']
        ).joinpath(f"{self._standard_group}")
        real_path = relative_path.resolve()
        optcommands = []
        if not real_path == relative_path :
            optcommands = [
                f"{self.config['global']['binary']['rm']} -f {relative_path}",
            ]

        commands = [
            f"{self.config['binary']['groupdel']} {self._standard_group}",
            f"{self.config['global']['binary']['update-cache']}"
        ] + optcommands + [            
            f"{self.config['global']['binary']['rmdir']} {real_path}",
        ]

        if doit:
            if self._standard_musers:
                raise RuntimeError(
                    f"Group has user members ({self._standard_musers})"
                )
            runs(commands)
            return None
        else:
            return commands

# @ctrace
class UnixGroups(GenericObjects):
    """
    List of UnixGroup objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="groups", multiple=False)
        self._register_index(index_name="gids", multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: UnixGroup):
        """ Add a UnixGroup object to the list

        :param UnixGroup obj: A UnixGroup object
        """
        super().add(obj)
        # Add group and gid index
        self._add_to_groups(obj.group, obj)
        self._add_to_gids(obj.gid, obj)

    def delete(self, obj: UnixGroup):
        """ Remove a UnixGroup object from the list

        :param UnixGroup obj: A UnixGroup object
        """
        super().delete(obj)
        # Remove group and gid from index
        self._delete_from_gids(obj.gid, obj)
        self._delete_from_groups(obj.group, obj)

    def populate(self, groups: Optional[List[str]] = None):
        """ Populate unix group list from system (getent group command). 
        Populate all groups by default.

        :param Optional[List[str]] groups: List of group name to retrieve.
                                           None means all groups.

        :raise RuntimeError: if a group in group list is not found.
        """
        if groups is None or isinstance(groups, list) and \
                all([isinstance(g, str) for g in groups]):
            if groups is None:
                search_groups = []
            else:
                search_groups = groups
            command = f"{self.config['binary']['getent']} " \
                      f"group {' '.join(search_groups)}"

            # getent return duplicate entries
            output = list(set(run(command)))
            cdata = DictReader(
                output, fieldnames=['name', 'password', 'gid', 'musers'],
                delimiter=":"
            )

            self.__log__.trace(f"Found row : '{cdata}'")
            self.__log__.trace(f"Populate command : '{command}'")

            self.adds([
                UnixGroup(
                    group=str(d['name']), password=str(d['password']), 
                    gid=int(d['gid']),
                    musers=[
                        str(user) for user in d['musers'].split(',') 
                        if not user == ''
                    ]
                ) for d in cdata 
                if groups is None or str(d['name']) in search_groups
            ])

            self.__log__.trace(
                f"Found groups '{self.get_groups()}' in unix groups (asked "
                f"for '{groups}')"
            )
            self.__log__.debug(
                f"Found groups '{pplist(self.get_groups())}' in unix groups "
                f"(asked for '{groups}')"
            )

            if groups is not None and not self.len() == len(groups):
                raise RuntimeError(
                    f"Groups "
                    f"'{[g for g in groups if g not in self.get_groups()]}' "
                    f"not found in unix groups."
                )
        else:
            raise ValueError(
                "Group list must be None or a list of group name"
            )


# @ctrace
class UnixUser(GenericObject):
    """
    Unix user. Standard parameters are those in /etc/passwd file.
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes([{
        "name": "login", "category": "standard", "type": str, 
        "default": None, "help": "Unix user login name"
    }, {
        "name": "password", "category": "standard", "type": str, 
        "default": None, "help": "Unix user password"
    }, {
        "name": "uid", "category": "standard", "type": int, 
        "default": None, "help": "Unix user uid"
    }, {
        "name": "gid", "category": "standard", "type": int, 
        "default": None, "help": "Unix user gid"
    }, {
        "name": "comment", "category": "standard", "type": str, 
        "default": None, "help": "Unix user comment"
    }, {
        "name": "home", "category": "standard", "type": Path,
        "default": None, "help": "Unix user home"
    }, {
        "name": "shell", "category": "standard", "type": Path, 
        "default": None, "help": "Unix user shell"
    }, {
        "name": "pgroup", "category": "standard", "type": str,
        "default": None, "help": "Unix user primary group name"
    }, {
        "name": "mgroups", "category": "extended", "type": list, 
        "default": [], "help": "Unix user group's name member list"
    }, {
        "name": "category", "category": "extended", "type": str, 
        "default": None,
        "help": f"User group category ({', '.join(config['category'])})"
    }, {
        "name": "idindividu", "category": "extended", "type": int, 
        "default": None, "help": "Gramc user idindividu in comment field"
    }, {
        "name": "nom", "category": "extended", "type": str,
        "default": None, "help": "User family name  in comment field"
    }, {
        "name": "prenom", "category": "extended", "type": str, 
        "default": None, "help": "User first name  in comment field"
    }, {
        "name": "mail", "category": "extended", "type": str, 
        "default": None, "help": "User email  in comment field"
    }, {
        "name": "clearpassword", "category": "extended", "type": str,
        "default": None, 
        "help": "Unix user clear password (only for new users)"
    }, {
        "name": "cryptedpassword", "category": "extended", "type": str, 
        "default": None,
        "help": "Unix user encrypted password (only for new users) in shadow file"
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this user a generated user"
    }, {
        "name": "locked", "category": "extended", "type": bool, 
        "default": None, "help": "Unix user locking state"
    }])
    callables = hpc.utils.register_callables([
        hpc.utils.build_callable(
            action="list",      
            examples=[(
                "Lister les groupes ayant des utilisateurs ayant une configuration ssh", 
                "--attribute group category --filter 'group=^.+$'"
            ),(
                "Lister les membres du groupe p99099, 1 ligne par log", 
                "--attribute group category musers --filter 'group=^p99099$' --flat musers"
            )]),
        hpc.utils.build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["pgroup", "login"]
        ),
        hpc.utils.build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["pgroup", "login"]
        )
    ], attributes)
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._set_extended_comment_attrs()
        if self._extended_clearpassword is not None:
            self._extended_cryptedpassword = encrypted_password_generator(
                self._extended_clearpassword
            )

    def _set_extended_comment_attrs(self):
        """ This method try to extract extended attributes (mail, individu, 
        nom and prenom) from comment attribute. The comment attribute should 
        be "idindividu,prenom,nom,mail" or "prenom nom,mail"

        Set nothing if it can't retrieve at least the mail attribute
        """
        if self._standard_comment is not None and self.config['user']['extractExtendedComment']:
            ext_attrs = self._standard_comment.split(',')
            if len(ext_attrs) == 4:
                if ext_attrs[0].isdigit():
                    self._extended_idindividu = int(ext_attrs[0])
                self._extended_nom = ext_attrs[1].lower()
                self._extended_prenom = ext_attrs[2].lower()
                self._extended_mail = ssafelower(ext_attrs[3])
            elif len(ext_attrs) == 2:
                if not self._extended_category == 'system':
                    self.__log__.warning(
                        f"Old comment style 'prenom nom,mail', please update to "
                        f"new one 'idindividu,prenom,nom,mail' "
                        f"({self._standard_login}: {self._standard_comment})"
                    )
                self._extended_nom = ext_attrs[0].lower()
                self._extended_mail = ssafelower(ext_attrs[1])
            else:
                self._extended_nom = self._standard_comment.lower()
                self._extended_mail = ssafelower(self._standard_comment)
                if not self._extended_category == 'system':
                    self.__log__.error(
                        f"Bad formatted comment, if an hpc user, please update "
                        f"to new style 'idindividu,prenom,nom,mail', else do "
                        f"not try to set extended attributes for this user "
                        f"({self._standard_login}: {self._standard_comment})"
                    )

    def addmgroup(self, value: str):
        """ Append a new group to user group member list

        :param UnixGroup value: Unix group to add

        :raise ValueError: if value is already in group member list (Group 
                           member must be unique
        :raise ValueError: if value is not a string or is empty
        """
        if isinstance(value, str) and not value == "":
            if value in self._extended_mgroups:
                raise ValueError(
                    f"Group '{value}' already in group member list "
                    f"'{self._extended_mgroups}' (Group member must be "
                    f"unique)"
                )
            else:
                self._extended_mgroups.append(value)
        else:
            raise ValueError(f"Bad member group oid '{value}'")

    def delmgroup(self, value: str):
        """ Remove a group from user group member list

        :param str value: Group oid to remove
        :raise ValueError: if value is not a string or is empty
        """
        if isinstance(value, str) and not value == "":
            self._extended_mgroups.remove(value)
        else:
            raise ValueError(f"Bad member group oid '{value}'")

    def create(self, doit: bool = False) -> Optional[List[str]]:
        """ Create a unix user on the system with the useradd command

        :param bool doit: If True really creates user on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If unix user primary group gid or name is not set
        """
        if self._standard_gid is None:
            if self._extended_pgroup is None:
                raise RuntimeError(
                    "Unix user primary group gid or name must be set."
                )
            else:
                ugroup = self._extended_pgroup
        else:
            ugroup = self._standard_gid

        commands = [
            f"{self.config['binary']['useradd']} -u {self._standard_uid} "
            f"-g {ugroup} -d {self._standard_home} -s {self._standard_shell} "
            f'-c "{self._standard_comment}" '
            f'-m {self._standard_login}',
            f'{self.config["binary"]["update-cache"]}'
        ]
        self.__log__.debug(f"Home folder '{self._standard_home}' created : {self._standard_home.exists()}")
        
        if self._standard_home.exists():
            self.__log__.debug(f"Home folder content : {[f for f in self._standard_home.iterdir()]}")
        else:
            commands += [
                f'{self.config["binary"]["update-cache"]}',
                f"{self.config['global']['binary']['mkdir']} -p '{self._standard_home}'",
                f"{self.config['global']['binary']['chmod']} {self.config['user']['folderRights']} '{self._standard_home}'",
                #f"{self.config['global']['binary']['chown']} {self._standard_login} {ugroup} '{self._standard_home}'",
                f"echo {self.config['global']['binary']['sudo']} -u '{self._standard_login}' -- {self.config['global']['binary']['sudo']} /etc/skel -type f -exec cp '{{}}' '{self._standard_home}'",
            ]

        if doit:
            runs(commands)
            return None
        else:
            return commands

    def shadow(self):
        """ Populate extended shadow info for all users.

        :raise RuntimeError: if a user in users list is not found in shadow.
        """
        command = f"{self.config['binary']['getent']} shadow '{self.login}'"

        # getent return duplicate entries
        output = list(set(run(command)))
        shadow_fields = [ 
            'cryptedpassword', 'pwdchangedate', 'pwdminage', 'pwdmaxage', 
            'pwdwarnduration', 'pwdidleduration', 'pwdexpiredate', 
            'pwdreserved' 
        ]
        if output:
            cdata = DictReader(
                output, fieldnames=['login']+shadow_fields, delimiter=":"
            )
            return {
                f: v for u in cdata for f, v in u.items() if not f == 'login'
            }


    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """ Delete a unix user on the system with the userdel command

        :param bool doit: If True really deletes user on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        commands = [
            f"{self.config['binary']['userdel']} -r {self._standard_login}",
            f"{self.config['global']['binary']['update-cache']}"
        ]
        if self._standard_home.exists():
            commands += [
                f"{self.config['global']['binary']['rmdir']} '{self._standard_home}'",
            ]
        if doit:
            runs(commands)
            return None
        else:
            return commands

    def activity_details(self) -> Optional[List[str]]:
        """ Display user process for a unix user on the system login nodes.

        :return: list of dict containing nonde name and process informations 
                 for this user on all login nodes. Process informations 
                 fields are set in activity configuration key
        """
        pdata = self.activity()
        if len(pdata) > 0:
            for node, process in pdata.items():
                self.__log__.info(
                    f"  Process for user '{self._standard_login}' on node "
                    f"'{node}' :")
                sfieds = ' '.join([
                    f"{r:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}"
                    for r in self.config['activity']
                ])
                self.__log__.info(f"  {sfieds}")
                for p in process:
                    sdata = ' '.join([
                        f"{v:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}" 
                        for r, v in p.items()
                    ])
                    self.__log__.info(f"  {sdata}")

        return pdata
                        

    def activity(self) -> Optional[List[str]]:
        """ Find user process for a unix user on the system login nodes.

        :return: list of dict containing nonde name and process informations 
                 for this user on all login nodes. Process informations 
                 fields are set in activity configuration key

        :raise ValueError: If activity configuration si not valid

        .. TODO:: Track clush command failure 
                  Exemple : clush commande with single quote missing
        """
        sactivity = ','.join([
            c['abrv'] for a, c in self.config['activity'].items()
        ])
        (command, exit_codes) = (
            f"{self.config['global']['binary']['clush']} --nostdin -q -S "
            f"-w {','.join(self.config['global']['loginNodes'])} " 
            f"'{self.config['binary']['ps']} --no-headers "
            f"--user {self._standard_login} --format {sactivity} -w -w'", 
            [0, 1]
        )

        if isinstance(self.config['activity'], dict) and \
           len(self.config['activity']) > 0:
            self.__log__.debug(f"  {command}")
            output = list(set(run(command, exit_codes)))

            fieldnames = ['node'] + list(self.config['activity'].keys())
            pdata = { 
                d['node']: [{r: d[r] for r in self.config['activity']}] 
                for d in [
                    dict(zip(
                        fieldnames, 
                        split(':\s+|\s+',l,len(self.config['activity']))
                    )) for l in output
                ]
            }
            if len(pdata) > 0:
                for node, process in pdata.items():
                    self.__log__.debug(
                        f"  Process for user '{self._standard_login}' on "
                        "node '{node}' :"
                    )
                    sfieds = ' '.join([
                        f"{r:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}" 
                        for r in self.config['activity']
                    ])
                    self.__log__.debug(f"  {sfieds}")
                    for p in process:
                        sdata = ' '.join([
                            f"{v:{self.config['activity'][r]['justify']}{self.config['activity'][r]['size']}}" 
                            for r, v in p.items()
                        ])
                        self.__log__.debug(f"  {sdata}")

                nodes_details = [
                    f"{len(p)} on '{n}'" for n, p in pdata.items()
                ]
                self.__log__.warning(
                    f"User has {len(pdata)} remaining process on login "
                    f"nodes ({', '.join(nodes_details)})"
                )
            return pdata
        else:
            raise ValueError(
                "Unix configuration key 'activity' must be an array "
                "containing at least one ps field name"
            )

    def lock(self, doit: bool = False) -> Optional[List[str]]:
        """ Lock a unix user on the system. Locking a user mean change user 
        shell to '/sbin/locked' which point to '/bin/bash' to permit root 
        su login and expire user password with chage. Killing user's sessions 
        is not done by this method

        :param bool doit: If True really lock user on system else just return 
                          the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """

        locking_date = date.today()
        commands = [
            f"{self.config['binary']['usermod']} "
            f"--expiredate {locking_date} --lock --shell "
            f"{self.config['user']['disabled']} {self._standard_login}",
            f"{self.config['global']['binary']['update-cache']}"
        ]
        if doit:
            runs(commands)
            return None
        else:
            return commands

    def unlock(self, doit: bool = False) -> Optional[List[str]]:
        """ Unlock a unix user on the system. Unlocking a user mean change 
        user shell to default shell and unexpire user password with chage. If 
        cryptedpassword is not None, it also change user password.

        :param bool doit: If True really unlock user on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """

        commands = []
        if self._extended_cryptedpassword is not None:
            commands.append(
                f"{self.config['binary']['usermod']} --password "
                f"'{self._extended_cryptedpassword}' {self._standard_login}"
            )
        commands += [
            f"{self.config['binary']['usermod']} --expiredate -1 --unlock "
            f"--shell {self.config['user']['shell']} {self._standard_login}",
            f"{self.config['global']['binary']['update-cache']}",
        ]
        if doit:
            runs(commands)
            return None
        else:
            return commands

    def killall(self, doit: bool = False) -> Optional[List[str]]:
        """ Kill all unix user's process on all login nodes with the killall 
        command.

        :param bool doit: If True really kill all unix user's process on all 
                          login nodes else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If login is root
        """
        if self._standard_login == 'root':
            raise RuntimeError(
                "You can't cancel root process with this method"
            )

        ccommand = f"{self.config['global']['binary']['clush']} --nostdin -q -S " \
                   f"-w {','.join(self.config['global']['loginNodes'])}"
        kcommand = f"{self.config['binary']['killall']} -q -9 " \
                   f"-u '{self._standard_login}'"

        commands = [(f'{ccommand} "{kcommand}"',[0,1])]
                
        if doit:
            runs(commands)
            return None
        else:
            return [c[0] if isinstance(c,tuple) else c for c in commands]


# @ctrace
class UnixUsers(GenericObjects):
    """
        List of UnixUser objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="logins", multiple=False)
        self._register_index(index_name="mails", multiple=True)
        self._register_index(index_name="idindividus", multiple=True)
        self._register_index(index_name="pgroups", multiple=True)
        super().__init__(**kwargs)

    def add(self, obj: UnixUser):
        """ Add a UnixUser object to the list

        :param UnixUser obj: A UnixUser object
        """
        super().add(obj)
        self._add_to_logins(obj.login, obj)
        if obj.mail is not None:
            self._add_to_mails(obj.mail, obj)
        if obj.idindividu is not None:
            self._add_to_idindividus(obj.idindividu, obj)
        if obj.pgroup is not None:
            self._add_to_pgroups(obj.pgroup, obj)

    def delete(self, obj: UnixUser):
        """ Remove a UnixUser object from the list

        :param UnixUser obj: A UnixUser object
        """
        super().delete(obj)
        self._delete_from_logins(obj.login, obj)
        self._delete_from_mails(obj.mail, obj)
        self._delete_from_idindividus(obj.idindividu, obj)
        if obj.pgroup is not None:
            self._delete_from_pgroups(obj.pgroup, obj)

    @staticmethod
    def ugids(
            ugroups: 'UnixGroups', gnames: Optional[List[str]]
        ) -> Optional[List[int]]:
        """ Gets unix gid list from a list of unix group name if gnames is 
        not None

        :param UnixGroups ugroups: List of all unix Groups
        :param Optionnal[List[str]] gnames: List of group already used gids
        
        :return: A list of unix group gid corresponding to unix name list or 
                 None
        """
        if gnames is None:
            return None
        else:
            if isinstance(gnames, list) and \
               all([isinstance(gname, str) for gname in gnames]):
                return list(set([
                    ugroups.get_by_gids(gname) for gname in gnames
                ]))

    def populate(
            self, groups: Optional[List[str]] = None, 
            users: Optional[List[str]] = None
        ):
        """ Populate unix user list from system (getent passwd). Populate all 
        users by default.

        We populate groups to add extended informations in the user list

        :param Optional[List[str]] groups: List of user user group name to 
                                           retrieve. None means no filter on 
                                           user groups.
        :param Optional[List[str]] users: List of user name to retrieve.
                                          None means no filter on users.

        :raise RuntimeError: if a user in users list is not found.
        :raise ValueError: if group list is not None or a list of group name 
                           and user list is not None or a list of user name.
        """
        
        # Populate unix groups
        ugroups = UnixGroups()
        ugroups.populate()

        if (groups is None or (
                   isinstance(groups, list) and
                   all([isinstance(g, str) for g in groups]))) and \
           (users is None or (
                    isinstance(users, list) and
                    all([isinstance(u, str) for u in users]))):
            if groups is None:
                search_groups = []
            else:
                search_groups = self.ugids(ugroups, groups)

            if users is None:
                search_users = []
            else:
                search_users = users
            command = f"{self.config['binary']['getent']} " \
                      f"passwd {' '.join(search_users)}"

            # getent return duplicate entries
            output = list(set(run(command)))
            cdata = DictReader(
                output,
                fieldnames=[
                    'login', 'password', 'uid', 'gid', 
                    'comment', 'home', 'shell'
                ],
                delimiter=":"
            )

            self.__log__.trace(f"Found row : '{cdata}'")
            self.__log__.trace(f"Populate command : '{command}'")

            self.adds([
                UnixUser(
                    login=str(d['login']), password=str(d['password']), 
                    uid=int(d['uid']), gid=int(d['gid']), 
                    comment=str(d['comment']), home=Path(d['home']),
                    shell=Path(d['shell']),
                    pgroup=ugroups.get_by_gids(int(d['gid'])).group,
                    locked=Path(d['shell']) == Path(self.config['user']['disabled']),
                    category=ugroups.get_by_gids(int(d['gid'])).category
                ) for d in cdata
                if (users is None or str(d['login']) in search_users) and 
                   (groups is None or int(d['gid']) in search_groups)
            ])

            self.__log__.debug(
                f"Found users '{pplist(self.get_logins())}' in unix users "
                f"(asked for '{users}')"
            )
            self.__log__.trace(
                f"Found users '{self.get_logins()}' in unix users (asked "
                f"for '{users}')"
            )

            if users is not None and not self.len() == len(users):
                raise RuntimeError(
                    f"Users "
                    f"'{[u for u in users if u not in self.get_logins()]}' "
                    f"not found in unix users."
                )
            self._populate_extended_group_attrs(ugroups)
        else:
            raise ValueError(
                "Group list must be None or a list of group name and "
                "User list must be None or a list user name"
            )

    def _populate_extended_group_attrs(self, ugroups: 'UnixGroups'):
        """ Populate extended group info for all users

          * pgroup : Primary group name
          * category : Group category (recherche, entreprise, etc ..)

        """
        # Add secondary group member
        for ug in ugroups:
            for ulogin in ug.musers:
                uuser_std_oid = self.get_by_logins(ulogin)
                if uuser_std_oid is None:
                    self.__log__.debug(
                        f"Unable to add secondary group '{ug.group}' for "
                        f"user '{ulogin}' (User not populated)."
                    )
                else:
                    self.__log__.trace(
                        f"Add secondary group '{ug.group}' for user "
                        f"'{ulogin}'."
                    )
                    self.get_by_logins(ulogin).addmgroup(ug.group)
