# -*- coding: utf-8 -*-

# pylint: disable=no-member
# pylint: disable=E1101

""" Module for managing hpc ssh for users and groups

This module can be used to set and unset ssh keys on system.

Configuration of this module can be found in config/configSsh.py

.. TODO:: 
  * Rewrite module import and use
  * rewrite method to only return command type, command, priority and 
    expected return code and let the manager do run
"""
import hpc.generics
import pathlib
import typing
import config.config as gconfig
import config.configManager
import hpc.utils
import re
import cilogger.cilogger

log = cilogger.cilogger.ccilogger(__name__)

# @ctrace
class SshGroup(hpc.generics.GenericObject):
    """
    Ssh group class

    An ssh group is an unix group having users with a ssh folder as defined in
    configSsh.py file.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    attributes = hpc.utils.register_attributes([{
        "name": "group", "category": "standard", "type": str,
        "default": None, "help": "Ssh group name",
    }, {
        "name": "musers", "category": "extended", "type": list,
        "default": [], "help": "List of user names members of the group",
    }, {
        "name": "category", "category": "extended", "type": str,
        "default": None,
        "help": f"Group category ({', '.join(gconfig.config['category'])})",
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this group a generated group"
    }])
    callables = hpc.utils.register_callables([
        hpc.utils.build_callable(
            action="list",      
            examples=[(
                "List groups with at least one user having a valid ssh folder", 
                "--attribute group category --filter 'group=^.+$'"
            )]),
        hpc.utils.build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["group"]),
        hpc.utils.build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["group"])
    ], attributes)
    __doc__ += hpc.utils.attributes_to_docstring(attributes)

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
                f"Category can not be define for group '{self._standard_group}' "
                f"from configured "
                f"categories '{[c for c in self.config['global']['category']]}' "
            )
        else:
            self._extended_category = defined_category
    
    @property
    def ssh_folder(self) -> pathlib.Path:
        """ ssh group folder computed attribute from root path

        :return: ssh group folder computed attribute from root path

        :raise RuntimeError: if group name is not set
        """
        if self.group is not None:
            return pathlib.Path(self.config['sshRootPath']).joinpath(self.group)
        else:
            raise RuntimeError(
                f"Unable to set ssh folder : group name is not set ({self.group})"
            )

# @ctrace
class SshGroups(hpc.generics.GenericObjects):
    """
    List of SshGroup objects.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="groups", multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: SshGroup):
        """ Add a SshGroup object to the list

        :param SshGroup obj: A SshGroup object
        """
        super().add(obj)
        self._add_to_groups(obj.group, obj)

    def delete(self, obj: SshGroup):
        """ Remove a SshProjet object from the list

        :param SshGroup obj: A SshGroup object
        """
        super().delete(obj)
        self._delete_from_groups(obj.group, obj)

    def populate(self, groups: typing.Optional[typing.List[str]] = None):
        """Populate group ssh for all groups having users with ssh folder files. 
        Populate all groups by default.

        :param Optional[List[str]] groups: List of group name to retrieve.
                                           None means all groups.

        :raise ValueError: if group list is not None and is not a list of 
                           group name
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

        ssh_groups = {}
        for folder in [
            gf
            for gf in pathlib.Path(self.config['sshRootPath']).glob(f"*/*/{self.config['sshFolder']}")
            if gf.match(f"{self.config['sshRootPath']}/*/*/{self.config['sshFolder']}")
            and (search_groups is None or gf in search_groups)
        ]:
            (group, user) = folder.parent.relative_to(self.config['sshRootPath']).parts
            self.__log__.trace(f"Found group '{group}' and user '{user}' in path '{folder}'")
            
            if group in ssh_groups:
                ssh_groups[group].append(user)
            else:
                ssh_groups.update({group: [user]})
            
        for group, musers in ssh_groups.items():
            self.add(SshGroup(group=group, musers=musers))

        self.__log__.debug(
            f"Found {self.len()} groups '{self.get_groups()}' in ssh groups (asked for '{groups}')"
        )
        if groups is not None and not self.len() == len(groups):
            raise RuntimeError(
                f"Groups '{[g for g in groups if g not in self.get_groups()]}' not found in "
                f"ssh groups."
            )

# @ctrace
class SshUser(hpc.generics.GenericObject):
    """
    Ssh user class

    An ssh user is an unix user having authorised_keys and internal keys in 
    ssh folder as defined in configSsh.py file.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    attributes = hpc.utils.register_attributes(
        [
            {
                "name": "login",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "Ssh user login name",
            },
            {
                "name": "pgroup",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "Ssh user primary group name",
            },
            {
                "name": "authpubkeysuser",
                "category": "standard",
                "type": list,
                "default": None,
                "help": "Ssh authorized public key list for this user",
            },
            {
                "name": "authpubkeysinternal",
                "category": "standard",
                "type": list,
                "default": None,
                "help": "Ssh authorized internal public key list for this user",
            },
            {
                "name": "authpubkeyspi",
                "category": "standard",
                "type": list,
                "default": None,
                "help": "Ssh authorized project inverstigator public key list for this user",
            },
            {
                "name": "authpubkeysadmin",
                "category": "standard",
                "type": list,
                "default": None,
                "help": "Ssh authorized admin public key list for this user",
            },
            {
                "name": "internalpubkey",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "Ssh user internal public key",
            },
            {
                "name": "internalprivkey",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "Ssh user internal private key",
            },
            {
                "name": "folder", "category": "extended", "type": pathlib.Path, 
                "default": None, "help": f"Ssh user folder path"
            },
            {
                "name": "category",
                "category": "extended",
                "type": str,
                "default": None,
                "help": f"Ssh User group category ({', '.join(gconfig.config['category'])})",
            }, {
                "name": "generated", "category": "extended", "type": bool, 
                "default": False, "help": f"Is this user a generated user"
            }
        ]
    )
    callables = hpc.utils.register_callables([
        hpc.utils.build_callable(
            action="list",
            examples=[(
                "List internal user public ssh key for user with login 'toto'", 
                "--attribute login pgroup category internalpubkey --filter 'login=^toto$'"
            )]),
        hpc.utils.build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["pgroup", "login"]),
        hpc.utils.build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["pgroup", "login"]),
        hpc.utils.build_callable(
            action="add",
            command="sshpubkey",
            check="presence",
            doit=True,
            label="Add an ssh public key to an authorized file for this user",
            required_attributes=["pgroup", "login"],
            additional_arguments=[
                hpc.utils.to_parser("--pubkey", 
                    dest=f"add_sshpubkey_additional_arguments_pubkey", 
                    metavar=f"<pubkey>",
                    type=str, required=True,
                    help=f"Ssh public key string"
                ),
                hpc.utils.to_parser("--authid", 
                    dest=f"add_sshpubkey_additional_arguments_authid", 
                    metavar=f"<authid>",
                    type=str, required=True,
                    help=f"Authorized file id ( must be one of {', '.join(__config__['sshAuthorizedKeysFiles'].keys())})"
                ),
            ]),
        hpc.utils.build_callable(
            action="remove",
            command="sshpubkey",
            check="presence",
            doit=True,
            label="Remove an ssh public key from an authorized file for this user",
            required_attributes=["pgroup", "login"],
            additional_arguments=[
                hpc.utils.to_parser("--pubkey", 
                    dest=f"remove_sshpubkey_additional_arguments_pubkey", 
                    metavar=f"<pubkey>",
                    type=str, required=True,
                    help=f"Ssh public key string"
                ),
                hpc.utils.to_parser("--authid", 
                    dest=f"remove_sshpubkey_additional_arguments_authid", 
                    metavar=f"<authid>",
                    type=str, required=True,
                    help=f"Authorized file id ( must be one of {', '.join(__config__['sshAuthorizedKeysFiles'].keys())})"
                ),
            ])
    ], attributes)
    __doc__ += hpc.utils.attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        try:
            self._extended_folder = self.ssh_folder
        except Exception as e:
            self._extended_folder = None
    
    @property
    def ssh_folder(self) -> pathlib.Path:
        """ User ssh folder full path computed from config file

        :return: ssh user folder computed attribute from root path

        :raise RuntimeError: if group name is not set
        :raise RuntimeError: if user login name is not set
        """
        if self._standard_pgroup is None or not isinstance(self._standard_pgroup, str):
            raise ValueError(
                f"Ssh group name '{self._standard_pgroup}' is not valid"
            )
        elif self._standard_login is None or not isinstance(self._standard_login, str):
            raise RuntimeError(
                f"You must set a valid ssh user login name ({self.login})"
            )
        else:
            ssh_folder=pathlib.Path(
                self.config['sshRootPath']
            ).joinpath(
                self.pgroup
            ).joinpath(self.login).joinpath(self.config['sshFolder'])
            return ssh_folder
        
    def _predefined_commands(self, method: str) -> typing.List[str]:
        """ Predefined commands for creating or deleting ssh user environnment

        :param str method: Method name (create or delete)

        :return: Creation or deletion commands list

        :raise ValueError: if method name is invalid
        """
        # Create and delete
        binary = self.config['binary']
        gbinary = self.config['global']['binary']
        ssh_internal_privkey_file = self.ssh_folder.joinpath(self.config['sshInternalKeyFiles']['priv'])
        ssh_internal_pubkey_file = self.ssh_folder.joinpath(self.config['sshInternalKeyFiles']['pub'])
        ssh_internal_privkey_name = f"{self.login}.{self.config['sshInternalKeyFiles']['priv']}"
        create_and_delete_commands = [(
            (f"{gbinary['mkdir']} '{self.ssh_folder}'", [0]), 
            (f"{gbinary['rmdir']} '{self.ssh_folder}'", [0]),
        ), (
            (f"{gbinary['chown']} {self.login}.{self.pgroup} '{self.ssh_folder}'", [0]), 
            (None, [0])
        ), (
            (f"{gbinary['chmod']} {self.config['sshFolderRights']} '{self.ssh_folder}'", [0]),
            (None, [0])
        ), (
            (f"{binary['ssh-keygen']} {self.config['default-ssh-keygen-create-options']} -f '{ssh_internal_privkey_file}' -C '{ssh_internal_privkey_name}'", [0]),
            (f"{gbinary['rm']} -f '{ssh_internal_privkey_file}' '{ssh_internal_pubkey_file}'", [0])
        ), (       
            (f"{gbinary['chown']} {self.login}.{self.pgroup} '{ssh_internal_privkey_file}'", [0]),
            (None, [0])
        ), (
            (f"{gbinary['chmod']} {self.config['sshInternalKeyFileRights']} '{ssh_internal_privkey_file}'", [0]),
            (None, [0])
        )]

        for authkeyfile in self.config['sshAuthorizedKeysFiles'].values():
            ssh_authkeys_file = self.ssh_folder.joinpath(authkeyfile)
            create_and_delete_commands += [(
                (f"{gbinary['touch']} {ssh_authkeys_file}", [0]),
                (f"{gbinary['rm']} -f '{ssh_authkeys_file}'", [0])
            ), (
                (f"{gbinary['chown']} {self.login}.{self.pgroup} {ssh_authkeys_file}", [0]),
                (None, [0])
            ), (
                (f"{gbinary['chmod']} {self.config['sshAuthorizedKeysFileRights']} {ssh_authkeys_file}", [0]),
                (None, [0])
            )]
         
        if method == "create":
            return [c[0] for c in create_and_delete_commands]
        elif method == "delete":
            return [c[1] for c in create_and_delete_commands[::-1] if c[1]]
        else:
            raise ValueError(f"Unable to find commands for method '{method}'")

    def create(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """Create a ssh user

        :param bool doit: If True really creates ssh user environment on system 
                          else just return the command as a string

        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        commands = self._predefined_commands("create")
        if doit:
            hpc.utils.runs(commands)
            return f"Succes to create ssh folder for user '{self._standard_login}'"
        else:
            return commands

    def delete(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """Delete a ssh user

        :param bool doit: If True really deletes ssh user environment on system 
                          else just return the command as a string

        :return: A success string message or None if doit is True and no raise 
                 else just return commands that should be done as string array

        :raise RuntimeError: If command fails
        """
       
        commands = self._predefined_commands("delete")
        if doit:
            hpc.utils.runs(commands)
            return f"Succes to delete ssh folder for user '{self._standard_login}'"
        else:
            return commands
        
    def check_sshpubkey(self, sshpubkey: str) -> bool:
        """ Check if ssh private or public key is valid and match allowed 
            algorithms

        :param str sshpubkey: Ssh private key or public key string

        :return: True if ssh key is valid else False

        :raise RuntimeError: If ssh key is not valid
        """
        try:
            key_fingerprint = hpc.utils.run(
                f"{self.config['binary']['ssh-keygen']} "
                f"{self.config['default-ssh-keygen-check-options']} "
                f"-f - <<< '{sshpubkey}'"
            )
            fingerprint_regex = re.compile(
                r'^(?P<size>[0-9]+)\s+[A-Z0-9]+:\S+\s+(?P<name>\S+|no comment)\s+\((?P<algorithm>\S+)\)$'
            )
            fingerprint_match = fingerprint_regex.match(key_fingerprint[0])
            if fingerprint_match:
                key_size = fingerprint_match.group('size')
                key_name = fingerprint_match.group('name')
                key_algorithm = fingerprint_match.group('algorithm')
                if key_algorithm in self.config['sshAllowedAlgorithm']:
                    if key_size >= self.config['sshAllowedAlgorithm'][key_algorithm]['min-size']:
                        self.__log__.debug(
                            f"Ssh key '{key_name}' with algorithm '{key_algorithm}' and size '{key_size}' is ok")
                        return True
                    else:
                        self.__log__.critical(f"Key size '{key_size}' is too low for algorithm '{key_algorithm}' on this cluster")
                else:
                    self.__log__.critical(f"Algorithm '{key_algorithm}' is not allowed on this cluster")
            else:
                self.__log__.critical(f"No match for '{key_fingerprint[0]}' on fingerprint regex '{fingerprint_regex}'")

        except RuntimeError as e:
            self.__log__.debug(e)
            self.__log__.critical(f"Not not a valid key ({sshpubkey})")
        return False

    def add_sshpubkey(self, authid: str, pubkey: str, doit: bool = False):
        """Add a public key to an authorized_keys file
        
        :param ssh authid: Ssh authorized_keys file name (as describe in 
                           config file)
        :param ssh pubkey: Ssh public key string to add

        :return: True if ssh key is valid else False

        :raise RuntimeError: If ssh public key is not valid
        :raise RuntimeError: If ssh public key is already in authorized_keys 
                             file
        :raise RuntimeError: If authorized_keys file type is not str or list
        :raise RuntimeError: If authorized_keys file can not be found
        :raise RuntimeError: If authorized_keys folder can not be found
        :raise RuntimeError: If authorized_keys configuration can not be found
        """
        if not self.check_sshpubkey(pubkey):
            raise RuntimeError(
                f"Ssh key ({pubkey}) is not a valid on this cluster"
            ) 
        if authid in self.config['sshAuthorizedKeysFiles']:
            authorized_keys_file = self.config['sshAuthorizedKeysFiles'][authid]
            self.__log__.debug(
                f"Trying to add ssh public key '{pubkey}' to authorized_keys file "
                f"'{authorized_keys_file}' in folder '{self._extended_folder}'"
            )
            if self._extended_folder is not None \
               and self._extended_folder.exists():
                akf = self.ssh_folder.joinpath(authorized_keys_file)
                if akf.exists():
                    current = getattr(self,f"authpubkeys{authid}")
                    ctype = self.attribute(f"authpubkeys{authid}")['type']
                    self.__log__.debug(f"Key type: {ctype}")
                    if ctype is str:
                        if pubkey == current:
                            raise RuntimeError(
                                f"Ssh public key '{pubkey}' is already "
                                f"added to authorized_keys file "
                                f"'{authorized_keys_file}' in folder "
                                f"'{self._extended_folder}'"
                            )
                        else:
                            if doit:
                                with open(akf, 'w') as h_akf:
                                    h_akf.write(f"{pubkey}\n")
                                return (
                                    f"Succes to add ssh public key '{pubkey}' "
                                    f"to authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                )
                            else:
                                return ([
                                    f"Append ssh public key '{pubkey}' to "
                                    f"authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                ])
                            
                    elif ctype is list:
                        if pubkey in current:
                            raise RuntimeError(
                                f"Ssh public key '{pubkey}' is already "
                                f"added to authorized_keys file "
                                f"'{authorized_keys_file}' in folder "
                                f"'{self._extended_folder}'"
                            )
                        else:
                            if doit:
                                with open(akf, 'a') as h_akf:
                                    h_akf.write(f"{pubkey}\n")
                                return (
                                    f"Succes to add ssh public key '{pubkey}' "
                                    f"to authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                )
                            else:
                                return ([
                                    f"Append ssh public key '{pubkey}' to "
                                    f"authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                ])
                    else:
                        raise RuntimeError(
                            f"Type '{type(current)}' not allowed"
                    ) 
                else:
                    raise RuntimeError(
                        f"Unable to find authorized_keys file "
                        f"'{authorized_keys_file}' in folder "
                        f"'{self._extended_folder}'"
                    )   
            else:
                raise RuntimeError(
                    f"Unable to find authorized_keys folder '{self._extended_folder}'"
                )
        else:
            raise RuntimeError(
                f"No configuration found for authorized_keys with id '{authid}'"
            )

    def remove_sshpubkey(self, authid: str, pubkey: str, doit: bool = False):
        """Remove a public key from an authorized_keys file
        
        :param ssh authid: Ssh authorized_keys file name (as describe in 
                           config file)
        :param ssh pubkey: Ssh public key string to add

        :return: True if ssh key is valid else False

        :raise RuntimeError: If ssh public key is not valid
        :raise RuntimeError: If ssh public key is already not in authorized_keys 
                             file
        :raise RuntimeError: If authorized_keys file type is not str or list
        :raise RuntimeError: If authorized_keys file can not be found
        :raise RuntimeError: If authorized_keys folder can not be found
        :raise RuntimeError: If authorized_keys configuration can not be found
        """
        if not self.check_sshpubkey(pubkey):
            raise RuntimeError(
                f"Ssh key ({pubkey}) is not a valid on this cluster"
            ) 
        if authid in self.config['sshAuthorizedKeysFiles']:
            authorized_keys_file = self.config['sshAuthorizedKeysFiles'][authid]
            self.__log__.debug(
                f"Trying to remove ssh public key '{pubkey}' from authorized_keys file "
                f"'{authorized_keys_file}' in folder '{self._extended_folder}'"
            )
            if self._extended_folder is not None \
               and self._extended_folder.exists():
                akf = self.ssh_folder.joinpath(authorized_keys_file)
                if akf.exists():
                    current = getattr(self,f"authpubkeys{authid}")
                    ctype = self.attribute(f"authpubkeys{authid}")['type']
                    self.__log__.debug(f"Key type: {ctype}")
                    if ctype is str:
                        if pubkey == current:
                            if doit:
                                with open(akf, 'w') as h_akf:
                                    h_akf.write(f"")
                                return (
                                    f"Succes to remove ssh public key '{pubkey}' "
                                    f"from authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                )
                            else:
                                return ([
                                    f"Remove ssh public key '{pubkey}' from "
                                    f"authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                ])
                        else:
                            raise RuntimeError(
                                f"Ssh public key '{pubkey}' is already not "
                                f"in authorized_keys file "
                                f"'{authorized_keys_file}' in folder "
                                f"'{self._extended_folder}'"
                            )
                        
                            
                    elif ctype is list:
                        if pubkey in current:
                            if doit:
                                with open(akf, 'w') as h_akf:
                                    for k in current:
                                        if not k == pubkey:
                                            h_akf.write(f"{k}\n")
                                return (
                                    f"Succes to remove ssh public key '{pubkey}' "
                                    f"from authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                )
                            else:
                                return ([
                                    f"Remove ssh public key '{pubkey}' from "
                                    f"authorized_keys file "
                                    f"'{authorized_keys_file}' in folder "
                                    f"'{self._extended_folder}'"
                                ])
                        else:
                            raise RuntimeError(
                                f"Ssh public key '{pubkey}' is already "
                                f"removed from authorized_keys file "
                                f"'{authorized_keys_file}' in folder "
                                f"'{self._extended_folder}'"
                            )  
                    else:
                        raise RuntimeError(
                            f"Type '{type(current)}' not allowed"
                    ) 
                else:
                    raise RuntimeError(
                        f"Unable to find authorized_keys file "
                        f"'{authorized_keys_file}' in folder "
                        f"'{self._extended_folder}'"
                    )   
            else:
                raise RuntimeError(
                    f"Unable to find authorized_keys folder '{self._extended_folder}'"
                )
        else:
            raise RuntimeError(
                f"No configuration found for authorized_keys with id '{authid}'"
            )
    
# @ctrace
class SshUsers(hpc.generics.GenericObjects):
    """
    List of SshGroup objects.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="logins", multiple=False)
        self._register_index(index_name="pgroups", multiple=True)
        super().__init__(**kwargs)

    def add(self, obj: SshUser):
        """ Add a SshUser object to the list

        :param SshUser obj: A SshUser object
        """
        super().add(obj)
        self._add_to_logins(obj.login, obj)
        self._add_to_pgroups(obj.pgroup, obj)

    def delete(self, obj: SshUser):
        """ Remove a SshUser object from the list

        :param SshUser obj: A SshUser object
        """
        super().delete(obj)
        self._delete_from_logins(obj.login, obj)
        self._delete_from_pgroups(obj.pgroup, obj)

    def _populate_helper(self, user: str, user_group_object: SshGroup) -> dict:
        """ Create a usable dict containing all attributes needed by SshUser
        constructor as parameters
        
        :param dict user: A ssh user login name
        :param dict user_group_object: Ssh user project object from 
                                       SshGroups

        :return: Formatted ssh user data usable by SshUser constructor 
                 as parameters
        """
        ssh_folder=pathlib.Path(
            self.config['sshRootPath']
        ).joinpath(
            user_group_object.group
        ).joinpath(user).joinpath(self.config['sshFolder'])
        
        formatted_user_datas = {
            "login": user,
            "pgroup": user_group_object.group,
            "category": user_group_object.category,
            "authpubkeysuser": None,
            "authpubkeysinternal": None,
            "authpubkeyspi": None,
            "authpubkeysadmin": None,
            "internalpubkey": None,
            "internalprivkey":  None
        }
        # Authorized keys
        for k,v in self.config['sshAuthorizedKeysFiles'].items(): 
            ssh_file = ssh_folder.joinpath(v)
            if ssh_file.exists():
                with open(ssh_file, 'r') as ssh_fh:
                    self.__log__.trace(f"Reading file '{ssh_file}' content ...")
                    ssh_keys = ssh_fh.read().splitlines()
                    if ssh_keys:
                        formatted_user_datas.update({
                            f"authpubkeys{k}": ssh_keys
                        })
                    else:
                        formatted_user_datas.update({
                            f"authpubkeys{k}": []
                        })
            else:
                self.__log__.warn(f"Authorized keys '{ssh_file}' not found")
        # Internal ssh key          
        for k,v in self.config['sshInternalKeyFiles'].items(): 
            ssh_file = ssh_folder.joinpath(v)
            if ssh_file.exists():
                with open(ssh_file, 'r') as ssh_fh:
                    self.__log__.trace(f"Reading file '{ssh_file}' content ...")
                    formatted_user_datas.update({
                        f"internal{k}key": ssh_fh.read().rstrip()
                    })
            else:
                self.__log__.warn(f"Authorized keys '{ssh_file}' not found")       
        # self.__log__.debug(f"formatted_user_datas : {formatted_user_datas}")
        return formatted_user_datas

    def populate(self, users: typing.Optional[typing.List[str]] = None):
        """Populate user ssh for all users from ssh folder. Populate all 
        users by default.

        :param Optional[List[str]] users: List of user ssh login name to retrieve.
                                          None means all users.

        :raise ValueError: If user list is not None and is not a list of user 
                           login name
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

        sgs = SshGroups()
        sgs.populate()

        for folder in [
            uf
            for sg in sgs 
            for uf in sg.ssh_folder.glob(f"*/{self.config['sshFolder']}") 
            if uf.match(f"{self.config['sshRootPath']}/*/*/{self.config['sshFolder']}")
               and search_users is None or uf in search_users
        ]:
            (group, user) = folder.parent.relative_to(self.config['sshRootPath']).parts
            self.__log__.trace(f"Found group '{group}' and user '{user}' in path '{folder}'")
            
            self.add(
                SshUser(**self._populate_helper(user, sgs.get_by_groups(group)))
            )

        self.__log__.debug(
            f"Found {self.len()} users '{self.get_logins()}' in users ssh "
            f"(asked for '{users}')"
        )

        if users is not None and not self.len() == len(users):
            raise RuntimeError(
                f"Users '{[u for u in users if u not in self.get_logins()]}' "
                f"not found in users ssh."
            )