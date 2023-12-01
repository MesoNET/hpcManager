# -*- coding: utf-8 -*-
""" Module for managing ldapds users and groups
"""
import hpc.generics
import typing
import config.config
import hpc.utils
import datetime
import csv
import itertools
import pathlib
import ldap
import io
import re
import cilogger.cilogger
import config.configManager
log = cilogger.cilogger.ccilogger(__name__)


# @ctrace
class LdapGroup(hpc.generics.GenericObject):
    """
    LdapDS group. Standards attributes are a subset of those in posixGroup
    object class.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    attributes = hpc.utils.register_attributes([{
        "name": "cn", "category": "standard", "type": str, 
        "default": None, "help": "Ldap group name"
    }, {
        "name": "gidnumber", "category": "standard", "type": int, 
        "default": None, "help": "Ldap group gidNumber"
    }, {
        "name": "musers", "category": "standard", "type": list, 
        "default": [],
        "help": "List of user dn of users who are members of the group"
    }, {
        "name": "dn", "category": "extended", "type": str, 
        "default": None,
        "help": f"Ldap group dn"
    }, {
        "name": "category", "category": "extended", "type": str, 
        "default": None,
        "help": f"Group category ({', '.join(config.config.config['category'])})"
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this group a generated group"
    }])
    callables = hpc.utils.register_callables([
        hpc.utils.build_callable(
            action="list",      
            examples=[(
                "List name, gid and members of ldap group 'm99099'", 
                "--attribute cn gidnumber musers --filter 'group=^m99099$'"
            )]
        ),
        hpc.utils.build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["cn"]),
        hpc.utils.build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["cn"]),
        hpc.utils.build_callable(
            action="add", 
            command="attribute",
            check="presence",
            doit="remove_attribute",
            label="Add an attribute to an ldap group entry",
            required_attributes=["cn"],
            additional_arguments=[
                hpc.utils.to_parser("--attribute", 
                    dest=f"add_attribute_additional_arguments_attribute", 
                    metavar=f"<attribute>",
                    type=str, required=True,
                    help=f"Ldap attribute name to add"
                ),
                hpc.utils.to_parser("--value", 
                    dest=f"add_attribute_additional_arguments_value", 
                    metavar=f"<value>",
                    type=str, required=True,
                    help=f"Ldap attribute value to add"
                )
            ]
        ),
        hpc.utils.build_callable(
            action="remove", 
            command="attribute",
            check="presence",
            doit="add_attribute",
            label="Delete an attribute from an ldap group entry",
            required_attributes=["cn"],
            additional_arguments=[
                hpc.utils.to_parser("--attribute", 
                    dest=f"remove_attribute_additional_arguments_attribute", 
                    metavar=f"<attribute>",
                    type=str, required=True,
                    help=f"Ldap attribute name to delete"
                ),
                hpc.utils.to_parser("--value", 
                    dest=f"remove_attribute_additional_arguments_value", 
                    metavar=f"<value>",
                    type=str, required=True,
                    help=f"Ldap attribute value to delete"
                )
            ]
        ),
        hpc.utils.build_callable(
            action="modify", 
            command="attribute",
            check="presence",
            doit=True,
            label="Modify an attribute in an ldap group entry (must be single valuated)",
            required_attributes=["cn"],
            additional_arguments=[
                hpc.utils.to_parser("--attribute", 
                    dest=f"modify_attribute_additional_arguments_attribute", 
                    metavar=f"<attribute>",
                    type=str, required=True,
                    help=f"Ldap attribute name to modify"
                ),
                hpc.utils.to_parser("--value", 
                    dest=f"modify_attribute_additional_arguments_value", 
                    metavar=f"<value>",
                    type=str, required=True,
                    help=f"Ldap attribute value to modify"
                )
            ]
        ),
    ], attributes)
    __doc__ += hpc.utils.attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._define_category()
        self._define_dn()
    
    def _define_dn(self):
        """ Build dn from cn and config ou
        """
        self._extended_dn = f"cn={self._standard_cn},{self.config['group']['ou']}"

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
                category_regex = re.compile(r"{}".format(data['regex']))
                if category_regex.match(str(self._standard_cn)):
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

    def add_attribute(
                self, attribute: str, 
                value: typing.Union[str,typing.List],
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Add an attribute to a ldap group entry

        :param bool doit: If True really add attribute to ldap group entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string or a list
        """
        values = []
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
        commands = []
        for v in values:
            commands += [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"posixgroup modify {self._standard_cn} add:{attribute}:{v}"
            ]
        commands += [
            f"{self.config['global']['binary']['update-cache']}"
        ]
        if doit:
            hpc.utils.runs(commands)
            return f"Success to add attribute '{attribute}' with value(s) "\
                   f"'{values}' to ldap group entry '{self._standard_cn}'"
        else:
            return commands
    
    def modify_attribute(
                self, attribute: str, 
                value: str,
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Modify an attribute in a ldap group entry. Replace all 
        occurences found if multiple attribute with same value.

        :param bool doit: If True really modify attribute in ldap group entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string
        :raise ValueError: if attribute is not set or is multivalued
        """
        if isinstance(value, str):
            ldaplogs=io.StringIO()
            ldap_handler = ldap.initialize(

                uri = self.config['uri'], trace_level=0, trace_file=ldaplogs
            )
            search_filter = f"(&(objectClass=*)(cn={self._standard_cn}))"
            self.__log__.debug(f"Search Filter : {search_filter}")
            r = ldap_handler.search_s(
                base=self.config['group']['ou'],
                scope=ldap.SCOPE_ONELEVEL,
                filterstr=search_filter,
                attrlist=[f"{attribute}"]
            )

            if len(r) == 1:
                self.__log__.debug(f"Result : {r} ({next(iter(r))[1]})")
                values = [str(a.decode()) for a in next(iter(r))[1][attribute]]
                if len(values) == 1:
                    self.__log__.debug(
                        f"Ldap attribute '{attribute}' has one value ({len(r)}), "
                        f"we use 'replace' keyword"
                    )
                elif len(values) < 1:
                    raise ValueError(
                        f"Ldap attribute '{attribute}' has no value ({len(r)}). "
                        f"Use add_attribute method"
                    )
                else:
                    raise ValueError(
                        f"Ldap attribute '{attribute}' is mutltivalued ({len(r)}). "
                        f"Use 'remove_attribute' first then 'add_attibute' method"
                    )
            else:
                raise ValueError(
                    f"Entry Not found : {r}"
                )
           
            commands = [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"posixgroup modify {self._standard_cn} "
                f"replace:{attribute}:{value}",
                f"{self.config['global']['binary']['update-cache']}"
            ]

            if doit:
                hpc.utils.runs(commands)
                return f"Success to modify attribute '{attribute}' with "\
                       f"value(s) '{value}' in ldap group entry "\
                       f"'{self._standard_cn}'"
            else:
                return commands
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
    def remove_attribute(
                self, attribute: str, 
                value: typing.Union[str,typing.List],
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Add an attribute to a ldap group entry

        :param bool doit: If True really add attribute to ldap group entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string or a list
        """
        values = []
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
        commands = []
        for v in values:
            commands += [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"posixgroup modify {self._standard_cn} delete:{attribute}:{v}"
            ]
        commands += [
            f"{self.config['global']['binary']['update-cache']}"
        ]

        if doit:
            hpc.utils.runs(commands)
            return f"Success to delete attribute '{attribute}' with value(s) "\
                   f"'{values}' from ldap group entry '{self._standard_cn}'"
        else:
            return commands

    def create(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """ Create a ldapds group on the system with the dsidm command

        :param bool doit: If True really creates group on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        commands = [
            f"{self.config['binary']['dsidm']} {self.config['instance']} "
            f"posixgroup create --cn {self._standard_cn} "
            f"--gidNumber {self._standard_gidnumber}",
            f"{self.config['global']['binary']['update-cache']}"
        ]

        if doit:
            hpc.utils.runs(commands)
            return None
        else:
            return commands

    def delete(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """ Delete a ldapds group on the system with the dsidm command

        :param bool doit: If True really deletes group on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If user members not empty or user primary 
                             members not empty
        """
        
        confirmation = f"echo '{self.config['confirmation']}'"
        commands = [
            f"{confirmation} | {self.config['binary']['dsidm']} "
            f"{self.config['instance']} group delete {self._extended_dn}",
            f"{self.config['global']['binary']['update-cache']}"
        ]

        if doit:
            if self._standard_musers:
                raise RuntimeError(
                    f"Group has user members ({self._standard_musers})"
                )
            hpc.utils.runs(commands)
            return None
        else:
            return commands

# @ctrace
class LdapGroups(hpc.generics.GenericObjects):
    """
    List of LdapDS objects.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="cns", multiple=False)
        self._register_index(index_name="gidnumbers", multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: LdapGroup):
        """ Add a LdapGroup object to the list

        :param LdapGroup obj: A LdapGroup object
        """
        super().add(obj)
        # Add group and gidnumber index
        self._add_to_cns(obj.cn, obj)
        self._add_to_gidnumbers(obj.gidnumber, obj)

    def delete(self, obj: LdapGroup):
        """ Remove a LdapGroup object from the list

        :param LdapGroup obj: A LdapGroup object
        """
        super().delete(obj)
        # Remove group and gidnumber from index
        self._delete_from_gidnumbers(obj.gidnumber, obj)
        self._delete_from_cns(obj.cn, obj)

    def populate(self, groups: typing.Optional[typing.List[str]] = None):
        """ Populate ldap group list from system (/usr/bin/ldapsearch -x -LLL 
        -b "ou=groups,dc=...,dc=..." command).

        Populate all ldap groups by default.

        :param Optional[List[str]] groups: List of group name to retrieve.
                                           None means all groups.

        :raise RuntimeError: if a group in group list is not found.
        """
        if groups is None or isinstance(groups, list) and \
                all([isinstance(g, str) for g in groups]):
            if groups is None:
                search_groups = "(objectClass=*)"
            else:
                search_groups = f"(|(cn={')(cn='.join(groups)}))"
            
            ldaplogs=io.StringIO()
            #ldap.set_option()
            ldap_handler = ldap.initialize(
                uri = self.config['uri'], trace_level=0, trace_file=ldaplogs
            )
            r = ldap_handler.search_s(
                base=self.config['group']['ou'],
                scope=ldap.SCOPE_ONELEVEL,
                filterstr=search_groups,
                attrlist=["cn", "gidNumber", "member"]
            )
            self.adds([
                LdapGroup(
                    cn=str(next(iter(entry['cn']),'unkown_cn').decode()),
                    gidnumber=int(next(iter(entry['gidNumber']),'unkown_gidNumber').decode()),
                    musers=[str(m.decode()) for m in entry['member']]
                ) if 'member' in entry else
                LdapGroup(
                    cn=str(next(iter(entry['cn']),'unkown_cn').decode()),
                    gidnumber=int(next(iter(entry['gidNumber']),'unkown_gidNumber').decode()),
                    musers=[]
                ) 
                for _, entry in r 
            ])
            self.__log__.trace(
                f"Found groups '{self.get_cns()}' in ldap groups (asked "
                f"for '{groups}')"
            )
            self.__log__.debug(
                f"Found groups '{hpc.utils.pplist(self.get_cns())}' in ldap groups "
                f"(asked for '{groups}')"
            )

            if groups is not None and not self.len() == len(groups):
                raise RuntimeError(
                    f"Groups "
                    f"'{[g for g in groups if g not in self.get_cns()]}' "
                    f"not found in ldap groups."
                )
        else:
            raise ValueError(
                "Group list must be None or a list of group name"
            )


# @ctrace
class LdapUser(hpc.generics.GenericObject):
    """
    LdapDS user. Standards attributes are a subset of those in posixAccount 
    object class.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    attributes = hpc.utils.register_attributes([{
        "name": "uid", "category": "standard", "type": str, 
        "default": None, "help": "Ldap user id"
    }, {
        "name": "cn", "category": "standard", "type": str, 
        "default": None, "help": "Ldap user common name"
    }, {
        "name": "displayname", "category": "standard", "type": str, 
        "default": None, "help": "Ldap user display name"
    }, {
        "name": "uidnumber", "category": "standard", "type": int, 
        "default": None, "help": "Ldap user uidNumber"
    }, {
        "name": "gidnumber", "category": "standard", "type": int, 
        "default": None, "help": "Ldap user gidnumber"
    }, {
        "name": "homedirectory", "category": "standard", "type": pathlib.Path,
        "default": None, "help": "Ldap user home directory"
    }, {
        "name": "mail", "category": "standard", "type": str,
        "default": None, "help": "Ldap user email"
    }, {
        "name": "loginshell", "category": "standard", "type": pathlib.Path, 
        "default": None, "help": "Ldap user login shell"
    }, {
        "name": "gecos", "category": "standard", "type": int, 
        "default": None, "help": "Ldap user gecos (Gramc idindividu)"
    }, {
        "name": "dn", "category": "extended", "type": str,
        "default": None, "help": "Ldap user dn"
    },  {
        "name": "pgroup", "category": "standard", "type": str,
        "default": None, "help": "Ldap user primary group name"
    }, {
        "name": "mgroups", "category": "extended", "type": list, 
        "default": [], "help": "Ldap user group's name member list"
    }, {
        "name": "category", "category": "extended", "type": str, 
        "default": None,
        "help": f"User group category ({', '.join(config.config.config['category'])})"
    },{
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this user a generated ldap user"
    }, {
        "name": "locked", "category": "extended", "type": bool, 
        "default": None, "help": "Ldap user locking state"
    }])
    callables = hpc.utils.register_callables([
        hpc.utils.build_callable(
            action="list",      
            examples=[(
                "List mail and shell for all users in project 'm99099'", 
                "--attribute mail loginshell --filter 'projet=^m99099$'"
            )]
        ),
        hpc.utils.build_callable(
            action="create",
            check="absence",
            doit="delete",
            required_attributes=["uid", "pgroup"]),
        hpc.utils.build_callable(
            action="delete",
            check="presence",
            doit="create",
            required_attributes=["uid", "pgroup"]),
        hpc.utils.build_callable(
            action="add", 
            command="attribute",
            check="presence",
            doit="remove_attribute",
            label="Add an attribute to an ldap user entry",
            required_attributes=["uid", "pgroup"],
            additional_arguments=[
                hpc.utils.to_parser("--attribute", 
                    dest=f"add_attribute_additional_arguments_attribute", 
                    metavar=f"<attribute>",
                    type=str, required=True,
                    help=f"Ldap attribute name to add"
                ),
                hpc.utils.to_parser("--value", 
                    dest=f"add_attribute_additional_arguments_value", 
                    metavar=f"<value>",
                    type=str, required=True,
                    help=f"Ldap attribute value to add"
                )
            ]
        ),
        hpc.utils.build_callable(
            action="remove", 
            command="attribute",
            check="presence",
            doit="add_attribute",
            label="Delete an attribute from an ldap user entry",
            required_attributes=["uid", "pgroup"],
            additional_arguments=[
                hpc.utils.to_parser("--attribute", 
                    dest=f"remove_attribute_additional_arguments_attribute", 
                    metavar=f"<attribute>",
                    type=str, required=True,
                    help=f"Ldap attribute name to delete"
                ),
                hpc.utils.to_parser("--value", 
                    dest=f"remove_attribute_additional_arguments_value", 
                    metavar=f"<value>",
                    type=str, required=True,
                    help=f"Ldap attribute value to delete"
                )
            ]
        ),
        hpc.utils.build_callable(
            action="modify", 
            command="attribute",
            check="presence",
            doit=True,
            label="Modify an attribute in an ldap user entry (must be single valuated)",
            required_attributes=["uid", "pgroup"],
            additional_arguments=[
                hpc.utils.to_parser("--attribute", 
                    dest=f"modify_attribute_additional_arguments_attribute", 
                    metavar=f"<attribute>",
                    type=str, required=True,
                    help=f"Ldap attribute name to modify"
                ),
                hpc.utils.to_parser("--value", 
                    dest=f"modify_attribute_additional_arguments_value", 
                    metavar=f"<value>",
                    type=str, required=True,
                    help=f"Ldap attribute value to modify"
                )
            ]
        ),
    ], attributes)
    
    __doc__ += hpc.utils.attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._define_dn()
        self._define_category()

    def _define_dn(self):
        """ Build dn from cn and config ou

        :raise RuntimeError: If a dn can not be define
        """
        self._extended_dn = f"uid={self._standard_uid},{self.config['user']['ou']}"

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
                category_regex = re.compile(r"{}".format(data['regex']))
                if category_regex.match(str(self._standard_pgroup)):
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

    def addmgroup(self, value: str):
        """ Append a new group to user group member list

        :param str value: Group name to add

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

        :param str value: Group name to remove
        :raise ValueError: if value is not a string or is empty
        """
        if isinstance(value, str) and not value == "":
            self._extended_mgroups.remove(value)
        else:
            raise ValueError(f"Bad member group oid '{value}'")
    

    def add_attribute(
                self, attribute: str, 
                value: typing.Union[str,typing.List],             
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Add an attribute to a ldap user entry

        :param bool doit: If True really add attribute to ldap user entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string or a list
        """
        values = []
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
        commands = []
        for v in values:
            commands += [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"user modify {self._standard_uid} add:{attribute}:{v}"
            ]
        commands += [
            f"{self.config['global']['binary']['update-cache']}"
        ]
        if doit:
            hpc.utils.runs(commands)
            return f"Success to add attribute '{attribute}' with value(s) "\
                   f"'{values}' to ldap user entry '{self._standard_uid}'"
        else:
            return commands
    
    def modify_attribute(
                self, attribute: str, 
                value: str,
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Modify an attribute in a ldap user entry. Replace all 
        occurences found if multiple attribute with same value.

        :param bool doit: If True really modify attribute in ldap user entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string
        :raise ValueError: if attribute is not set or is multivalued
        """
        if isinstance(value, str):
            ldaplogs=io.StringIO()
            ldap_handler = ldap.initialize(

                uri = self.config['uri'], trace_level=0, trace_file=ldaplogs
            )
            search_filter = f"(&(objectClass=*)(uid={self._standard_uid}))"
            self.__log__.debug(f"Search Filter : {search_filter}")
            r = ldap_handler.search_s(
                base=self.config['user']['ou'],
                scope=ldap.SCOPE_ONELEVEL,
                filterstr=search_filter,
                attrlist=[f"{attribute}"]
            )

            if len(r) == 1:
                self.__log__.debug(f"Result : {r} ({next(iter(r))[1]})")
                values = []
                if attribute in next(iter(r))[1] :
                    values = [str(a.decode()) for a in next(iter(r))[1][attribute]]
                if len(values) == 1:
                    self.__log__.debug(
                        f"Ldap attribute '{attribute}' has one value ({len(r)}), "
                        f"we use 'replace' keyword"
                    )
                elif len(values) < 1:
                    raise ValueError(
                        f"Ldap attribute '{attribute}' has no value ({len(r)}). "
                        f"Use add attribute instead"
                    )
                else:
                    raise ValueError(
                        f"Ldap attribute '{attribute}' is mutltivalued ({len(r)}). "
                        f"Use 'remove attribute' first then 'add attribute' instead"
                    )
            else:
                raise ValueError(
                    f"Entry Not found : {r}"
                )
           
            commands = [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"user modify {self._standard_uid} "
                f"replace:{attribute}:{value}",
                f"{self.config['global']['binary']['update-cache']}"
            ]

            if doit:
                hpc.utils.runs(commands)
                return f"Success to modify attribute '{attribute}' with "\
                       f"value(s) '{value}' in ldap user entry "\
                       f"'{self._standard_uid}'"
            else:
                return commands
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
    def remove_attribute(
                self, attribute: str, 
                value: typing.Union[str,typing.List],
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Add an attribute to a ldap user entry

        :param bool doit: If True really add attribute to ldap user entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string or a list
        """
        values = []
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
        commands = []
        for v in values:
            commands += [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"user modify {self._standard_uid} delete:{attribute}:{v}"
            ]
        commands += [
            f"{self.config['global']['binary']['update-cache']}"
        ]

        if doit:
            hpc.utils.runs(commands)
            return f"Success to delete attribute '{attribute}' with value(s) "\
                   f"'{values}' from ldap uid entry '{self._standard_uid}'"
        else:
            return commands

    def create(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """ Create a ldap user on the system with the dsidm command

        :param bool doit: If True really creates user on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If ldap user primary group gidnumber or name is not set
        """
        if self._standard_gidnumber is not None:
            self._standard_pgroup = hpc.utils.name_from_gidnumber(
                self._standard_gidnumber, self.config
            )
        
        if self._standard_pgroup is None:
            raise RuntimeError(
                "Ldap user primary group gid or name must be set."
            )
        self._define_category()

        commands = [
            f"{self.config['binary']['dsidm']} {self.config['instance']} "
            f"user create --uid '{self._standard_uid}' --cn '{self._standard_cn}' "
            f"--displayName '{self._standard_displayname}' "
            f"--uidNumber {self._standard_uidnumber} "
            f"--gidNumber {self._standard_gidnumber} "
            f"--homeDirectory '{self._standard_homedirectory}'",
            f"{self.config['global']['binary']['update-cache']}"
        ] + self.add_attribute(attribute="loginshell", value=f"{self._standard_loginshell}", doit=False)
        
        if self._standard_mail is not None:
            commands += self.add_attribute(attribute="mail", value=f"{self._standard_mail}", doit=False)
        if self._standard_gecos is not None:
            commands += self.add_attribute(attribute="gecos", value=f"{self._standard_gecos}", doit=False)

        if self._extended_category in self.config['group'] \
           and "groups" in self.config['group'][self._extended_category]:
            for g in self.config['group'][self._extended_category]['groups']:
                commands += self.add_group_attribute(group_name=g, attribute="member", value=f"{self._extended_dn}", doit=False)
        if doit:
            hpc.utils.runs(commands)
            return None
        else:
            return commands

    def delete(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """ Delete a ldap user on the system with the dsidm command

        :param bool doit: If True really deletes user on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        confirmation = f"echo '{self.config['confirmation']}'"
        commands = [
            f"{confirmation} | {self.config['binary']['dsidm']} "
            f"{self.config['instance']} user delete {self._extended_dn}"
        ]
        if self._extended_category in self.config['group'] \
           and "groups" in self.config['group'][self._extended_category]:
            for g in self.config['group'][self._extended_category]['groups']:
                commands += self.delete_group_attribute(group_name=g, attribute="member", value=f"{self._extended_dn}", doit=False)

        if doit:
            hpc.utils.runs(commands)
            return None
        else:
            return commands
    
    def add_group_attribute(
                self, group_name: str, attribute: str, 
                value: typing.Union[str,typing.List],
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Add an attribute to a ldap group entry

        :param bool doit: If True really add attribute to ldap group entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string or a list
        """
        values = []
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
        commands = []
        for v in values:
            commands += [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"posixgroup modify {group_name} add:{attribute}:{v}"
            ]
        commands += [
            f"{self.config['global']['binary']['update-cache']}"
        ]
        if doit:
            hpc.utils.runs(commands)
            return f"Success to add attribute '{attribute}' with value(s) "\
                   f"'{values}' to ldap group entry '{group_name}'"
        else:
            return commands
    
    def modify_group_attribute(
                self, group_name: str, attribute: str, 
                value: str,
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Modify an attribute in a ldap group entry. Replace all 
        occurences found if multiple attribute with same value.

        :param bool doit: If True really modify attribute in ldap group entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string
        :raise ValueError: if attribute is not set or is multivalued
        """
        if isinstance(value, str):
            ldaplogs=io.StringIO()
            ldap_handler = ldap.initialize(

                uri = self.config['uri'], trace_level=0, trace_file=ldaplogs
            )
            search_filter = f"(&(objectClass=*)(cn={group_name}))"
            self.__log__.debug(f"Search Filter : {search_filter}")
            r = ldap_handler.search_s(
                base=self.config['group']['ou'],
                scope=ldap.SCOPE_ONELEVEL,
                filterstr=search_filter,
                attrlist=[f"{attribute}"]
            )

            if len(r) == 1:
                self.__log__.debug(f"Result : {r} ({next(iter(r))[1]})")
                values = [str(a.decode()) for a in next(iter(r))[1][attribute]]
                if len(values) == 1:
                    self.__log__.debug(
                        f"Ldap attribute '{attribute}' has one value ({len(r)}), "
                        f"we use 'replace' keyword"
                    )
                elif len(values) < 1:
                    raise ValueError(
                        f"Ldap attribute '{attribute}' has no value ({len(r)}). "
                        f"Use add_attribute method"
                    )
                else:
                    raise ValueError(
                        f"Ldap attribute '{attribute}' is mutltivalued ({len(r)}). "
                        f"Use 'remove_attribute' first then 'add_attibute' method"
                    )
            else:
                raise ValueError(
                    f"Entry Not found : {r}"
                )
           
            commands = [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"posixgroup modify {group_name} "
                f"replace:{attribute}:{value}",
                f"{self.config['global']['binary']['update-cache']}"
            ]

            if doit:
                hpc.utils.runs(commands)
                return f"Success to modify attribute '{attribute}' with "\
                       f"value(s) '{value}' in ldap group entry "\
                       f"'{group_name}'"
            else:
                return commands
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
    def delete_group_attribute(
                self, group_name: str, attribute: str, 
                value: typing.Union[str,typing.List],
                doit: bool = False
            ) -> typing.Optional[typing.List[str]]:
        """ Add an attribute to a ldap group entry

        :param bool doit: If True really add attribute to ldap group entry on 
                          system else just return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        :raise ValueError: if value is not a string or a list
        """
        values = []
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            raise TypeError(f"Bad type for value (must be str or list).")
        
        commands = []
        for v in values:
            commands += [
                f"{self.config['binary']['dsidm']} {self.config['instance']} "
                f"posixgroup modify {group_name} delete:{attribute}:{v}"
            ]
        commands += [
            f"{self.config['global']['binary']['update-cache']}"
        ]

        if doit:
            hpc.utils.runs(commands)
            return f"Success to delete attribute '{attribute}' with value(s) "\
                   f"'{values}' from ldap group entry '{group_name}'"
        else:
            return commands

    def lock(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """ Lock a ldap user on the system. Locking a user mean change user 
        shell to '/sbin/disabled' which point to '/bin/bash' to permit root 
        su login and expire user password with chage. Killing user's sessions 
        is not done by this method

        :param bool doit: If True really lock user on system else just return 
                          the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array
        """
        commands = [
            f"{self.config['binary']['dsidm']} {self.config['instance']} account lock {self._extended_dn}",
            self.modify_attribute(
                attribute="loginshell", 
                value=f"{self.config['user']['disabled']}", doit=False
            ),
            f"{self.config['global']['binary']['update-cache']}",
            f"{self.config['global']['binary']['clush']} --nostdin -q -S"
            f" -w {','.join(self.config['global']['loginNodes'])}"
            f" '{self.config['global']['binary']['update-cache']}'"
        ]
        if doit:
            hpc.utils.runs(commands)
            return None
        else:
            return commands

    def unlock(self, doit: bool = False) -> typing.Optional[typing.List[str]]:
        """ Unlock a ldap user on the system. Unlocking a user mean change 
        user shell to default shell and unexpire user password with chage. If 
        cryptedpassword is not None, it also change user password.

        :param bool doit: If True really unlock user on system else just 
                          return the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """

        commands = [
            self.modify_attribute(
                attribute="loginshell", 
                value=f"{self.config['user']['shell']}", doit=False
            ),
            f"{self.config['binary']['dsidm']} {self.config['instance']} account unlock {self._extended_dn}",
            f"{self.config['global']['binary']['update-cache']}",
            f"{self.config['global']['binary']['clush']} --nostdin -q -S"
            f" -w {','.join(self.config['global']['loginNodes'])}"
            f" '{self.config['global']['binary']['update-cache']}'"
        ]
        if doit:
            hpc.utils.runs(commands)
            return None
        else:
            return commands

# @ctrace
class LdapUsers(hpc.generics.GenericObjects):
    """ List of LdapUser objects.
    """
    __config__ = hpc.utils.load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="uids", multiple=False)
        self._register_index(index_name="mails", multiple=True)
        self._register_index(index_name="gecoss", multiple=True)
        self._register_index(index_name="pgroups", multiple=True)
        super().__init__(**kwargs)

    def add(self, obj: LdapUser):
        """ Add a LdapUser object to the list

        :param LdapUser obj: A LdapUser object
        """
        super().add(obj)
        self._add_to_uids(obj.uid, obj)
        if obj.mail is not None:
            self._add_to_mails(obj.mail, obj)
        if obj.gecos is not None:
            self._add_to_gecoss(obj.gecos, obj)
        if obj.pgroup is not None:
            self._add_to_pgroups(obj.pgroup, obj)

    def delete(self, obj: LdapUser):
        """ Remove a LdapUser object from the list

        :param LdapUser obj: A LdapUser object
        """
        super().delete(obj)
        self._delete_from_uids(obj.uid, obj)
        if obj.mail is not None:
            self._delete_from_mails(obj.mail, obj)
        if obj.gecos is not None:
            self._delete_from_gecoss(obj.gecos, obj)
        if obj.pgroup is not None:
            self._delete_from_pgroups(obj.pgroup, obj)

    def _populate_helper(self, user_datas: dict, user_group_objects: LdapGroups) -> dict:
        """ Convert raw LDAP in an dict usable by 
        LdapdsUser constructor as parameters
        :param dict project_datas: Raw LDAP project data from LDAP query
        :param dict user_group_object: Ldapds user group object list LdapdsGroups


        :return: Formatted ldap group data usable by LdapdsUser constructor 
                 as parameters
        """
        gid = int(next(iter(user_datas['gidNumber']),'unkown_gidNumber').decode())

        formatted_project_datas = {
            "uid": str(next(iter(user_datas['uid']),'unkown_uid').decode()),
            "cn": str(next(iter(user_datas['cn']),'unkown_cn').decode()),
            "displayname": str(next(iter(user_datas['displayName']),'unkown_displayName').decode()),
            "uidnumber": int(next(iter(user_datas['uidNumber']),'unkown_uidNumber').decode()),
            "gidnumber": gid,
            "homedirectory": pathlib.Path(str(next(iter(user_datas['homeDirectory']),'unkown_homeDirectory').decode())),
            "loginshell": pathlib.Path(str(next(iter(user_datas['loginShell']),'unkown_loginShell').decode())),
            "pgroup": user_group_objects.get_by_gidnumbers(gid).cn
        }
        formatted_project_datas.update(
            {"locked": f"{formatted_project_datas['loginshell']}" == f"{self.config['user']['disabled']}"}
        )
        if 'mail' in user_datas:
            formatted_project_datas.update(
                {"mail": str(next(iter(user_datas['mail']),'unkown_mail').decode())}
            )
        if 'gecos' in user_datas:
            formatted_project_datas.update(
                {"gecos": int(next(iter(user_datas['gecos']),'unkown_gecos').decode())}
            )

        return formatted_project_datas

    def populate(
            self, groups: typing.Optional[typing.List[str]] = None, 
            users: typing.Optional[typing.List[str]] = None
        ):
        """ Populate ldap user list from system with python ldap module. 
        Populate all users by default.

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
        
        # Populate ldap groups
        lgroups = LdapGroups()
        lgroups.populate()

        if (groups is None or (
                   isinstance(groups, list) and
                   all([isinstance(g, str) for g in groups]))) and \
           (users is None or (
                    isinstance(users, list) and
                    all([isinstance(u, str) for u in users]))):
            
            search_users = "(&(uid=*)(objectClass=*))"
            if groups is not None:
                gids = list(set([
                    lgroups.get_by_gidnumbers(name) for name in groups
                ]))
                search_users = f"(|(cn={')(gidNumber='.join(gids)}))"
                
            if users is not None:
                if groups is None:
                    search_users = f"(|(uid={')(uid='.join(users)}))"
                else:
                    search_users = f"(&{search_users}(|(uid={')(uid='.join(users)})))"
            
            entries = hpc.utils.ldap_call(
                uri=self.config['uri'],
                base=self.config['user']['ou'],
                scope=ldap.SCOPE_ONELEVEL, 
                filterstr=search_users,
                attrlist=[
                    "uid", "cn", "displayName", "uidNumber", "gidNumber", 
                    "homeDirectory", "mail", "loginShell", "gecos"
                ]
            )

            self.adds([
                LdapUser(**self._populate_helper(entry, lgroups))
                for entry in entries
            ])

            self.__log__.debug(
                f"Found users '{hpc.utils.pplist(self.get_uids())}' in ldap users "
                f"(asked for '{users}')"
            )
            self.__log__.trace(
                f"Found users '{self.get_uids()}' in ldap users (asked "
                f"for '{users}')"
            )

            if users is not None and not self.len() == len(users):
                raise RuntimeError(
                    f"Users "
                    f"'{[u for u in users if u not in self.get_uids()]}' "
                    f"not found in ldap users."
                )
            self._populate_extended_group_attrs(lgroups)
        else:
            raise ValueError(
                "Group list must be None or a list of group name and "
                "User list must be None or a list user name"
            )

    def _populate_extended_group_attrs(self, lgroups: LdapGroups):
        """ Populate extended group info for all users

        """
        # Add secondary group member
        for lg in lgroups:
            for dn in lg.musers:
                uid = dn.replace('uid=','').replace(f",{self.config['user']['ou']}",'')
                luser_std_oid = self.get_by_uids(uid)
                if luser_std_oid is None:
                    self.__log__.debug(
                        f"Unable to add secondary group '{lg.cn}' for "
                        f"user '{uid}' (User not populated)."
                    )
                else:
                    self.__log__.trace(
                        f"Add secondary group '{lg.cn}' for user "
                        f"'{uid}'."
                    )
                    self.get_by_uids(uid).addmgroup(lg.cn)
