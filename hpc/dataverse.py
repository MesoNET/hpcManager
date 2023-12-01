# -*- coding: utf-8 -*-

# pylint: disable=no-member
# pylint: disable=E1101

""" Module for managing hpc history for users and groups

Work in progress. Do not use in production
"""
from hpc.generics import GenericObjects, GenericObject
from pathlib import Path
from typing import List, Optional
from config.config import config
from hpc.utils import (
    runs, register_attributes,register_callables, attributes_to_docstring, 
    load_config, get_effective_user_name, api_call
)
import re
from argparse import FileType
from sys import stdout
from datetime import datetime
from cilogger.cilogger import ccilogger  # , ctrace

log = ccilogger(__name__)


# @ctrace
class DataverseRepo(GenericObject):
    """
    Dataverse repository.
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes([{
        "name": "name", "category": "standard", "type": str,
        "default": None, "help": "Dataverse collection name",
    }, {
        "name": "alias", "category": "standard", "type": str,
        "default": None,
        "help": "Gramc project id",
    }, {
        "name": "labo", "category": "standard", "type": str,
        "default": None,
        "help": "Gramc project laboratory",
    }, {
        "name": "description", "category": "standard", "type": str,
        "default": None,
        "help": "Gramc project summary",
    }, {
        "name": "type", "category": "extended", "type": str,
        "default": None,
        "help": "Dataverse Repository Type",
    }, {
        "name": "contact", "category": "standard", "type": str,
        "default": None,
        "help": "Dataverse Repository Contact",
    }
    ])
    callables = register_callables([], attributes)
    __doc__ += attributes_to_docstring(attributes)

    def _define_type(self): 
        self._extended_type="LABORATORY"
    

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._define_type()

    
    @property
    def _api_endpoint(self) -> str:
        """ API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['collection_endpoint']}"
        )

    def create(self, doit: bool = False) -> Optional[List[str]]:
        """Create a group history

        :param bool doit: If True really creates history group file on system else just return the command as a string
        :return: None if doit is True and no raise else just return commands that should be done as string array

        :raise RuntimeError: If command fails
        :raise RuntimeError: If history group name is not set
        """
        
        # S'inspirer de la méthode update de gramc pour faire des api call
        # Pour bénéficier du do et undo
        #

        request_data = {
            "name": self._standard_name,
            "alias": self._standard_alias,
            "affiliation": self._standard_labo,
            "dataverseType": self._extended_type,
            "dataverseContacts" : [{"contactEmail": self._standard_contact}],
            "description": self._standard_description
        }
        request_headers = {
            "content-type": "application/json",
            "X-Dataverse-key": self.config['apiToken']
        }

        update_result = api_call(
           url=f"{self._api_endpoint}", data=request_data, 
           auth=(None,None) , headers=request_headers, rscode=201, doit=doit
        )

        self.__log__.debug(f"Update result : {update_result}")
        if doit:
            return update_result
        else:
            return {"OK": update_result}

    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """Delete a group history

        :param bool doit: If True really deletes history group file on system else just return the command as a string
        :return: None if doit is True and no raise else just return commands that should be done as string array

        :raise RuntimeError: If command fails
        :raise RuntimeError: If history group name is not set
        """
        commands = ["echo 'delete'"]
        # S'inspirer de la méthode update de gramc pour faire des api call
        # Pour bénéficier du do et undo
        #
        # update_result = api_call(
        #   url=f"{self._api_endpoint}/{method}", data=request_data, 
        #   auth=self._api_auth, headers=request_headers, doit=doit
        # )
        if doit:
            runs(commands)
            return None
        else:
            return commands


# @ctrace
class DataverseRepos(GenericObjects):
    """
    List of HistoryGroup objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="names", multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: DataverseRepo):
        super().add(obj)
        self._add_to_names(obj.name, obj)

    def delete(self, obj: DataverseRepo):
        super().delete(obj)
        self._delete_from_names(obj.name, obj)

    def populate(self, groups: Optional[List[str]] = None):
        """Populate group history for all groups from history files. Populate all groups by default.

        :param Optional[List[str]] groups: List of group name to retrieve.
                                           None means all groups.

        :raise RuntimeError: if a group in group list is not found.
        """
        # On récupère les objets depuis une requete api dataverse probalement
        # puis on instancie les objets 
        for r in ["p0043", "p0111"]:
            self.add(DataverseRepo(name=r,alias="toto",labo="titi"))


# @ctrace
class DataverseUser(GenericObject):
    """
    Unix group history.
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes(
        [
            {
                "name": "contact",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "Dataverse user email",
            },{
                "name": "alias", 
                "category": "standard", 
                "type": str,
                "default": None,
                "help": "Gramc project id",
            },{
                "name": "nom",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "Dataverse user lastname",
            }, {
                "name": "prenom",
                "category": "standard",
                "type": str,
                "default": None,
                "help": "Dataverse user firstname",
            },
        ]
    )
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
    def _api_user_endpoint(self,api_name) -> str:
        """ API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config[api_name]}"
        )


    def create(self, doit: bool = False) -> Optional[List[str]]:
        """Create a group history

        :param bool doit: If True really creates history group file on system else just return the command as a string
        :return: None if doit is True and no raise else just return commands that should be done as string array

        :raise RuntimeError: If command fails
        :raise RuntimeError: If history group name is not set
        """
        configfile = open("puid_count.txt",'r')
        value = configfile.readlines()[0].replace("-","")
        configfile.close()
        puid = str(int(value) + 1)
        new_puid = puid[0:4]+"-"+puid[4:8]+"-"+puid[8:12]+"-"+puid[12:16]
        configfile = open("puid_count.txt",'w')
        configfile.write(new_puid)
        configfile.close()

        request_data = {
            "authenticationProviderId": self.config['idp'],
            "persistentUserId": new_puid,
            "identifier": self._standard_contact.replace("@",""),
            "firstName": self._standard_nom,
            "lastName" : self._standard_prenom,
            "email": self._standard_contact
        }
        request_headers = {
            "content-type": "application/json",
            "X-Dataverse-key": self.config['apiToken']
        }
        
        update_result = api_call(
            url=f"{self._api_user_endpoint('user_endpoint')}", data=request_data, 
            auth=(None,None) , headers=request_headers, rscode=[200,500], doit=doit
        )
        self.__log__.debug(f"Update result : {update_result}")

        #Seconde requete CURL: positionne les droits de l'utilisateur
        #Sur le depot concerne
        request_data = {
            "assignee": "@"+self._standard_contact.replace("@",""),
            "role": self.config['defaultRole']
        }
        request_headers = {
            "content-type": "application/json",
            "X-Dataverse-key": self.config['apiToken']
        }

        update_result = api_call(
           url=f"{self._api_user_endpoint('repos_endpoint')}"+self._standard_alias+f"{self.config['accessRights_endpoint']}", data=request_data, 
           auth=(None,None) , headers=request_headers, doit=doit
        )

        self.__log__.debug(f"Update result : {update_result}")
        if doit:
            return update_result
        else:
            return {"OK": update_result}

    def delete(self, doit: bool = False) -> Optional[List[str]]:
        """Delete a group history

        :param bool doit: If True really deletes history group file on system else just return the command as a string
        :return: None if doit is True and no raise else just return commands that should be done as string array

        :raise RuntimeError: If command fails
        :raise RuntimeError: If history group name is not set
        """
        commands = ["echo 'delete'"]
        # S'inspirer de la méthode update de gramc pour faire des api call
        # Pour bénéficier du do et undo
        #
        # update_result = api_call(
        #   url=f"{self._api_endpoint}/{method}", data=request_data, 
        #   auth=self._api_auth, headers=request_headers, doit=doit
        # )
        if doit:
            runs(commands)
            return None
        else:
            return commands


# @ctrace
class DataverseUsers(GenericObjects):
    """
    List of HistoryGroup objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="contacts", multiple=False)
        super().__init__(**kwargs)

    def add(self, obj: DataverseUser):
        super().add(obj)
        self._add_to_contacts(obj.contact, obj)

    def delete(self, obj: DataverseUser):
        super().delete(obj)
        self._delete_from_contacts(obj.contact, obj)

    def populate(self, 
            users: Optional[List[str]] = None
        ):
        """Populate user history for all users from history files. Populate all users by default.
        
        :param Optional[List[str]] users: List of user login name to retrieve.
                                          None means all users.

        :raise RuntimeError: if a user in user list is not found.
        """
       
        # On récupère les objets depuis une requete api dataverse probalement
        # puis on instancie les objets 
        for m,rs in [("user1@example.com",["p0044", "p0111"]),("user2@example.com",["p0044", "p0111"])]:
            self.add(DataverseUser(contact=m, alias='placeholder',nom='placeholder',prenom='placeholder'))