# -*- coding: utf-8 -*-
""" Useful generators
"""
from typing import Optional, List
from config.configUnix import config as uconfig
from config.config import config as gconfig
from hpc.utils import ssafe, loginsafe, pplist 
from pathlib import Path
from secrets import token_hex
from random import sample
from string import ascii_letters
from crypt import crypt
from cilogger.cilogger import ccilogger, ftrace
log = ccilogger(__name__)


@ftrace
def login_generator(
        projet: str, lastname: str, firstname: str, idindividu: int, 
        ulogins: list, login: Optional[str] = None, 
        prefix: Optional[str] = None) -> str:
    """ Generate an unique unix login for a unix user from Gramc user infos 
    if no login is provided else just return login.

    Logins are check against unix login list in this order :

      * Use first 8 characters of lastname in lowercase as login
      * Use project name with first letter from lastname and firstname in 
        lowercase as login
      * Use an unique login starting with "change_me" and ended by idindividu 
        and project name

    :param str projet: User project name in Gramc
    :param str lastname: User last name in Gramc
    :param str firstname: User first name in Gramc
    :param int idindividu: User idindividu in Gramc
    :param list ulogins: Current list of login already used
    :param Optional[str] login: Current unix login in gramc if exists, no 
                                generation
    :param Optional[str] prefix: A prefix to add to a generated login if not 
                                 None

    :return: a unique and non already used unix login

    Example :

    >>> login_generator("p20001", "Doe", "John", 10, [])
    "doe"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe"])
    "p20001dj"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe"], None,)
    "p20001dj"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe", "p20001dj"])
    "change_me_10_p20001"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe"], "doe")
    "doe"

    .. TODO:: Force all login to be unique to avoid a same login 
              belonging to different user in same project
    """
    if login is None:
        ulogin = loginsafe(ssafe(lastname.lower()))[0:8]
        if ulogin in ulogins:
            ulogin = loginsafe(ssafe(
                f"{projet}{lastname.lower()[0:1]}{firstname.lower()[0:1]}"
            ))
            if ulogin in ulogins:
                # log.debug(f"Login '{ulogin}' found in logins '{ulogins}'")
                ulogin = f"change_me_{idindividu}_{projet}"
        if prefix is None:
            # log.debug(
            #     f"Generating login (current: '{login}' with lastname "
            #     f"'{lastname}', firstname '{firstname}' and "
            #     f"idindividu '{idindividu}' against current "
            #     f"login list {pplist(ulogins)} => '{ulogin}'"
            # )
            return ulogin
        else:
            # log.debug(
            #     f"Generating prefixed login (current: '{login}' with "
            #     f"lastname '{lastname}', firstname '{firstname}' and "
            #     f"idindividu '{idindividu}' against current "
            #     f"login list {pplist(ulogins)} => '{prefix}{ulogin}'"
            # )
            return f"{prefix}{ulogin}" 
    else:
        # log.debug(
        #     f"No Generation of login (current: '{login}' with "
        #     f"lastname '{lastname}', firstname '{firstname}' and "
        #     f"idindividu '{idindividu}' against current "
        #     f"login list {pplist(ulogins)} => '{login}'"
        # )
        return login

@ftrace
def anonymous_login_generator(
        projet: str, lastname: str, firstname: str, idindividu: int, 
        ulogins: list, login: Optional[str] = None, 
        prefix: Optional[str] = None) -> str:
    """ Generate an unique unix login for a unix user from Gramc user infos 
    if no login is provided else just return login.

    Logins are check against unix login list in this order :

      * Use first 8 characters of lastname in lowercase as login
      * Use project name with first letter from lastname and firstname in 
        lowercase as login
      * Use an unique login starting with "change_me" and ended by idindividu 
        and project name

    :param str projet: User project name in Gramc
    :param str lastname: User last name in Gramc
    :param str firstname: User first name in Gramc
    :param int idindividu: User idindividu in Gramc
    :param list ulogins: Current list of login already used
    :param Optional[str] login: Current unix login in gramc if exists, no 
                                generation
    :param Optional[str] prefix: A prefix to add to a generated login if not 
                                 None

    :return: a unique and non already used unix login

    Example :

    >>> login_generator("p20001", "Doe", "John", 10, [])
    "doe"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe"])
    "p20001dj"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe"], None,)
    "p20001dj"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe", "p20001dj"])
    "change_me_10_p20001"
    >>> login_generator("p20001", "Doe", "John", 10, ["doe"], "doe")
    "doe"

    .. TODO:: Force all login to be unique to avoid a same login 
              belonging to different user in same project
    """
    lastname_without_vowels=[
        l for l in lastname.lower() 
        if l not in ['a','e','i','o','u','y']
    ]
    firstname_without_vowels=[
        l for l in firstname.lower() 
        if l not in ['a','e','i','o','u','y']
    ]     
    if login is None:
        ulogin = loginsafe(ssafe(
            f"{projet}{lastname_without_vowels}{firstname_without_vowels}"
        ))[0:10]
        if ulogin in ulogins:           
            ulogin = loginsafe(ssafe(
                f"{projet}{firstname_without_vowels}{lastname_without_vowels}"
            ))[0:10]
            if ulogin in ulogins:
                # log.debug(f"Login '{ulogin}' found in logins '{ulogins}'")
                ulogin = f"change_me_{idindividu}_{projet}"
        if prefix is None:
            # log.debug(
            #     f"Generating login (current: '{login}' with lastname "
            #     f"'{lastname}', firstname '{firstname}' and "
            #     f"idindividu '{idindividu}' against current "
            #     f"login list {pplist(ulogins)} => '{ulogin}'"
            # )
            return ulogin
        else:
            # log.debug(
            #     f"Generating prefixed login (current: '{login}' with "
            #     f"lastname '{lastname}', firstname '{firstname}' and "
            #     f"idindividu '{idindividu}' against current "
            #     f"login list {pplist(ulogins)} => '{prefix}{ulogin}'"
            # )
            return f"{prefix}{ulogin}" 
    else:
        # log.debug(
        #     f"No Generation of login (current: '{login}' with "
        #     f"lastname '{lastname}', firstname '{firstname}' and "
        #     f"idindividu '{idindividu}' against current "
        #     f"login list {pplist(ulogins)} => '{login}'"
        # )
        return login


# @ftrace
def real_root_path_generator(root_paths: List[str], gid: int) -> Path:
    """This function choose one of the possible root path. Its look 
    the group id and choose the root path corresponding to the modulo 
    of gid and root paths count

    :param list[str] root_paths: List of possible root paths on the cluster
    :param int gid: Gid of the group used to pickup one of the paths (must be 
                greater than 0)

    :return: The root path corresponding to the modulo of gid and root paths 
             count

    :raise ValueError: if root_paths is not a list of string
    :raise ValueError: if gid is not a int > 0
    """
    if isinstance(root_paths, list) and \
       all([isinstance(p, str) for p in root_paths]):
        if isinstance(gid, int) and gid > 0:
            root_paths_count = len(root_paths)
            log.debug(
                f"Generated real root path ({gid%root_paths_count}): "
                f"'{Path(root_paths[gid%root_paths_count])}'"
            )
            return(Path(root_paths[gid%root_paths_count]))
        else:
            raise ValueError(f"Group gid is not a int > 0 ({gid})")
    else:
        raise ValueError(f"Root path is not a list of string ({root_paths})")


# @ftrace
def numeric_id_generator(numeric_ids: List[int]) -> int:
    """ Return first unused numeric id from numeric id list

    :param List[int] numeric_ids: Current unix numeric id list already used
   
    :return: a unique and non already used unix numeric id
    
    :raise ValueError: if we are unable to find an unused numeric id
    """
    usable_std_uids = set(range(uconfig['user']['uid_usable'],
                                uconfig['user']['uid_max'], 1))
    used_std_uids = set(numeric_ids)
    #log.debug(f"Usable range : [{uconfig['user']['uid_usable']}-{uconfig['user']['uid_max']}]")
    #log.debug(f"Used range : {used_std_uids}")
    unused_std_uids = next(
        iter(sorted(usable_std_uids - used_std_uids, key=int)), None
    )
    #log.debug(f"Generated id : {unused_std_uids}")

    if unused_std_uids is None:
        raise ValueError("Unable to find an unused uid list")
    else:
        return unused_std_uids


# @ftrace
def home_generator(ulogin: str, upgroup: str) -> Optional[Path]:
    """ Generate a user home folder from an login and a unix group name.
    If home folder already exists, it returns None

    :param str ulogin: A unix user login
    :param str upgroup: A unix primary group name
    :return: Generated home path or None if home path already exists
    """
    root_path = Path(gconfig['homeRootPath'])
    if ulogin is None or upgroup is None:
        return None
    home = root_path.joinpath(upgroup, ulogin)
    if home.exists():
        return None
    else:
        return home


# @ftrace
def password_generator(nchar: int) -> str:
    """ Generate a plain password string with nchar characters

    :param int nchar: Number of characters in pplain password
    :return: A plain string password
    """
    return token_hex(nchar)[0:nchar]


# @ftrace
def encrypted_password_generator(plain_standard_password: str) -> str:
    """ Generate an encrypted password from a cleartext_password

    :param str plain_standard_password: a plain paswword in clear text
    :return: an encrypted unix password
    """
    randomsalt = ''.join(sample(ascii_letters, 8))
    encrypted_standard_password = crypt(
        plain_standard_password, f"$6${randomsalt}$"
    )
    return f"{encrypted_standard_password}"
