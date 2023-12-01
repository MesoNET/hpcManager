# -*- coding: utf-8 -*-
""" Module for managing hpc users and groups
"""
from hpc.meta import MetaGroup, MetaGroups, MetaUser, MetaUsers
from hpc.utils import (
    register_attributes, attributes_to_docstring,
    load_config
)
class HpcGroup(MetaGroup):
    """
    Hpc group
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes(__config__['modules']['group'], meta=True)
    __doc__ += attributes_to_docstring(attributes)

class HpcGroups(MetaGroups):
    """
    List of HpcGroup objects.
    """
    __config__ = load_config(locals()['__module__'])

class HpcUser(MetaUser):
    """
    Hpc user
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes(__config__['modules']['user'], meta=True)
    __doc__ += attributes_to_docstring(attributes)

class HpcUsers(MetaUsers):
    """
    List of HpcUser objects.
    """
    __config__ = load_config(locals()['__module__'])