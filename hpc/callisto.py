# -*- coding: utf-8 -*-
""" Module for managing hpc users and groups
"""
from hpc.meta import MetaGroup, MetaGroups, MetaUser, MetaUsers
from hpc.utils import (
    register_attributes, attributes_to_docstring,
    load_config
)
class CallistoGroup(MetaGroup):
    """
    Callisto group
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes(__config__['modules']['group'], meta=True)
    __doc__ += attributes_to_docstring(attributes)

class CallistoGroups(MetaGroups):
    """
    List of CallistoGroup objects.
    """
    __config__ = load_config(locals()['__module__'])


class CallistoUser(MetaUser):
    """
    Meta user
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes(__config__['modules']['user'], meta=True)
    __doc__ += attributes_to_docstring(attributes)

class CallistoUsers(MetaUsers):
    """
    List of CallistoUser objects.
    """
    __config__ = load_config(locals()['__module__'])