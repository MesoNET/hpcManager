Standalone Module Managers
==========================

Each standalone module’s has its own manager to manage individualy all its groups and users.

hpcGramcManager
---------------

This manager manage gramc and gramc meso "utilisateur" and "projet" on the cluster.

.. argparse::
   :ref: hpcGramcManager.init_parser
   :prog: hpcGramcManager.py
   :nodefault:	

hpcSshManager
-------------

This manager manage ssh "user" and "group" on the cluster

.. argparse::
   :ref: hpcSshManager.init_parser
   :prog: hpcSshManager.py
   :nodefault:	

hpcLdapdsManager
----------------

This manager manage Red Hat Directory Server (dsidm) "user" and "group" on the cluster

.. argparse::
   :ref: hpcLdapdsManager.init_parser
   :prog: hpcLdapdsManager.py
   :nodefault:

hpcUnixManager
--------------

This manager manage unix "user" and "group" on the cluster

.. argparse::
   :ref: hpcUnixManager.init_parser
   :prog: hpcUnixManager.py
   :nodefault:

hpcSlurmManager
---------------

This manager manage slurm "user" and "account" on the cluster

.. argparse::
   :ref: hpcSlurmManager.init_parser
   :prog: hpcSlurmManager.py
   :nodefault:

hpcHistoryManager
-----------------

This manager manage history "user" and "group" on the cluster

.. argparse::
   :ref: hpcHistoryManager.init_parser
   :prog: hpcHistoryManager.py
   :nodefault:
