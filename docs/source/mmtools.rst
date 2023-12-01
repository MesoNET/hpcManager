HPC Meta Manager and other tools
================================

HpcManager
----------
HpcManager is a tools that can manage users and groups from severals modules. It is useful to
merge, join, filter and displays data from modules in csv format.

Filters :
^^^^^^^^^

Filters can be combined with logicals expressions 'and' and 'or'. These expressions are evaluated
according to the `reverse polish notation syntax <https://en.wikipedia.org/wiki/Reverse_Polish_notation>`_.

Filters can be used to compare value of different modules with this syntax `<module>_<attribute><operator>[<module>_<attribute>]`. 
For example, to search in 'ldapds' module users that have gecos attribute value different from attribute "" in gramc Meso :

   .. code-block::

      hpcManager.py list user --filter 'ldapds_uid=^.+$' 'gramc_category=^mesonet$' 'ldapds_gecos!^[gramc_idindividu]$' 'and' 'and'

At the moment, there are 6 filters type available :

  * regex ('=' symbol)
  * not ('!' symbol)
  * inferior ('<' symbol)
  * superior ('>' symbol)
  * search ('@' symbol)
  * count ('#' symbol)

Regex filter
""""""""""""

This filter does a regex match on the attribute. It is case insensitive and work on substring by
default unless providing regex start '^' or end '$' character.

Example :

* Searching for case unsensitive string matching 'Doe' on attribute 'nom' in module 'gramc' :
  
  .. code-block::

    hpcManager.py list user --filter 'gramc_nom=Doe'
   
* Searching for case unsensitive string exact matching 'Doe' on attribute 'nom' in module 'gramc' :
  
  .. code-block::

    hpcManager.py list user --filter 'gramc_nom=^Doe$'

Not filter
""""""""""

This filter does a negation on a regex match on the attribute. It is case insensitive and work on substring by
default unless providing regex start '^' or end '$' character.

Example :

* Searching for case unsensitive string not matching 'Doe' on attribute 'nom' in module 'gramc' :
  
  .. code-block::

    hpcManager.py list user --filter 'gramc_nom!Doe'
   
* Searching for case unsensitive string not exact matching 'Doe' on attribute 'nom' in module 'gramc' :
  
  .. code-block::

    hpcManager.py list user --filter 'gramc_nom!^Doe$'

Inferior or superior filter
"""""""""""""""""""""""""""

This filter does a strict inferior or superior case sensitive comparison on the value of the attribute. It tries first to convert
attribute in int or float. If its fails, it does a lexical comparison according to 
`python lexical comparison algorithlm <https://docs.python.org/3/reference/expressions.html#comparisons>`_

Example :

* Searching for gramc active session attribution strictly superior than 5000 :
  
  .. code-block::

    hpcManager.py list user --filter 'gramc_aatribution>5000'
   
Search filter
"""""""""""""

This filter search in a list, a dictionary or a GenericObjects object.

* If targeted attribute is a list, then the syntax is 'module\_attribute@key<value'. It, then, performs a search  and looks up for exact item 'key' in list.

* If targeted attribute is a dictionary, then the syntax is 'module\_attribute@key<value'. It, then, performs a search and looks up for exact key 'key' in dict having 'value' as value. The comparison for the value is done with a regex macth as in regex filter. Special character '*' can be used instead value and means that looks up for key in dictionary is done whathever its value.

* If targeted attribute is a GenericObjects, then the syntax is 'module\_attribute@key<value'. It, then, performs a search and looks up for exact attribute 'key' in object having 'value' as value. The comparison for the value is done with a regex match as in regex filter. Special character '*' can be used instead value and means that looks up for key in dictionary is done whathever its value.
  
Example :

* Searching for value in attribute 'projets' (a list) in module 'gramc' :
  
  .. code-block::

    hpcManager.py list user --filter 'gramc_projets@m23099<'
   
* Searching in 'history' attribute 'logs' a message containing string 'creation' :
  
  .. code-block::

    hpcHistoryManager.py user list --filter 'logs@message<creation'

* Searching in 'history' attribute 'logs' a message containing exact string 'creation' :
  
  .. code-block::

    hpcHistoryManager.py user list --filter 'logs@message<^creation$'

* Searching in 'history' attribute 'logs' whathever key containing 'creation' :
  
  .. code-block::

    hpcHistoryManager.py user list --filter 'logs@*<^creation$'

Count filter
""""""""""""

This filter count occurences of an item in a list, of a key in dictionary or of an object in a GenericObjects object list.

Example :

* Searching in history logs having stricly more than 10 entries :
  
  .. code-block::

    hpcHistoryManager.py user list --filter 'logs#>10'

Examples :
^^^^^^^^^^
* List mesonet user attribute unix login, slurm user, ldap uid and gramc utilisateur for gramc meso user named John Doe :

   .. code-block::
      
      hpcManager.py list user --attribute unix_login slurm_user ldapds_uid --filter gramc_nom='^Doe$' gramc_prenom='^John$' 'and'

   Output:

      .. code-block::

         unix_login,slurm_user,ldapds_uid,gramc_utilisateur
         jdoe,jdoe,jdoe,john.doe@example.net

.. argparse::
   :ref: hpcManager.init_parser
   :prog: hpcManager.py
   :nodefault:

HpcMesoManager
------------------

This tools can be use to retreive pending attributions and networks to be allowed on cluster from GRAMC 
Meso API.

.. argparse::
   :ref: hpcMesoManager.init_parser
   :prog: hpcMesoManager.py
   :nodefault:


HpcPasswordManager
------------------

This tools can be use to lock and unlock users accross all modules on the cluster. For example,
if unix and slurm modules are properly configured, it locks unix account and prevent user from 
lauching jobs. Used with --killall option it can also ends all activity of the user (process and 
jobs in this case) on logins nodes.

.. argparse::
   :ref: hpcPasswordManager.init_parser
   :prog: hpcPasswordManager.py
   :nodefault: