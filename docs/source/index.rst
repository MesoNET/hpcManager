
=======================================
Welcome to hpcManager's documentation !
=======================================

Installation and configuration
==============================

Installation requirements
-------------------------

Python modules installations :

.. code-block:: 

   pip3 install git+https://github.com/christophe-marteau/python-cilogger#egg=cilogger --user
   pip3 install python-ldap  --user

Git repository clone :

.. code-block::

   git clone https://github.com/MesoNET/hpcManager.git python-hpcManager
   cd python-hpcManager

All folders with full path defined in confirguration files must also be created.

Meta and standalone modules configuration
-----------------------------------------

For the moment, there is 6 standalones modules "unix", "ldapds", "ssh", "history", 
"slurm" and "gramc". 

Each standalone module has its own configuration file located in "config" folder 
and named "config<Module>.py". Each configuration option is documented inside thoses 
files.

Each module needs 2 config files :

  * config<Module>.py
  * config<Module>Filters.py

Samples for all of thoses files can be found in the config directory.

An extra configuration file "binSettings.sh" can be used to configure bash helper scripts in "bin" folder.

Tools and Usages
================

.. toctree::
   :maxdepth: 2

   mmtools

.. toctree::
   :maxdepth: 2

   smmtools

.. toctree::
   :maxdepth: 2

   hpc

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
