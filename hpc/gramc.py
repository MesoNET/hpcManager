# -*- coding: utf-8 -*-

""" Module for managing gramc projects and users

This module can be used to retreive attributes from GRAMC API. It can handle 
GRAMC and GRAMC for mesonet

Configuration of this module can be found in config/configGramc.py

.. TODO:: 
  * Split in 2 modules : one for GRAMC and one for GRAMC meso
  * Rewrite module import and use
  * rewrite method to only return command type, command, priority and 
    expected return code and let the manager do run 
"""

from hpc.generics import GenericObjects, GenericObject
from typing import Optional, List
from config.configGramc import config
from hpc.utils import (
    api_call, ssafelower, register_attributes, 
    attributes_to_docstring, load_config, ssafe,
    register_callables, build_callable, to_parser
)
from hpc.generators import anonymous_login_generator
from re import compile
# To have class traces, uncomment the line below and all "@ctrace" line
# before Class definition (Slowdown execution)
# from cilogger.cilogger import ctrace

# @ctrace
class GramcProjet(GenericObject):
    """
    Gramc project class

    Many attributes have active and last version ("active" and "derniere" in
    GRAMC API). Active version means that the value is the value in the 
    current version in production. Last version means that it is the value 
    of the last attribute value. Active version can be empty. if active value 
    is not set, that means that this project is no longer in production and 
    should be locked or remove. Active attributes are prefixed by "a" and 
    last by "l" letter.
    """
    __config__ = load_config(locals()['__module__'])

    # # We do not use global project state
    # }, {
    #     "name": "pstate", "category": "standard", "type": str, 
    #     "default": None, "help": "Gramc project state string"
    # }, {
    # # We do not use active project id 
    # }, {
    #     "name": "aidprojet", "category": "standard", "type": str, 
    #     "default": None, "help": "Gramc active project ID"
    # }, {
    # # We do not use last project id 
    # }, {
    #     "name": "lidprojet", "category": "standard", "type": str, 
    #     "default": None, "help": "Gramc last project ID"
    # }, {
    attributes = register_attributes([{
        "name": "projet", "category": "standard", "type": str, 
        "default": None, "help": "Gramc project name"
    }, {
        "name": "idprojet", "category": "standard", "type": str, 
        "default": None, "help": "Gramc project ID"
    }, { 
        "name": "mstate", "category": "standard", "type": str, 
        "default": None, "help": "Gramc project meta state string"
    }, { 
        "name": "mtype", "category": "standard", "type": str, 
        "default": None, "help": "Gramc project meta type string"
    }, {
        ## Active version
        "name": "apstate", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project state string"
    }, {
        "name": "aattribution", "category": "standard", "type": int, 
        "default": None, "help": "Gramc active project cpu hour attribution"
    }, {
        "name": "avstate", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project version state string"
    }, {
        "name": "asession", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active session ID (Gramc only)"
    }, {
        "name": "aversion", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project version ID"
    }, {
        "name": "amail", "category": "standard", "type": str, 
        "default": None, 
        "help": "Gramc active project Principal Investigator (PI) email"
    }, {
        "name": "aquota", "category": "standard", "type": int, 
        "default": None, 
        "help": "Gramc active project cpu hour quota (Gramc only)"
    }, {
        "name": "astore", "category": "standard", "type": str, 
        "default": None, 
        "help": "Gramc active project store space asked  (Gramc only)"
    }, {
        "name": "aasked", "category": "standard", "type": int, 
        "default": None, 
        "help": "Gramc active project cpu hour asked (Meso only)"
    }, {
        "name": "aconsumption", "category": "standard", "type": int, 
        "default": None, 
        "help": "Gramc active project cpu hour consumption (Meso only)"
    }, {        
        "name": "alabo", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project laboratory"
    }, {        
        "name": "aidlabo", "category": "standard", "type": int, 
        "default": None, "help": "Gramc active project laboratory ID "
                                 "(Meso only)"
    }, { 
       "name": "ametadonnees", "category": "standard", "type": str, 
       "default": None, "help": "Gramc active project metadata (Gramc only)"
    }, { 
       "name": "aresume", "category": "standard", "type": str, 
       "default": None, "help": "Gramc active project summary"
    }, {
       "name": "athematic", "category": "standard", "type": str, 
       "default": None, "help": "Gramc active project or active laboraory "
                                "thematic"
    }, {
       "name": "aidthematic", "category": "standard", "type": int, 
       "default": None, 
       "help": "Gramc active project or active laboraory thematic ID "
               "(Meso only)"
    }, { 
        "name": "atitre", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project title"
    }, { 
        "name": "astart", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project start date (Meso only)"
    }, { 
        "name": "aend", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project end date (Meso only)"
    }, { 
        "name": "alimit", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project limit date (Meso only)"
    }, {
        "name": "aclusters", "category": "extended", "type": list, 
        "default": None, "help": f"Gramc active project list of cluster"
    }, { 
        ## Last version
        "name": "lpstate", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project state string"
    }, {
        "name": "lattribution", "category": "standard", "type": int, 
        "default": None, "help": "Gramc last project cpu hour attribution"
    }, {
        "name": "lvstate", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project version state string"
    }, {
        "name": "lsession", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last session ID (Gramc only)"
    }, {
        "name": "lversion", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project version ID"
    }, {
        "name": "lmail", "category": "standard", "type": str, 
        "default": None, 
        "help": "Gramc last project Principal Investigator (PI) email"
    }, {
        "name": "lquota", "category": "standard", "type": int, 
        "default": None, 
        "help": "Gramc last project cpu hour quota (Gramc only)"
    }, {
        "name": "lstore", "category": "standard", "type": str, 
        "default": None, 
        "help": "Gramc last project store space asked (Gramc only)"
    }, {
        "name": "lasked", "category": "standard", "type": int, 
        "default": None, 
        "help": "Gramc last project cpu hour asked (Meso only)"
    }, {
        "name": "lconsumption", "category": "standard", "type": int, 
        "default": None, 
        "help": "Gramc last project cpu hour consumption (Meso only)"
    }, {        
        "name": "llabo", "category": "standard", "type": str, 
        "default": None, "help": "Gramc project laboratory"
    }, {        
        "name": "lidlabo", "category": "standard", "type": int, 
        "default": None, "help": "Gramc last project laboratory ID (Meso only)"
    }, { 
       "name": "lmetadonnees", "category": "standard", "type": str, 
       "default": None, "help": "Gramc last project metadata (Gramc only)"
    }, { 
       "name": "lresume", "category": "standard", "type": str, 
       "default": None, "help": "Gramc last project summary"
    }, {
       "name": "lthematic", "category": "standard", "type": str, 
       "default": None, "help": "Gramc last project or laboratory thematic"
    }, {
       "name": "lidthematic", "category": "standard", "type": int, 
       "default": None, 
       "help": "Gramc last project or last laboratory thematic ID (Meso only)"
    }, { 
        "name": "ltitre", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project title"
    }, { 
        "name": "lstart", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project start date (Meso only)"
    }, { 
        "name": "lend", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project end date (Meso only)"
    }, { 
        "name": "llimit", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project limit date (Meso only)"
    }, {
        "name": "lclusters", "category": "extended", "type": list, 
        "default": None, "help": f"Gramc last project list of cluster"
    }, {
        ## extended attributes
        "name": "category", "category": "extended", "type": str, 
        "default": None,
        "help": f"Project category ({', '.join(config['global']['category'])})"
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this project a generated project"},
    ])
    callables = register_callables([
        build_callable(
            action="list",      
            examples=[(
                "List project, category and laboratory in active session for "
                "project m99099", 
                "--attribute projet category alabo --filter 'group=^m99099$'"
            )]
        ),
        build_callable(
            action="set", 
            command="attribution-done",
            check="presence",
            doit=True,
            label="Set attribution done for a project (Gramc Meso only)",
            required_attributes=["projet"]
        ),
        build_callable(
            action="set", 
            command="consumption",
            check="presence",
            doit=True,
            label="Set project consumption until now (Gramc Meso only)",
            required_attributes=["projet"],
            additional_arguments=[
                to_parser("--consommation", 
                    dest=f"set_consumption_additional_arguments_consumption", 
                    metavar=f"<consommation>",
                    type=int, required=True,
                    help=f"Consommation en heure cpu"
                )
            ]
        )
    ], attributes)
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._meso = self.config['resource']
        self._define_category()

    @property
    def _api_endpoint(self) -> str:
        """ API endpoint full url helper

        :return: main API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['projet_endpoint']}"
        )

    @property
    def _api_todo_endpoint(self) -> str:
        """ API todo endpoint full url helper

        :return: "todo" API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['todo_endpoint']}"
        )
    
    @property
    def _api_conso_endpoint(self) -> str:
        """ API conso endpoint full url helper

        :return: "conso" API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['conso_endpoint']}"
        )

    @property
    def _api_auth(self) -> tuple:
        """ API auth tuple (user, password) helper

        :return: A tuple containing API user and password (user, password)
        """
        return (self.config['apiUser'], self.config['apiPassword'])

    def _define_category(self):
        """ Define a category from a list of categories defined in config

        :raise RuntimeError: If a category can not be define

        .. TODO:: 
          * Use gramc project type instead when available in gramc API
        """
        defined_category = None
        default_category = None
        for category, data in self.config['global']['category'].items():
            if data['regex'] is None:
                default_category = category
            else:
                category_regex = compile(r"{}".format(data['regex']))
                if category_regex.match(str(self._standard_projet)):
                    defined_category = category

        if defined_category is None:
            defined_category = default_category

        if defined_category is None:
            raise RuntimeError(
                f"Category can not be define for group "
                f"'{self._standard_projet}' from configured categories "
                f"'{[c for c in self.config['global']['category']]}' "
            )
        else:
            self._extended_category = defined_category

    def set_attribution_done(self, doit: bool = False) -> Optional[List[str]]:
        """set attribution done for a gramc meso project

        :param bool doit: If True really add new log entry to history group 
                          file on system else just return which log line would 
                          be added and in which file (False by default)
        
        :return: None if doit is True and no raise else just return what should 
                 be done as string array (one action per element)

        :raise RuntimeError: If command fails
        """
        response = self.update(method="attributiondone", doit=doit)      
        if isinstance(response, dict):
            (rcode, rmesg) = next(
                iter(response.items()), ('KO', 'Unknown error')
            )
        else:
            rcode = next(iter(response), ('KO'))
            rmesg = "Unexpected error"

        if rcode == "OK":
            if doit:
                return (
                    f"Success to set attribution done for "
                    f"project '{self.idprojet}' ({rcode})"
                )
            else:
                return [rmesg]
        else:
            if doit:
                raise RuntimeError(
                    f"Failed to set attribution done on GRAMC MESO "
                    f"API for project '{self.idprojet}' "
                    f"({next(iter(rmesg), ('Unknown error'))})"
                )
            else: 
                return [rmesg]

    def set_consumption( 
                self, consumption: int, doit: bool = False
            ) -> Optional[List[str]]:
        """set attribution done for a gramc meso project

        :param int consumption: Project consumption from project start to now
        :param bool doit: If True really add new log entry to history group 
                          file on system else just return which log line would 
                          be added and in which file (False by default)
        
        :return: None if doit is True and no raise else just return what should 
                 be done as string array (one action per element)

        :raise RuntimeError: If command fails
        """
        self.aconsumption = consumption
        response = self.update(method="setconso", doit=doit)      
        if isinstance(response, dict):
            (rcode, rmesg) = next(
                iter(response.items()), ('KO', 'Unknown error')
            )
        else:
            rcode = response
            rmesg = "Unexpected error"

        if rcode == "OK":
            if doit:
                return (
                    f"Success to set consumption to '{self.aconsumption}' "
                    f"for project '{self.idprojet}' ({rcode})"
                )
            else:
                return [rmesg]
        else:
            if doit:
                raise RuntimeError(
                    f"Failed to set consumption to '{self.aconsumption}' "
                    f"on GRAMC MESO API for project '{self.idprojet}' "
                    f"({rmesg})"
                )
            else: 
                return [rmesg]

    def update(self, method: str, doit=False) -> dict:
        """ Call a GRAMC API method to update gramc attributes

        :param str method: A GRAMC API method name
        :param bool doit: Really make update (default to False)

        :return: A dict with API response as attribute and API message as 
                 value ({"response": "Message"})

        :raise NotImplementedError: If gramc API method is not found
        :raise RuntimeError: If it method fails 
        :raise AttributeError: If gramc required attributes are not set in 
                               gramc object
        """
        
        request_headers = {"content-type": "application/json"}
        request_data = {}
        if method == "setconso" and self.config['type'] == "MESO": 
            if isinstance(self._standard_idprojet, str) and \
               isinstance(self._standard_aconsumption, int):
                # New fashion with post data
                request_data = {
                    "projet": f"{self._standard_idprojet}",
                    "ressource": f"{self._meso}",
                    "conso": f"{self._standard_aconsumption}"
                }
                endpoint = f"{self._api_conso_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (projet, ressource and "
                    f"aconsumption) are not set for API "
                    f"method '{method}' ({self})"
                )
        
        elif method == "attributiondone" and self.config['type'] == "MESO":
            if isinstance(self._standard_idprojet, str):
                # New fashion with post data
                request_data = {
                    "projet": f"{self._standard_idprojet}",
                    "ressource": f"{self._meso}",
                }
                endpoint = f"{self._api_todo_endpoint}/done"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (idprojet and ressource "
                    f"are not set for API method '{method}' ({self})"
                )
        elif method == "setquota" and self.config['type'] == "GRAMC":
            if isinstance(self._standard_projet, str) and \
                isinstance(self._standard_asession, str) and \
                isinstance(self._standard_aquota, int):
                # New fashion with post data
                request_data = {
                    "projet": f"{self._standard_projet.title()}",
                    "session": f"{self._standard_asession}",
                    "quota": f"{self._standard_aquota}"
                }
                endpoint=f"{self._api_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (projet, asession and "
                    f"aquota) are not set for API "
                    f"method '{method}' ({self})"
                )
        else:
            raise NotImplementedError(
                f"Gramc update method '{method}' not found"
            )
      
        if self.config['apiUrl'] == self.config['apiDevUrl']: 
            self.__log__.warning("We are on GRAMC dev API")
        
        update_result = api_call(
            url=endpoint, data=request_data, 
            auth=self._api_auth, headers=request_headers, doit=doit
        )

        self.__log__.debug(f"Update result : {update_result}")
        if doit:
            return update_result
        else:
            return {"OK": update_result}


# @ctrace
class GramcProjets(GenericObjects):
    """
    List of GramcProjet objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._meso = self.config['resource']
        self._register_index(index_name="projets", multiple=False)
        super().__init__(**kwargs)
    
    @property
    def _api_endpoint(self) -> str:
        """ API endpoint full url helper

        :return: main API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['projet_endpoint']}"
        )

    @property
    def _api_todo_endpoint(self) -> str:
        """ API todo endpoint full url

        :return: "todo" API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['todo_endpoint']}"
        )

    @property
    def _api_ipaddress_endpoint(self) -> str:
        """ API ip addresses endpoint full url

        :return: "ip-address" API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['ipaddress_endpoint']}"
        )

    @property
    def _api_auth(self) -> tuple:
        """ API auth tuple (user, password)

        :return: A tuple containing API user and password (user, password)
        """
        return (self.config['apiUser'], self.config['apiPassword'])

    def add(self, obj: GramcProjet):
        """ Add a GramcProjet object to the list

        :param GramcProject obj: A GramcProjet object
        """
        super().add(obj)
        self._add_to_projets(obj.projet, obj)

    def delete(self, obj: GramcProjet):
        """ Remove a GramcProjet object from the list

        :param GramcProject obj: A GramcProjet object
        """
        super().delete(obj)
        self._delete_from_projets(obj.projet, obj)

    def i2state(self, value: int) -> str:
        """ Convert an int state value to a string state value

        :param int value: int state value

        :return: string state value or "UNKNOWN" if int state is not known in 
                 config file

        :raise ValueError: If value is not an int
        """
        if isinstance(value, int):
            if value in self.config['states']:
                return self.config['states'][value]
            else:
                return f"UNKNOWN_{value}"
        else:
            raise ValueError(f"Bad project state '{value}' (Must be an int)")
    
    def i2type(self, value: int) -> str:
        """ Convert an int project type value to a string type value

        :param int value: int project type value

        :return: string project type value or "UNKNOWN" if int type is not 
                 known in config file

        :raise ValueError: If value is not an int
        """
        if isinstance(value, int):
            if value in self.config['types']:
                return self.config['types'][value]
            else:
                return f"UNKNOWN_{value}"
        else:
            raise ValueError(f"Bad project type '{value}' (Must be an int)")
    
    def get_pending_actions(self) -> List[dict]:
        """ Request gramc meso API and check projects which needs theirs 
        attributions updated (Gramc meso only).

        .. code-block:: python

            {
                "action" : "attribution",
                "attribution" : 20000,
                "idProjet" : "M12345",
                "idRallonge" : "01M23001R1",
                "ressource" : "TURPAN"
            }

        Actions attributes are : 

            * **action**: Action type
            * **attribution**: Value of the allocation to be positioned
            * **idProjet**: Gramc project ID (with uppercase first character)
            * **idRallonge**: Gramc allocation version ID
            * **ressource**: Gramc resource name
          
        :return: Actions as a dict containing actions attributes
        """
        request_headers = {"content-type": "application/json"}
        request_data = {}
        method = "get"
        if self.config['type'] == "MESO": 
            endpoint = f"{self._api_todo_endpoint}/{method}"
        else:
            raise NotImplementedError(
                f"Gramc update method '{method}' not found"
            )
      
        if self.config['apiUrl'] == self.config['apiDevUrl']:
            self.__log__.warning("We are on GRAMC dev API")
        
        get_result = api_call(
            url=endpoint, data=request_data, 
            auth=self._api_auth, headers=request_headers, 
            rtype="GET", doit=True
        )

        self.__log__.debug(f"Update result : {get_result}")
        
        return get_result

    def get_ip_addresses(
                self, details: bool=True, limited: bool=True
            ) -> List[str]:
        """ Request gramc meso API and retrieve list allowed IP or network 
        in CIDR notation (GRamc meso ony)

        :param bool details: Get also laboratory name
        :param bool limited: Only get ip addresses or network for configured 
                             resource

        :return: A list allowed IP or network as a string in CIDR notation

        """
        request_headers = {"content-type": "application/json"}
        request_data = {"labo": details, "verif": limited}
        method = "get"
        if self.config['type'] == "MESO": 
            endpoint = f"{self._api_ipaddress_endpoint}/{method}"
        else:
            raise NotImplementedError(
                f"Gramc update method '{method}' not found"
            )
      
        if self.config['apiUrl'] == self.config['apiDevUrl']:
            self.__log__.warning("We are on GRAMC dev API")
        
        get_result = api_call(
            url=endpoint, data=request_data,
            auth=self._api_auth, headers=request_headers, 
            doit=True
        )

        self.__log__.debug(f"Update result : {get_result}")

        return get_result

    def _populate_helper(self, project_datas: dict) -> dict:
        """ Convert raw GRAMC or MESO project data in an dict usable by 
        GramcGroup constructor as parameters
        :param dict project_datas: Raw gramc project data from API

        :return: Formatted gramc project data usable by GramcGroup constructor 
                 as parameters

        :raise ValueError: If value is gramc config "type" value is not "GRAMC"
                           or MESO
        """
              
        formatted_project_datas = {
            "projet": str(project_datas['idProjet']).lower(), 
            "idprojet": str(project_datas['idProjet']), 
            "mstate": str(project_datas['metaEtat']),
            "mtype": self.i2type(int(project_datas['typeProjet'])),
            ## Derniere version
            "lpstate": None, "lattribution": None, "lvstate": None, 
            "lsession": None, "lversion": None, "lmail": None, "lquota": None,
            "lstore": None, "llabo": None, "lmetadonnees": None, 
            "lresume": None, "lthematic": None, "ltitre": None, 
            "lconsumption": None, "lasked": None, "lidlabo": None,
            "lidthematic": None, "lstart": None, "lend": None, "llimit": None,
            "lclusters": None,
            ## Active version
            "apstate": None, "aattribution": None, "avstate": None, 
            "asession": None, "aversion": None, "amail": None, "aquota": None,
            "astore": None, "alabo": None, "ametadonnees": None, 
            "aresume": None, "athematic": None, "atitre": None, 
            "aconsumption": None, "aasked": None, "aidlabo": None,
            "aidthematic": None, "astart": None, "aend": None, "alimit": None,
            "aclusters": None
            
        }

        gramc_versions = [
            { "version": 'derniere', "prefix": 'l'},
            { "version": 'active', "prefix": 'a'},
        ]
        
        for d in gramc_versions :
            p, v = [value for k, value in sorted(d.items())]
            if v in project_datas['versions']:
                version = project_datas['versions'][v]
                formatted_project_datas.update({
                    f"{p}pstate": self.i2state(int(version['etatProjet'])),
                    f"{p}vstate": self.i2state(int(version['etatVersion'])),
                    f"{p}version": str(version['idVersion']),
                    f"{p}mail": str(version['mail']),
                    f"{p}labo": ssafe(str(version['labo'])),
                    f"{p}thematic": ssafe(str(version['thematique'])),
                    f"{p}titre": ssafe(str(version['titre'])),
                })
                if self.config["type"] == "GRAMC":
                    formatted_project_datas.update({
                        f"{p}attribution": int(version['attrHeures']),
                        f"{p}session": str(version['idSession']),           
                        f"{p}quota": int(version['quota']),
                        f"{p}store": str(version['sondVolDonnPerm']),
                        f"{p}metadonnees": ssafe(str(version['metadonnees'])),                   
                        f"{p}resume": ssafe(str(version['resume']))
                    })
                elif self.config["type"] == "MESO":
                    resource = version['ressources'][self._meso]
                    formatted_project_datas.update({
                        f"{p}attribution": int(resource['attribution']),
                        f"{p}resume": str(version['expose']),
                        f"{p}consumption": int(resource['consommation']),
                        f"{p}asked": int(resource['demande']),
                        f"{p}idlabo": int(version['idLabo']),
                        f"{p}idthematic": int(version['idthematique']),
                        f"{p}start": str(version['startDate']),
                        f"{p}end": str(version['endDate']),
                        f"{p}limit": str(version['limitDate']),
                        f"{p}clusters": list([
                            c for c in version['ressources'].keys()
                            if version['ressources'][c]['attribution'] > 0
                        ])
                    })
                else:
                    raise ValueError(
                        "Gramc projet type must be GRAMC or MESO"
                    )

        return formatted_project_datas

    def populate(self, 
            projet: Optional[str] = None, session: Optional[str] = None
        ):
        """ Populate gramc project list. Populate all gramc projects by 
        default. Project string is case insensitive.

        :param Optional[str] projet: Gramc project to retrieve. None means 
                                     all projects.
        :param Optional[str] session: Gramc project in this session to 
                                      retrieve. None means all projects.

        :raise ValueError: If Gramc projet and session is not None or a string
        """
        if (projet is None or isinstance(projet, str)) and \
           (session is None or isinstance(session, str)):
            request_data = {"long": True}
            if projet is not None:
                request_data.update({"projet": projet.upper()})
            if session is not None:
                request_data.update({"session": session})

            request_headers = {"content-type": "application/json"}

            if self.config['apiUrl'] == self.config['apiDevUrl']:
                self.__log__.warning("We are on GRAMC dev API")
            
            projets = api_call(
                url=f"{self._api_endpoint}/get", data=request_data, 
                auth=self._api_auth, headers=request_headers
            )
            
            self.adds([
                GramcProjet(**self._populate_helper(d))
                for d in projets 
                    if (
                        ("derniere" in d['versions'] or 
                            "active" in d['versions']) and
                        projet is None
                    ) or (
                        ("derniere" in d['versions'] or 
                            "active" in d['versions']) and 
                        str(d['idProjet']).lower() == projet.lower()
                    )

            ])

            # self.__log__.trace(
            #     f"Found {self.len()} project '{self.get_projets()}' in gramc "
            #     f"projects (asked for project '{projet}' and "
            #     f"session '{session}')"
            # )

        else:
            raise ValueError(
                "Gramc projet and session must be None or a string"
            )


# @ctrace
class GramcUtilisateur(GenericObject):
    """
    Gramc User class

    Many attributes have active and last version ("active" and "derniere" in
    GRAMC API). Active version means that the value is the value in the 
    current version in production. Last version means that it is the value 
    of the last attribute value. Active version can be empty. if active value 
    is not set, that means that this project is no longer in production and 
    should be locked or remove. Active attributes are prefixed by "a" and 
    last by "l" letter.
    """
    __config__ = load_config(locals()['__module__'])
    attributes = register_attributes([{
        "name": "loginname", "category": "standard", "type": str, 
        "default": None, 
        "help": "Unix login in gramc or generated login if not set in gramc"
    }, {
        "name": "utilisateur", "category": "standard", "type": str, 
        "default": None, "help": "Gramc user email"
    }, {
        "name": "nom", "category": "standard", "type": str, 
        "default": None, "help": "Gramc user's lastname"
    }, {
        "name": "prenom", "category": "standard", "type": str, 
        "default": None, "help": "Gramc user's firstname"
    }, {
        "name": "idindividu", "category": "standard", "type": int, 
        "default": None, "help": "Gramc project individu ID"
    },{
        "name": "mprojets", "category": "extended", "type": list, 
        "default": [], "help": "Gramc user project's name member list"
    }, {
        "name": "projet", "category": "standard", "type": str, 
        "default": None, "help": "Gramc project"
    }, {
        "name": "aversion", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project version id in gramc"
    }, {
        "name": "lversion", "category": "standard", "type": str, 
        "default": None, 
        "help": "Gramc last project version id in gramc (for this user)"
    }, {
        "name": "gloginname", "category": "standard", "type": str, 
        "default": None, "help": "Gramc loginname in gramc"
    }, {
        "name": "aloginname", "category": "standard", "type": str, 
        "default": None, "help": "Cluster account for active gramc version"
    }, {
        "name": "lloginname", "category": "standard", "type": str, 
        "default": None, 
        "help": "Cluster account for last gramc version (for this user)"
    }, {
        "name": "adeleted", "category": "standard", "type": bool, 
        "default": None, 
        "help": "Cluster account deletion flag for active gramc version "
                "(for this user)"
    }, {
        "name": "ldeleted", "category": "standard", "type": bool, 
        "default": None, 
        "help": "Cluster account deletion flag for last gramc version "
                "(for this user)"
    }, {
        "name": "alogin", "category": "standard", "type": bool, 
        "default": None, "help": "Cluster account for active gramc session"
    }, {
        "name": "aclogin", "category": "standard", "type": bool, 
        "default": None, "help": 
        "Callisto account for active gramc session (Gramc only)"
    }, {
        "name": "llogin", "category": "standard", "type": bool, 
        "default": None, "help": "Cluster account for last gramc session"
    }, {
        "name": "lclogin", "category": "standard", "type": bool, 
        "default": None, 
        "help": "Callisto account for last gramc session (Gramc only)"
    }, {
        "name": "pmstate", "category": "extended", "type": str, 
        "default": None, "help": f"Gramc project meta state"
    }, { 
        "name": "pmtype", "category": "standard", "type": str, 
        "default": None, "help": "Gramc project meta type string"
    }, {
        "name": "api", "category": "extended", "type": str, 
        "default": None, "help": f"Active project's Principal Investigator"
    }, {
        "name": "lpi", "category": "extended", "type": str, 
        "default": None, "help": f"Last project's Principal Investigator"
    }, {
        "name": "category", "category": "extended", "type": str, 
        "default": None, 
        "help": f"Project category ({', '.join(config['global']['category'])})"
    }, {
        "name": "apstate", "category": "extended", "type": str, 
        "default": None, "help": "Gramc active project state string"
    }, {
        "name": "lpstate", "category": "extended", "type": str, 
        "default": None, "help": "Gramc last project state string"
    }, {
        "name": "apvstate", "category": "standard", "type": str, 
        "default": None, "help": "Gramc active project version state string"
    }, {
        "name": "lpvstate", "category": "standard", "type": str, 
        "default": None, "help": "Gramc last project version state string"
    }, {
        "name": "apsession", "category": "extended", "type": str, 
        "default": None, "help": f"Project active session"
    }, {
        "name": "lpsession", "category": "extended", "type": str, 
        "default": None, "help": f"Project last session"
    }, {
        "name": "apversion", "category": "extended", "type": str, 
        "default": None, "help": f"Project active version"
    }, {
        "name": "lpversion", "category": "extended", "type": str, 
        "default": None, "help": f"Project last version"
    }, {
        "name": "lsshkeyid", "category": "extended", "type": int, 
        "default": None, 
        "help": f"Last user resource ssh public key ID (Meso only)"
    }, {
        "name": "lsshpublickey", "category": "extended", "type": str, 
        "default": None, 
        "help": f"Last user resource ssh public key string (Meso only)"
    }, {
        "name": "lsshkeyname", "category": "extended", "type": str, 
        "default": None, 
        "help": f"Last user resource ssh public key name (Meso only)"
    }, {
        "name": "lsshkeydeployed", "category": "extended", "type": bool, 
        "default": None, 
        "help": f"Is last user resource ssh public key deployed (Meso only)"
    }, {
        "name": "lsshkeyrevoked", "category": "extended", "type": bool, 
        "default": None, 
        "help": f"Is last user resource ssh public key revoked (Meso only)"
    }, {
        "name": "asshkeyid", "category": "extended", "type": int, 
        "default": None, 
        "help": f"Active user resource ssh public key ID (Meso only)"
    }, {
        "name": "asshpublickey", "category": "extended", "type": str, 
        "default": None, 
        "help": f"Active user resource ssh public key string (Meso only)"
    }, {
        "name": "asshkeyname", "category": "extended", "type": str, 
        "default": None, 
        "help": f"Active user resource ssh public key name (Meso only)"
    }, {
        "name": "asshkeydeployed", "category": "extended", "type": bool, 
        "default": None, 
        "help": f"Is active user resource ssh public key deployed (Meso only)"
    }, {
        "name": "asshkeyrevoked", "category": "extended", "type": bool, 
        "default": None, 
        "help": f"Is active user resource ssh public key revoked (Meso only)"
    }, {
        "name": "auserid", "category": "standard", "type": int, 
        "default": None, 
        "help": f"Last user resource ID (Meso only)"
    }, {
        "name": "luserid", "category": "standard", "type": int, 
        "default": None, 
        "help": f"Active user resource ID (Meso only)"
    }, {
        "name": "aclusters", "category": "standard", "type": list, 
        "default": None, 
        "help": f"Last user clusters list (Meso only)"
    }, {
        "name": "lclusters", "category": "standard", "type": list, 
        "default": None, 
        "help": f"Active user clusters list (Meso only)"
    }, {
        "name": "generated", "category": "extended", "type": bool, 
        "default": False, "help": f"Is this user a generated user"
    }, {
        "name": "password", "category": "extended", "type": str, 
        "default": None, 
        "help": "Gramc temporary clear password (only use for update) "
                "(Gramc only)"
    }, {
        "name": "cpassword", "category": "extended", "type": str, 
        "default": None, 
        "help": "Gramc temporary encrypted password fingerprint "
                "(only use for update) (Gramc only)"
    }
    ])
    callables = register_callables([
        build_callable(
            action="list",      
            examples=[(
                "List first and last names of all users in project m99099", 
                "--attribute nom prenom --filter 'projet=^m99099$'"
            )]
        ),
        build_callable(
            action="set", 
            command="loginname",
            check="presence",
            doit="unset_loginname",
            label="Set attribution done for a project (Gramc Meso only)",
            required_attributes=["loginname", "idindividu", "projet"]
        ),
        build_callable(
            action="unset", 
            command="loginname",
            check="presence",
            doit="set_loginname",
            label="Set attribution done for a project (Gramc Meso only)",
            required_attributes=["loginname", "projet"]
        ),
        build_callable(
            action="set", 
            command="sshpubkey",
            check="presence",
            doit=True,
            label="Mark ssh public key as deployed for a user "
                  "(Gramc Meso only)",
            required_attributes=["loginname", "projet"]
        ),
        build_callable(
            action="unset", 
            command="sshpubkey",
            check="presence",
            doit=True,
            label="Mark ssh public key as revoked for a user "
                  "(Gramc Meso only)",
            required_attributes=["loginname", "projet"],
            additional_arguments=[
                to_parser("--pubkeyid", 
                    dest=f"unset_sshpubkey_additional_arguments_pubkeyid", 
                    metavar=f"<ssh pubkey id>",
                    type=int, required=True,
                    help=f"Gramc public ssh key id to revoke (idCle)"
                )
            ]
        ),
    ], attributes)    
    __doc__ += attributes_to_docstring(attributes)

    def __init__(self, **kwargs):
        self._meso = self.config['resource']
        super().__init__(**kwargs)

    @property
    def _api_endpoint(self) -> str:
        """ API endpoint full url helper

        :return: main API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['user_endpoint']}"
        )

    @property
    def _api_clessh_endpoint(self) -> str:
        """ API ssh key endpoint full url helper

        :return: "clessh" API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['clessh_endpoint']}"
        )

    @property
    def _api_auth(self) -> tuple:
        """ API auth tuple (user, password) helper

        :return: A tuple containing API user and password (user, password)
        """
        return (self.config['apiUser'], self.config['apiPassword'])

    def lock(self, doit: bool = False) -> Optional[str]:
        """ Lock a gramc user with the API. It calls GRAMC API and clear 
        cleartext password for a given loginname (Gramc only)

        :param bool doit: If True really lock gramc user else just return the 
                          command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        if self.config['type'] == 'MESO':
            response = {'OK', "Nothing to do here !"}
        else:
            response = self.update(method="clearpassword", doit=doit)      
        
        (rcode, rmesg) = next(iter(response.items()), ('KO', 'Unknown error'))
        if rcode == "OK":
            if doit:
                return None
            else:
                return [rmesg]
        else:
            if doit:
                if rcode == 'KO' and \
                   rmesg == f"No password stored for '{self.loginname}'":
                    self.__log__.warning(
                        f"No temporary password stored for "
                        f"user '{self.loginname}' in GRAMC"
                    )
                else:
                    raise RuntimeError(
                        f"Failed to call method clearpassword on GRAMC "
                        f"API for user '{self.loginname}' ({rmesg})"
                    )
            else:
                return [rmesg]

    def unlock(self, doit: bool = False) -> Optional[str]:
        """ Unlock a gramc user with the API. If both password and cpassword 
        are set, it calls GRAMC API and set a cleartext and encrypted 
        password for a given loginname else do nothing because it is just a 
        cluster unlock (Gramc only)

        :param bool doit: If True really unlock gramc user else just return 
                          the command as a string
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        if self._extended_password is not None and \
           self._extended_cpassword is not None:
            
            if self.config['type'] == 'MESO':
                response = {'OK', "Nothing to do here !"}
            else:
                response = self.update(method="setpassword", doit=doit)
                
            (rcode, rmesg) = next(iter(response.items()), ('KO', 'Unknown error'))
            if rcode == "OK":
                if doit:
                    return None
                else:
                    return [rmesg]
            else:
                if doit:
                    raise RuntimeError(
                        f"Failed to call method setpassword on GRAMC "
                        f"API for user '{self.loginname}' ({rmesg})"
                    )
                else:
                    return [rmesg]
        else:
            self.__log__.debug(
                f"GRAMC password '{self._extended_password}' or "
                f"cpassword '{self._extended_cpassword}' is None : "
                f"nothing to do."
            )
            return []
                    
    def clear(self, doit: bool = False) -> Optional[str]:
        """ Clear a gramc user with the API. It calls GRAMC API and clear 
        cleartext password for a given loginname. This method is call when a 
        user has changed his password on cluster.

        :param bool doit: If True really lock gramc user else just return the 
                          command as a string
        
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        response = self.update(method="clearpassword", doit=doit)
        (rcode, rmesg) = next(iter(response.items()), ('KO', 'Unknown error'))
        if rcode == "OK":
            if doit:
                return None
            else:
                return [rmesg]
        else:
            if doit:
                raise RuntimeError(
                    f"Failed to call method clearpassword on GRAMC "
                    f"API for user '{self.loginname}' ({rmesg})"
                )
            else:
                return [rmesg]
    
    def set_loginname(self, doit: bool = False) -> Optional[str]:
        """ set a loginname to a gramc user with the API. This method should 
        be called when a user is created on cluster to update GRAMC database.

        :param bool doit: If True really lock gramc user else just return the 
                          command as a string
        
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        response = self.update(method="setloginname", doit=doit)
        if isinstance(response, dict):
            (rcode, rmesg) = next(
                iter(response.items()), ('KO', 'Unknown error')
            )
        else:
            rcode = response
            rmesg = "Unexpected error"

        if rcode == "OK":
            if doit:
                return (
                    f"Success to set loginname for user '{self.loginname}' "
                    f"({self.idindividu}) in project '{self.projet}' ({rcode})"
                )
            else:
                return [rmesg]
        else:
            if doit:
                raise RuntimeError(
                    f"Failed to call method setloginname on GRAMC "
                    f"API for user '{self.loginname}' "
                    f"({rmesg})"
                )
            else:
                return [rmesg]
    
    def unset_loginname(self, doit: bool = False) -> Optional[str]:
        """Unset a loginname to a gramc user with the API. This method should 
        be called when a user is deleted on cluster to update GRAMC database.

        :param bool doit: If True really lock gramc user else just return the 
                          command as a string
        
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        response = self.update(method="clearloginname", doit=doit)
        (rcode, rmesg) = next(iter(response.items()), ('KO', 'Unknown error'))
        if rcode == "OK":
            if doit:
                return (
                    f"Success to clear loginname for user '{self.loginname}' "
                    f"({self.idindividu}) in project '{self.projet}' ({rcode})"
                )
            else:
                return [rmesg]
        else:
            if doit:
                raise RuntimeError(
                    f"Failed to call method clearloginname on GRAMC "
                    f"API for user '{self.loginname}' "
                    f"({rmesg})"
                )
            else:
                return [rmesg]

    def set_sshpubkey(self, doit: bool = False) -> Optional[str]:
        """ Mark a ssh public key as deployed for a user with the API. This 
        method should be called when a ssh public has been deployed on 
        cluster to update GRAMC database (Gramc meso only).

        :param bool doit: If True really lock gramc user else just return the 
                          command as a string
        
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        response = self.update(method="deployer", doit=doit)
        if isinstance(response, dict):
            (rcode, rmesg) = next(
                iter(response.items()), ('KO', 'Unknown error')
            )
        else:
            rcode = response
            rmesg = "Unexpected error"

        if rcode == "OK":
            if doit:
                return (
                    f"Success to set ssh public key '{self.asshkeyname}' "
                    f"as deployed for user '{self.loginname}'"
                    f"({self.idindividu}/{self.utilisateur}) "
                    f"in project '{self.projet}' ({rcode})"
                )
            else:
                return [rmesg]
        else:
            if doit:
                raise RuntimeError(
                    f"Failed to call method deployer on GRAMC "
                    f"API for user '{self.loginname}' "
                    f"({rmesg})"
                )
            else:
                return [rmesg]

    def unset_sshpubkey(
                self, pubkeyid: int, doit: bool = False
            ) -> Optional[str]:
        """ Mark a ssh public key as revoked for a user with the API. This 
        method should be called when a ssh public has been deleted on 
        cluster to update GRAMC database (Gramc meso only).

        :param int pubkeyid: Gramc public ssh key id to revoke (idCle)
        :param bool doit: If True really lock gramc user else just return the 
                          command as a string
        
        :return: None if doit is True and no raise else just return commands 
                 that should be done as string array

        :raise RuntimeError: If command fails
        """
        response = self.update(method="revoquer", doit=doit)
        if isinstance(response, dict):
            (rcode, rmesg) = next(
                iter(response.items()), ('KO', 'Unknown error')
            )
        else:
            rcode = response
            rmesg = "Unexpected error"

        if rcode == "OK":
            if doit:
                return (
                    f"Success to unset ssh public '{self.asshkeyid}' key as "
                    f"revoked for user '{self.loginname}' ({self.idindividu}) "
                    f"in project '{self.projet}' ({rcode})"
                )
            else:
                return [rmesg]
        else:
            if doit:
                raise RuntimeError(
                    f"Failed to call method deployer on GRAMC "
                    f"API for user '{self.loginname}' "
                    f"({rmesg})"
                )
            else:
                return [rmesg]

    def update(self, method: str, doit=False) -> dict:
        """ Call a GRAMC API method to update gramc attributes

        :param str method: A GRAMC API method name
        :param bool doit: Really make update (default to False)

        :return: A dict with API response as attribute and API message as 
                 value ({"response": "Message"})

        :raise NotImplementedError: If gramc API method is not found
        :raise RuntimeError: If it method fails 
        :raise AttributeError: If gramc required attributes are not set in 
                               gramc object
        """
        
        request_headers = {"content-type": "application/json"}
        request_data = {}
        if method == "setloginname": 
            if isinstance(self._standard_projet, str) and \
                isinstance(self._standard_idindividu, int) and \
                isinstance(self._standard_loginname, str):
                # New fashion with post data
                if self.config["type"] == "GRAMC":
                    request_data = {
                        "projet": f"{self._standard_projet.title()}",
                        "idIndividu": f"{self._standard_idindividu}",
                        "loginname": f"{self._standard_loginname}"
                    }
                elif self.config["type"] == "MESO":
                    request_data = {
                        "projet": f"{self._standard_projet.title()}",
                        "idIndividu": f"{self._standard_idindividu}",
                        "loginname": f"{self._standard_loginname}@{self._meso}"
                    }
                else:
                    raise ValueError(
                        "Gramc projet type must be GRAMC or MESO"
                    )
                endpoint = f"{self._api_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (projet, idindivdu and "
                    f"loginname) are not set for API "
                    f"method '{method}' ({self})"
                )
        elif method == 'clearloginname': 
            if isinstance(self._standard_projet, str) and \
                isinstance(self._standard_idindividu, int) and \
                isinstance(self._standard_loginname, str):
                # New fashion with post data
                if self.config["type"] == "GRAMC":
                    request_data = {
                        "projet": f"{self._standard_projet.title()}",
                        "idIndividu": f"{self._standard_idindividu}",
                        "loginname": f"{self._standard_loginname}"
                    }
                elif self.config["type"] == "MESO":
                    request_data = {
                        "projet": f"{self._standard_projet.title()}",
                        "idIndividu": f"{self._standard_idindividu}",
                        "loginname": f"{self._standard_loginname}@{self._meso}"
                    }
                else:
                    raise ValueError(
                        "Gramc projet type must be GRAMC or MESO"
                    )
                endpoint = f"{self._api_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (projet, idindivdu and "
                    f"loginname) are not set for API "
                    f"method '{method}' ({self})"
                )
        elif method == 'setpassword':
            if isinstance(self._standard_loginname, str) and \
                isinstance(self._extended_password, str) and \
                isinstance(self._extended_cpassword, str):
                request_data = {
                    "loginname": f"{self._standard_loginname}",
                    "password":  f"{self._extended_password}",
                    "cpassword": f"{self._extended_cpassword}"
                }
                endpoint = f"{self._api_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (loginname, password and "
                    f"cpassword) are not set for API "
                    f"method {method}"
                )
        elif method == 'clearpassword':
            if isinstance(self._standard_loginname, str):
                request_data = {
                    "loginname": f"{self._standard_loginname}"
                }
                endpoint = f"{self._api_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attribute (loginname) is not set for API "
                    f"method {method}"
                )
        elif method == 'deployer':
            if isinstance(self._standard_projet, str) and \
                isinstance(self._standard_idindividu, int) and \
                isinstance(self._standard_loginname, str):
                # New fashion with post data
                if self.config["type"] == "GRAMC":
                    raise NotImplementedError(
                        f"Gramc update method '{method}' not found"
                    )
                elif self.config["type"] == "MESO":
                    request_data = {
                        "projet": f"{self._standard_projet.title()}",
                        "idIndividu": f"{self._standard_idindividu}",
                        "loginname": f"{self._standard_loginname}@{self._meso}"
                    }
                else:
                    raise ValueError(
                        "Gramc projet type must be GRAMC or MESO"
                    )
                endpoint = f"{self._api_clessh_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (projet, idindivdu and "
                    f"loginname) are not set for API "
                    f"method '{method}' ({self})"
                )
        elif method == 'revoquer':
            if isinstance(self._standard_idindividu, int) and \
                isinstance(self._extended_asshkeyid, int):
                # New fashion with post data
                if self.config["type"] == "GRAMC":
                    raise NotImplementedError(
                        f"Gramc update method '{method}' not found"
                    )
                elif self.config["type"] == "MESO":
                    request_data = {
                        "idIndividu": f"{self._standard_idindividu}",
                        "idCle": f"{self._extended_asshkeyid}"
                    }
                else:
                    raise ValueError(
                        "Gramc projet type must be GRAMC or MESO"
                    )
                endpoint = f"{self._api_clessh_endpoint}/{method}"
            else: 
                raise AttributeError(
                    f"Gramc required attributes (projet, idindivdu and "
                    f"loginname) are not set for API "
                    f"method '{method}' ({self})"
                )
        else:
            raise NotImplementedError(
                f"Gramc update method '{method}' not found"
            )
        if self.config['apiUrl'] == self.config['apiDevUrl']:
            self.__log__.warning("We are on GRAMC dev API")
        
        update_result = api_call(
            url=endpoint, data=request_data, 
            auth=self._api_auth, headers=request_headers, doit=doit
        )

        self.__log__.debug(f"Update result : {update_result}")
        if doit:
            return update_result
        else:
            return {"OK": update_result}

# @ctrace()
class GramcUtilisateurs(GenericObjects):
    """
    List of GramcUtilisateur objects.
    """
    __config__ = load_config(locals()['__module__'])
    def __init__(self, **kwargs):
        self._register_index(index_name="loginnames", multiple=False)
        self._register_index(index_name="utilisateurs", multiple=True)
        self._register_index(index_name="idindividus", multiple=True)
        self._register_index(index_name="mprojets", multiple=True)
        self._meso = self.config['resource']
        super().__init__(**kwargs)

    def add(self, obj: GramcUtilisateur):
        """ Add a GramcUtilisateur object from the list

        :param GramcUtilisateur obj: A GramcUtilisateur object
        """
        super().add(obj)
        self._add_to_loginnames(obj.loginname, obj)
        self._add_to_utilisateurs(obj.utilisateur, obj)
        self._add_to_idindividus(obj.idindividu, obj)
        for projet in obj.mprojets:
            self._add_to_mprojets(projet, obj)

    def delete(self, obj: GramcUtilisateur):
        """ Remove a GramcUtilisateur object from the list

        :param GramcUtilisateur obj: A GramcUtilisateur object
        """
        super().delete(obj)
        self._delete_from_loginnames(obj.loginname, obj)
        self._delete_from_utilisateurs(obj.utilisateur, obj)
        self._delete_from_idindividus(obj.idindividu, obj)
        for projet in obj.projets:
            self._delete_from_projets(projet, obj)

    @property
    def _api_endpoint(self) -> str:
        """ API ip addresses endpoint full url

        :return: "ip-address" API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['user_endpoint']}"
        )

    @property
    def _api_clessh_endpoint(self) -> str:
        """ API ssh key endpoint full url helper

        :return: "clessh" API endpoint full url
        """
        return(
            f"{self.config['apiUrl']}{self.config['clessh_endpoint']}"
        )

    @property
    def _api_auth(self) -> tuple:
        """ API auth tuple (user, password) helper

        :return: A tuple containing API user and password (user, password)
        """
        return (self.config['apiUser'], self.config['apiPassword'])


    def get_pending_ssh_pub_key(self) -> List[dict]:
        """ Request gramc meso API and check for ssh public key which needs 
        to be deployed.
          
        :return: Actions as a dict containing actions attributes
        """
        request_headers = {"content-type": "application/json"}
        request_data = {}
        method = "get"
        if self.config['type'] == "MESO": 
            endpoint = f"{self._api_clessh_endpoint}/{method}"
        else:
            raise NotImplementedError(
                f"Gramc update method '{method}' not found"
            )
      
        if self.config['apiUrl'] == self.config['apiDevUrl']:
            self.__log__.warning("We are on GRAMC dev API")
        
        get_result = api_call(
            url=endpoint, data=request_data, 
            auth=self._api_auth, headers=request_headers, doit=True
        )

        self.__log__.debug(f"Update result : {get_result}")
        
        return get_result


    def _initialize_logins(self, users_datas: dict ):
        """ User logins list used for login login unicity check and user 
        login generation
        
        :param dict users_datas: Raw gramc users data from API

        """  
        if self.config["type"] == "GRAMC":
            self._logins=list(set([
                str(gl['loginname']) for _, d in users_datas.items()
                    for _, gl in d['projets'].items()
                    if gl is not None and gl['loginname'] is not None
            ]))
        elif self.config["type"] == "MESO":
            self._logins=list(set([
                str(gl['loginnames'][self._meso]['nom']) 
                for _, d in users_datas.items()
                for _, gl in d['projets'].items()
                if gl is not None 
                   and 'loginnames' in gl
                   and self._meso in gl['loginnames']
                   and 'nom' in gl['loginnames'][self._meso]
                   and gl['loginnames'][self._meso]['nom'] is not None
            ]))
        else:
            raise ValueError(
                "Gramc projet type must be GRAMC or MESO"
            )
        
    def _populate_helper(
                self, user_mail:str, user_primary_datas: dict, 
                user_project_datas: dict, user_project_object: GramcProjet
            ) -> dict:
        """ Convert raw GRAMC or MESO user data in an dict usable by 
        GramcUser constructor as parameters
        :param dict user_datas: Raw gramc user data from API
        :param dict user_project_datas: Raw gramc user project data from API
        :param dict user_project_object: Gramc user project object from 
                                         GramcProjects

        :return: Formatted gramc user data usable by GramcUser constructor 
                 as parameters

        :raise ValueError: If value is gramc config "type" value is not "GRAMC"
                           or MESO
        """
        if self.config["type"] == "GRAMC":
            versions = user_project_datas['versions']
            gloginname = user_project_datas['loginname']
        elif self.config["type"] == "MESO":
            versions = user_project_datas
            gloginname = user_project_datas['loginnames'][self._meso]['nom']
        else:
            raise ValueError(
                "Gramc projet type must be GRAMC or MESO"
            )

        formatted_user_datas = {
            "loginname": None,
            "utilisateur": ssafelower(str(user_mail)),
            "nom": ssafe(str(user_primary_datas['nom'])),
            "prenom": ssafe(str(user_primary_datas['prenom'])),
            "idindividu": int(user_primary_datas['idIndividu']),
            "mprojets": [p for p in user_primary_datas['projets']],
            "projet": user_project_object.projet,
            "gloginname": gloginname,
            "pmstate": user_project_object.mstate,
            "pmtype": user_project_object.mtype,
            "category": user_project_object.category,
            "generated": False,
            "password": None,
            "cpassword": None,

            ## Active version
            "aversion": None, "aloginname": None, "adeleted": None,
            "alogin": None, "aclogin": None,
            "api": user_project_object.amail,
            "apstate": user_project_object.apstate,
            "apvstate": user_project_object.avstate,
            "apsession": user_project_object.asession,
            "apversion": user_project_object.aversion,
            "asshkeyid": None, "asshpublickey": None, "asshkeyname": None, 
            "asshkeydeployed": None, "asshkeyrevoked": None,
            "auserid": None, "aclusters": None,

            ## Derniere version
            "lversion": None, "lloginname": None, "ldeleted": None,
            "llogin": None, "lclogin": None,  
            "lpi": user_project_object.lmail,
            "lpstate": user_project_object.lpstate, 
            "lpvstate": user_project_object.lvstate,
            "lpsession": user_project_object.lsession,
            "lpversion": user_project_object.lversion,
            "lsshkeyid": None, "lsshpublickey": None, "lsshkeyname": None, 
            "lsshkeydeployed": None, "lsshkeyrevoked": None,
            "luserid": None, "lclusters": None
        }
        
        gramc_versions = [
            { "version": 'derniere', "prefix": 'l'},
            { "version": 'active', "prefix": 'a'},
        ]
        for d in gramc_versions :
            p, v = [value for k, value in sorted(d.items())]
            if v in versions:
                formatted_user_datas.update({
                    f"{p}version": versions[v]['version'],
                    f"{p}deleted": versions[v]['deleted']
                })
                if self.config["type"] == "GRAMC":
                    formatted_user_datas.update({
                        f"{p}login": versions[v]['login'],
                        f"{p}clogin": versions[v]['clogin'],
                        f"{p}loginname": versions[v]['loginname'],
                    })
                elif self.config["type"] == "MESO":
                    resource = versions[v]['loginnames'][self._meso]
                    cluster = getattr(user_project_object, f"{p}clusters")
                    formatted_user_datas.update({
                        f"{p}login": resource['login'],
                        f"{p}loginname": resource['nom'],
                        f"{p}userid": int(resource['userid']),
                        f"{p}clusters": cluster,
                    })
                    if 'clessh' in resource and resource['clessh'] is not None:
                        formatted_user_datas.update({
                            f"{p}sshkeyid": int(resource['clessh']['idCle']),
                            f"{p}sshpublickey": resource['clessh']['pub'],
                            f"{p}sshkeyname": resource['clessh']['nom'],
                            f"{p}sshkeydeployed": resource['clessh']['deploy'],
                            f"{p}sshkeyrevoked": resource['clessh']['rvk']
                        })
                    else:
                        formatted_user_datas.update({
                            f"{p}sshkeydeployed": False,
                            f"{p}sshkeyrevoked": False
                        })
                else:
                    raise ValueError(
                        "Gramc projet type must be GRAMC or MESO"
                    )
        self.__log__.debug(
            f"gloginname : {gloginname}, logins: {self._logins}"
        )
        loginname = gloginname
        generated = False
        if gloginname is None or gloginname == "nologin":
            loginname = anonymous_login_generator(
                user_project_object.projet, 
                str(user_primary_datas['nom']),
                str(user_primary_datas['prenom']),
                int(user_primary_datas['idIndividu']), 
                self._logins, None, None
            )
            generated = True
            self.__log__.debug(
                f"loginname : {loginname}, logins: {self._logins}"
            )
            self._logins = list(set(self._logins + [loginname]))

        formatted_user_datas.update({
            "loginname": loginname,
            "generated": generated
        })
        self.__log__.debug(f"formatted_user_datas : {formatted_user_datas}")
        return formatted_user_datas

    def populate(
            self, projet: Optional[str] = None, mail: Optional[str] = None
        ):
        """ Populate gramc user list. Populate all gramc users by default. 
        Project string is case insensitive.

        :param Optional[str] projet: Gramc project to retrieve users from. 
                                     None means all users.
        :param Optional[str] mail: Gramc user email to retrieve. None means 
                                   all users.

        :raise ValueError: If gramc user project and mail is not None or a 
                           string
        """
        if (projet is None or isinstance(projet, str)) and \
           (mail is None or isinstance(mail, str)):
            request_data = {}
            if projet is not None:
                request_data.update({"projet": projet.upper()})
            if mail is not None:
                request_data.update({"mail": mail})

            request_headers = {"content-type": "application/json"}

            if self.config['apiUrl'] == self.config['apiDevUrl']:
                self.__log__.warning("We are on GRAMC dev API")

            users = api_call(
                url=f"{self._api_endpoint}/get", data=request_data, 
                auth=self._api_auth, headers=request_headers
            )

            if users:
                gps = GramcProjets()
                gps.populate()
                self._initialize_logins(users)

                [
                    self.add(GramcUtilisateur(**self._populate_helper(
                        m, d, gl, gps.get_by_projets(gp.lower())
                    )))
                    for m, d in users.items()
                    for gp, gl in d['projets'].items()
                    if ( projet is None 
                         or str(projet.lower()) 
                            in [str(p).lower() for p in d['projets']]
                       ) and (
                           mail is None 
                           or mail.lower() == ssafelower(str(m))
                       )
                ]
                        
            # self.__log__.trace(
            #     f"Found {self.len()} users "
            #     f"'{[u for u in self.get_utilisateurs()]}' in gramc users "
            #     f"(asked for projet '{projet}', mail '{mail}')"
            # )
            self._logins = None

        else:
            raise ValueError(
                "Gramc user project and mail must be None or a string"
            )