# -*- coding: utf-8 -*-

"""Hpc GRAMC Update

This program is used to update GRAMC with cluster info

"""
from sys import exit, argv
from argparse import ArgumentParser
from hpc.gramc import GramcProjets, GramcUtilisateurs
from hpc.utils import fingerprint
from hpc.generators import encrypted_password_generator
from cilogger.cilogger import _rcilogger #, ftrace
rootlogger = _rcilogger({
    'INFO' : '<color fg=cyan>{asctime:12s}</> '
             '<level>{levelname: >8s}</> '
             '<level>{message}</>',
    'WARNING' : '<color fg=cyan>{asctime:12s}</> '
                '<level>{levelname: >8s}</> '
                '<level>{message}</>',
    'ERROR' : '<color fg=cyan>{asctime:12s}</> '
              '<level>{levelname: >8s}</> '
              '<level>{message}</>',
    'CRITICAL' : '<color fg=cyan>{asctime:12s}</> '
                 '<level>{levelname: >8s}</> '
                 '<level>{message}</>',
})

log = rootlogger.getChild(__name__)
rootlogger.setLevel("INFO")


# @ftrace
def init_parser() -> ArgumentParser:
    """Initialize argparse parser. We use a function to be able to add help in pydoc

    :return: An initialized argparse parser
    """

    actions = {
        "projet": {
            "label": "Update gramc projet attributes",
        },
        "utilisateur": {
            "label": "Update gramc user attributes",
        },
    }

    local_parser = ArgumentParser(description="Hpc GRAMC user and group updater",
                                           allow_abbrev=True)
    levels = ["CRITICAL", "INFO", "WARNING", "ERROR", "DEBUG", "TRACE"]
    all_levels = [l.lower() if low else l for l in levels for low in [True, False]]
    local_parser.add_argument("--debug", dest="debug", metavar="<level>", type=str, required=False,
                              choices=all_levels, default="INFO",
                              help=f"Set debug level ({', '.join(levels)})")

    action_subparser = local_parser.add_subparsers(dest="actions")
    for action, actdata in actions.items():
        action_parser = action_subparser.add_parser(
            f"{action}", help=f"{actdata['label']}, "
        )
        if action == "projet":
            object_subparser = action_parser.add_subparsers(dest="fields")
            options = {
                "set-quota": {
                    "help": "Set Gramc hour attribution for a project",
                    "required" : [
                        {
                            "name": "projet", "metavar": "Projet", "type": str, 
                            "help": "Gramc project" 
                        }, {
                            "name": "quota", "metavar": "Quota", "type": int, 
                            "help": "Gramc cpu hour quota on cluster for the project"                            
                        }
                    ]
                },
            }
        if action == "utilisateur":
            object_subparser = action_parser.add_subparsers(dest="fields")
            options = {
                "set-loginname": {
                    "help": "Set Gramc login name for user in a project",
                    "required" : [
                        {
                            "name": "utilisateur", "metavar": "utilisateur@example.fr", "type": str, 
                            "help": "Gramc user email"
                        }, {
                            "name": "projet", "metavar": "Projet", "type": str, 
                            "help": "Gramc user project"                            
                        }, {
                            "name": "loginname", "metavar": "loginname", "type": str, 
                            "help": "Cluster login name for the user in the project"                            
                        }

                    ]
                },
                "clear-loginname": {
                    "help": "Clear Gramc login name for user in a project",
                    "required" : [
                        {
                            "name": "utilisateur", "metavar": "utilisateur@example.fr", "type": str, 
                            "help": "Gramc user email"
                        }, {
                            "name": "projet", "metavar": "Projet", "type": str, 
                            "help": "Gramc user project"                            
                        }, {
                            "name": "loginname", "metavar": "loginname", "type": str, 
                            "help": "Cluster login name for the user in the project"                            
                        }

                    ]
                },
                "set-password": {
                    "help": "Set Gramc temporary clear and encrypted password for user login",
                    "required" : [
                       {
                            "name": "utilisateur", "metavar": "utilisateur@example.fr", "type": str, 
                            "help": "Gramc user email"
                        }, {
                            "name": "projet", "metavar": "Projet", "type": str, 
                            "help": "Gramc user project"                            
                        }, {
                            "name": "loginname", "metavar": "loginname", "type": str, 
                            "help": "Cluster login name for the user in the project"
                        }, {
                            "name": "password", "metavar": "clear password", "type": str, 
                            "help": "Cluster login temporary clear password"                            
                        }, {
                            "name": "cpassword", "metavar": "clear password", "type": str, 
                            "help": "Cluster login temporary crypted password"                            
                        }
                    ]
                },
                "clear-password": {
                    "help": "Clear Gramc temporary clear and encrypted password for user login",
                    "required" : [
                        {
                            "name": "utilisateur", "metavar": "utilisateur@example.fr", "type": str, 
                            "help": "Gramc user email"
                        }, {
                            "name": "projet", "metavar": "Projet", "type": str, 
                            "help": "Gramc user project"                            
                        }, {
                            "name": "loginname", "metavar": "loginname", "type": str, 
                            "help": "Cluster login name for the user in the project"
                        }
                    ]
                }
            }
        for opt_name, opt_data in options.items():
            object_parser = object_subparser.add_parser(
                f"{opt_name}", help=f"{opt_data['help']}"
            )
            for r_arg in opt_data['required']:
                object_parser.add_argument(
                    f"--{r_arg['name']}", dest=f"{action}_{opt_name}_{r_arg['name']}",
                    metavar=f"<{r_arg['metavar']}>", required=True, type=r_arg['type'], help=f"{r_arg['help']}"
                )
    return local_parser


# @ftrace
def main(args, parser: ArgumentParser) -> int:
    parser_options = parser.parse_args(args)
    rootlogger.setLevel(parser_options.debug.upper())
    log.debug(f"Arguments found : {parser_options}")
    dpo = vars(parser_options)
    log.debug(f"Arguments found (dict) : {dpo}")
    current_action = dpo["actions"]

    if current_action == 'projet':
        current_field = dpo["fields"]
        if current_field is None:
            parser.print_help()
            parser.exit(status=0)
        else: 
            projet = dpo[f"{current_action}_{current_field}_projet"]
            quota = dpo[f"{current_action}_{current_field}_quota"]
            gps = GramcProjets()
            gps.populate(projet=projet)
            if gps.len() == 1:
                gp = next(iter(gps.get()), None)
                if gp is None:
                    log.error(f"No project named '{projet}' in any sessions")
                    parser.exit(status=1)
                else:
                    gp.aquota = quota
                    if current_field == 'set-quota':
                        api_method = "setquota"
                    else:
                        parser.print_help()
                        parser.exit(status=1)
                    if gp.asession in gps.config['session']['current']:
                        response = gp.update(method=api_method, doit=True)
                    elif gp.lsession in [gps.config['session']['new']]:
                        log.warn(f"Project '{projet}' not found in current sessions")
                        response = gp.update(method=api_method, doit=True)
                    else:
                        log.error(f"Project '{projet}' not found in current and new sessions")
                        response = gp.update(method=api_method, doit=True)

                    (rcode, rmesg) = next(iter(response.items()), ('KO', 'Unknown error'))
                    if rcode == "OK":
                        log.info(f"Success to call method '{api_method}' on GRAMC API ({rmesg})")
                        return 0
                    else:
                        log.critical(f"Failed to call method '{api_method}' on GRAMC API ({rmesg})")
                        return 2
            elif gps.len() == 0:
                log.error(f"No project '{projet}' found in project in any sessions")
                return 2
            else:
                log.error(f"More than one project '{projet}' found.")
                return 2

    elif current_action == 'utilisateur':
        current_field = dpo["fields"]
        if current_field is None:
            parser.print_help()
            parser.exit(status=0)
        else: 
            utilisateur = dpo[f"{current_action}_{current_field}_utilisateur"]
            projet = dpo[f"{current_action}_{current_field}_projet"]
            gus = GramcUtilisateurs()
            gus.populate(projet=projet, mail=utilisateur)
            if gus.len() == 1:
                gu = next(iter(gus.get()), None)
                if gu is None:
                    log.error(f"No user named '{utilisateur}' found in project '{projet}' for any sessions")
                    parser.exit(status=1)
                else:
                    gu.loginname = dpo[f"{current_action}_{current_field}_loginname"]
                    if current_field == 'set-loginname':
                        api_method = "setloginname"
                    elif current_field == 'clear-loginname':
                        api_method = "clearloginname"
                    elif current_field == 'set-password':
                        gu.password = dpo[f"{current_action}_{current_field}_password"]
                        cryptedpwd = dpo[f"{current_action}_{current_field}_cpassword"]
                        gu.cpassword = cryptedpwd
                        api_method =  "setpassword"
                    elif current_field == 'clear-password':
                        api_method = "clearpassword"
                    else:
                        parser.print_help()
                        parser.exit(status=1)
                    if gu.apsession in gus.config['session']['current']:
                        response = gu.update(method=api_method, doit=True)
                    elif gu.lpsession in [gus.config['session']['new']]:
                        log.error(f"No user '{utilisateur}' found in project '{projet}' for current sessions")
                        response = gu.update(method=api_method, doit=True)
                    else:
                        log.error(f"No user '{utilisateur}' found in project '{projet}' for current and new sessions")
                        response = gu.update(method=api_method, doit=True)

                    (rcode, rmesg) = next(iter(response.items()), ('KO', 'Unknown error'))
                    if rcode == "OK":
                        log.info(f"Success to call method '{api_method}' on GRAMC API ({rmesg})")
                        return 0
                    else:
                        log.critical(f"Failed to call method '{api_method}' on GRAMC API ({rmesg})")
                        return 2
            elif gus.len() == 0:
                log.error(f"No user '{utilisateur}' found in project '{projet}' for any sessions")
                return 2
            else:
                log.error(f"More than one ({gus.len()}) user '{utilisateur}' found in project '{projet}' for any sessions.")
                return 2
    else:
        parser.print_help()
        parser.exit(status=0)

    return 0


root_parser = init_parser()
# doc__ += f"{root_parser.format_help()}"

if __name__ == '__main__':
    exit(main(argv[1:], parser=root_parser))
