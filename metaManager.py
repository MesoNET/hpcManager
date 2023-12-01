# -*- coding: utf-8 -*-

"""Meta manager program

This program is used for managing hpc users and groups

"""
from csv import writer, DictWriter, DictReader, QUOTE_MINIMAL
from sys import argv, exit, stdout
from argparse import (
    ArgumentParser, FileType, RawDescriptionHelpFormatter, SUPPRESS
)
from itertools import chain
from config.configGramc import config as grconfig
from hpc.utils import (
    help_format, ssafe, run, fingerprint, 
    get_current_meta_module_config, is_number
)
#from config.configFilters import predefined
from hpc.filters import (
    predefined_filters_expand, predefined_filters_help_format
)
from pathlib import Path
from datetime import datetime
from config.config import config
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
rootlogger.setLevel("CRITICAL")
#rootlogger.setLevel("TRACE")

# @ftrace
def init_parser() -> ArgumentParser:
    """Initialize argparse parser. We use a function to be able to add help 
    in pydoc

    :return: An initialized argparse parser
    """

    meta_module = get_current_meta_module_config(__file__)
    actions = {
        "list": {
            "label": "List objects (all local cluster objects by default)",
        },
        "create": {
            "label": "Create group, password and shadow file for new users",
        },
        "delete": {
            "label": "Delete group",
        },
        "update": {
            "label": "Update project quota",
        }
    }

    mm_name = meta_module['name']
    mm_group = meta_module['group']['type']
    mm_groups = meta_module['group']['list']
    mm_user = meta_module['user']['type']
    mm_users = meta_module['user']['list']
    predefined = meta_module['filters']

    # Common args for all sub parsers
    common_args_parser = ArgumentParser(
        add_help=False
    )
    levels = ["CRITICAL", "INFO", "WARNING", "ERROR", "DEBUG", "TRACE"]
    all_levels = [l.lower() if low else l for l in levels for low in [True, False]]
    common_args_parser.add_argument(
        '--debug', dest='debug', metavar='<level>', type=str, 
        required=False, choices=all_levels, default=SUPPRESS, 
        help=f"Set debug level ({', '.join(levels)})"
    )

    # Main parser
    local_parser = ArgumentParser(
        description=f"{mm_name.title()} user and group manager", 
        parents=[common_args_parser],
        allow_abbrev=True
    )
    action_subparser = local_parser.add_subparsers(dest="actions")
    for action, actdata in actions.items():
        action_parser = action_subparser.add_parser(
            f"{action}", parents=[common_args_parser], 
            help=f"{actdata['label']}, "
        )

        if action == "create" or action == "delete":
            object_subparser = action_parser.add_subparsers(dest="objects")
            for oname, obj in {"group": mm_group, "user": mm_user}.items():
                object_parser = object_subparser.add_parser(
                    f"{oname}", parents=[common_args_parser], 
                    help=f"{action.title()} hpc {oname}s"
                )
                object_parser.add_argument(
                    "--from-csv", dest=f"{action}_from_csv", nargs='+', 
                    metavar="</path/to/file.csv>",
                    type=FileType('r'), required=True,
                    help=f"{action.title()} {oname} from csv file"
                )
                if config['develop'] == "On":
                    object_parser.add_argument(
                        "--doit", dest=f"{action}_doit", 
                        metavar=f"YesIReallyWantToUseThisBetaFeature{action.title()}",
                        type=str, required=False,
                        help=f"Really {action} {oname} from csv file "
                             f"(YesIReallyWantToUseThisBetaFeature{action.title()})"
                    )
                    object_parser.add_argument(
                        "--continue-on-failure", 
                        dest=f"{action}_continue_on_failure", 
                        action='store_true',
                        required=False, 
                        help=f"Continue {action} {oname} even if an "
                             f"error occurs."
                    )
        elif action == "list":
            action_parser.add_argument(
                "--output", dest="list_output", nargs='?', 
                metavar="</path/to/file.csv>",
                type=FileType('w'), required=False, default=stdout,
                help=f"Output file (stdout by default)"
            )
            action_parser.add_argument(
                "--delimiter", dest="list_delimiter", nargs='?', 
                metavar="<delimiter>",
                type=str, required=False, default=',',
                help=f"Output field delimiter (',' by default)"
            )
            action_parser.add_argument(
                "--no-header", dest="list_no_header", 
                action='store_true', required=False,
                help=f"Remove headers from output"
            )
            action_parser.add_argument(
                "--generate-missing", dest="list_generate_missing", 
                action='store_true', required=False,
                help=f"Generate missing modules data if module is "
                     f"loaded and module's attributes have generators"
            )

            object_subparser = action_parser.add_subparsers(dest="objects")
            for oname, obj in {"group": mm_group, "user": mm_user}.items():
                examples = {
                    "group": [(
                        "List groups from 'entreprise' category",
                        "hpcManager.py list group --attribute unix_group "
                        "--filter unix_category='entreprise'"
                    ), (
                        "List research groups to delete",
                        "hpcManager.py list group --attribute unix_group "
                        "--filter predefined=OldGroups"
                    )],
                    "user": [(
                        "List research iser in active project needed to "
                        "be deleted",
                        "hpcManager.py list user --attribute unix_login "
                        "--filter predefined='OldUsers'"
                    ), (
                        "List user not in 'other' category but having an unix "
                        "login",
                        "hpcManager.py list user "
                        "--attribute unix_login unix_category "
                        "--filter unix_category='^(?!other).*$' "
                        "--filter 'unix_login=^.+$'"
                    ), (
                        "List research user in current session needed to be "
                        "created and generate missing attributes modules",
                        "hpcManager.py list --generate-missing user "
                        "--attribute unix_login unix_clearpassword "
                        "gramc_login gramc_pi "
                        "--filter 'unix_login=^$' "
                        "--filter 'gramc_category=^recherche|test$' "
                        "--filter 'gramc_session=[CURRENT]' "
                        "--filter 'gramc_psession=[CURRENT]'"
                    )],
                }

                epilog = "\n".join(
                    [f"Attribute field description :\n"] +
                    [
                        f"  * {module} :\n\n{help_format(a.help())}\n\n" 
                        for module, a in obj.atypes().items()
                    ] +
                    [f"Predefined filters :\n"] +
                    [predefined_filters_help_format(predefined, oname)]
                )

                epilog += "\n\n\nExamples :\n\n" + "\n\n".join([
                    f"  * {e} :\n{c}" for e, c in examples[oname]
                ])

                all_attributes = [
                    f"{module}_{a}" 
                    for module, o in obj.atypes().items() 
                    for a in o.attrs() + o.attrs_ext()
                ]  + list(
                    chain.from_iterable([
                        [f"{module}_all", f"{module}_std", f"{module}_ext"] 
                        for module in obj.atypes()
                    ])
                )

                object_parser = object_subparser.add_parser(
                    f"{oname}", help=f"Manage {mm_name} {oname}s", 
                    parents=[common_args_parser], epilog=epilog,
                    formatter_class=RawDescriptionHelpFormatter
                )

                object_parser.add_argument(
                    f"--attribute", dest=f"{action}_{oname}_attribute",
                    metavar="<fields>", action="append", nargs='*',
                    choices=all_attributes,
                    default=None, required=False,
                    help="Display attribute info (see 'Attribute field "
                         "description'). You can use '<module>_all', "
                         "'<module>_std' or '<module>_ext' to display all, "
                         "standard or extended attributes for this module."
                )

                # Filter
                object_parser.add_argument(
                    "--filter", dest=f"{action}_{oname}_filter",
                    metavar="<filter>", action="append", nargs='*',
                    default=None, required=False,
                    help=f"Filter an attribute value with a regexp "
                         f"'module-name_attribute-name[!|=]regex' or with "
                         f"a key in a list, a dict or list dict with "
                         f"'<module_name>_<attribute_name>@[key|*]<regex. "
                         f"You can use * in key to specify all keys and you "
                         f"can use [module-name_attribute-name] in "
                         f"regex if you want to use the value of an other "
                         f"attribute in the regex. Filter example : "
                         f"'unix_login=^toto.*', "
                         f"gramc_projets=p99001<^None$', "
                         f"'gramc_login=^gramc_[unix_login]$' or "
                         f"gramc_projets=*<^[unix_login]$'",
                )

    return local_parser

# @cilogger.cilogger.ftrace
def main(args, parser: ArgumentParser, meta_module: dict) -> int:
    parser_options = parser.parse_args(args)
    if 'debug' in parser_options:
        rootlogger.setLevel(parser_options.debug.upper())
    log.debug(f"Arguments found : {parser_options}")
    dpo = vars(parser_options)
    log.debug(f"Arguments found (dict) : {dpo}")
    current_action = dpo["actions"]

    mm_name = meta_module['name']
    mm_group = meta_module['group']['type']
    mm_groups = meta_module['group']['list']
    mm_user = meta_module['user']['type']
    mm_users = meta_module['user']['list']
    predefined = meta_module['filters']

    if current_action == 'list':
        current_object = dpo["objects"]
        obj = None
        if current_object == "group":
            obj = mm_group
        elif current_object == "user":
            obj = mm_user
        else:
            parser.exit(
                status=1,
                message=f"\nBad object must be group or user.\n\n"
            )
        # Generate filters
        filters = []
        if dpo[f"{current_action}_{current_object}_filter"] is None:
            dpo[f"{current_action}_{current_object}_filter"] = [
                [f"predefined={mm_name.title()}{current_object.title()}s"]
            ]
            
        opt_filters = list(chain.from_iterable(
            dpo[f"{current_action}_{current_object}_filter"]
        ))

        log.debug(f"Parsing filters : {opt_filters}")
        predefined_filters_attributes = None
        try:
            (predefined_filters_attributes, real_filters) = predefined_filters_expand(
                predefined, current_object, opt_filters
            )
            filters = obj.to_filters(real_filters)
        except ValueError as e:
            parser.exit(
                status=1,
                message="\n".join(
                    [f"\n{e}\n"] +
                    ["Filter usage : "] +
                    ["    Filter an attribute value with a regexp "
                     "'module-name_attribute-name[!|=]regex' or with"] +
                    ["    a key in a list, a dict or list dict with "
                     "'<module_name>_<attribute_name>@[key|*]<regex.\n"] +
                    ["    You can use * in key to specify all keys and you "
                     "can use [module-name_attribute-name] in"] +
                    ["    regex if you want to use the value of an other "
                     "attribute in the regex.\n"] +
                    ["    Finaly, mutiples filters can be given and are "
                     "evaluated as 'and' if no filtor operator is"] +
                    ["    given or with reverse polish notation evaluation "
                     "if filter 'or' or filter 'and' is in"] +
                    ["    expression (--filter 'or' or --filter 'and')"] +
                    ["\nFilter example :"] +
                    ["    --filter 'unix_login=^toto.*'"] + 
                    ["    --filter 'gramc_projets=p99001<^None$'"] +
                    ["    --filter 'gramc_login=^gramc_[unix_login]$'"] + 
                    ["    --filter 'gramc_projets=*<^[unix_login]$'"] +
                    ["    --filter 'predefined=SanityCheckGramcLoginMissing'"] +
                    ["    --filter 'gramc_projet=^p20' --filter "
                     "'gramc_projet=^p21' --filter 'or'\n"] +
                    ["Predefined filters :"] +
                    [predefined_filters_help_format(predefined, current_object)] +
                    ["\n"])
                
            )
        except Exception as e:
            raise

        log.debug(f"Found filters : {filters}")

        # Generate headers and attributes list to retrieve for csv output
        option_name = f"{current_action}_{current_object}_attribute"
        if dpo[option_name] is None:
            if predefined_filters_attributes is None:
               parser.exit(
                status=1,
                message=f"\n\nNo default attributes\n"
            ) 
            else:
                dpo[option_name] = [[a] for a in predefined_filters_attributes]
                log.debug(f"Predefined attributes : {dpo[option_name]}")
        cli_attrs = list(chain.from_iterable(dpo[option_name]))

        # Expand cli attrs 
        requested_attrs = []
        for a in cli_attrs:
            if a.endswith("_all"):
                module = a.replace("_all", "")
                m = obj.atypes()[module]
                requested_attrs += [
                    f"{module}_{a}" for a in m.attrs() + m.attrs_ext()
                ]
            elif a.endswith("_std"):
                module = a.replace("_std", "")
                m = obj.atypes()[module]
                requested_attrs += [f"{module}_{a}" for a in m.attrs()]
            elif a.endswith("_ext"):
                module = a.replace("_ext","")
                m = obj.atypes()[module]
                requested_attrs += [f"{module}_{a}" for a in m.attrs_ext()]
            else:
                requested_attrs.append(a)
        log.debug(f"Requested command line attributes : {requested_attrs}")

        if requested_attrs:

            hheaders = requested_attrs
            log.debug(f"Headers : {hheaders}")

            # Process all needed populate
            hpcs = None
            if current_object == "group":
                hpcs = mm_groups()
                hpcs.populate()
            elif current_object == "user":
                hpcs = mm_users()
                hpcs.populate()
            else:
                raise NotImplementedError(
                    f"Unknown object '{current_object}' ..."
                )

            if dpo[f"{current_action}_generate_missing"]:
                log.debug(f"Generate missing attributes ...")
                hpcs.generate_missing()

            # Filter
            if hpcs is not None and filters:
                log.debug(f"Applying filters {filters} ...")
                hfiltered = hpcs.filters(filters)
                hdisplay = hfiltered
            else:
                hdisplay = hpcs

            # Write csv headers
            if not parser_options.list_no_header:
                head_csv = writer(
                    parser_options.list_output,
                    delimiter=parser_options.list_delimiter, 
                    lineterminator='\n'
                )
                head_csv.writerow(hheaders)
            # Write csv data
            if hdisplay is not None:
                attr_dict = hdisplay.fdattrs(requested_attrs)
                attr_csv = DictWriter(
                    parser_options.list_output, fieldnames=hheaders,
                    delimiter=parser_options.list_delimiter,
                    extrasaction='ignore', restval="", lineterminator='\n', 
                    quoting=QUOTE_MINIMAL
                )
                attr_csv.writerows(attr_dict)
        else:
            parser.exit(
                status=1,
                message=f"\n\nYou must provide at least one attribute\n"
            )
    elif current_action in ['create','delete']:
        current_object = dpo["objects"]
        obj = None
        if current_object == "group":
            obj = mm_group
        elif current_object == "user":
            obj = mm_user
        if current_object in ['group', 'user']:
            for csv_file in dpo[f'{current_action}_from_csv']:
                log.debug(
                    f"{current_action.title()} {obj} from file "
                    f"{csv_file.name} ..."
                )
                csv_obj_data = DictReader(csv_file, delimiter=':')
                for obj_data in csv_obj_data:
                    log.debug(
                        f"{current_action.title()} {obj} '{obj_data}' from "
                        f"file {csv_file.name} ..."
                    )
                    o = obj()
                    o.from_dict(obj_data)
                    doit = False
                    if dpo[f'{current_action}_doit'] == f'YesIReallyWantToUseThisBetaFeature{current_action.title()}':
                        doit = True
                    if current_action == 'create':
                        o.call(
                            command="create",undo="delete",doit=doit,
                            stop_on_failure=not dpo['create_continue_on_failure']
                        )
                    elif current_action == 'delete':
                        o.call(
                            command="delete",undo="create",
                            doit=doit,stop_on_failure=not dpo['delete_continue_on_failure'],
                            revert_order=True
                        )
        else:
            if current_action == 'delete':
                parser.print_help()
                parser.exit(
                    status=0,
                )
            elif current_action == 'create':
                # TODO : Ajouter un sleep de 10s tous les 10 quotas
                if 'debug' not in parser_options \
                   or parser_options.debug.upper() not in ["INFO", "DEBUG", "TRACE"]:
                    rootlogger.setLevel("INFO")

                if config['develop'] == "On":
                    quota_list_file_name = Path(
                        config["rootPath"]
                    ).joinpath("olympe/etc/quotas")
                    with open(quota_list_file_name) as quota_list_file:
                        acct = quota_list_file.readlines()
                else:
                    acct = run(
                        f"{config['binary']['conso_manager']} list --quota "
                        "--type recherche"
                    )

                pacct = DictReader(
                    acct, fieldnames=["projet", "quota"], delimiter=":"
                )

                pcquotas = {
                    a["projet"]: int(a["quota"]) 
                    if is_number(a["quota"]) else 0
                    for a in pacct
                }

                ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%s')

                # All groups
                hpcgs = mm_groups()
                hpcgs.populate()
                hpcgs.generate_missing()

                # New groups
                uheaders = [
                    'unix_group', 'unix_password', 'unix_gid', 'unix_musers'
                ]

                if grconfig['apiUrl'] == grconfig['apiDevUrl']:
                    (_, ng_filters) = predefined_filters_expand(
                        predefined,
                        'group', ['predefined=PreSessionNewGroups']
                    )
                else:
                    (_, ng_filters) = predefined_filters_expand(
                        predefined,
                        'group', ['predefined=SessionNewGroups']
                    )

                ng_filtered = hpcgs.filters(mm_group.to_filters(ng_filters))

                log.info(
                    f"Found {ng_filtered.len()} new groups to create for "
                    f"session {grconfig['session']['new']}"
                )
                # Write group file with unix group attributes
                if ng_filtered.len() > 0:
                    attr_dict = ng_filtered.fdattrs(uheaders)

                    output_group_file_name = Path(
                        config['rootPath']
                    ).joinpath(
                        config['dataPath'], 
                        f"group_{grconfig['session']['new']}_{ts}"
                    )
        
                    log.info(
                        f"Generating new group file for session "
                        f"{grconfig['session']['new']} ..."
                    )
                    with open(
                            output_group_file_name, 'w'
                        ) as output_group_file:
                        attr_csv = DictWriter(
                            output_group_file, fieldnames=uheaders, 
                            delimiter=':', extrasaction='ignore', 
                            restval="", lineterminator='\n'
                        )
                        attr_csv.writerows(attr_dict)
                        log.info(
                            f"  => Generated file : {output_group_file_name}"
                        )
                        log.info(
                            f"Generating new group file for session "
                            f"{grconfig['session']['new']} : [DONE]"
                        )

                # Renew groups
                if grconfig['apiUrl'] == grconfig['apiDevUrl']:
                    (_, rng_filters) = predefined_filters_expand(
                        predefined,
                        'group', ['predefined=PreSessionReNewGroups']
                    )
                else:
                    (_, rng_filters) = predefined_filters_expand(
                        predefined,
                        'group', ['predefined=SessionReNewGroups']
                    )
                
                rng_filtered = hpcgs.filters(mm_group.to_filters(rng_filters))
                log.info(
                    f"Found {rng_filtered.len()} groups to renew for session "
                    f"{grconfig['session']['new']}"
                )

                # Users
                hpcus = mm_users()
                hpcus.populate()
                hpcus.generate_missing()
                
                # New users
                if grconfig['apiUrl'] == grconfig['apiDevUrl']:
                    (_, u_filter) = predefined_filters_expand(
                        predefined,
                        'user', ['predefined=PreSessionNewUsers']
                    )
                else:
                    (_, u_filter) = predefined_filters_expand(
                        predefined,
                        'user', ['predefined=SessionNewUsers']
                    )   
                nu_filtered = hpcus.filters(mm_user.to_filters(u_filter))

                # Hook to set user gid
                for user in nu_filtered:
                    user.unix.gid = hpcgs.get_by_ids(user.unix.pgroup).unix.gid

                passwd_attr_dict = []
                shadow_attr_dict = []
                uemails = []
                nquotas = {}
                piemails = []

                # Mail merge for new project
                log.info("New accounts for new groups")
                np_attrs_dict = []
                for np in ng_filtered:
                    npusers = nu_filtered.filters([
                        (None, 'unix_pgroup', '=', f'^{np.unix.group}$')
                    ])
                    
                    if npusers.len() > 0:
                        upheaders = [
                            'unix_login', 'unix_password', 'unix_uid', 
                            'unix_gid', 'unix_comment', 'unix_home',
                            'unix_shell'
                        ]
                        passwd_attr_dict += npusers.fdattrs(upheaders)
                        usheaders = ['unix_login', 'unix_cryptedpassword']
                        shadow_attr_dict += npusers.fdattrs(usheaders)

                        uemails += [
                            f"{np.gramc.utilisateur}\n" for np in npusers
                        ]

                        np_accounts = "<br/>".join(
                            [f"Utilisateur : {npu.unix.login} "
                            f"({ssafe(npu.gramc.prenom)} "
                            f"{ssafe(npu.gramc.nom)}, "
                            f"{npu.gramc.utilisateur})"
                            for npu in npusers]
                        )
                        log.debug(f"New accounts : {np_accounts}")
                        u_name_list = [ 
                            f"{u.gramc.prenom} {u.gramc.nom}" 
                            for u in npusers
                        ]
                        log.info(
                            f"  * {np.unix.group} : {npusers.len()} user(s) "
                            f"{u_name_list} to create"
                        ) 
                    else:
                        np_accounts = grconfig['createNoUserMsg']

                    np_dict = np.fdattrs([
                        "gramc_idprojet", "gramc_lmail", "gramc_lsession"
                    ])[0]
                    attribution = np.gramc.lattribution
                    np_dict.update({
                        "session_lattribution": attribution})
                    np_dict.update({"accounts": np_accounts})
                    np_attrs_dict.append(np_dict)
                    nquotas.update({np.unix.group: np.gramc.lattribution})
                    piemails.append(f"{np.gramc.lmail}\n")

                if np_attrs_dict:
                    uheaders = [
                        "gramc_idprojet", "gramc_lmail", "gramc_lsession", 
                        "session_lattribution", "accounts"
                    ]
                    output_mailmerge_np_file_name = Path(
                        config['rootPath']
                    ).joinpath(
                        config['dataPath'], 
                        f"mailmerge_new_{grconfig['session']['new']}_{ts}.csv"
                    )

                    log.info(
                        f"Generating mail merge for new project for "
                        f"session {grconfig['session']['new']} ..."
                    )
                    with open(
                            output_mailmerge_np_file_name, 'w', 
                            encoding="utf8"
                        ) as output_mailmerge_np_file:
                        # Write csv headers
                        head_csv = writer(
                            output_mailmerge_np_file, delimiter=',', 
                            lineterminator='\n'
                        )
                        head_csv.writerow(uheaders)
                        # Write csv data
                        attr_csv = DictWriter(
                            output_mailmerge_np_file, fieldnames=uheaders, 
                            delimiter=',', extrasaction='ignore', 
                            restval="", lineterminator='\n'
                        )
                        attr_csv.writerows(np_attrs_dict)
                        log.info(
                            f"  => Generated file : "
                            f"{output_mailmerge_np_file_name}"
                        )
                        log.info(
                            f"Generating mail merge for new project for "
                            f"session {grconfig['session']['new']} : [DONE]"
                        )

                # Mail merge for renewed project
                rnpwu_attrs_dict = []
                rnpwou_attrs_dict = []

                if grconfig['apiUrl'] == grconfig['apiDevUrl']:
                    log.warning(
                        "We are on GRAMC dev API, we do not check "
                        "attribution > quota"
                    )
                    rngq = [
                        rng for rng in rng_filtered
                        if rng.unix.group in pcquotas
                    ]
                else:
                    rngq = [
                        rng for rng in rng_filtered
                        if rng.unix.group in pcquotas and 
                           rng.gramc.lattribution > pcquotas[rng.unix.group]
                    ]

                for rnp in rngq:
                    rnpusers = nu_filtered.filters([
                        (None, 'unix_pgroup', '=', f'^{rnp.unix.group}$')
                    ])
                    if rnpusers.len() > 0:
                        log.info("New accounts for renew groups")
                        upheaders = [
                            'unix_login', 'unix_password', 'unix_uid', 
                            'unix_gid', 'unix_comment', 'unix_home',
                            'unix_shell'
                        ]
                        passwd_attr_dict += rnpusers.fdattrs(upheaders)
                        usheaders = ['unix_login', 'unix_cryptedpassword']
                        shadow_attr_dict += rnpusers.fdattrs(usheaders)

                        uemails += [
                            f"{rnp.gramc.utilisateur}\n" for rnp in rnpusers
                        ]

                        # With new users
                        rnp_accounts = "<br/>".join(
                            [f"Utilisateur : {npu.unix.login} "
                            f"({ssafe(npu.gramc.prenom)} "
                            f"{ssafe(npu.gramc.nom)}, "
                            f"{npu.gramc.utilisateur})"
                            for npu in rnpusers]
                        )
                        rnp_dict = rnp.fdattrs([
                            "gramc_idprojet", "gramc_lmail", "gramc_lsession"
                        ])[0]
                        attribution = rnp.gramc.lattribution - pcquotas[rnp.gramc.projet]
                        rnp_dict.update(
                            {"session_lattribution": attribution})
                        rnp_dict.update({"accounts": rnp_accounts})
                        rnpwu_attrs_dict.append(rnp_dict)
                        u_name_list = [ 
                            f"{u.gramc.prenom} {u.gramc.nom}" 
                            for u in rnpusers
                        ]
                        log.info(
                            f"  * {rnp.unix.group} : {rnpusers.len()} "
                            f"user(s) {u_name_list} to create"
                        )

                    else:
                        # Without new users
                        rnp_dict = rnp.fdattrs([
                            "gramc_idprojet", "gramc_lmail", "gramc_lsession"
                        ])[0]
                        attribution = rnp.gramc.lattribution - pcquotas[rnp.gramc.projet]
                        rnp_dict.update({"session_lattribution": attribution})
                        rnpwou_attrs_dict.append(rnp_dict)

                    nquotas.update({rnp.unix.group: rnp.gramc.lattribution})

                if rnpwu_attrs_dict:
                    # Mail merge for renewed project with users
                    uheaders = [
                        "gramc_idprojet", "gramc_lmail", "gramc_lsession", 
                        "session_lattribution", "accounts"
                    ]
                    output_mailmerge_rnpwu_file_name = Path(
                        config['rootPath']
                    ).joinpath(
                        config['dataPath'], 
                        f"mailmerge_renew_with_user_{grconfig['session']['new']}_{ts}.csv"
                    )

                    log.info(
                        f"Generating mail merge for project renew with user "
                        f"for session {grconfig['session']['new']}  ..."
                    )
                    with open(
                            output_mailmerge_rnpwu_file_name, 'w'
                        ) as output_mailmerge_rnpwu_file:
                        # Write csv headers
                        head_csv = writer(
                            output_mailmerge_rnpwu_file, delimiter=',', 
                            lineterminator='\n'
                        )
                        head_csv.writerow(uheaders)
                        # Write csv data
                        attr_csv = DictWriter(
                            output_mailmerge_rnpwu_file, fieldnames=uheaders,
                            delimiter=',', extrasaction='ignore', 
                            restval="", lineterminator='\n'
                        )
                        attr_csv.writerows(rnpwu_attrs_dict)
                        log.info(
                            f"  => Generated file : "
                            f"{output_mailmerge_rnpwu_file_name}"
                        )
                        log.info(
                            f"Generating mail merge for project renew with "
                            f"user for session {grconfig['session']['new']} "
                            f": [DONE]")

                if rnpwou_attrs_dict:
                    # Mail merge for renewed project without users
                    uheaders = [
                        "gramc_idprojet", "gramc_lmail", "gramc_lsession", 
                        "session_lattribution"
                    ]
                    output_mailmerge_rnpwou_file_name = Path(
                        config['rootPath']
                    ).joinpath(
                        config['dataPath'], 
                        f"mailmerge_renew_without_user_{grconfig['session']['new']}_{ts}.csv"
                    )

                    log.info(
                        f"Generating mail merge renew for project without "
                        f"user for session {grconfig['session']['new']} ..."
                    )
                    with open(
                            output_mailmerge_rnpwou_file_name, 'w'
                        ) as output_mailmerge_rnpwou_file:
                        # Write csv headers
                        head_csv = writer(output_mailmerge_rnpwou_file,
                                        delimiter=',', lineterminator='\n')
                        head_csv.writerow(uheaders)
                        # Write csv data
                        attr_csv = DictWriter(
                            output_mailmerge_rnpwou_file, fieldnames=uheaders,
                            delimiter=',', extrasaction='ignore', 
                            restval="", lineterminator='\n'
                        )
                        attr_csv.writerows(rnpwou_attrs_dict)
                        log.info(
                            f"  => Generated file : "
                            f"{output_mailmerge_rnpwou_file_name}"
                        )
                        log.info(
                            f"Generating mail merge for project renew without "
                            f"user for session {grconfig['session']['new']} "
                            f": [DONE]")

                if passwd_attr_dict:
                    # Write password file with unix user password file 
                    # attributes
                    output_passwd_file_name = Path(
                        config['rootPath']
                    ).joinpath(
                        config['dataPath'], f"passwd_{grconfig['session']['new']}_{ts}"
                    )

                    log.info(
                        f"Generating new passwd file for session "
                        f"{grconfig['session']['new']} ..."
                    )
                    uheaders = [
                        "unix_login", "unix_password", "unix_uid", "unix_gid",
                        "unix_comment", "unix_home", "unix_shell"
                    ]
                    with open(
                            output_passwd_file_name, 'w'
                        ) as output_passwd_file:
                        attr_csv = DictWriter(
                            output_passwd_file, fieldnames=uheaders,
                            delimiter=':', extrasaction='ignore', 
                            restval="", lineterminator='\n'
                        )
                        attr_csv.writerows(passwd_attr_dict)
                        log.info(
                            f"  => Generated file : {output_passwd_file_name}"
                        )
                        log.info(
                            f"Generating new passwd file for session "
                            f"{grconfig['session']['new']} : [DONE]"
                        )

                if shadow_attr_dict:
                    # Write shadow file with unix user shadow file attributes
                    output_shadow_file_name = Path(
                        config['rootPath']
                    ).joinpath(
                        config['dataPath'], f"shadow_{grconfig['session']['new']}_{ts}"
                    )

                    log.info(
                        f"Generating new shadow file for session "
                        f"{grconfig['session']['new']} ..."
                    )
                    uheaders = [
                        'unix_login', 'unix_cryptedpassword', 'lastchanged', 
                        'minimum', 'maximum', 'warn', 'inactive', 'expire'
                    ]
                    with open(
                            output_shadow_file_name, 'w'
                        ) as output_shadow_file:
                        attr_csv = DictWriter(
                            output_shadow_file, fieldnames=uheaders,
                            delimiter=':', extrasaction='ignore', 
                            restval="", lineterminator='\n'
                        )
                        attr_csv.writerows(shadow_attr_dict)
                        log.info(
                            f"  => Generated file : "
                            f"{output_shadow_file_name}"
                        )
                        log.info(
                            f"Generating new shadow file for session "
                            f"{grconfig['session']['new']} : [DONE]"
                        )

                if uemails:
                    if grconfig['session']['new'].endswith("B"):
                        # Write user emails to add to sympa mailling list
                        output_emails_file_name = Path(
                            config['rootPath']
                        ).joinpath(
                            config['dataPath'], 
                            f"sympa_user_emails_{grconfig['session']['new']}_{ts}"
                        )

                        log.info(
                            f"Generating sympa user emails for "
                            f"session {grconfig['session']['new']} ..."
                        )
                        with open(
                                output_emails_file_name, 'w'
                            ) as output_emails_file:
                            output_emails_file.writelines(uemails)
                            log.info(
                                f"  => Generated file : "
                                f"{output_emails_file_name}"
                            )
                            log.info(
                                f"Generating sympa user emails for session "
                                f"{grconfig['session']['new']} : [DONE]"
                            )
                    else:
                        log.warning(
                            f"Generating sympa user emails for session "
                            f"{grconfig['session']['new']} must be done by "
                            f"hand when all users and projects are created"
                        )

                if piemails:
                    if grconfig['session']['new'].endswith("B"):
                        # Write pi emails to add to sympa mailling list
                        output_piemails_file_name = Path(
                            config['rootPath']
                        ).joinpath(
                            config['dataPath'], 
                            f"sympa_pi_emails_{grconfig['session']['new']}_{ts}"
                        )

                        log.info(
                            f"Generating sympa pi emails for session "
                            f"{grconfig['session']['new']} ..."
                        )
                        with open(
                                output_piemails_file_name, 'w'
                            ) as output_piemails_file:
                            output_piemails_file.writelines(piemails)
                            log.info(
                                f"  => Generated file : "
                                f"{output_piemails_file_name}"
                            )
                            log.info(
                                f"Generating sympa user piemails for session "
                                f"{grconfig['session']['new']} : [DONE]"
                            )
                    else:
                        log.warning(
                            f"Generating sympa pi emails for session "
                            f"{grconfig['session']['new']} must be done by "
                            f"hand when all projects are created")

                if nquotas:
                    # Write project quota command to update project's quota
                    output_quotas_file_name = Path(
                        config['rootPath']
                    ).joinpath(
                        config['dataPath'], 
                        f"project_quotas_{grconfig['session']['new']}_{ts}.command"
                    )

                    commands = []
                    sleep_step = 10
                    sleep_counter = 0
                    for p, q in nquotas.items():
                        quotacmd = f"{config['binary']['conso_manager']} " \
                                   f"quota --group {p} " \
                                   f"--cpu {q} --gpu {q}\n"
                        unlockcommand = f"{config['binary']['conso_manager']} " \
                                        f"unlock --group {p}\n"

                        if sleep_counter > 0 \
                           and sleep_counter % sleep_step == 0 :
                            commands += [f"sleep {sleep_step}\n"]
                        
                        commands += [
                            f"# {p}\n", quotacmd, unlockcommand, "#\n"
                        ]
                        sleep_counter += 1

                    log.info(
                        f"Generating project quota command for session "
                        f"{grconfig['session']['new']} ..."
                    )
                    with open(
                            output_quotas_file_name, 'w'
                        ) as output_quotas_file:
                        output_quotas_file.writelines(commands)
                        log.info(
                            f"  => Generated file : {output_quotas_file_name}"
                        )
                        log.info(
                            f"Generating project quota command for session "
                            f"{grconfig['session']['new']} : [DONE]"
                        )

    elif current_action == 'update':
        if parser_options.debug not in ["INFO", "DEBUG", "TRACE"]:
            rootlogger.setLevel("INFO")

        if config['develop'] == "On":
            quota_list_file_name = Path(
                config["rootPath"]
            ).joinpath("olympe/etc/quotas")
            with open(quota_list_file_name) as quota_list_file:
                acct = quota_list_file.readlines()
        else:
            acct = run(
                f"{config['binary']['conso_manager']} "
                f"list --quota --type recherche"
            )

        pacct = DictReader(acct, fieldnames=["projet", "quota"], delimiter=":")

        pcquotas = {a["projet"]: int(a["quota"]) for a in pacct}

        ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%s')

        # All groups
        hpcgs = mm_groups()
        hpcgs.populate()

        # All actif groups
        (_, g_filter) = predefined_filters_expand(
            predefined,
            'group', ['predefined=SessionGroups']
        )
        g_filtered = hpcgs.filters(mm_group.to_filters(g_filter))

        log.info(
            f"Found {g_filtered.len()} groups in active state for new session "
            f"session {grconfig['session']['new']} and current sessions "
            f"{grconfig['session']['current']}"
        )

        nquotas = {}
        p_attrs_dict = []
        
        if grconfig['apiUrl'] == grconfig['apiDevUrl']:
            log.warning(
                "We are on GRAMC dev API, we do not check attribution > quota"
            )
            gq = [g for g in g_filtered if g.unix.group in pcquotas]
        else:
            gq = [
                g for g in g_filtered
                if g.unix.group in pcquotas and 
                   g.gramc.lattribution < pcquotas[g.unix.group]
            ]

        for p in gq:
            p_dict = p.fdattrs(["gramc_idprojet", "gramc_lmail"])[0]
            p_dict.update({"session": grconfig['session']['new']})
            p_attrs_dict.append(p_dict)
            nquotas.update({p.unix.group: p.gramc.lattribution})
        
        if nquotas:
            # Write project quota command to update project's quota
            output_quotas_file_name = Path(config['rootPath']).joinpath(
                config['dataPath'], f"project_update_quotas_{ts}.command"
            )

            commands = []
            for p, q in nquotas.items():
                quotacmd = f"{config['binary']['conso_manager']} " \
                           f"quota --group {p} " \
                           f"--cpu {q} --gpu {q}\n"
                commands += [f"# {p}\n", quotacmd, "#\n"]

            log.info(
                f"Generating project quota command for applying penalities ..."
            )
            with open(output_quotas_file_name, 'w') as output_quotas_file:
                output_quotas_file.writelines(commands)
                log.info(f"  => Generated file : {output_quotas_file_name}")
                log.info(
                    f"Generating project quota command for applying "
                    f"penalities : [DONE]"
                )

        if p_attrs_dict:

            uheaders = ["gramc_idprojet", "gramc_lmail", "lsession"]
            output_mailmerge_p_file_name = Path(config['rootPath']).joinpath(
                config['dataPath'], f"mailmerge_update_quotas_{ts}.csv"
            )

            log.info(f"Generating mail merge for update quotas projects ...")
            with open(
                    output_mailmerge_p_file_name, 'w', encoding="utf8"
                ) as output_mailmerge_p_file:
                # Write csv headers
                head_csv = writer(
                    output_mailmerge_p_file, delimiter=',', 
                    lineterminator='\n'
                )
                head_csv.writerow(uheaders)
                # Write csv data
                attr_csv = DictWriter(
                    output_mailmerge_p_file, fieldnames=uheaders, 
                    delimiter=',', extrasaction='ignore', 
                    restval="", lineterminator='\n'
                )
                attr_csv.writerows(p_attrs_dict)
                log.info(
                    f"  => Generated file : {output_mailmerge_p_file_name}"
                )
                log.info(
                    f"Generating mail merge for update quotas projects "
                    f": [DONE]"
                )

    else:
        parser.print_help()
        parser.exit(
            status=0,
        )

    return 0

meta_module = get_current_meta_module_config(__file__)
root_parser = init_parser()
__doc__ += f"{root_parser.format_help()}"

if __name__ == '__main__':
    exit(main(argv[1:], parser=root_parser, meta_module=meta_module))
