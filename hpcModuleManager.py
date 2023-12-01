# -*- coding: utf-8 -*-

"""Hpc Module manager program

This program is used for managing hpc users and groups from module

"""
from csv import writer, DictWriter, DictReader
from sys import argv, exit, stdout
from argparse import (
    ArgumentParser, FileType, RawDescriptionHelpFormatter, SUPPRESS
)
from config.configManager import continue_on_failure_parser
from itertools import chain
from config.config import config
from hpc.utils import help_format, get_current_module_config
from sys import exit
from hpc.generics import GenericObjects
#from config.configFilters import predefined
from hpc.filters import (
    predefined_filters_expand, predefined_filters_help_format
)


# Comment next line when in prod
#from cilogger.cilogger import rootlogger #, ftrace
# Uncomment next lines when in prod
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
#rootlogger.setLevel("TRACE")

def action_properties(d_action: dict, dpo: dict) -> tuple:
    # Check for common options 'doit' or 'continue on failure' and if 
    # method has undo method associated
    if 'common_doit' in dpo:
        doit = dpo['common_doit']
    else:
        doit = False
    
    if isinstance(d_action['doit'], str):
        undo = d_action['doit']
    else:
        undo = None

    if 'common_continue_on_failure' in dpo:
        continue_on_failure = dpo['common_continue_on_failure']
    else:
        continue_on_failure = False

    log.debug(
        f"Action : doit={doit}, undo={undo}, "
        f"continue_on_failure={continue_on_failure}"
    )
    return (doit, undo, continue_on_failure)

def action_check(d_action: dict, module: dict, obj: str, odatas: list) -> list:
    
    mok = [k for k in module['objects'][obj]['keys']]
    l_o = []

    # we check if keys are requires arguments and raise error if not
    if set(d_action['required_attributes']) >= set(mok):
        # we check required_attributes are in object given attributes

        moname = module['objects'][obj]['name']
        mos = module['objects'][obj]['list']
        mo = module['objects'][obj]['type']
        
        os = mos()
        os.populate()
        
        for o_data in odatas:
            o = None
            if set(o_data.keys()) >= set(d_action['required_attributes']):
                s_o = os.filters(
                    [(None, k, '=', f'^{o_data[k]}$') for k in mok]
                )
            
                opts = [f"{k}={o_data[k]}" for k in mok]
                if d_action['check'] == 'presence':
                    # Object must exist to do the action
                    
                    if s_o.len() == 1 and None not in s_o:
                        o = next(iter(s_o),None)
                        log.debug(
                            f"Found unique object {o} with keys "
                            f"{' and '.join(opts)} (Presence check)."
                        )
                    elif s_o.len() < 1 or ( s_o.len() == 1 and None in s_o ):
                        log.error(
                            f"Unable to find {moname} {obj} object with "
                            f"keys {' and '.join(opts)} (Presence check)."
                        )
                        exit(2)
                    else:
                        raise ValueError(
                            f"For some unknown reason object search with keys "
                            f"{' and '.join(opts)} gives more than one object "
                            f"(Presence check)." 
                        )

                elif d_action['check'] == 'absence':
                    # Object must exist to do the action
                    if s_o.len() == 0 or ( s_o.len() == 1 and None in s_o ):
                        log.debug(
                            f"Unique object with keys {' and '.join(opts)} "
                            f"not found (Missing check)."
                        )
                        o = mo()
                        try:
                            log.debug(f"Trying to create object from dict {o_data}")
                            o.from_dict(
                                o_data, d_action['required_attributes'], 
                                d_action['optional_attributes']
                            )
                        except Exception as e :
                            log.error(e)
                            if rootlogger.isEnabledFor(rootlogger.DEBUG):
                                raise(e)
                            exit(1)
                        
                    elif s_o.len() == 1 and None not in s_o:
                        log.error(
                            f"{moname.title()} {obj} object with "
                            f"keys {' and '.join(opts)} already exists "
                            f"(Missing check)."
                        
                        )
                        exit(2)
                    else:
                        raise ValueError(
                            f"For some unknown reason object search with keys "
                            f"{' and '.join(opts)} gives more than one object "
                            f"(Missing check)." 
                        )
                else:
                    raise NotImplementedError(
                        f"Check '{d_action['check']}' is not available for callable."
                    )
            else:
                raise ValueError(
                    "All required attributes must at least be in given attributes by "
                    "design, so strange behavior happens ..."
                )
        l_o.append(o)
    else:
        raise ValueError(
            "All attributes keys must at least be in required attributes if "
            "you want to check absence or presence"
        )
    
    return l_o

def action_do(
        objects: list, command: str, doit: bool=False, undo: str=None, continue_on_failure: 
        bool=False, **kwargs):

    # Calling method
    for o in objects:
        
        try:
            done = o.call(
                command=command, undo=undo, doit=doit,
                stop_on_failure=not continue_on_failure, **kwargs
            )
            if done and doit:
                for r in done:
                    log.info(r)
        except Exception as e:
            log.error(e)
            if rootlogger.isEnabledFor(rootlogger.DEBUG):
                raise(e)


# @ftrace
def init_parser() -> ArgumentParser:
    """Initialize argparse parser. We use a function to be able to add help in 
    pydoc

    :return: An initialized argparse parser
    """
    module = get_current_module_config(__file__)
    log.trace(
        f"Actions for groups : "
        f"{module['objects']['group']['type'].actions(names=True)}"
    )
    log.trace(
        f"Actions for users : "
        f"{module['objects']['user']['type'].actions(names=True)}"
    )
    log.trace(
        f"Actions with methods for groups : "
        f"{module['objects']['group']['type'].actions(command=True, names=True)}"
    )
    log.trace(
        f"Actions with methods for users : "
        f"{module['objects']['user']['type'].actions(command=True, names=True)}"
    )

    module_objects = list(module['objects'].keys())
    log.trace(f"Module objects names : {module_objects}")

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

    # Doit parser
    doit_parser = ArgumentParser(
        add_help=False
    )
    doit_parser.add_argument(
        '--doit', dest='common_doit', 
        required=False, action='store_true',
        help=f"Really do actions else just print what should be done"
    )

    # Main parser
    local_parser = ArgumentParser(
        description=f"{module['name'].title()} user and group manager",
        parents=[common_args_parser],
        allow_abbrev=True,
    )

    # Objects options
    object_subparser = local_parser.add_subparsers(dest="objects")
    
    for oname, obj in module['objects'].items():
        mo = obj['type']
        object_parser = object_subparser.add_parser(
            f"{oname}",
            parents=[common_args_parser],
            help=f"Manage {module['name'].title()} for {oname}s"
        )

        action_subparser = object_parser.add_subparsers(
            dest="actions", 
            title="Actions available for this module",
            help='',
            metavar=''
        )

        for aname in mo.actions(names=True):
            command_subparser = {}
            log.trace(f"Add action parser '{aname}'")

            s_cmd = ''
            commands = mo.commands(action=aname, names=True)
            if commands:
                s_cmd = f"{' and '.join(commands)} for "

            action_parser = action_subparser.add_parser(
                f"{aname}",
                parents=[common_args_parser],
                help=f"{aname.title()} {s_cmd}{module['name'].title()} {oname}s"
            )

            # Default options for actions
            # TODO : Make a config file

            ### Default options for create or delete actions
            if aname in mo.actions(command=False, names=True) and \
               (aname == "create" or aname == "delete"):
                
                d_action = mo.action(action=aname, command=None)
                command_subparser.update({aname: action_parser.add_subparsers(
                    dest="commands", 
                    title=f"{aname.title()} actions available for this module",
                    help='',
                    metavar=''
                )})
        
                delimiter=':'
                csv_parser = command_subparser[aname].add_parser(
                    "from-csv",
                    parents=[
                        common_args_parser, doit_parser, 
                        continue_on_failure_parser
                    ],
                    help=f"{aname.title()} a {oname} from a csv file with at "
                         f"least required fields "
                         f"({', '.join(d_action['required_attributes'])}) "
                         f"separated by '{delimiter}' by default"
                )

                csv_parser.add_argument(
                    "--csv-file", dest=f"{aname}_from-csv_csv-file", nargs="+",
                    metavar="</path/to/file.csv>",
                    type=FileType('r'), required=True,
                    help=f"{aname.title()} {module['name']} {oname} from csv "
                         f"file separated by '{delimiter}' by default"
                )
                csv_parser.add_argument(
                    "--delimiter", dest=f"{aname}_from-csv_delimiter", 
                    metavar="<delimiter>", type=str, 
                    required=False, default=delimiter,
                    help=f"Output field delimiter ('{delimiter}' by default)"
                )
        
                inline_parser = command_subparser[aname].add_parser(
                    "inline",
                    parents=[
                        common_args_parser, doit_parser, 
                        continue_on_failure_parser
                    ],
                    help=f"{aname.title()} a {oname} from arguments provided "
                         f"on command line"
                )    

                for attribute in d_action['required_attributes']:
                    d_attribute = mo.attribute(attribute)
                    input_type = d_attribute['type']
                    if issubclass(d_attribute['type'], GenericObjects):
                        input_type = list
                    inline_parser.add_argument(
                        f"--{attribute}", dest=f"{aname}_inline_{attribute}", 
                        metavar=f"<{attribute}>",
                        type=input_type, required=True,
                        help=f"{d_attribute['help']} (required)"
                    )
                for attribute in d_action['optional_attributes']:
                    d_attribute = mo.attribute(attribute)
                    input_type = d_attribute['type']
                    if issubclass(d_attribute['type'], GenericObjects):
                        input_type = list
                    inline_parser.add_argument(
                        f"--{attribute}", dest=f"{aname}_inline_{attribute}", 
                        metavar=f"<{attribute}>",
                        type=input_type, required=False,
                        help=f"{d_attribute['help']}"
                    )

            ### Default options for list action
            elif aname in mo.actions(command=False, names=True) \
                 and (aname == "list"):
                action_parser.add_argument(
                    "--output", dest=f"{aname}_output", nargs='?', 
                    metavar="</path/to/file.csv>", type=FileType('w'), 
                    required=False, default=stdout,
                    help=f"Output file (stdout by default)"
                )
                action_parser.add_argument(
                    "--delimiter", dest=f"{aname}_delimiter", nargs='?', 
                    metavar="<delimiter>", type=str, 
                    required=False, default=',', 
                    help=f"Output field delimiter (',' by default)"
                )
                action_parser.add_argument(
                    "--no-header", dest=f"{aname}_no_header", 
                    action='store_true', required=False,
                    help=f"Remove headers from output"
                )

                # TODO : Check if needed ...
                # # Not implemented
                # action_parser.add_argument(
                #     "--generate-missing", dest=f"{aname}_generate_missing", action='store_true', required=False,
                #     help=f"Generate missing data if module's attributes have generators"
                # )

                log.trace(
                    f"Action '{aname}' examples tuples : {mo.action(aname)}"
                )
                
                epilog = "\n".join(
                    [f"Attribute field description :\n"] +
                    [f"{help_format(mo.help())}\n\n"]
                )
                d_action = mo.action(action=aname, command=None)
                if d_action is not None :
                    epilog += "\n\n\nExamples :\n\n" + "\n\n".join([
                        f"  * {e} :\n{__file__} {aname} {oname} {c}" 
                        for e, c in d_action['examples']
                    ])

                log.trace(f"Modules attributes : {mo.attrs()} {mo.attrs_ext()}")
                all_attributes = [
                    f"{a}" for a in mo.attrs() + mo.attrs_ext()
                ] + ["all", "std", "ext"]

                log.trace(f"Modules all attributes : {all_attributes}")
                
                action_parser.epilog=epilog
                action_parser.formatter_class=RawDescriptionHelpFormatter
            
                action_parser.add_argument(
                    f"--attribute", dest=f"{aname}_attribute",
                    metavar="<fields>", action="append", nargs='*',
                    choices=all_attributes,
                    default=None, required=False,
                    help="Display attribute info (see 'Attribute field "
                         "description'). You can use 'all', 'std' or 'ext' "
                         "to display all, standard or extended attributes."
                )

                # Filter
                action_parser.add_argument(
                    "--filter", dest=f"{aname}_filter",
                    metavar="<filter>", action="append", nargs='*',
                    default=None, required=False,
                    help=f"Filter an attribute value with a regexp "
                         f"'<attribute_name>=<regex>'. "
                         f"Filter example : 'unix_login=^toto*'",
                )
                
                all_generic_objects_attributes = [
                    f"{a}" for a, t in mo.atypes().items() 
                    if issubclass(t, GenericObjects) or issubclass(t,list)
                ]

                # Flatten a list or a GenericObjects attribute one line per object
                action_parser.add_argument(
                    "--flat", dest=f"{aname}_flat",
                    metavar="<attribute>", type=str, required=False, 
                    default=None, choices=all_generic_objects_attributes,
                    help=f"Expand a object list with one line per object."
                )
            else:
                if aname in mo.actions(command=False, names=True) \
                   and not mo.commands(action=aname):
                    log.trace(
                        f"Unhandled non default action '{aname}' without commands"
                    )
                    d_action = mo.action(action=aname, command=None)
                    for attribute in d_action['required_attributes']:
                        log.trace(
                            f"Adding required attribute '{attribute}' "
                            f"to action {aname} ..."
                        )
                        d_attribute = mo.attribute(attribute)
                        input_type = d_attribute['type']
                        if issubclass(d_attribute['type'], GenericObjects):
                            input_type = list
                        action_parser.add_argument(
                            f"--{attribute}", dest=f"{aname}_{attribute}", 
                            metavar=f"<{attribute}>",
                            type=input_type, required=True,
                            help=f"{d_attribute['help']} (required)"
                        )
                    for attribute in d_action['optional_attributes']:
                        log.trace(
                            f"Adding optional attribute '{attribute}' "
                            f"to action {aname} ..."
                        )
                        d_attribute = mo.attribute(attribute)
                        input_type = d_attribute['type']
                        if issubclass(d_attribute['type'], GenericObjects):
                            input_type = list
                        action_parser.add_argument(
                            f"--{attribute}", dest=f"{aname}_{attribute}", 
                            metavar=f"<{attribute}>",
                            type=input_type, required=False,
                            help=f"{d_attribute['help']}"
                        )
                else:
                    log.trace(
                        f"Unhandled non default action '{aname}' with commands"
                    )

            # Actions with commands   
            commands = mo.commands(action=aname)
            log.trace(f"[{aname}] Commands : {mo.commands(action=aname, names=True)}")
            if commands:
                if aname not in command_subparser:
                    command_subparser.update({aname: action_parser.add_subparsers(
                        dest="commands", 
                        title=f"{aname.title()} actions available for this module",
                        help='',
                        metavar=''
                    )})        
            
                for command in commands:
                    log.trace(f"Parsing command {command} ...")
                    
                    parent_parsers = [common_args_parser]
                    
                    if command['doit'] is not None or command['doit']:
                        parent_parsers += [doit_parser]
                    
                    if command['additional_arguments'] is not None:
                        for parser in command['additional_arguments']:
                            parent_parsers += [parser]

                    command_parser = command_subparser[aname].add_parser(
                        f"{command['command']}",
                        parents=parent_parsers,
                        help=f"{command['label']}s"
                    )

                    d_action = mo.action(action=aname, command=command['command'])
                    for attribute in d_action['required_attributes']:
                        log.trace(
                            f"Adding required attribute '{attribute}' "
                            f"to command {command['command']} ..."
                        )
                        d_attribute = mo.attribute(attribute)
                        input_type = d_attribute['type']
                        if issubclass(d_attribute['type'], GenericObjects):
                            input_type = list
                        command_parser.add_argument(
                            f"--{attribute}", dest=f"{aname}_{command['command']}_{attribute}", 
                            metavar=f"<{attribute}>",
                            type=input_type, required=True,
                            help=f"{d_attribute['help']} (required)"
                        )
                    for attribute in d_action['optional_attributes']:
                        log.trace(
                            f"Adding optional attribute '{attribute}' "
                            f"to command {command['command']} ..."
                        )
                        d_attribute = mo.attribute(attribute)
                        input_type = d_attribute['type']
                        if issubclass(d_attribute['type'], GenericObjects):
                            input_type = list
                        command_parser.add_argument(
                            f"--{attribute}", dest=f"{aname}_{command['command']}_{attribute}", 
                            metavar=f"<{attribute}>",
                            type=input_type, required=False,
                            help=f"{d_attribute['help']}"
                        )

    return local_parser


# @cilogger.cilogger.ftrace
def main(args: any, parser: ArgumentParser, module: dict) -> int:
    """Main program
    
    :param any args: Program args
    :param ArgumentParser parser: Program parser
    :param dict module: Module name

    :return: Excution status code

    :raise Exception: if an unhandled error is found when parsing filters
    :raise NotImplementedError: if a command is not implemented
    """
    parser_options = parser.parse_args(args)
    if 'debug' in parser_options:
        rootlogger.setLevel(parser_options.debug.upper())
    log.debug(f"Arguments found : {parser_options}")
    dpo = vars(parser_options)
    log.debug(f"Arguments found (dict) : {dpo}")
    log.debug(f"Loaded module : {module}")
    module_objects = list(module['objects'].keys())
    log.trace(f"Module objects names : {module_objects}")
    
    predefined = module['filters']

    current_object = dpo["objects"]
    if current_object in module_objects:

        current_action = dpo["actions"]
        moname = module['objects'][current_object]['name']
        mos = module['objects'][current_object]['list']
        mo = module['objects'][current_object]['type']

        if current_action in mo.actions(command=False, names=True) \
           and current_action  == "list":
            # Generate filters
            filters = []
            if dpo[f"{current_action}_filter"] is None:
                dpo[f"{current_action}_filter"] = [
                    [f"predefined={moname.title()}{current_object.title()}s"]
                ]
                
            opt_filters = list(chain.from_iterable(
                dpo[f"{current_action}_filter"]
            ))

            log.debug(f"Parsing filters : {opt_filters}")
            predefined_filters_attributes = None
            try:
                (predefined_filters_attributes, real_filters) = predefined_filters_expand(
                        predefined, current_object, opt_filters, moname
                    )
                log.debug(f"Object : {mo}")
                filters = mo.to_filters(real_filters)
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
                        [
                            "    --filter 'login=^toto.*' "
                            "--filter 'projet=^p21' "
                            "--filter 'or'\n"
                        ] +
                        ["Predefined filters :"] +
                        [
                            predefined_filters_help_format(
                                predefined, current_object, moname
                            )
                        ] +
                        ["\n"])
                    
                )
            except Exception as e:
                raise

            log.debug(f"Found filters : {filters}")

            # Generate headers and attributes list to retrieve for csv output
            option_name = f"{current_action}_attribute"
            if dpo[option_name] is None:
                if predefined_filters_attributes is None:
                    parser.exit(
                        status=1,
                        message=f"\n\nNo default attributes\n"
                    ) 
                else:
                    dpo[option_name] = [
                        [a] for a in predefined_filters_attributes
                    ]
                    log.debug(f"Predefined attributes : {dpo[option_name]}")
            cli_attrs = list(chain.from_iterable(dpo[option_name]))

            # Expand cli attrs 
            requested_attrs = []
            for a in cli_attrs:
                if a == "all":
                    requested_attrs += [
                        f"{a}" for a in mo.attrs() + mo.attrs_ext()
                    ]
                elif a == "std":
                    requested_attrs += [f"{a}" for a in mo.attrs()]
                elif a == "ext":
                    requested_attrs += [f"{a}" for a in mo.attrs_ext()]
                else:
                    requested_attrs.append(a)
            log.debug(f"Requested command line attributes : {requested_attrs}")

            if requested_attrs:
                oheaders = requested_attrs
                log.debug(f"Headers : {oheaders}")
                
                # Process all needed populate
                os = mos()
                os.populate()

                # Filter
                if os is not None and filters:
                    log.debug(f"Applying filters {filters} ...")
                    ofiltered = os.filters(filters)
                    odisplay = ofiltered
                else:
                    odisplay = os

                # TODO : Check if needed ...
                # # Not implemented
                # if dpo[f"{current_action}_generate_missing"]:
                #     log.debug(f"Generate missing attributes ...")
                #     odisplay.generate_missing()

                # Write csv headers
                if not parser_options.list_no_header:
                    head_csv = writer(
                        parser_options.list_output,
                        delimiter=parser_options.list_delimiter, 
                        lineterminator='\n'
                    )
                    head_csv.writerow(oheaders)
                # Write csv data
                if odisplay is not None:
                    flat_option_name = f"{current_action}_flat"
                    attr_dict = odisplay.fdattrs(
                        requested_attrs, flat=dpo[flat_option_name]
                    )
                    attr_csv = DictWriter(
                        parser_options.list_output, fieldnames=oheaders,
                        delimiter=parser_options.list_delimiter,
                        extrasaction='ignore', restval="", lineterminator='\n'
                    )
                    attr_csv.writerows(attr_dict)
            else:
                print("\nError : You must provide at least one attribute\n")
                parser_options = parser.parse_args(args+['-h'])
                
        elif current_action in mo.actions(command=False, names=True) \
             and current_action in ['create','delete']:

            current_command = dpo["commands"]
            if current_command in ["inline", "from-csv"]:
                csv_obj_data = []
                d_action = mo.action(action=current_action, command=None)
                if current_command == "from-csv":
                    for csv_file in dpo[f'{current_action}_{current_command}_csv-file']:
                        log.debug(
                            f"{current_action.title()} {moname} from file "
                            f"{csv_file.name} ..."
                        )
                        csv_obj_data.extend([
                            cod 
                            for cod in DictReader(
                                csv_file, 
                                delimiter=dpo[f'{current_action}_{current_command}_delimiter']
                            )
                        ])
                elif current_command == "inline":
                    cod = {
                        a: dpo[f"{current_action}_inline_{a}"]
                        for a in d_action['required_attributes'] + d_action['optional_attributes']
                        if f"{current_action}_inline_{a}" in dpo and 
                        dpo[f"{current_action}_inline_{a}"] is not None
                    }
                    csv_obj_data.append(cod)
                else:
                    raise NotImplementedError(
                        f"Command '{current_command}' not implemented : "
                        f"Should never happend ..."
                    )

                (doit, undo, continue_on_failure) = action_properties(d_action, dpo)
                os = action_check(d_action, module, current_object, csv_obj_data)
                action_do(objects=os, command=current_action, doit=doit, undo=undo, continue_on_failure=continue_on_failure)
                
            elif current_command is not None:
                log.debug(
                    f"Triggered (not None) {current_action} command : {current_command}"
                )
            else:
                print(
                    f"\nError : You must provide action command "
                    f"(inline or from-csv)"
                )
                parser_options = parser.parse_args(args+['-h'])
        elif 'commands' in dpo:
            current_command = dpo["commands"]
            d_action = mo().command(action=current_action, command=current_command)
            if d_action:
                log.debug(
                    f"Triggered {current_action} command : {current_command}"
                )

                # Triks to permit command with dash and method with underscore
                # as python methods does not suport dash in names
                cname = f"{current_action}_{current_command.replace('-', '_')}"

            elif mo.action(action=current_action) is not None:
                d_action = mo.action(action=current_action, command=None)
                log.debug(
                    f"Triggered action {current_action} with no command"
                )

                cname = f"{current_action}"

            else:
                print(
                    f"\nError : Bad action command invocation "
                    f"(must be one of [{ ', '.join(mo.actions(command=True, names=True))}]).\n"
                )
                parser_options = parser.parse_args(args+['-h'])        

            # Provisioning everythings before methode call
            (doit, undo, continue_on_failure) = action_properties(d_action, dpo)
            obj_datas = [{
                a: dpo[f"{current_action}_{current_command}_{a}"]
                for a in d_action['required_attributes'] + d_action['optional_attributes']
                if f"{current_action}_{current_command}_{a}" in dpo
                and dpo[f"{current_action}_{current_command}_{a}"] is not None
            }]
            os = action_check(d_action, module, current_object, obj_datas)
            # Generating kwargs arguments from command line
            ad_prefix = f"{current_action}_{current_command}_additional_arguments_"
            kwargs = { 
                ad.replace(ad_prefix,"",1): 
                dpo[f"{ad_prefix}{ad.replace(ad_prefix,'',1)}"]
                for ad in dpo
                if ad.startswith(ad_prefix)
            }
            action_do(objects=os, command=cname, doit=doit, undo=undo, continue_on_failure=continue_on_failure, **kwargs)    
        else:
            print(
                f"\nError : Bad action (must be one of [{ ', '.join(mo.actions(names=True))}]).\n"
            )
            parser_options = parser.parse_args(args+['-h'])       
    else:
        print(f"\nError : Bad object must be {' or '.join(module_objects)}.\n")
        parser_options = parser.parse_args(args+['-h'])
    
    return 0

module = get_current_module_config(__file__)
root_parser = init_parser()
# doc__ += f"{root_parser.format_help()}"

if __name__ == '__main__':
    exit(main(argv[1:], parser=root_parser, module=module))
