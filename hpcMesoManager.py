# -*- coding: utf-8 -*-

"""Hpc meso manager

This program is used to list pending attribution and IPs network to be allowed
from GRAMC meso API
"""
from sys import exit, argv, stdout
from argparse import ArgumentParser, SUPPRESS
from ipaddress import ip_network
from hpc.gramc import GramcProjets
from csv import writer, DictWriter, writer, QUOTE_MINIMAL
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


# @ftrace
def init_parser() -> ArgumentParser:
    """Initialize argparse parser. We use a function to be able to add help 
    in pydoc

    :return: An initialized argparse parser
    """

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
        description="Hpc Gramc Meso Manager",
        parents=[common_args_parser],
        allow_abbrev=True
    )
    action_subparser = local_parser.add_subparsers(dest="actions")
    list_pending_attributions = action_subparser.add_parser(
        "list-pending-attributions",
        parents=[common_args_parser],
        help=f"List pending attributions for Gramc Meso in csv format"
    )

    list_pending_attributions.add_argument(
        "--details", dest="list_pending_details", 
        required=False,  action='store_true',
        help=f"Display all fields"
    )
    
    list_pending_attributions.add_argument(
        "--all", dest="list_pending_all", required=False,  action='store_true',
        help=f"Display all attributions not only those for local resource"
    )
    
    list_pending_attributions.add_argument(
        "--no-header", dest="list_pending_no_header", required=False,  
        action='store_true',
        help=f"Do not display fields headers"
    )

    list_ips = action_subparser.add_parser(
        "list-ips",
        parents=[common_args_parser],
        help=f"List allowed IPs in CIDR format one by line"
    )
    list_ips.add_argument(
        "--details", dest="list_ips_details", 
        required=False, action='store_true',
        help=f"Display laboratory name and all networks separated by semicolon"
    )
    return local_parser


# @ftrace
def main(args, parser: ArgumentParser) -> int:
    parser_options = parser.parse_args(args)
    if 'debug' in parser_options:
        rootlogger.setLevel(parser_options.debug.upper())
    log.debug(f"Arguments found : {parser_options}")
    dpo = vars(parser_options)
    log.debug(f"Arguments found (dict) : {dpo}")

    if parser_options.actions == "list-pending-attributions":        
        log.debug("Looking for pendings attributions in GRAMC MESO ...")
        gps = GramcProjets()
        r = gps.get_pending_actions()     
        if isinstance(r, list) and \
           all([isinstance(entry, dict) for entry in r]):
            log.debug(f"List of pendings attributions in GRAMC MESO : {r}")
            if len(r) < 1:
                log.info("No pending attribution found in GRAMC MESO")
            else:
                log.debug(f"List of pendings attributions in GRAMC MESO : {r}")
                head_csv = writer(
                    stdout,
                    delimiter=',', 
                    lineterminator='\n'
                )
                headers=["Project", "Attribution"]
                if parser_options.list_pending_details:
                    headers += ["Action", "RallongeID", "Ressource"]
                if not parser_options.list_pending_no_header:
                    head_csv.writerow(headers)
                for entry in r:
                    # Check all need keys
                    must_have_keys_rallonge = sorted([
                        "action", "attribution", "idProjet", 
                        "ressource"])
                    must_have_keys_attribution = sorted([
                        "action", "attribution", "idProjet", 
                        "idRallonge", "ressource"])
                    entry_keys = sorted(list(entry.keys()))
                    if entry_keys == must_have_keys_rallonge \
                        or entry_keys == must_have_keys_attribution:
                        log.debug(f"Config : {gps.config['resource']}")
                        
                        fieldnames = ["idProjet", "attribution"]                     
                        if parser_options.list_pending_details:
                            fieldnames += ["action", "idRallonge", "ressource"]
                                       
                        if parser_options.list_pending_all \
                           or entry["ressource"] == gps.config['resource']:     
                            writer_csv = DictWriter(
                                stdout, fieldnames=fieldnames,
                                delimiter=',',
                                extrasaction='ignore', restval="", lineterminator='\n', 
                                quoting=QUOTE_MINIMAL
                            )
                        writer_csv.writerow(entry)  

                    else:
                        log.critical(
                            f"Failed to find pendings attributions : keys "
                            f"mismatch (needed : {must_have_keys_attribution} "
                            f"or {must_have_keys_rallonge} and get "
                            f"{entry_keys})"
                        ) 
        else:
            log.critical(
                f"Bad response format (Must be a list of dict)"
            )

    elif parser_options.actions == "list-ips":
        log.debug("Looking for ip or network address for our resource ...")
        gps = GramcProjets()
        r = gps.get_ip_addresses()
        if isinstance(r, dict) and \
           all([isinstance(k, str) and isinstance(v, list) for k, v in r.items()]):
            log.debug(f"List of ip or network address for our resource in GRAMC MESO : {r}")
            if len(r) < 1:
                log.info("No ip or network address for our resource found in GRAMC MESO")
            else:
                log.debug(f"List of ip or network address for our resource GRAMC MESO : {r}")
                writer_csv = writer(
                        stdout,
                        delimiter=',',
                        lineterminator='\n', 
                        quoting=QUOTE_MINIMAL
                    )

                if parser_options.list_ips_details:
                    writer_csv.writerow(["Laboratoire", "Reseaux"])
                else:
                    writer_csv.writerow(["Reseaux"])
                lines = []
                for labo, networks in dict(sorted(r.items())).items():
                    verified_networks = []
                    for n in networks:
                        try:
                            tested_network = ip_network(n)
                            verified_networks += [n]
                        except ValueError:
                            log.critical(
                                f'Removing bad cidr formated network "{n}"'
                            )
                    # Check all need keys
                    log.debug(f"Config : {labo}, {';'.join(verified_networks)}")
                    if parser_options.list_ips_details:
                        lines += [(labo,';'.join(sorted(verified_networks)))]
                    else:
                        for n in verified_networks:
                            lines += [(n,)]
                for l in sorted(lines):
                    writer_csv.writerow(l)
                
        else:
            log.critical(
                f"Bad response format (Must be a dict of key with list as value)"
            )
    else:
        parser.print_help()
        parser.exit(status=0)

    return 0


root_parser = init_parser()
# doc__ += f"{root_parser.format_help()}"

if __name__ == '__main__':
    exit(main(argv[1:], parser=root_parser))
