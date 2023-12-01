# -*- coding: utf-8 -*-

"""Hpc temporary password manager

This program is used to expires unix and gramc temporary passwords and 
lock users.

.. TODO:: 
  * Check user's crontab
"""
from sys import exit, argv
from argparse import ArgumentParser, SUPPRESS
from config.configGramc import config as grconfig
from hpc.hpc import HpcUsers
from hpc.utils import api_call, fingerprint
from hpc.generators import password_generator, encrypted_password_generator
from hashlib import md5, sha512
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
    common_args_parser.add_argument(
        '--doit', dest='doit', required=False, 
        action='store_true', default=SUPPRESS,
        help=f"Really do actions else just print what should be done",
    )

    # Main parser
    local_parser = ArgumentParser(
        description="Hpc temporary password manager",
        parents=[common_args_parser],
        allow_abbrev=True
    )
    action_subparser = local_parser.add_subparsers(dest="actions")
    lock_and_expire = action_subparser.add_parser(
        "lock-and-expire",
        parents=[common_args_parser],
        help=f"Lock (automatic from gramc API) unix user accounts with "
             f"expired temporary password in GRAMC and also clear GRAMC "
             f"temporary passwords that have been changed on cluster. A "
             f"warning is prompted for locked users with active process "
             f"or jobs."
    )

    lock_and_expire.add_argument(
        "--details", dest="details", required=False,  action='store_true',
        help=f"Display full user activity instead of a summary"
    )
    lock = action_subparser.add_parser(
        "lock",
        parents=[common_args_parser],
        help=f"Lock (manual) unix user account and clear GRAMC temporary "
             f"password for this account. A warning is prompted for locked "
             f"users with active process or jobs."
    )

    lock.add_argument(
        "--login", dest="login", required=True,
        help=f"User login to lock"
    )
    lock.add_argument(
        "--killall", dest="killall", required=False, action='store_true',
        help=f"Kill all process and job for this user after account is locked"
    )
    lock.add_argument(
        "--details", dest="details", required=False,  action='store_true',
        help=f"Display full user activity instead of a summary"
    )
    lock.add_argument(
        "--local-user", dest="local_user", 
        required=False,  action='store_true',
        help=f"Local cluster user, no check on gramc"
    )
    lock.add_argument(
        "--slurm-user", dest="slurm_user", 
        required=False,  action='store_true',
        help=f"Slurm cluster user only, no action on other modules"
    )
    renew_and_unlock = action_subparser.add_parser(
        "renew-and-unlock",
        parents=[common_args_parser],
        help=f"Unlock unix account and change user password with a generated "
             f"password, cleartext password can be displayed with debug "
             f"'DEBUG' flag or with querying GRAMC API."
    )

    renew_and_unlock.add_argument(
        "--login", dest="login", required=True,
        help=f"User login to set a new generated password to"
    )
    
    unlock = action_subparser.add_parser(
        "unlock",
        parents=[common_args_parser],
        help=f"Unlock (manual) unix user account. No new password is set, "
             f"only unlock unix and slurm users."
    )

    unlock.add_argument(
        "--login", dest="login", required=True,
        help=f"User login to unlock"
    )
    unlock.add_argument(
        "--local-user", dest="local_user", default=False,
        required=False,  action='store_true',
        help=f"Local cluster user, no check on gramc"
    )
    unlock.add_argument(
        "--slurm-user", dest="slurm_user", 
        required=False,  action='store_true',
        help=f"Slurm cluster user only, no action on other modules"
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

    exec_mode = False
    slurm_msg = ""

    if 'doit' in dpo:
        exec_mode = parser_options.doit

    if parser_options.actions == "lock-and-expire":
        # Populating users
        hpc_users = HpcUsers()
        hpc_users.populate()


        if not exec_mode:
            log.info("Dry run mode (show what would be done) ...")
            
        log.debug("Looking for temporary password set in GRAMC ...")
        request_headers = {"content-type": "application/json"}
        api_url = f"{grconfig['apiUrl']}{grconfig['user_endpoint']}"
        request_url = f"{api_url}/checkpassword"
        request_auth = (grconfig['apiUser'], grconfig['apiPassword'])
        r = api_call(
            url=request_url, data={}, auth=request_auth, 
            headers=request_headers, rtype="GET"
        )
        if isinstance(r, list) and \
           all([isinstance(entry, dict) for entry in r]):
            log.debug(f"List of temporary password accounts : {r}")
            if len(r) < 1:
                log.info("No user with temporary password found in gramc")
            for entry in r:
                if 'cpassword' in entry and entry['cpassword'] is not None and entry['expire']:
                    log.debug(
                        f"Locking user and expiring temporary password on GRAMC for login "
                        f"'{entry['loginname']}'"
                    )
                    ufilters = [
                        (None, 'gramc_loginname', '=', f'^{entry["loginname"]}$'),
                        (None, 'unix_login', '=', f'^{entry["loginname"]}$')
                    ]
                    hpc_users_filtered = hpc_users.filters(ufilters)
                    if hpc_users_filtered.len() < 1:
                        log.critical(
                            f"Failed to find hpc user '{entry['loginname']}' "
                            f"on cluster"
                        )
                    elif hpc_users_filtered.len() > 1:
                        log.critical(
                            f"Too many hpc users '{entry['loginname']}' "
                            f"on cluster"
                        )
                    else:
                        hpc_user = next(iter(hpc_users_filtered))
                        log.debug(f"Found user {hpc_user}")
                        # Lock & warning si process ou des jobs
                        clearpwd = password_generator(12)
                        cryptedpwd = encrypted_password_generator(clearpwd)
                        hpc_user.unix.clearpassword = clearpwd
                        hpc_user.unix.cryptedpassword = cryptedpwd
                        hpc_user.gramc.password = clearpwd
                        hpc_user.gramc.cpassword = cryptedpwd
                        hpc_user.call(
                            command="activity", undo=None, doit=None
                        )
                        if not exec_mode:
                            log.info(
                                f"Temporary password has expired for user "
                                f"'{hpc_user.gramc.loginname}' "
                            )
                        hpc_user.call(
                            command="lock", undo="unlock", 
                            doit=exec_mode
                        )
                        if exec_mode:
                            log.info(
                                f"Success to lock user "
                                f"'{hpc_user.gramc.loginname}' "
                                f"({hpc_user.gramc.utilisateur}) on GRAMC "
                                f"(temporary password has expired)"
                            )
       
                elif 'loginname' in entry and \
                     'cpassword' in entry and entry['cpassword'] is not None and not entry['expire']:
                    log.debug(
                        f"Checking temporary password change on cluster for "
                        f"login '{entry['loginname']}'"
                    )
                    ufilters = [
                        (None, 'gramc_loginname', '=', f'^{entry["loginname"]}$'),
                        (None, 'unix_login', '=', f'^{entry["loginname"]}$')
                    ]
                    hpc_users_filtered = hpc_users.filters(ufilters)
                    if hpc_users_filtered.len() < 1:
                        log.critical(
                            f"Failed to find hpc user '{entry['loginname']}' "
                            f"on cluster"
                        )
                    elif hpc_users_filtered.len() > 1:
                        log.critical(
                            f"Too many hpc users '{entry['loginname']}' "
                            f"on cluster"
                        )
                    else:
                        hpc_user = next(iter(hpc_users_filtered))
                        log.debug(f"Found user {hpc_user}")
                        cryptedpwd = fingerprint(hpc_user.unix.shadow()['cryptedpassword'])
                        log.debug(
                            f"Password fingerprint '{cryptedpwd}' "
                            f"for login '{entry['loginname']}'"
                        )
                        if entry['cpassword'] == cryptedpwd:
                            log.info(
                                f"No password change on cluster for login "
                                f"'{entry['loginname']}' has been done yet : "
                                f"Nothing to do"
                            )
                        else: 
                            log.debug(
                                f"Password has been change on cluster for "
                                f"login {entry['loginname']}'"
                            )
                            if not exec_mode:
                                log.info(
                                    f"Password has been change on cluster for "
                                    f"login {entry['loginname']}'"
                                )
                            hpc_user.call(
                                command="clear", undo=None, 
                                doit=exec_mode
                            )
                            if exec_mode:
                                log.info(
                                    f"Success to clear password for user "
                                    f"'{hpc_user.gramc.loginname}' "
                                    f"({hpc_user.gramc.utilisateur}) on GRAMC "
                                    f"(temporary password has been changed)"
                                )
        else:
            log.critical(
                f"Failed to analyse method checkpassword "
                f"result (Bad formatted results)"
            )
            return 2

    elif parser_options.actions == "lock":
        # Populating users
        hpc_users = HpcUsers()
        hpc_users.populate()
        if parser_options.local_user:
            ufilters = [(
                None, 'unix_login', '=', f'^{parser_options.login}$'
            )]
        else:
            ufilters = [(
                None, 'gramc_loginname', '=', f'^{parser_options.login}$'
            )]
        hpc_users_filtered = hpc_users.filters(ufilters)
        if hpc_users_filtered.len() < 1:
            log.critical(
                f"Failed to find hpc user '{parser_options.login}' on cluster"
            )
            return 2
        elif hpc_users_filtered.len() > 1:
            log.critical(
                f"Too many hpc users '{parser_options.login}' on cluster"
            )
            return 2
        else:
            hpc_user = next(iter(hpc_users_filtered))
            log.debug(f"Found user {hpc_user}")
            if not exec_mode:
                log.info("Dry run mode (show what would be done) ...")
            
            # Lock & warning si process ou des jobs
            clearpassword = password_generator(12)
            cryptedpassword = encrypted_password_generator(clearpassword)
            hpc_user.unix.clearpassword = clearpassword
            hpc_user.unix.cryptedpassword = cryptedpassword
            if parser_options.local_user:
                hpc_user.gramc = None
            else :
                hpc_user.gramc.password = clearpassword
                hpc_user.gramc.cpassword = cryptedpassword
            if parser_options.details:
                hpc_user.call(command="activity_details", undo=None, doit=None)
            else:
                hpc_user.call(command="activity", undo=None, doit=None)
            
            if parser_options.slurm_user:
                slurm_msg = " (slurm user only)" 
                r = hpc_user.slurm.call(
                    command="lock", undo="unlock", doit=exec_mode
                ) 
            else:
                r = hpc_user.call(
                    command="lock", undo="unlock", doit=exec_mode
                )

            if parser_options.killall:
                if parser_options.slurm_user:
                    slurm_msg = " (slurm user only)" 
                    hpc_user.slurm.call(
                        command="killall", undo=None, doit=exec_mode
                    )
                else:
                    hpc_user.call(
                        command="killall", undo=None, doit=exec_mode
                    )
                if exec_mode:
                    if parser_options.slurm_user:
                        slurm_msg = " (slurm user only)" 
                        activities = hpc_user.slurm.call(
                            command="activity_details", undo=None, doit=None
                        )
                    else:
                        activities = hpc_user.call(
                            command="activity_details", undo=None, doit=None
                        )
                    
                    log.debug(f"Activities : {activities}")
                    if any([a for a in activities]):
                        if parser_options.local_user:
                            log.error(
                                f"Success to lock but fails to stop "
                                f"activities for user "
                                f"'{parser_options.login}'{slurm_msg}."
                            )
                        else:
                            log.error(
                                f"Success to lock but fails to stop "
                                f"activities for user "
                                f"'{parser_options.login}' "
                                f"({hpc_user.gramc.utilisateur}){slurm_msg}"
                            )
                    else:
                        if parser_options.local_user:
                            log.info(
                                f"Success to lock and stop activities "
                                f"for user '{parser_options.login}'{slurm_msg}."
                            )
                        else:
                            log.info(
                                f"Success to lock and stop activities "
                                f"for user '{parser_options.login}' "
                                f"({hpc_user.gramc.utilisateur}){slurm_msg}"
                                )
            else:
                if exec_mode:
                    if parser_options.local_user:
                        log.info(
                            f"Success to lock local user "
                            f"'{parser_options.login}'{slurm_msg}"
                        )
                    else:
                         log.info(
                            f"Success to lock user '{parser_options.login}' "
                            f"({hpc_user.gramc.utilisateur}){slurm_msg}"
                        )

    elif parser_options.actions == "renew-and-unlock":
        # Populating users
        hpc_users = HpcUsers()
        hpc_users.populate()

        ufilters = [(
            None, 'gramc_loginname', '=', f'^{parser_options.login}$'
        )]
        hpc_users_filtered = hpc_users.filters(ufilters)
        if hpc_users_filtered.len() < 1:
            log.critical(
                f"Failed to find hpc user '{parser_options.login}' on cluster"
            )
            return 2
        elif hpc_users_filtered.len() > 1:
            log.critical(
                f"Too many hpc users '{parser_options.login}' on cluster"
            )
            return 2
        else:
            hpc_user = next(iter(hpc_users_filtered))
            log.debug(f"Found user {hpc_user}")
            if not exec_mode:
                log.info("Dry run mode (show what would be done) ...")
            clearpassword = password_generator(12)
            cryptedpassword = encrypted_password_generator(clearpassword)
            hpc_user.unix.clearpassword = clearpassword
            hpc_user.unix.cryptedpassword = cryptedpassword
            hpc_user.gramc.password = clearpassword
            hpc_user.gramc.cpassword = fingerprint(cryptedpassword)
            r = hpc_user.call(
                command="unlock", undo="lock", doit=exec_mode
            )
            if exec_mode:
                log.info(
                    f"Success to change password for user "
                    f"'{parser_options.login}' "
                    f"({hpc_user.gramc.utilisateur})"
                )
    elif parser_options.actions == "unlock":
        # Populating users
        hpc_users = HpcUsers()
        hpc_users.populate()
        if parser_options.local_user:
            ufilters = [(
                None, 'unix_login', '=', f'^{parser_options.login}$'
            )]
        else:
            ufilters = [(
                None, 'gramc_loginname', '=', f'^{parser_options.login}$'
            )]
        hpc_users_filtered = hpc_users.filters(ufilters)
        if hpc_users_filtered.len() < 1:
            log.critical(
                f"Failed to find hpc user '{parser_options.login}' on cluster"
            )
            return 2
        elif hpc_users_filtered.len() > 1:
            log.critical(
                f"Too many hpc users '{parser_options.login}' on cluster"
            )
            return 2
        else:
            hpc_user = next(iter(hpc_users_filtered))
            log.debug(f"Found user {hpc_user}")
            if not exec_mode:
                log.info("Dry run mode (show what would be done) ...")
            clearpassword = None
            cryptedpassword = None
            hpc_user.unix.clearpassword = clearpassword
            hpc_user.unix.cryptedpassword = cryptedpassword
            if parser_options.local_user:
                hpc_user.gramc = None
            else:
                hpc_user.gramc.password = clearpassword
                hpc_user.gramc.cpassword = cryptedpassword

            if parser_options.slurm_user:
                slurm_msg = " (slurm user only)" 
                r = hpc_user.slurm.call(
                    command="unlock", undo="lock", doit=exec_mode
                )
            else:
                r = hpc_user.call(
                    command="unlock", undo="lock", doit=exec_mode
                )

            if exec_mode:
                if parser_options.local_user:
                    log.info(
                        f"Success to unlock user "
                        f"'{parser_options.login}'{slurm_msg}."
                    )
                else:
                    log.info(
                        f"Success to unlock user "
                        f"'{parser_options.login}' "
                        f"({hpc_user.gramc.utilisateur}){slurm_msg}"
                    )
    else:
        parser.print_help()
        parser.exit(status=0)

    return 0


root_parser = init_parser()
# doc__ += f"{root_parser.format_help()}"

if __name__ == '__main__':
    exit(main(argv[1:], parser=root_parser))
