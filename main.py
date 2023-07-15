import argparse
import logging
import sys

from certipy.lib.target import Target
from certipy.commands.parsers import target
from impacket.examples import logger

from exploits import ALL_EXPLOITS

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Active Directory Vulnerability Scanner",
    )

    parser.add_argument('module', choices=ALL_EXPLOITS.keys(), help='modules')
    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS,
                        help="Show this help message and exit")
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    target.add_argument_group(parser)

    group = parser.add_argument_group("multi targets options")
    group.add_argument('-all-dc', action='store_true', help='attack all dcs')
    group.add_argument('-tf', metavar='target file', action='store', help='path to targets file')
    group.add_argument('--threads', metavar='threads', default=10, help='number of worker threads', type=int)

    group = parser.add_argument_group("ntlm info options")
    group.add_argument('-ntlm-method', choices=['rpc', 'smb'], help='method for ntlm info detection')

    group = parser.add_argument_group("ldap connection options")
    group.add_argument('-ldap-scheme', choices=['ldap', 'ldaps'], default='ldaps', help='method for ntlm info detection')

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    options.no_pass = True
    t = Target.from_options(options)

    act = ALL_EXPLOITS.get(options.module)
    runner = act(t, options)
    if any([options.tf, options.all_dc]):
        runner.run_multi(options.tf, options.threads)
    else:
        runner.run()
