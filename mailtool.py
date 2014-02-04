#!/usr/bin/env python2

# automate the tasks of managing a file-based postfix virtual alias / mailbox server
# written by masenf
# one day hack, the Version

import argparse
import base64
import logging
import pwd
import os
import random
import shutil
import sys
import tempfile
import time
from subprocess import check_output

# DEFAULT PATHS LOCATIONS
#VALIASES = "/etc/postfix/virtual"
#VMAILBOXES = "/etc/postfix/vmailbox"
#MAINCF = "/etc/postfix/main.cf"
VALIASES = "/root/pftest/virtual"
VMAILBOXES = "/root/pftest/vmailbox"
MAINCF = "/root/pftest/main.cf"

# FILE / DIR FORMATS
BACKUPS = "/root/pftest/backup"
VMAILBASE = "/root/pftest/vhosts"
PASSWDFILE = "%(domain)s/passwd"
HOMEDIR = "%(domain)s/%(user)s"
USERLINE = "%(user)s:%(passwd)s:::"

def backup_file(fname):
    basename = os.path.basename(fname)
    dsuffix = time.strftime("%Y_%m_%d_%H%M%S")
    try:
        os.makedirs(BACKUPS)
    except: pass
    backup_path = os.path.join(BACKUPS, "{}.{}".format(basename, dsuffix))
    shutil.copyfile(fname, backup_path)
    logging.info("backed up %s to %s", fname, backup_path)
def setup_logging(str_level):
    """process the default parser arguments"""
    logfmt = "%(levelname)7s %(funcName)-32s %(message)s"
    logging.basicConfig(format=logfmt, level=getattr(logging, str_level))
    logging.debug("logging initialized")
def is_local_delivery(target):
    """ return true if target identifies an address for local delivery:
            1) unix system account
            2) virtual alias
            3) virtual mailbox"""

    # target is a unix system user?
    try:
        pwentry = pwd.getpwnam(target)
        logging.debug("True: %s is a unix user", target)
        return True
    except KeyError:
        pass

    if target.find("@") > 0:
        # target is a virtual mailbox
        user, domain = target.split("@")
        mailboxes = get_mailboxes(domain)
        for mb in mailboxes:
            if mb[0] == user:
                logging.debug("True: %s is a virtual mailbox", target)
                return True
        # target is a virtual alias
        aliases = get_aliases(domain)
        for a in aliases:
            if a[0] == target:
                logging.debug("True: %s is a virtual alias", target)
                return True
    return False

def alias(args):
    """process the alias sub command"""
    if args.list:
        aliases = get_aliases()
        print("\n".join(["{:45} {}".format(*a) for a in aliases]))
        return True
    elif args.add:
        return add_alias(*args.add)
    elif args.rm:
        return rm_alias(~args.rm)
    return False
def parse_keyvalue_line(line):
    """ take a line from the alias file and return a tuple of (key, value) or None """
    # remove comments from the line
    cmt = line.find("#")
    if cmt > -1:
        line = line[:cmt].strip()
    value = line.strip()

    if value:
        try:
            key, value = value.split()
            logging.debug("parsed entry: %s --> %s", key, value)
            return key, value
        except Exception, e:
            logging.warning("couldn't parse line: %s,\n%s", line, e)
    return None
def get_aliases(domain=""):
    """ return a list of tuples specify addr -> target """
    with open(VALIASES, "r") as va:
        logging.debug("opened file %s for reading", VALIASES)
        return [alias for alias in 
                   [parse_keyvalue_line(line) for line in va] 
                if alias is not None and alias[0].endswith(domain)]
def add_alias(addr, target):
    daliases = dict(get_aliases())

    # see if the alias already exists
    if addr in daliases:
        logging.error("%s is already an alias to %s", addr, daliases[addr])
        return False
    if not is_local_delivery(target) and not args.remote:
        logging.error("target %s is remote, specify --remote to add anyway", target)
        return False

    backup_file(VALIASES)
    with open(VALIASES, "a") as va:
        logging.debug("opened file %s for append", VALIASES)
        va.write("{:45} {}\n".format(addr, target))
    logging.info("successfully added alias %s --> %s", addr, target)
    return True
def rm_alias(addr):
    return rm_key_from_file(VALIASES, addr)
def rm_key_from_file(fname, key):
    found = False
    with tempfile.NamedTemporaryFile() as out:
        logging.debug("opened file %s for writing", out.name)
        with open(fname, "r") as f:
            logging.debug("opened file %s for reading", fname)
            try:
                for line in f:
                    kv = parse_keyvalue_line(line)
                    if kv is not None:
                        if kv[0] == key:
                            logging.debug("found line to delete: %s", line.strip())
                            found = True
                            continue
                    out.write(line)
                out.flush()
            except Exception, e:
                logging.debug("encountered exception reading file (%s): %s", fname, e)
                return False
        if found:
            backup_file(fname)
            shutil.copyfile(out.name, fname)
        else:
            logging.info("%s was not found in file (%s)", key, fname)
    return True

def mailbox(args):
    """process the mailbox sub command"""
    print("Mailbox parser")
    if args.list:
        mailboxes = get_mailboxes(args.domain)
        print("\n".join(["{}@{}".format(*mb) for mb in mailboxes]))
        return True
    elif args.add:
        user, domain = args.add[0].split("@",1)
        return add_mailbox(user, domain)
    elif args.rm:
        user, domain = args.rm[0].split("@",1)
        return rm_mailbox(user, domain)
    elif args.passwd:
        user, domain = args.passwd[0].split("@",1)
        new_password = dc_crypt()
        if new_password.startswith("{SHA512-CRYPT}"):
            return update_user(user, domain, dc_crypt())
        else:
            logging.error("Password hash should be in SHA512-CRYPT format, command returned: %s", new_password)
    return False
def get_mailboxes(domain=None):
    """ return a list of virtual mailbox tuples (user, domain) """
    with open(VMAILBOXES, "r") as vm:
        logging.debug("opened file %s for reading", VMAILBOXES)
        allboxes = [mb for mb in 
                       [parse_keyvalue_line(line) for line in vm]
                    if mb is not None]
        mailboxes = [mb[0].strip().split("@") for mb in allboxes]
        if domain:
            return filter(lambda mb: mb[1] == domain, mailboxes)
        return mailboxes
def add_mailbox(user, domain):
    mailboxes = get_mailboxes(domain)
    users = [u for u,d in mailboxes]

    # see if the alias already exists
    if user in users:
        logging.error("%s@%s is already a virtual mailbox", user, domain)
        return False
    home_dir_suff = HOMEDIR % {"user": user, "domain": domain}
    home_dir = os.path.join(VMAILBASE, home_dir_suff)
    delivery_dir_suff = os.path.join(home_dir_suff, "Maildir/")
    delivery_dir = os.path.join(VMAILBASE, delivery_dir_suff)
    if os.path.exists(home_dir):
        logging.warning("virtual mailbox directory already exists - "
                        "new user may have access to old mails. "
                        "manually inspect and remove %s to continue", home_dir)
        return False
    os.makedirs(delivery_dir)

    backup_file(VMAILBOXES)
    with open(VMAILBOXES, "a") as vm:
        logging.debug("opened file %s for append", VMAILBOXES)
        vm.write("{}@{:45} {}\n".format(user, domain, delivery_dir_suff))
    logging.info("successfully added mailbox %s@%s --> %s", user, domain, delivery_dir_suff)
    randompass = base64.b64encode(os.urandom(6))
    if not update_user(user, domain, dc_crypt(randompass)):
        return False
    print("Add mailbox: {}@{} with password {}".format(user, domain, randompass))
    return True
def rm_mailbox(user, domain):
    success = True
    addr = "{}@{}".format(user, domain)
    if rm_key_from_file(VMAILBOXES, addr):
        logging.debug("removed %s from virtual mail delivery", addr)
    else:
        logging.error("could not remove %s, check debug logging", addr)
        success = False

    home_dir_suff = HOMEDIR % {"user": user, "domain": domain}
    home_dir = os.path.join(VMAILBASE, home_dir_suff)

    if os.path.exists(home_dir):
        shutil.rmtree(home_dir, onerror=lambda func, path, excinfo: logging.warning("removing "
            "path %s failed on %s: %s", path, func, excinfo))
    if update_user(user, domain, None):
        logging.debug("removed %s from IMAP/SMTP auth", addr)
    else:
        logging.error("could not remove  %s from IMAP/SMTP auth", addr)
        success = False

    aliases = get_aliases()
    for alias in aliases:
        if alias[1] == addr:
            logging.info("also removing stale alias %s --> %s", alias[0], alias[1])
            rm_alias(alias[0])
    return success
    
def dc_crypt(password=None):
    cmd = ["doveadm", "pw", "-s", "SHA512-CRYPT"]
    logging.debug("shelling out to doveadm for password hashing")
    if password:
        cmd += ["-p", password]
    return check_output(cmd).strip()
def update_user(user, domain, password=None):
    """ create/update user record. if password is None, the user is 
        removed. Password should already be SHA512-CRYPT'd """
    passwdf = os.path.join(VMAILBASE, PASSWDFILE % {"domain": domain})
    found = False
    modified = False
    with tempfile.NamedTemporaryFile() as out:
        logging.debug("opened file %s for writing", out.name)
        if not os.path.exists(passwdf):
            logging.debug("creating non-existent password file: %s", passwdf)
            with open(passwdf, "w") as pf: pass
        with open(passwdf, "r") as pf:
            logging.debug("opened file %s for reading", passwdf)
            try:
                for line in pf:
                    luser, rest = line.split(":",1)
                    if user == luser:
                        logging.debug("found user: %s", user)
                        found = True
                        if password:
                            # update the user record
                            out.write(USERLINE % {"user": user, "passwd": password})
                            out.write("\n")
                            logging.info("update user record for: %s@%s", user, domain)
                        else:
                            # delete the user record by not copying the line
                            logging.info("remove user record for: %s@%s", user, domain)
                        modified = True
                        continue
                    out.write(line)
                if not found and password:
                    out.write(USERLINE % {"user": user, "passwd": password})
                    out.write("\n")
                    modified = True
                    logging.info("add user record for: %s@%s", user, domain)
                out.flush()
            except Exception, e:
                logging.error("encountered exception reading passwd-file (%s): %s", passwdf, e)
                return False
        if modified:
            backup_file(passwdf)
            shutil.copyfile(out.name, passwdf)
        else:
            logging.info("%s was not found in file", user)
    return True
def domain(args):
    """process the domain sub command"""
    if args.list:
        alias_domains, mailbox_domains = get_domains()
        print("\n".join(["a:{}".format(a) for a in alias_domains]))
        print("\n".join(["m:{}".format(m) for m in mailbox_domains]))
    elif args.rm:
        rm_domain(args.rm[0])
    elif args.valias:
        add_domain(args.valias[0], "alias")
    elif args.vmailbox:
        add_domain(args.vmailbox[0], "mailbox")
    return False
def get_domains():
    """get all virtual alias and virtual mailbox domains in a tuple of list"""
    alias_domains = []
    mailbox_domains = []
    with open(MAINCF, "r") as mc:
        logging.debug("opened file %s for reading", MAINCF)
        for line in mc:
            line = line.strip()
            if line.startswith("virtual_alias_domains"):
                key, value = line.split("=")
                alias_domains.extend([v.strip() for v in value.split(",")])
            elif line.startswith("virtual_mailbox_domains"):
                key, value = line.split("=")
                mailbox_domains.extend([v.strip() for v in value.split(",")])
    return alias_domains, mailbox_domains
def update_main_cf(key, value):
    found = False
    with tempfile.NamedTemporaryFile() as out:
        logging.debug("opened file %s for writing", out.name)
        with open(MAINCF, "r") as mc:
            logging.debug("opened file %s for reading", MAINCF)
            try:
                for line in mc:
                    sline = line.strip()
                    if sline.startswith(key):
                        k, v = sline.split("=")
                        if k.strip() == key:
                            found = True
                            if value:
                                out.write("{} = {}\n".format(key, value))
                                logging.info("updating %s = %s", key, value)
                        modified = True
                        continue
                    out.write(line)
                if not found and value:
                    out.write("{} = {}\n".format(key, value))
                    modified = True
                    logging.info("adding %s = %s", key, value)
                out.flush()
            except Exception, e:
                logging.error("encountered exception updating main.cf (%s): %s", MAINCF, e)
                return False
        if modified:
            backup_file(MAINCF)
            shutil.copyfile(out.name, MAINCF)
        else:
            logging.info("%s was not found in file", user)
    return True
def add_domain(domain, style="mailbox"):
    style = style.lower()
    if style not in  ["mailbox", "alias"]:
        logging.error("domain style must be either mailbox or alias, not %s", style)
        return False
    alias_domains, mailbox_domains = get_domains()
    if domain in alias_domains:
        logging.warning("domain %s is already a virtual alias domain")
        return False
    elif domain in mailbox_domains:
        logging.warning("domain %s is already a virtual mailbox domain")
        return False
    if style == "mailbox":
        domains = mailbox_domains
    else:
        domains = alias_domains
    domains.append(domain)

    return update_main_cf("virtual_{}_domains".format(style), ", ".join(domains))
def rm_domain(domain):
    alias_domains, mailbox_domains = get_domains()
    if domain in alias_domains:
        alias_domains.remove(domain)
        for alias in get_aliases(domain):
            rm_alias(alias[0])
        update_main_cf("virtual_alias_domains", ", ".join(alias_domains))
        logging.info("removed virtual alias domain %s", domain)
    elif domain in mailbox_domains:
        mailbox_domains.remove(domain)
        for mb in get_mailboxes(domain):
            rm_mailbox(*mb)
        update_main_cf("virtual_mailbox_domains", ", ".join(mailbox_domains))
        logging.info("removed virtual mailbox domain %s", domain)
    else:
        logging.info("domain %s is not hosted here", domain)
        return False
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="Select an object to modify from the list")
    parser.add_argument("--level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO",
                        help="set the logging verbosity level")

    p_alias = subparsers.add_parser("alias", help="Operate on virtual alias entries")
    p_alias.set_defaults(func=alias)
    a_mexg = p_alias.add_mutually_exclusive_group(required=True)
    a_mexg.add_argument("--list", "-l", action='store_true', help="list all virtual aliases")
    a_mexg.add_argument("--add", "-a", nargs=2, metavar=("ADDR", "TARGET"),
                        help="add a new virtual alias redirecting ADDR to the TARGET account")
    a_mexg.add_argument("--rm", "-r", nargs=1, metavar="ADDR",
                        help="remove ADDR from the virtual alias table")
    p_alias.add_argument("--remote", action='store_true', help="allow remote TARGET for alias creation")

    p_mailbox = subparsers.add_parser("mailbox", help="Operate on virtual mailbox entries")
    p_mailbox.set_defaults(func=mailbox)
    m_mexg = p_mailbox.add_mutually_exclusive_group(required=True)
    m_mexg.add_argument("--list", "-l", action='store_true', help="list virtual mailboxes")
    m_mexg.add_argument("--add", "-a", nargs=1, metavar="ADDR",
                        help="add a new virtual mailbox with ADDR")
    m_mexg.add_argument("--rm", "-r", nargs=1, metavar="ADDR",
                        help="remove virtual mailbox ADDR")
    m_mexg.add_argument("--passwd", "-p", nargs=1, metavar="ADDR",
                        help="Reset IMAP/SMTP password for ADDR") 
    p_mailbox.add_argument("--domain", "-d", action='store_true', help="restrict listing to DOMAIN")

    p_domain = subparsers.add_parser("domain", help="Add or remove hosted domains")
    p_domain.set_defaults(func=domain)
    d_mexg = p_domain.add_mutually_exclusive_group(required=True)
    d_mexg.add_argument("--list", "-l", action='store_true', help="list all hosted domains")
    d_mexg.add_argument("--valias", "-a", nargs=1, metavar="DOMAIN",
                        help="add a new virtual alias domain DOMAIN")
    d_mexg.add_argument("--vmailbox", "-m", nargs=1, metavar="DOMAIN",
                        help="add a new virtual mailbox domain DOMAIN")
    d_mexg.add_argument("--rm", "-r", nargs=1, metavar="DOMAIN",
                        help="stop hosting DOMAIN")

    args = parser.parse_args(sys.argv[1:])
    setup_logging(args.level)
    sys.exit(not args.func(args))
