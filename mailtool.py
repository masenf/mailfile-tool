#!/usr/bin/env python2

# automate the tasks of managing a file-based postfix virtual alias / mailbox server
# written by masenf
# one day hack, the Version

import argparse
import base64
import difflib
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
VALIASES = "etc/postfix/virtual"
VMAILBOXES = "etc/postfix/vmailbox"
MAINCF = "etc/postfix/main.cf"
DOVEADM = "./doveadm"

# FILE / DIR FORMATS
BACKUPS = "etc/backup"
VMAILBASE = "etc/vhosts"
PASSWDFILE = "%(domain)s/passwd"
HOMEDIR = "%(domain)s/%(user)s"
USERLINE = "{}:{}:::"

class KeyValueFile(object):
    open_files = {}
    @classmethod
    def open_file(cls, path, *args, **kwds):
        """ create / fetch a global instance of KeyValueFile for the given path,
            additional arguments will be passed to the constructor upon first
            instantiation. If the file is already open, *args and **kwds will be
            ignored. Typically use the same invocation parameters for a given file
            anywhere that open_file is called"""
        if path not in cls.open_files:
            cls.open_files[path] = KeyValueFile(path, *args, **kwds)
        return cls.open_files[path]
    @classmethod
    def commit_all(cls):
        """ for each open file, write current changes and remove the instance
            return True if all writes were successful"""
        if not cls.open_files:
            return True
        dirty = [of for path, of in cls.open_files.iteritems() if of.dirty]
        if dirty:
            logging.info("saving changes to {} dirty files".format(len(dirty)))
            results = [of.write() for of in dirty]
            cls.open_files.clear()
            return all(results)
        return True
    def __init__(self, path, comment_char="#", separator=None, backupdir=BACKUPS, lineformat="{:45} {}\n"):
        self.fpath = path
        self.k = {}
        self.mods = []
        self.comment_char = comment_char
        self.separator = separator
        self.backupdir = backupdir
        self.lineformat = lineformat
        self.dirty = False
        self.refresh()
    def __len__(self):
        return len(self.get_valid_keys())
    def __getitem__(self, key):
        changes, new_keys = self.get_current_changes()
        if key in changes:
            if changes[key]:
                return changes[key]
            else:
                raise KeyError("{} has been deleted from cache (not-persisted)".format(key))
        return self.k[key]
    def __setitem__(self, key, value):
        logging.debug("caching %s --> %s", key, value)
        self.dirty = True
        self.mods.append((key, value))
    def __delitem__(self, key):
        self.__setitem__(key, None)
    def __iter__(self):
        return self.get_valid_keys().__iter__()
    def refresh(self):
        # create a non-existent file
        if not os.path.exists(self.fpath):
            with open(self.fpath, "w") as f: pass
        with open(self.fpath, "r") as f:
            self.lines = f.readlines()
        self.k.clear()
        for line in self.lines:
            kv = self.parse_line(line)
            if kv:
                self.k[kv[0]] = kv[1]
        logging.debug("refreshed from %s", self.fpath)
    def get_valid_keys(self):
        valid_keys = set(self.k.keys())
        for k, val in self.mods:
            if k in valid_keys:
                if val:
                    valid_keys.add(k)
                else:
                    valid_keys.remove(k)
            elif val:
                valid_keys.add(k)
        return valid_keys
    def get_current_changes(self):
        changes = {}
        new_keys = []
        if self.dirty:
            for k, val in self.mods:
                # keep track of which keys need to be added
                if k not in self.k and k not in new_keys:
                    new_keys.append(k)
                changes[k] = val
                if val is None:
                    try:
                        # I guess keys could be added or removed in a single session
                        # don't add new keys which later get removed, or something
                        new_keys.remove(k)
                    except ValueError: pass
        return changes, new_keys
    def write(self):
        if not self.dirty:
            logging.debug("no changes to write")
            return True
        modified = False
        changes, new_keys = self.get_current_changes()
        diff_in = []
        diff_out = []
        with tempfile.NamedTemporaryFile() as out:
            logging.debug("opened file %s for writing", out.name)
            with open(self.fpath, "r") as f:
                logging.debug("opened file %s for reading", self.fpath)
                try:
                    for line in f:
                        diff_in.append(line)
                        kv = self.parse_line(line)
                        if kv:       # we found an actual entry
                            key, value = kv
                            if key in changes:
                                if changes[key]:
                                    newline = self.lineformat.format(key, changes[key])
                                    out.write(newline)
                                    diff_out.append(newline)
                                    logging.debug("update key: %s --> %s", key, changes[key])
                                else:
                                    logging.debug("remove key: %s", key)
                                modified = True
                                continue
                        out.write(line)
                        diff_out.append(line)
                    for key in new_keys:
                        # write new entries to file
                        newline = self.lineformat.format(key, changes[key])
                        out.write(newline)
                        diff_out.append(newline)
                        logging.debug("add key: %s --> %s", key, changes[key])
                        modified = True
                    out.flush()
                except Exception, e:
                    logging.error("encountered exception rewriting file (%s): %s", self.fpath, e)
                    return False
            if modified:
                self.backup_file(self.fpath)
                logging.info("updating disk file, diff:\n\t\t%s", "\t\t".join(difflib.unified_diff(diff_in, diff_out, fromfile=self.fpath, tofile=out.name)))
                shutil.copyfile(out.name, self.fpath)
            else:
                logging.debug("%s was not modified", self.fpath)
        self.mods = []
        self.dirty = False
        self.refresh()
        return True
    def parse_line(self, line):
        # remove comments from the line
        cmt = line.find(self.comment_char)
        if cmt > -1:
            line = line[:cmt].strip()
        value = line.strip()

        if value:
            try:
                key, value = value.split(self.separator, 1)
                logging.debug("parsed entry: %s --> %s", key, value)
                return key.strip(), value.strip()
            except Exception, e:
                logging.warning("couldn't parse line: %s,\n%s", line, e)
        return None
    def backup_file(self, fname):
        basename = os.path.basename(fname)
        dsuffix = time.strftime("%Y_%m_%d_%H%M%S")
        try:
            os.makedirs(self.backupdir)
        except: pass
        backup_path = os.path.join(self.backupdir, "{}.{}".format(basename, dsuffix))
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
        aliases = get_aliases(args.domain)
        print("\n".join(["{:45} {}".format(*a) for a in aliases]))
        return True
    elif args.add:
        return add_alias(*args.add)
    elif args.rm:
        return rm_alias(*args.rm)
    return False
def get_aliases(domain=""):
    """ return a list of tuples specify addr -> target """
    aliases = KeyValueFile.open_file(VALIASES)
    laliases = sorted([a for a in aliases.get_valid_keys() if a.endswith(domain)])
    return [(a, aliases[a]) for a in laliases]

def add_alias(addr, target):
    aliases = KeyValueFile.open_file(VALIASES)
    # ensure valid form
    try:
        user, domain = addr.split("@",1)
    except KeyError:
        logging.error("%s must be an email address", addr)
        return False
    # see if the alias already exists
    if addr in aliases:
        logging.error("%s is already an alias to %s", addr, aliases[addr])
        return False
    # check for remote delivery
    if not args.remote and not is_local_delivery(target):
        logging.warning("target %s is remote, specify --remote to add anyway", target)
        return False
    # ensure that the requested address is hosted here
    alias_domains, mailbox_domains = get_domains()
    if domain not in alias_domains + mailbox_domains:
        logging.error("%s must be a domain hosted here", addr)
        return False

    aliases[addr] = target
    return True

def rm_alias(addr):
    aliases = KeyValueFile.open_file(VALIASES)
    del aliases[addr]
    return True

def mailbox(args):
    """process the mailbox sub command"""
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
    vmailboxes = KeyValueFile.open_file(VMAILBOXES)
    mailboxes = [addr.split("@") for addr in vmailboxes.get_valid_keys()]
    if domain:
        return filter(lambda mb: mb[1] == domain, mailboxes)
    return mailboxes
def add_mailbox(user, domain):
    addr = "{}@{}".format(user, domain)

    # ensure that the requested address is hosted here
    alias_domains, mailbox_domains = get_domains()
    if domain not in mailbox_domains:
        if domain in alias_domains:
            logging.error("%s is a virtual alias domain, cannot create virtual mailbox", domain)
        else:
            logging.error("%s must be hosted here to create virtual mailbox", domain)
        return False

    mailboxes = get_mailboxes(domain)
    aliases = get_aliases(domain)
    users = [u for u,d in mailboxes]

    # see if the mailbox already exists
    if user in users:
        logging.error("%s is already a virtual mailbox", addr)
        return False
    for a in aliases:
        if a[0] == addr:
            logging.error("%s is already a virtual alias to %s", addr, a[1])
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

    vmailboxes = KeyValueFile.open_file(VMAILBOXES)
    vmailboxes[addr] = delivery_dir_suff
    logging.debug("added mailbox %s --> %s", addr, delivery_dir_suff)
    randompass = base64.b64encode(os.urandom(6))
    if not update_user(user, domain, dc_crypt(randompass)):
        return False
    print("Add mailbox: {} with password {}".format(addr, randompass))
    return True
def rm_mailbox(user, domain):
    success = True
    addr = "{}@{}".format(user, domain)
    vmailboxes = KeyValueFile.open_file(VMAILBOXES)
    del vmailboxes[addr]

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
            logging.info("remove dangling alias %s --> %s", alias[0], alias[1])
            rm_alias(alias[0])
    return success
    
def dc_crypt(password=None):
    cmd = [DOVEADM, "pw", "-s", "SHA512-CRYPT"]
    logging.debug("shelling out to doveadm for password hashing")
    if password:
        cmd += ["-p", password]
    return check_output(cmd).strip()
def update_user(user, domain, password=None):
    """ create/update user record. if password is None, the user is 
        removed. Password should already be SHA512-CRYPT'd """
    passwdf = os.path.join(VMAILBASE, PASSWDFILE % {"domain": domain})
    passwdb = KeyValueFile.open_file(passwdf, separator=":", lineformat=USERLINE+"\n")
    passwdb[user] = password
    return True
def domain(args):
    """process the domain sub command"""
    if args.list:
        alias_domains, mailbox_domains = get_domains()
        print("\n".join(["a:{}".format(a) for a in alias_domains]))
        print("\n".join(["m:{}".format(m) for m in mailbox_domains]))
        return True
    elif args.rm:
        return rm_domain(args.rm[0])
    elif args.valias:
        return add_domain(args.valias[0], "alias")
    elif args.vmailbox:
        return add_domain(args.vmailbox[0], "mailbox")
    return False
def get_domains():
    """get all virtual alias and virtual mailbox domains in a tuple of list"""
    alias_domains = []
    mailbox_domains = []
    mc = KeyValueFile.open_file(MAINCF, separator="=", lineformat="{} = {}\n")

    if "virtual_alias_domains" in mc:
        alias_domains.extend([v.strip() for v in mc["virtual_alias_domains"].split(",")])
    if "virtual_mailbox_domains" in mc:
        mailbox_domains.extend([v.strip() for v in mc["virtual_mailbox_domains"].split(",")])
    return alias_domains, mailbox_domains
def update_main_cf(key, value):
    mc = KeyValueFile.open_file(MAINCF, separator="=", lineformat="{} = {}\n")
    mc[key] = value
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
            logging.info("remove undeliverable alias %s --> %s", *alias)
            rm_alias(alias[0])
        update_main_cf("virtual_alias_domains", ", ".join(alias_domains))
        logging.info("removed virtual alias domain %s", domain)
    elif domain in mailbox_domains:
        mailbox_domains.remove(domain)
        for mb in get_mailboxes(domain):
            logging.info("remove undeliverable mailbox %s@%s", *mb)
            rm_mailbox(*mb)
        for alias in get_aliases(domain):
            logging.info("remove undeliverable alias %s --> %s", *alias)
            rm_alias(alias[0])
        update_main_cf("virtual_mailbox_domains", ", ".join(mailbox_domains))
        logging.info("removed virtual mailbox domain %s", domain)
    else:
        logging.info("domain %s is not hosted here", domain)
        return False
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="Select an object to modify from the list")
    parser.add_argument("--level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="WARNING",
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
    p_alias.add_argument("--domain", "-d", help="restrict listing to DOMAIN")

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
    p_mailbox.add_argument("--domain", "-d", help="restrict listing to DOMAIN")

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
    if args.func(args):
        sys.exit(KeyValueFile.commit_all())
    sys.exit(1)
