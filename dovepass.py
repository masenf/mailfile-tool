#!/usr/bin/env python2

import getpass
import os
import shutil
import sys
import syslog
import tempfile
from subprocess import check_call, check_output, CalledProcessError, STDOUT

BASEDIR = "/etc/dovecot/auth/"
ULINE = "{}:{}:::\n"
DOVEADM = "/usr/bin/doveadm"
DEFAULT_SCHEME = "SSHA512"
SYSLOGFAC = syslog.LOG_MAIL
MINLENGTH = 9

def hash_passwd(passwd, scheme=DEFAULT_SCHEME):
    cmd = [DOVEADM, "pw", "-s", scheme, "-p", passwd]
    try:
        with open(os.devnull, 'w') as FNULL:
            hashword = check_output(cmd, stderr=FNULL).strip()
    except CalledProcessError, e:
        return False
    return hashword
def verify_passwd(hashword, passwd):
    # relying on the -t flag of doveadm for password verification
    # this allows the tool to recognize and `upgrade' passwords stored in
    # non-default hash schemes without internal knowledge of how salts and
    # password structures work for each scheme
    cmd = [DOVEADM, "pw", "-t", hashword, "-p", passwd]
    try:
        with open(os.devnull, 'w') as FNULL:
            check_call(cmd, stdout=FNULL, stderr=STDOUT)
    except CalledProcessError, e:
        return False
    return True
def chpass(user, domain, old_pass, new_pass):
    """ change a user password, old_pass must match before the 
        change is made.

        return a tuple of (success, message) where message describes
        the problem if success is False"""
    syslog.openlog("dovepass", logoption=syslog.LOG_PID, facility=SYSLOGFAC)
    message = "User not found"
    modified = False
    
    # password length requirement
    if len(new_pass) < MINLENGTH:
        return False, "Password must be at least {} characters".format(MINLENGTH)
    # ensure the the file being opened is based in BASEDIR
    passwdf = os.path.realpath(os.path.join(BASEDIR, "{}.passwd".format(domain)))
    if os.path.commonprefix([passwdf, BASEDIR]) != BASEDIR:
        message = "Attempt to open password file outside of base"
        syslog.syslog(message + ": u:{} d:{} passwdf:{}".format(user,domain,passwdf))
        return False, message
    # ignore non-existent password files
    if not os.path.exists(passwdf):
        message = "Password file does not exist, invalid domain"
        syslog.syslog(message + ": {}".format(domain))
        return False, message
    # ensure that we have permission
    if not os.access(passwdf, os.R_OK | os.W_OK):
        message = "Write permission denied for passwd file"
        syslog.syslog(message + ": {}".format(passwdf))
        return False, message

    with tempfile.NamedTemporaryFile() as out:
        with open(passwdf, 'r') as pf:
            for line in pf:
                line_user, line_pass = line.strip().split(":",1)
                if line_user == user:       # found the user in question
                    message = ""
                    cur_pass_hashed = line_pass.strip(":")
                    # verify the old password
                    if not verify_passwd(cur_pass_hashed, old_pass):
                        message = "Incorrect password"
                        syslog.syslog(message + ": u:{} d:{}".format(user, domain))
                        return False, message
                    else:
                        # set the new password
                        new_pass_hashed = hash_passwd(new_pass)
                        if not new_pass_hashed:
                            message = "Error setting password"
                            syslog.syslog(message + ": u:{} d:{}".format(user, domain))
                            return False, message
                        out.write(ULINE.format(user, new_pass_hashed))
                        modified = True
                        continue
                out.write(line)
        out.flush()
        if modified:
            shutil.copyfile(out.name, passwdf)
            syslog.syslog("Successfully updated password u:{} d:{}".format(user, domain))
        else:
            syslog.syslog("User not found u:{} d:{}".format(user, domain))
    return modified, message
def usage():
    sys.stderr.write("usage: dovepass <user>@<domain>\n")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    try:
        user, domain = sys.argv[1].split("@", 1)
    except ValueError:
        usage()
    try:
        opass = getpass.getpass("Old password: ").strip()
        npass = getpass.getpass("New password: ").strip()
        vpass = getpass.getpass("New password (verify): ").strip()
        if npass != vpass:
            print("Passwords do not match: {}, {}".format(npass, vpass))
            sys.exit(3)
        else:
            res, msg = chpass(user, domain, opass, npass)
            if not res:
                print(msg)
                sys.exit(4)
    except KeyboardInterrupt:
        print("\nAborted: no change")
        sys.exit(2)

    sys.exit(0)
