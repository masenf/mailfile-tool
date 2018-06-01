import logging
import os
import shutil
import tempfile
import time

class KeyValueFile(object):
    open_files = {}
    @classmethod
    def open_file(cls, path):
        if path not in cls.open_files:
            cls.open_files[path] = KeyValueFile(path)
        return cls.open_files[path]
    def __init__(self, path):
        logging.basicConfig(level=logging.DEBUG)
        self.fpath = path
        self.k = {}
        self.mods = []
        self.comment_char = "#"
        self.separator = None
        self.backupdir = "/tmp"
        self.lineformat = "{:45} {}\n"
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
        modified = False
        changes, new_keys = self.get_current_changes()
        if not changes:
            logging.debug("no changes to write")
            return False
        with tempfile.NamedTemporaryFile() as out:
            logging.debug("opened file %s for writing", out.name)
            with open(self.fpath, "r") as f:
                logging.debug("opened file %s for reading", self.fpath)
                try:
                    for line in f:
                        kv = self.parse_line(line)
                        if kv:       # we found an actual entry
                            key, value = kv
                            if key in changes:
                                if changes[key]:
                                    out.write(self.lineformat.format(key, changes[key]))
                                    logging.debug("update key: %s --> %s", key, changes[key])
                                else:
                                    logging.debug("remove key: %s", key)
                                modified = True
                                continue
                        out.write(line)
                    for key in new_keys:
                        # write new entries to file
                        out.write(self.lineformat.format(key, changes[key]))
                        logging.debug("add key: %s --> %s", key, changes[key])
                        modified = True
                    out.flush()
                except Exception, e:
                    logging.debug("encountered exception rewriting file (%s): %s", self.fpath, e)
                    return False
            if modified:
                self.backup_file(self.fpath)
                shutil.copyfile(out.name, self.fpath)
            else:
                logging.debug("%s was not modified", self.fpath)
        self.mods = []
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
                return key, value
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
