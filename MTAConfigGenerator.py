#!/usr/bin/env python

import sys
import os, os.path
import argparse
import subprocess
from tempfile import NamedTemporaryFile
import re

from Config import Config
from Errors import *

class MTAConfigFile():
  def __init__(self, path):
    self.path = path

    self.comment = "#"
    self.var_val_separator = "="

    self.orig_data = ""
    self.lines = []
    self.additions = []
    self.deletions = []
    self.new_data = ""
    self.changed = False

  def load(self):
    """Load the configuration file and reset instance's properties"""

    f = open(self.path, "r")
    self.orig_data = f.read()
    f.close()

    self.lines = self.orig_data.split("\n")

    # list of lines that need to be added
    self.additions = []

    # list of indices of lines that need to be removed
    self.deletions = []

    self.new_data = ""
    self.changed = False

  def parse_line(self, line_data):
    """
    Return the (line number, left hand side, right hand side) of a config 
    line.

    Lines are like:
    var = val
    smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
    var
    mynetworks = 127.0.0.0/8
     [::ffff:127.0.0.0]/104
     [::1]/128
    """
    num,line = line_data
    left, sep, right = line.partition(self.var_val_separator)
    if not sep:
      return (num, left.rstrip(), None)
    return (num, left.strip(), right.strip())

  def get_lines_starting_with(self,s):
    """
    Return list of (line_num,line).
    """
    pa = s + "\s*" + self.var_val_separator
    return [(n,l) for n,l in enumerate(self.lines) if re.match(pa,l)]

  def ensure_cf_var(self, var, ideal, also_acceptable):
    """
    Ensure that existing config @var is in the list of @acceptable
    values; if not, set it to the ideal value.

    Performed actions:
    - add new lines to self.additions;
    - add removed lines indexes to self.deletions;
    - set self.changed = True when changes are needed
    """
    acceptable = [ideal] + also_acceptable

    l = self.get_lines_starting_with(var)
    if not any(l):
      self.additions.append(var + self.var_val_separator + ideal)
      self.changed = True
    else:
      values = map(self.parse_line, l)

      if len(set(values)) > 1:
        conflicting_lines = [num for num,_,val in values]
        self.deletions.extend(conflicting_lines)
        self.additions.append(var + self.var_val_separator + ideal)
        self.changed = True

      val = values[0][2]

      if val not in acceptable:
        self.deletions.append(values[0][0])
        self.additions.append(var + self.var_val_separator + ideal)
        self.changed = True

  def get_cf_var(self, var):
    """
    Return config variable's value.
    """

    pa = var + "\s*" + self.var_val_separator
    l = self.get_lines_starting_with(var)
    if not any(l):
      return None
    else:
      _, left, right = self.parse_line(l[0])
      return right
    return None

  def build_new(self):
    """
    Build the content of the new configuration file

    Raise: BuildUnchangedConfigFileError

    Return the content itself.
    """
    
    if not self.changed:
      raise BuildUnchangedConfigFileError("Can't build an unchanged file")

    if len(self.additions) > 0:
      new_lines = [self.comment, self.comment +
                    " New config lines added by STARTTLS Everywhere",
                    self.comment]
      new_lines.extend(self.additions)
      new_cf_lines = "\n".join(new_lines) + "\n"
    else:
      new_cf_lines = ""

    self.new_data = ""
    for num, line in enumerate(self.lines):
      if num in self.deletions:
        self.new_data += self.comment + line + " " + self.comment + \
                          " Line removed by STARTTLS Everywhere\n"
      else:
        self.new_data += line + "\n"

    if new_cf_lines != "":
      self.new_data += "\n" + new_cf_lines

    return self.new_data

  def save(self):
    """
    Save the content of the new configuration file, then reload it to 
    reinitialize it
    """

    if self.new_data == "":
      return
    f = open(self.path,"w")
    f.write(self.new_data)
    f.close

    self.load()

# ----------------------------------------------------------------------------

class MTAConfigGenerator():
  allowed_ignore_list = {}

  def __init__(self, policy_config, fixup=False, ignore_list=[]):
    self.policy_config = policy_config
    self.fixup = fixup
    self.ignore_list = ignore_list

    for err in self.ignore_list:
      if err not in self.allowed_ignore_list:
        raise ValueError("Unsupported error to be ignored: %s" % err)

    self.changed_files = []

    self.policy_defs_file = ""
    self.policy_defs = ""

  def build_defs(self):
    """
    Build the new STARTTLS enforcing policy definitions.
    
    Must be implemented in child class.
    """

    raise NotImplementedError()

  def show_defs(self):
    """Print the new policy definitions."""

    sys.stdout.write(self.policy_defs)

  def update_defs(self):
    """
    Update STARTTLS enforcing policy definitions only
    without changing MTA's main configuration files.

    Return:
    - True if the new policy is immediately activated;
    - False if an external action is required to instruct the
      MTA to reload it.

    Should be implemented in child class; the following
    is only a basic implementation that save the new
    policy definitions into the defs_file.
    """
    if self.policy_defs != "":
      f = open(self.policy_defs_file, "w")
      f.write(self.policy_defs)
      f.close()

    return False

  def build_general_config(self):
    """
    Build changes needed to adapt MTA's main configuration
    to what's needed by STARTTLS-Everywhere.
    
    Return True if changes are needed, otherwise False.

    Files that need to be modified must be added to self.changed_files.
    
    Must be implemented in child class.
    """

    raise NotImplementedError()

  def show_new_general_config(self):
    """
    Print the new configuration for each file that needs
    to be changed.
    """

    for F in self.changed_files:
      print("File: {}".format(F.path))
      sys.stdout.write(F.new_data)

  def fix_general_config(self):
    """
    Update only MTA's main configuration files, adapting them
    to what's needed by STARTTLS-Everywhere.

    Return:
    - True if the new configuration is immediately activated;
    - False if an external action is required to instruct the
      MTA to reload it.
    """
    for F in self.changed_files:
      F.save()

    return False

  def show_new_general_config_diff(self):
    """
    Show a diff between current and new MTA's general config.

    It uses the command line provided in STARTTLS-Everywhere
    configuration.
    """

    diff_tpl = Config.get("general","diff_cmd")

    if diff_tpl.strip() == "":
      raise ValueError("The diff external command is missing; "
                       "please set the diff_cmd parameter in the general "
                       "STARTTLS-Everywhere configuration.")

    for F in self.changed_files:
      if F.changed:

        temp_f = NamedTemporaryFile(delete=False)
        temp_f.write(F.new_data)
        temp_f.close()

        diff_cmd = diff_tpl.format(old=F.path, new=temp_f.name)

        print("Differences between current {old} and "
        "the new configuration follow:\n\n"
        "\t{cmd}\n\n".format(old=F.path, cmd=diff_cmd))

        proc = subprocess.Popen(diff_cmd.split(" "))
        proc.communicate()
        os.remove(temp_f.name)

if __name__ == "__main__":
  def main():
    parser = argparse.ArgumentParser(
      description="""MTA configuration generator""")

    parser.add_argument("-c", "--cfg", default=Config.default_cfg_path,
                        help="general configuration file path", metavar="file",
                        dest="cfg_path")

    parser.add_argument("-m", default="Postfix",
                        help="MTA flavor", choices=["Postfix"],
                        dest="mta_flavor")

    parser.add_argument("-f", "--fix", action="store_true",
                        help="fix MTA general configuration; "
                        "by default, only STARTTLS policies are updated "
                        "while the main MTA configuration is kept unchanged. "
                        "Changes are saved only if -s | --save arguments are "
                        "given.",
                        dest="fixup")

    parser.add_argument("--show-ignore-list", action="store_true",
                        help="show the list of exceptions that can be "
                        "ignored for the given MTA", dest="show_ignore_list")

    parser.add_argument("--ignore", nargs="*",
                        help="ignore errors due to features not implemented",
                        metavar="error_type", dest="ignore_list")

    parser.add_argument("-s", "--save", action="store_true",
                        help="really write changes to disk (both for general "
                        "configuration changes and for policy definitions).",
                        dest="save")

    parser.add_argument("policy_def", help="JSON policy definitions file",
                        metavar="policy_defs.json")

    args = parser.parse_args()

    Config.read(args.cfg_path)

    import DefsParser
    c = DefsParser.Defs(args.policy_def)

    if args.ignore_list:
      ignore_list = args.ignore_list
    else:
      ignore_list = []

    if args.mta_flavor == "Postfix":
      from PostfixConfigGenerator import PostfixConfigGenerator

      postfix_dir = Config.get("postfix","cfg_dir")

      cfg_gen = PostfixConfigGenerator(c, postfix_dir, fixup=args.fixup,
                                     ignore_list=ignore_list)
    else:
      print("Unexpected MTA flavor: {}".format(args.mta_flavor))
      return

    if args.show_ignore_list:
      print("List of exceptions that can be ignored by "
            "%s config generator:" % args.mta_flavor)
      for err in cfg_gen.allowed_ignore_list:
        print(" - %s: %s" % (err,cfg_gen.allowed_ignore_list[err]))
      return

    if args.fixup:
      if cfg_gen.build_general_config():

        if args.save:
          if cfg_gen.fix_general_config():
            print("MTA general configuration changes saved and used by MTA!")
          else:
            print("MTA general configuration changes saved.")
            print("Ensure your MTA is using the new configuration; "
                  "reload it if needed.")
        else:
          print("MTA general configuration changes are needed.")

          try:
            cfg_gen.show_new_general_config_diff()
          except OSError:
            print("Error while showing configuration differences. "
            "The whole new configuration follows:")
            cfg_gen.show_new_general_config()

          print("\nMTA general configuration changes NOT saved: "
                "use -s | --save to save them.")
      else:
        print("No MTA general configuration changes are needed.")
    else:
      cfg_gen.build_defs()
      
      if args.save:
        if cfg_gen.update_defs():
          print("Policy definitions updated and used by MTA!")
        else:
          print("Policy definitions updated but not used yet by MTA: consider "
                "to reload it.")
      else:
        cfg_gen.show_defs()
        print("\nPolicy definitions NOT updated: "
              "use -s | --save to save them.")

  try:
    main()
  except (STARTTLSEverywhereCustomError,ValueError,TypeError) as e:
    print(e)
