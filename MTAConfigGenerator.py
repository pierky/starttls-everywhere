#!/usr/bin/env python

import sys
import string
import os, os.path
import argparse
import subprocess
from tempfile import NamedTemporaryFile

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

    l = [(num,line) for num,line in enumerate(self.lines) if line.startswith(var)]
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

  def build_new(self):
    """
    Build the content of the new configuration file

    Raise: BuildUnchangedConfigFileError

    Return the content itself.
    """
    
    if not self.changed:
      raise BuildUnchangedConfigFileError("Can't build an unchanged file")

    if len(self.additions) > 0:
      new_lines = [self.comment, self.comment + " New config lines added by STARTTLS Everywhere",
                    self.comment]
      new_lines.extend(self.additions)
      new_cf_lines = "\n".join(new_lines) + "\n"
    else:
      new_cf_lines = ""

    self.new_data = ""
    for num, line in enumerate(self.lines):
      if num in self.deletions:
        self.new_data += self.comment + line + " " + self.comment + " Line removed by STARTTLS Everywhere\n"
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

class PostfixConfigFile(MTAConfigFile):
  def __init__(self,path):
    MTAConfigFile.__init__(self,path)

    self.load()

# ----------------------------------------------------------------------------

class MTAConfigGenerator():
  def __init__(self, policy_config, fixup=False):
    self.policy_config = policy_config
    self.fixup = fixup

    self.changed_files = []

    self.policy_defs_file = ""
    self.policy_defs = ""

  def build_defs(self):
    """
    Build the new STARTTLS enforcing policy definitions.
    
    Must be implemented in child class.
    """

    self.policy_defs = ""

  def show_defs(self):
    """Print the new policy definitions."""

    sys.stdout.write(self.policy_defs)

  def update_defs(self):
    """
    Update STARTTLS enforcing policy definitions only
    without changing MTA's main configuration files.
    """
    if self.policy_defs != "":
      f = open(self.policy_defs_file, "w")
      f.write(self.policy_defs)
      f.close()

  def build_general_config(self):
    """
    Build changes needed to adapt MTA's main configuration
    to what's needed by STARTTLS-Everywhere.
    
    Return True if changes are needed, otherwise False.

    Files that need to be modified must be added to self.changed_files.
    
    Must be implemented in child class.
    """

    self.changed_files = []

  def show_new_general_config(self):
    """
    Print the new configuration for each file that needs
    to be changed
    """

    for F in self.changed_files:
      print("File: {}".format(F.path))
      sys.stdout.write(F.new_data)

  def fix_general_config(self):
    """
    Update only MTA's main configuration files, adapting them
    to what's needed by STARTTLS-Everywhere
    """
    for F in self.changed_files:
      F.save()

  def show_new_general_config_diff(self):
    """
    Show a diff between current and new MTA's general config.

    It uses the command line provided in STARTTLS-Everywhere
    configuration.
    """

    diff_tpl = Config.get("general","diff_cmd")

    for F in self.changed_files:
      if F.changed:

        temp_f = NamedTemporaryFile(delete=False)
        temp_f.write(F.new_data)
        temp_f.close()

        diff_cmd = diff_tpl.format(old=F.path, new=temp_f.name)

        print("Differences between {old} and "
        "the new configuration follow:\n\n"
        "\t{cmd}\n\n".format(old=F.path, cmd=diff_cmd))

        proc = subprocess.Popen(diff_cmd.split(" "))
        proc.communicate()
        os.remove(temp_f.name)

class PostfixConfigGenerator(MTAConfigGenerator):

  def __init__(self, policy_config, postfix_dir, fixup=False):
    MTAConfigGenerator.__init__(self, policy_config, fixup)

    self.postfix_dir = postfix_dir

    self.postfix_cf_file = \
      os.path.join(self.postfix_dir, \
      Config.get("postfix", "main_config_file"))

    self.policy_defs_file = \
      os.path.join(self.postfix_dir, \
      Config.get("postfix", "policy_defs_file"))

    if self.fixup:
      if not os.path.isfile(self.postfix_cf_file):
        raise FileNotFoundError("Postfix main configuration file "
                                "not found: {}".format(self.postfix_cf_file))

      if not os.access(self.postfix_cf_file, os.W_OK):
        raise InsufficientPermissionError("Can't write to %s, "
                                          "please re-run as root." % \
                                          self.postfix_cf_file)

    self.ca_file = Config.get("postfix","ca_file",default="")

    self.ca_path = Config.get("postfix","ca_path")
    
  def build_general_config(self):
    """Postfix: main.cf"""

    MTAConfigGenerator.build_general_config(self)

    MainCF = PostfixConfigFile(self.postfix_cf_file)

    # Check we're currently accepting inbound STARTTLS sensibly
    MainCF.ensure_cf_var("smtpd_use_tls", "yes", [])

    # Ideally we use it opportunistically in the outbound direction
    MainCF.ensure_cf_var("smtp_tls_security_level", "may", ["encrypt","dane"])

    # Maximum verbosity lets us collect failure information
    MainCF.ensure_cf_var("smtp_tls_loglevel", "1", [])

    # Inject a reference to our per-domain policy map
    policy_cf_entry = "texthash:" + self.policy_defs_file
    MainCF.ensure_cf_var("smtp_tls_policy_maps", policy_cf_entry, [])

    if self.ca_file != "":
      MainCF.ensure_cf_var("smtp_tls_CAfile", self.ca_file, [])
    if self.ca_path != "":
      MainCF.ensure_cf_var("smtp_tls_CApath", self.ca_path, [])

    changed = False
    if MainCF.changed:
      MainCF.build_new()
      changed = True
      self.changed_files.append(MainCF)

    return changed

  def build_defs(self):
    MTAConfigGenerator.build_defs(self)

    policy_lines = []
    for address_domain, properties in self.policy_config.acceptable_mxs.items():
      mx_list = properties["accept-mx-hostnames"]
      if len(mx_list) > 1:
        print "Lists of multiple accept-mx-hostnames not yet supported, skipping ", address_domain

      mx_domain = mx_list[0]

      mx_policy = self.policy_config.tls_policies[mx_domain]

      entry = address_domain + " encrypt"

      if "min-tls-version" in mx_policy:
        if mx_policy["min-tls-version"].lower() == "tlsv1":
          entry += " protocols=!SSLv2:!SSLv3"
        elif mx_policy["min-tls-version"].lower() == "tlsv1.1":
          entry += " protocols=!SSLv2:!SSLv3:!TLSv1"
        elif mx_policy["min-tls-version"].lower() == "tlsv1.2":
          entry += " protocols=!SSLv2:!SSLv3:!TLSv1:!TLSv1.1"
        else:
          print mx_policy["min-tls-version"]

      policy_lines.append(entry)

    self.policy_defs = "\n".join(policy_lines) + "\n"

if __name__ == "__main__":
  parser = argparse.ArgumentParser(
    description="""MTA configuration generator""")

  parser.add_argument("-c", "--cfg", default=Config.default_cfg_path,
                      help="general configuration file path", metavar="file",
                      dest="cfg_path")

  parser.add_argument("-m", default="postfix",
                      help="MTA flavor", choices=["postfix"], 
                      dest="mta_flavor")

  parser.add_argument("-f", "--fix", action="store_true",
                      help="fix MTA general configuration; "
                      "by default, only STARTTLS policies are updated "
                      "while the main MTA configuration is kept unchanged. "
                      "Changes are saved only if -s | --save arguments are "
                      "given.",
                      dest="fixup")

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

  if args.mta_flavor == "postfix":
    postfix_dir = Config.get("postfix","cfg_dir")
    pcgen = PostfixConfigGenerator(c, postfix_dir, fixup=args.fixup)

    if args.fixup:
      if pcgen.build_general_config():

        if args.save:
          pcgen.fix_general_config()
          print("General configuration changes saved!")
        else:
          print("General configuration changes are needed.")

          try:
            pcgen.show_new_general_config_diff()
          except OSError:
            print("Error while showing configuration differences. "
            "The whole new configuration follows:")
            pcgen.show_new_general_config()
          except:
            raise

          print("\nGeneral configuration changes NOT saved: use -s | --save to save them.")
      else:
        print("No general configuration changes are needed.")
    else:
      pcgen.build_defs()
      if args.save:
        pcgen.update_defs()
        print("Policy definitions updated!")
      else:
        pcgen.show_defs()
        print("\nPolicy definitions NOT updated: use -s | --save to save them.")
  else:
    raise ValueError("Unexpected MTA flavor: {}".format(args.mta_flavor))
