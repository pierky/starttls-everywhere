#!/usr/bin/env python

import sys
import string
import os, os.path

from Config import Config

def parse_line(line_data):
  """
  Return the (line number, left hand side, right hand side) of a stripped
  postfix config line.

  Lines are like:
  smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
  """
  num,line = line_data
  left, sep, right = line.partition("=")
  if not sep:
    return None
  return (num, left.strip(), right.strip())

class MTAConfigGenerator:
  def __init__(self, policy_config):
    self.policy_config = policy_config

class ExistingConfigError(ValueError): pass

class PostfixConfigGenerator(MTAConfigGenerator):
  def __init__(self, policy_config, postfix_dir, fixup=False):
    self.fixup = fixup
    self.postfix_dir = postfix_dir
    self.postfix_cf_file = self.find_postfix_cf()
    if not os.access(self.postfix_cf_file, os.W_OK):
      raise Exception("Can't write to %s, please re-run as root."
        % self.postfix_cf_file)
    self.policy_file = os.path.join(postfix_dir,
                                    Config.get("postfix","policy_file"))
    self.ca_file = os.path.join(postfix_dir, Config.get("postfix","ca_file"))
    MTAConfigGenerator.__init__(self, policy_config)
    self.wrangle_existing_config()
    self.set_domainwise_tls_policies()
    self.update_CAfile()
    os.system("sudo service postfix reload")

  def ensure_cf_var(self, var, ideal, also_acceptable):
    """
    Ensure that existing postfix config @var is in the list of @acceptable
    values; if not, set it to the ideal value.
    """
    acceptable = [ideal] + also_acceptable

    l = [(num,line) for num,line in enumerate(self.cf) if line.startswith(var)]
    if not any(l):
      self.additions.append(var + " = " + ideal)
    else:
      values = map(parse_line, l)
      if len(set(values)) > 1:
        if self.fixup:
          conflicting_lines = [num for num,_var,val in values]
          self.deletions.extend(conflicting_lines)
          self.additions.append(var + " = " + ideal)
        else:
          raise ExistingConfigError, "Conflicting existing config values " + `l`
      val = values[0][2]
      if val not in acceptable:
        if self.fixup:
          self.deletions.append(values[0][0])
          self.additions.append(var + " = " + ideal)
        else:
          raise ExistingConfigError, "Existing config has %s=%s"%(var,val)

  def wrangle_existing_config(self):
    """
    Try to ensure/mutate that the config file is in a sane state.
    Fixup means we'll delete existing lines if necessary to get there.
    """
    self.additions = []
    self.deletions = []
    self.fn = self.find_postfix_cf()
    self.raw_cf = open(self.fn).readlines()
    self.cf = map(string.strip, self.raw_cf)
    #self.cf = [line for line in cf if line and not line.startswith("#")]

    # Check we're currently accepting inbound STARTTLS sensibly
    self.ensure_cf_var("smtpd_use_tls", "yes", [])
    # Ideally we use it opportunistically in the outbound direction
    self.ensure_cf_var("smtp_tls_security_level", "may", ["encrypt","dane"])
    # Maximum verbosity lets us collect failure information
    self.ensure_cf_var("smtp_tls_loglevel", "1", [])
    # Inject a reference to our per-domain policy map
    policy_cf_entry = "texthash:" + self.policy_file

    self.ensure_cf_var("smtp_tls_policy_maps", policy_cf_entry, [])
    self.ensure_cf_var("smtp_tls_CAfile", self.ca_file, [])

    self.maybe_add_config_lines()

  def maybe_add_config_lines(self):
    if not self.additions:
      return
    if self.fixup:
      print "Deleting lines:", self.deletions
    self.additions[:0]=["#","# New config lines added by STARTTLS Everywhere","#"]
    new_cf_lines = "\n".join(self.additions) + "\n"
    print "Adding to %s:" % self.fn
    print new_cf_lines
    if self.raw_cf[-1][-1] == "\n":     sep = ""
    else:                               sep = "\n"

    self.new_cf = ""
    for num, line in enumerate(self.raw_cf):
      if self.fixup and num in self.deletions:
        self.new_cf += "# Line removed by STARTTLS Everywhere\n# " + line
      else:
        self.new_cf += line
    self.new_cf += sep + new_cf_lines

    f = open(self.fn, "w")
    f.write(self.new_cf)
    f.close()

  def find_postfix_cf(self):
    "Search far and wide for the correct postfix configuration file"
    return os.path.join(self.postfix_dir, "main.cf")

  def set_domainwise_tls_policies(self):
    self.policy_lines = []
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
      self.policy_lines.append(entry)

    f = open(self.policy_file, "w")
    f.write("\n".join(self.policy_lines) + "\n")
    f.close()

  def update_CAfile(self):
    os.system("cat /usr/share/ca-certificates/mozilla/*.crt > " +
      self.ca_file)

if __name__ == "__main__":
  import DefsParser
  if len(sys.argv) != 3:
    print "Usage: MTAConfigGenerator starttls-everywhere.json /etc/postfix"
    sys.exit(1)
  c = DefsParser.Defs(sys.argv[1])
  postfix_dir = sys.argv[2]
  pcgen = PostfixConfigGenerator(c, postfix_dir, fixup=True)
  print "Done."
