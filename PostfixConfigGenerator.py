import os, os.path
import subprocess
import base64
import hashlib

from MTAConfigGenerator import *
from Config import Config
from Errors import *
from Utils import *

class PostfixConfigFile(MTAConfigFile):
  def __init__(self,path):
    MTAConfigFile.__init__(self,path)

    self.load()

class PostfixConfigGenerator(MTAConfigGenerator):

  allowed_ignore_list = {
    "log-only": "skip policies where log-only = True",
    "ta-tlsa": "skip policies that require Trust Anchor validation "
               "but that provide certificate's or pubkey's digest "
               "only"
  }

  def __init__(self, policy_config, postfix_dir, fixup=False,
               ignore_list=None):
    MTAConfigGenerator.__init__(self, policy_config, fixup,
                                ignore_list)

    self.postfix_dir = postfix_dir

    self.postfix_cf_file = \
      os.path.join(self.postfix_dir, \
      Config.get("postfix", "main_config_file"))

    self.policy_defs_file = \
      os.path.join(self.postfix_dir, \
      Config.get("postfix", "policy_defs_file"))

    if self.fixup:
      if not os.path.isfile(self.postfix_cf_file):
        raise MissingFileError("Postfix main configuration file "
                                "not found: {}".format(self.postfix_cf_file))

      if not os.access(self.postfix_cf_file, os.W_OK):
        raise InsufficientPermissionError("Insufficient permissions to write "
                                          "Postfix configuration to %s" %
                                          self.postfix_cf_file)

    self.ca_file = Config.get("postfix","ca_file",default="")

    self.ca_path = Config.get("postfix","ca_path")

    self.tls_map_type = Config.get("postfix","smtp_tls_policy_maps_type")

    if self.tls_map_type not in [ "texthash", "hash", "btree" ]:
      raise ValueError("Unsupported type for smtp_tls_policy_maps: %s "
                       "Change the smtp_tls_policy_maps_type parameter in "
                       "the STARTTLS-Everywhere postfix configuration." %
                       self.tls_map_type)

    self.postmap_path = Config.get("postfix","postmap_path")
    if not os.path.isfile(self.postmap_path):
      raise MissingFileError("Postfix's postmap program not found at %s; "
                              "Change the postmap_path parameter in the "
                              "STARTTLS-Everywhere postfix configuration." %
                              self.postmap_path)
    if not os.access(self.postmap_path, os.X_OK):
      raise InsufficientPermissionError("Insufficient permissions to run "
                                        "postmap")

  def build_general_config(self):
    """Postfix: main.cf"""

    self.changed_files = []

    MainCF = PostfixConfigFile(self.postfix_cf_file)

    # Check we're currently accepting inbound STARTTLS sensibly
    MainCF.ensure_cf_var("smtpd_use_tls", "yes", [])

    # Ideally we use it opportunistically in the outbound direction
    MainCF.ensure_cf_var("smtp_tls_security_level", "may", ["encrypt","dane"])

    # Maximum verbosity lets us collect failure information
    MainCF.ensure_cf_var("smtp_tls_loglevel", "1", ["2","3","4"])

    # Ensure MD5 is not used to verify EE certificates fingerprints
    MainCF.ensure_cf_var("smtp_tls_fingerprint_digest", "sha256", ["sha1"])

    # Inject a reference to our per-domain policy map
    policy_cf_entry = self.tls_map_type + ":" + self.policy_defs_file
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

  def _get_cfg_var(self,var):
    MainCF = PostfixConfigFile(self.postfix_cf_file)
    return MainCF.get_cf_var(var)

  def _build_tafile_list(self,domain,lst):
    # http://www.postfix.org/postconf.5.html#smtp_tls_trust_anchor_file
    # "PEM-format files with trust-anchor certificates and/or public keys"
    # "the trust-anchor PEM file must be accessible to the Postfix SMTP client
    # in the chroot jail if applicable"
    """
    Return a list of file names as seen by Postfix (chrooted or not).
    Each file contains a PEM trusth anchor.

    Raise:
      PolicyNotImplementedError
      ValueError
      InsufficientPermissionError
    """
    res = []

    # Postfix needs a full certificate or full pubkey to perform
    # TA validation: check if at least one is given.
    full_entity_found = False
    for tlsa in lst:
      if "hash_alg" not in tlsa:
        full_entity_found = True

    if not full_entity_found:
      raise PolicyNotImplementedError("Not implemented: Trust Anchor "
                                      "verification required for %s but "
                                      "full certificate/pubkey not "
                                      "provided. "
                                      "Postfix needs the full certificate "
                                      "or the full public key, it can't "
                                      "perform TA verification using only "
                                      "their hash." % domain,
                                      ignore_flag="ta-tlsa")

    tafile_real_dir = Config.get("postfix","tafile_real_dir")
  
    # tafile_dir: how Postfix views the directory where tafile will be stored
    #             (chrooted or not, depending on its configuration)
    tafile_dir = Config.get("postfix","tafile_dir")

    if not os.path.isdir(tafile_real_dir):
      raise MissingFileError("The directory where Trust Anchor files have "
                              "to be stored (tafile_real_dir) does not "
                              "exist: %s" % tafile_real_dir)

    if not os.access(tafile_real_dir, os.W_OK):
      raise InsufficientPermissionError("Can't write new files into the "
                                        "Trust Anchor files directory "
                                        "(tafile_real_dir): %s" %
                                        tafile_real_dir)

    cnt = 0
    for tlsa in lst:
      if "hash_alg" not in tlsa:
        if tlsa["data_format"] == "hex":
          b64_data = base64.b64encode(hexstr_to_bin(tlsa["data"]))
        elif tlsa["data_format"] == "b64":
          b64_data = tlsa["data"]
        else:
          raise ValueError("Unknown data format for %s's Trust Anchor: %s" %
                           (domain,tlsa["data_format"]))

        cnt = cnt+1
        ta_filename = "tafile-%s-%s.pem" % (domain,cnt)
        ta_real_filepath = tafile_real_dir + "/" + ta_filename
        tafile = tafile_dir + "/" + ta_filename
        with open(ta_real_filepath, "w") as f:
          if tlsa["entity"] == "certificate":
            header = "-----BEGIN CERTIFICATE-----"
            footer = "-----END CERTIFICATE-----"
          elif tlsa["entity"] == "pubkey":
            header = "-----BEGIN PUBLIC KEY-----"
            footer = "-----END PUBLIC KEY-----"

          f.write(header + "\n" +
                  "\n".join(split_string_every_n_char(b64_data,64)) + "\n" +
                  footer)

        res.append(tafile)

    return res

  def _build_fingerprint_list(self,domain,lst):
    """
    Return a list of fingerprints in Postfix format:
      ["ab:12:cd:...", "34:ef:56:..."]

    Raise:
      ValueError
      ExistingConfigError
    """
    res = []

    # http://www.postfix.org/postconf.5.html#smtp_tls_fingerprint_digest
    smtp_tls_fingerprint_digest = \
      self._get_cfg_var("smtp_tls_fingerprint_digest")
    if not smtp_tls_fingerprint_digest:
      smtp_tls_fingerprint_digest = "md5"

    # Will be set to True if at least one of the provided fingerprints
    # uses an hash alg that matches the one used by Postfix.
    digest_matched = False

    for tlsa in lst:
      # hex_fprint will contain the fingerprint in hex str format: abcd12...
      hex_fprint = None

      if "hash_alg" in tlsa:
        # Fingerprint is given in the policy, just need to translate it in the
        # Postfix format: xx:xx:xx:...

        if tlsa["data_format"] == "hex":
          hex_fprint = tlsa["data"]
        elif tlsa["data_format"] == "b64":
          hex_fprint = bin_to_hexstr(base64.b64decode(tlsa["data"]))
        else:
          raise ValueError("Unknown data format for %s's EE fingerprint: %s" %
                           (domain,tlsa["data_format"]))

        if tlsa["hash_alg"] == smtp_tls_fingerprint_digest:
          digest_matched = True
      else:
        # The policy contains only the full entity (pubkey or leaf certificate)
        # so the fingerprint must be calculated here.

        if tlsa["data_format"] == "hex":
          bin_data = hexstr_to_bin(tlsa["data"])
        elif tlsa["data_format"] == "b64":
          bin_data = base64.b64decode(tlsa["data"])
        else:
          raise ValueError("Unknown data format for %s's EE fingerprint: %s" %
                           (domain,tlsa["data_format"]))

        if smtp_tls_fingerprint_digest == "sha1":
          dgst = hashlib.sha1()
        elif smtp_tls_fingerprint_digest == "sha256":
          dgst = hashlib.sha256()
        elif smtp_tls_fingerprint_digest == "sha512":
          dgst = hashlib.sha512()
        else:
          raise ExistingConfigError("Postfix is using an "
                           "unsupported hash algorithm "
                           "for smtp_tls_fingerprint_digest ({hash}), the EE "
                           "{entity}'s fingerprint for {domain}'s TLSA "
                           "can't be calculated. "
                           "Fix Postfix configuration or modify the "
                           "TLS policy.".format(domain=domain,
                           entity=tlsa["entity"],
                           hash=smtp_tls_fingerprint_digest))

        dgst.update(bin_data)
        hex_fprint = dgst.hexdigest()
        digest_matched = True

      res.append(hexstr_to_hexstr_with_colon(hex_fprint))

    if not digest_matched:
      raise ExistingConfigError("None of the TLSAs of {domain} matches the "
                       "current hash algorithm used by Postfix for "
                       "fingerprints matching: {hash}. "
                       "Fix Postfix configuration or modify the TLS "
                       "policy.".format(domain=domain,
                       hash=smtp_tls_fingerprint_digest))

    return res

  def _build_smtp_tls_policy_maps_line(self,domain,policy):
    # http://www.postfix.org/TLS_README.html#client_tls_policy
    """
    Return a line for smtp_tls_policy_maps file.

    Raise:
      PolicyNotImplementedError
    """

    if "log-only" in policy and policy["log-only"]:
      raise PolicyNotImplementedError("Not implemented: log-only = True (%s)" %
                                      domain, ignore_flag="log-only")

    res = domain

    if "certificate-matching" not in policy:
      # http://www.postfix.org/TLS_README.html#client_tls_encrypt
      res += " encrypt"

    else:
      if policy["certificate-matching"] == "valid":
        # http://www.postfix.org/TLS_README.html#client_tls_secure
        res += " secure"

      elif policy["certificate-matching"] == "TA":
        # http://www.postfix.org/postconf.5.html#smtp_tls_trust_anchor_file
        res += " secure " + " ".join( \
          ["tafile=" + tafile for tafile in \
          self._build_tafile_list(domain, policy["ta-tlsa"])])

      elif policy["certificate-matching"] == "EE":
        # http://www.postfix.org/TLS_README.html#client_tls_fprint
        res += " fingerprint match=" + "|".join(
               self._build_fingerprint_list(domain, policy["ee-tlsa"]))

      if policy["certificate-matching"] in ["valid","TA"]:
        # http://www.postfix.org/postconf.5.html#smtp_tls_verify_cert_match
        names = [ domain ]
        if "allowed-cert-names" in policy:
          names.extend(policy["allowed-cert-names"])
        res += " match=nexthop:" + ":".join(list(set(names)))

    if "min-tls-version" in policy:
      # Policy definitions format specifies protocol names that are already
      # compatible with Postfix (TLSv1, TLSv1.1, TLSv1.2, TLSv1.3);
      # just concat them.
      res += " protocols=" + ":".join(
             tls_protocols_higher_than(policy["min-tls-version"]))

    return res

  def build_defs(self):
    """Update self.policy_defs with the new policy in Postfix format."""
    self.policy_defs = ""

    # http://www.postfix.org/postconf.5.html#smtp_tls_policy_maps
    policy_lines = []

    for domain, properties in self.policy_config.tls_policies.items():
      try:
        new_line = self._build_smtp_tls_policy_maps_line(domain, properties)

        if new_line != "":
          if "comment" in properties:
            policy_lines.append("# " + properties["comment"].replace("\n"," "))
          policy_lines.append(new_line)
      except PolicyNotImplementedError as e:
        if e.ignore_flag and e.ignore_flag in self.ignore_list:
          pass
        else:
          raise

    self.policy_defs = "\n".join(policy_lines) + "\n"

  def update_defs(self):
    """
    Update the file referenced by Postfix's smtp_tls_policy_maps.

    It's a 3 steps process:

    1) create a temporary file with the new TLS policy;
    2) use postmap to build the real database (only for some table's types);
    3) move the new database into the path used by smtp_tls_policy_maps.

    Raise:
      PolicyBuildingError
    """
    args = [ self.postmap_path ]
    if self.policy_defs != "":
      # step 1
      try:
        tmp_file = self.policy_defs_file + ".in.tmp"
        with open(tmp_file, "w") as f:
          f.write(self.policy_defs)
      except Exception as e:
        raise PolicyBuildingError("Can't write the new TLS policy to "
                                  "temporary file {temp}: "
                                  "{e}".format(e=str(e), temp=tmp_file))

      # step 2
      if self.tls_map_type in [ "hash", "btree" ]:
        args.extend([self.tls_map_type + ":" + tmp_file])

        try:
          postmap_p = subprocess.Popen(args, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
          postmap_stdout, postmap_stderr = postmap_p.communicate()
          postmap_exitcode = postmap_p.wait()

          if postmap_exitcode != 0:
            raise PolicyBuildingError("The postmap program encountered a "
                                      "problem while processing the new TLS "
                                      "policy: exit code {code} - "
                                      "{stderr}".format(code=postmap_exitcode,
                                      stderr=postmap_stderr))
        except Exception as e:
          raise PolicyBuildingError("An error has occurred while running "
                                    "postmap to build the TLS policy "
                                    "{type} database: {e}".format(e=str(e),
                                    type=self.tls_map_type))

        tmp_db_file = tmp_file + ".db"
        new_db_file = self.policy_defs_file + ".db"
      else:
        tmp_db_file = tmp_file
        new_db_file = self.policy_defs_file

      # step 3
      try:
        os.rename(tmp_db_file, new_db_file)
      except Exception as e:
        raise PolicyBuildingError("Can't move the new TLS policy database "
                                  "into the path used by Postfix: "
                                  "{e}".format(e=str(e)))

      if self.tls_map_type in [ "hash", "btree" ]:
        return True
      else:
        return False
