#!/usr/bin/env python

import json
from datetime import datetime
import argparse
import base64
import re
from M2Crypto import X509,BIO,RSA

from Config import Config
from Utils import *
from Errors import *

TIMESTAMP_FORMAT="%Y-%m-%dT%H:%M:%S%Z"
MAX_VERSION="1.x"
MAX_VERSION_LAST_IMPLEMENTED_MAJOR=1

def parse_timestamp(ts):
  if type(ts) == int:
    try:
      return datetime.utcfromtimestamp(ts)
    except:
      raise ValueError("Invalid timestamp integer: %s" % ts)

  else:
    try:
      return datetime.strptime(ts+"UTC",TIMESTAMP_FORMAT)
    except:
      raise ValueError("Invalid timestamp: %s" % ts)

def parse_version(v):
  return [int(x) for x in re.sub(r'(\.0+)*$','', v).split(".")]

class Defs:
  legal = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
  known_tlds = []

  def looks_like_a_domain(self,s):
    """Return true if string looks like a domain, as best we can tell...

    Raise:
      ValueError
    """
    try:
      domain = s.lower()
      assert domain[0].islower()
      assert all([c in self.legal for c in domain])
    except:
      return False

    tld = s.split(".")[-1]
    if tld not in self.known_tlds:
      # hard-fail, since known_tlds is supposed to be 
      # official and up to date (within tlds_update_interval)
      raise ValueError("Unknown TLD for %s: %s" % (domain,tld))

    return True

  def _read_tlsas(self,name,lst):
    """
    Read and validate the list of TLSA.

    Return:
      list of TLSA objects
    """
    res = []

    for tlsa in lst:
      new_tlsa = self._read_tlsa(name,tlsa)
      res.append(new_tlsa)

    return res

  def _read_tlsa(self,name,tlsa):
    try:
      new_tlsa = {}
      for attr, val in tlsa.items():
        if type(val) not in [ str, unicode ]:
          raise TypeError("Invalid %s type for %s: must be string" %
                          (attr,name))

        elif attr == "entity":
          if val not in [ "pubkey", "certificate" ]:
            raise ValueError("Unknown %s for TLSA of %s: %s" %
                             (attr,name,val))
          new_tlsa[attr] = val

        elif attr == "hash_alg":
          if val not in [ "sha1", "sha256", "sha512" ]:
            raise ValueError("Unknown %s for TLSA of %s: %s" %
                             (attr,name,val))
          new_tlsa[attr] = val

        elif attr == "data_format":
          if val not in [ "hex", "b64" ]:
            raise ValueError("Unknown %s for TLSA of %s: %s" %
                             (attr,name,val))
          new_tlsa[attr] = val

        elif attr == "data":
          if val.strip() == "":
            raise ValueError("Empty %s value for TLSA of %s: %s" %
                             (attr,name,val))
          new_tlsa[attr] = val

      for e in [ "entity", "data_format", "data" ]:
        if e not in new_tlsa:
          raise ValueError("Missing %s for TLSA of %s" % (e,name))

      # data_len will be used to eventually verify digest length on the
      # basis of the selected hash alg.
      if new_tlsa["data_format"] == "b64":
        try:
          data_len = len(base64.b64decode(new_tlsa["data"]))
        except:
          raise ValueError("Data for TLSA of %s not in base64 format" % name)

      elif new_tlsa["data_format"] == "hex":
        new_tlsa["data"] = new_tlsa["data"].lower()

        try:
          assert all([c in "0123456789abcdef" for c in new_tlsa["data"]])
        except:
          raise ValueError("Invalid characters in hex data for TLSA of %s" %
                           (name))
        hex_data_len = len(new_tlsa["data"])

        if hex_data_len % 2 != 0:
          raise ValueError("Data lenght for TLSA of %s must be an even number"%
                           name)
        data_len = hex_data_len / 2

      else:
        raise ValueError("Data format %s for TLSA of %s not implemented" %
                         (new_tlsa["data_format"],name))

      if "hash_alg" in new_tlsa:
        try:
          dgst_len = {"sha1":20,"sha256":32,"sha512":64}[new_tlsa["hash_alg"]]
        except:
          raise ValueError("Hash algorithm %s for TLSA of %s not implemented" %
                           (new_tlsa["hash_alg"],name))

        if data_len != dgst_len:
          raise ValueError("Invalid %s digest data length for TLSA of %s: "
                          "should be %s bytes" %
                          (new_tlsa["hash_alg"],name,dgst_len))
      else:
        if new_tlsa["data_format"] == "b64":
          der_data = base64.b64decode(new_tlsa["data"])
        elif new_tlsa["data_format"] == "hex":
          der_data = hexstr_to_bin(new_tlsa["data"])

        if new_tlsa["entity"] == "certificate":
          try:
            X509.load_cert_string(der_data, X509.FORMAT_DER)
          except:
            raise ValueError("The certificate in %s's TLSA is not in a valid "
                             "format." % name)
        elif new_tlsa["entity"] == "pubkey":
          try:
            b64_data = "\n".join( \
              split_string_every_n_char(base64.b64encode(der_data),64))

            bio = BIO.MemoryBuffer("-----BEGIN PUBLIC KEY-----\n"
                                  "%s\n"
                                  "-----END PUBLIC KEY-----" %
                                  b64_data)
            RSA.load_pub_key_bio(bio)
          except:
            raise ValueError("The public key in %s's TLSA is not in a valid "
                             "format." % name)

    except:
      print("Error parsing TLSA for %s: %s" % (name,tlsa))
      raise

    return new_tlsa

  def _read_policy(self,name,dic,is_global=False,curr=None):
    """
    Read and validate attributes of a policy.

    When _read_policy is used to read local attributes of a policy
    that uses the from-global statement the curr argument is a 
    pointer to the current policy's dictionary.

    Return:
      dictionary with policy attributes

    Raise:
      ValueError, TypeError

    """
    if is_global:
      res = {}
    else:
      if curr is None:
        res = {}
      else:
        res = curr

    for attr, val in dic.items():
      if val is None:
        if is_global:
          raise ValueError("Global policies don't allow attributes to "
                           "be set to null: %s on %s " % (attr,name))
        else:
          res.pop(attr,None)
          continue

      if attr == "comment":
        if type(val) not in [ str, unicode ]:
          raise TypeError("Invalid %s type for %s: must be string" %
                          (attr,name))
        res[attr] = val

      elif attr == "certificate-matching":
        if type(val) not in [ str, unicode ]:
          raise TypeError("Invalid %s type for %s: must be string" %
                          (attr,name))

        if val not in [ "valid", "TA", "EE" ]:
          raise ValueError("Unknown %s for %s: %s" %
                           (attr,name,val))
        res[attr] = val
        
      elif attr == "log-only":
        if type(val) != bool:
          raise TypeError("Invalid %s type for %s: must be boolean" %
                          (attr,name))
        res[attr] = val

      elif attr == "min-tls-version":
        if type(val) not in [ str, unicode ]:
          raise TypeError("Invalid %s type for %s: must be string" %
                          (attr,name))

        if val not in [ "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" ]:
          raise ValueError("Unknown %s for %s: %s" %
                           (attr,name,val))
        res[attr] = val

      elif attr == "ee-tlsa" or attr == "ta-tlsa":
        if type(val) != list:
          raise TypeError("Invalid %s type for %s: must be a list" %
                          (attr,name))
        res[attr] = self._read_tlsas(name,val)

      elif attr == "allowed-cert-names":
        if type(val) != list:
          raise TypeError("Invalid %s type for %s: must be a list" %
                          (attr,name))

        for certname in val:
          if type(certname) not in [str,unicode]:
            raise TypeError("%s's allowed-cert-names must contain strings "
                            "only" % name)

          if certname.startswith("."):
            if not self.looks_like_a_domain(certname[1:]):
              raise ValueError("Invalid allowed-cert-name for %s: %s" %
                              (name,certname))
          else:
            if not self.looks_like_a_domain(certname):
              raise ValueError("Invalid allowed-cert-name for %s: %s" %
                               (name,certname))

        res["allowed-cert-names"] = val

    if "ee-tlsa" in res and "certificate-matching" not in res:
      #TODO: improve logging
      print("Warning: EE TLSAs with no certificate-matching for %s - "
            "they will be ignored" % name)
    if "ta-tlsa" in res and "certificate-matching" not in res:
      #TODO: improve logging
      print("Warning: TA TLSAs with no certificate-matching for %s - "
            "they will be ignored" % name )

    if "certificate-matching" in res:
      for attr, list_name in [("EE", "ee-tlsa"), ("TA", "ta-tlsa")]:
        if res["certificate-matching"] == attr:
          if list_name not in res:
            raise ValueError("Missing {attr} TLSAs with "
                             "certificate-matching = {attr} "
                             "for {name}".format(attr=attr,name=name))
          elif res[list_name] == []:
            raise ValueError("Empty list of {attr} TLSAs with "
                             "certificate-matching = {attr} "
                             "for {name}".format(attr=attr,name=name))

      if res["certificate-matching"] in [ "valid", "TA" ]:
        if "allowed-cert-names" in res:
          unique_names = []
          for certname in res["allowed-cert-names"]:
            if certname in unique_names:
              raise ValueError("Duplicate name found in allowed-cert-names "
                               "for %s: %s" % (name,certname))
            elif certname == name:
              raise ValueError("Can't include the same email domain of a "
                               "policy in its allowed-cert-names: %s" % name)
            else:
              unique_names.append(certname)
    if not "certificate-matching" in res or \
      res["certificate-matching"] == "EE":
      if "allowed-cert-names" in res:
        #TODO: improve logging
        print("Warning: allowed-cert-names for %s will be ignored unless "
              "certificate-matching is valid or TA." % name)

    return res

  def __init__(self, policy_file = "config.json"):
    """
    policy_file can be a string (policy file path) or a file object.

    Raise:
      ValueError
      TypeError
    """
    self.known_tlds = Config.get_tlds_list()

    self.global_policies = {}
    self.tls_policies = {}
    self.version = None
    self.author = None
    self.timestamp = None
    self.expires = None

    if type(policy_file) is str:
      f = open(policy_file)
    elif type(policy_file) is file:
      f = policy_file
    else:
      raise TypeError("Invalid policy_file: %s - must be string or file." %
                      type(policy_file))

    try:
      self.cfg = json.loads(f.read())
    except:
      raise ValueError("Policy definitions not in a valid JSON format")

    if not "version" in self.cfg:
      raise ValueError("Missing version")
    else:
      val = self.cfg["version"].strip()
      if type(val) not in [str, unicode]:
        raise TypeError("Version must be a string")
      if val == "":
        raise ValueError("Empty version")

      try:
        ver = parse_version(val)
      except:
        raise ValueError("Invalid version format: must be x.y")

      if ver[0] > MAX_VERSION_LAST_IMPLEMENTED_MAJOR:
        raise ValueError("Unknown policy definitions format version: %s "
                         "This version of the software implements only "
                         "versions up to %s" % (val,MAX_VERSION))
      self.version = val

    if not "author" in self.cfg:
      raise ValueError("Missing author")
    else:
      val = self.cfg["author"]
      if type(val) not in [str, unicode]:
        raise TypeError("Author must be a string")
      self.author = val

    if not "timestamp" in self.cfg:
      raise ValueError("Missing timestamp")
    else:
      val = self.cfg["timestamp"]
      self.timestamp = parse_timestamp(val)

    if not "expires" in self.cfg:
      raise ValueError("Missing expires")
    else:
      val = self.cfg["expires"]
      self.expires = parse_timestamp(val)

      if self.expires <= datetime.utcnow():
        raise ValueError("Policy has expired at %s UTC" % self.expires)

    if "global-policies" in self.cfg:
      for global_policy_name, policy in self.cfg["global-policies"].items():
        if type(policy) != dict:
          raise TypeError("Global policy %s must be a dict" %
                          global_policy_name)

        if "from-global" in policy:
          raise ValueError("Global policies can't contain "
                          "from-global statements: %s" % global_policy_name)

        self.global_policies[global_policy_name] = \
                                    self._read_policy(global_policy_name,
                                                      policy, is_global=True)

    if not "tls-policies" in self.cfg:
      raise ValueError("Missing tls-policies")
    else:
      if type(self.cfg["tls-policies"]) != dict:
        raise TypeError("tls-policies must be a dict")

      for domain, domain_policy in self.cfg["tls-policies"].items():
        if type(domain_policy) != dict:
          raise TypeError("Policy for %s domain must be a dict" %
                          domain)

        if not self.looks_like_a_domain(domain):
          raise ValueError("Invalid domain: %s" % domain)

        if "from-global" in domain_policy:
          if type(domain_policy["from-global"]) not in [str,unicode]:
            raise TypeError("from-global for %s domain must be a string" %
                            domain)

          if domain_policy["from-global"] not in self.global_policies:
            raise ValueError("Global policy referenced by %s from-global "
                            "does not exist in global-policies: %s" %
                            (domain,domain_policy["from-global"]))

          self.tls_policies[domain] = \
            self.global_policies[domain_policy["from-global"]].copy()

          self._read_policy(domain, domain_policy,
                            is_global=False, curr=self.tls_policies[domain])
        else:
          self.tls_policies[domain] = self._read_policy(domain,domain_policy)

  def to_json(self):
    """
    Return a dictionary, suitable for JSON representation.
    """
    res = {}
    for prop, attr in [(self.version,"version"),
                       (self.author,"author"),
                       (self.timestamp.strftime(TIMESTAMP_FORMAT),"timestamp"),
                       (self.expires.strftime(TIMESTAMP_FORMAT),"expires"),
                       (self.global_policies,"global-policies"),
                       (self.tls_policies,"tls-policies")]:
      res[attr] = prop
    return res

if __name__ == "__main__":
  parser = argparse.ArgumentParser(
    description="STARTTLS policy definitions validator")

  parser.add_argument("-c", "--cfg", default=Config.default_cfg_path,
                      help="general configuration file path", metavar="file",
                      dest="cfg_path")

  parser.add_argument("-j", nargs="?", const="*",
                      metavar="domain",
                      help="print the resultant JSON policy, optionally "
                      "limited to domain", dest="print_json")

  parser.add_argument("policy_def", help="""JSON policy definitions file; """
                      """"-" to read from stdin""",
                      metavar="policy_defs.json",
                      type=argparse.FileType("r"))

  args = parser.parse_args()

  try:
    Config.read(args.cfg_path)

    c = Defs(args.policy_def)
    print("Validation OK")
    if args.print_json:
      j = c.to_json()
      domain = args.print_json
      if domain == "*":
        print(json.dumps(j,indent=2))
      else:
        if domain in j["tls-policies"]:
          print(json.dumps(j["tls-policies"][domain],indent=2))
        else:
          print("The selected domain %s has not been found." % domain)
  except (ValueError, TypeError) as e:
    print("Validation failure: %s" % str(e))
  except STARTTLSEverywhereCustomError as e:
    print(e)
