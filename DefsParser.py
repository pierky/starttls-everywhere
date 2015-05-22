#!/usr/bin/env python

import sys
import json
from datetime import datetime
import string
import argparse
import base64

from Config import Config

TIMESTAMP_FORMAT="%Y-%m-%dT%H:%M:%S%Z"

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

 
class Defs:
  legal = string.letters + string.digits + ".-"
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

  def _read_tlsa(self,host,lst):
    """
    Read and validate the list of TLSA.

    Return:
      list of TLSA objects
    """
    res = []

    for tlsa in lst:
      new_tlsa = {}
      for attr, val in tlsa.items():
        if attr == "entity":
          if val not in [ "pubkey", "certificate" ]:
            raise ValueError("Unknown %s for TLSA of %s: %s" %
                             (attr,host,val))
          new_tlsa[attr] = val

        elif attr == "hash_alg":
          if val not in [ "sha1", "sha256", "sha512" ]:
            raise ValueError("Unknown %s for TLSA of %s: %s" %
                             (attr,host,val))
          new_tlsa[attr] = val

        elif attr == "data_format":
          if val not in [ "hex", "b64" ]:
            raise ValueError("Unknown %s for TLSA of %s: %s" %
                             (attr,host,val))
          new_tlsa[attr] = val

        elif attr == "data":
          if val.strip() == "":
            raise ValueError("Empty %s value for TLSA of %s: %s" %
                             (attr,host,val))
          new_tlsa[attr] = val

        else:
          #TODO: log warning
          print("Warning: unknown attribute '%s' ignored for TLSA of %s" %
                (attr,host))

      for e in [ "entity", "data_format", "data" ]:
        if e not in new_tlsa:
          raise ValueError("Missing %s for TLSA of %s" % (e,host))

      if new_tlsa["data_format"] == "b64":
        try:
          data_len = len(base64.b64decode(new_tlsa["data"]))
        except:
          raise ValueError("Data for TLSA of %s not in base64 format" % host)

      elif new_tlsa["data_format"] == "hex":
        new_tlsa["data"] = new_tlsa["data"].lower()

        try:
          assert all([c in "0123456789abcdef" for c in new_tlsa["data"]])
        except:
          raise ValueError("Invalid characters in hex data for TLSA of %s" %
                           (host))
        hex_data_len = len(new_tlsa["data"])

        if hex_data_len % 2 != 0:
          raise ValueError("Data lenght for TLSA of %s must be an even number"%
                           host)
        data_len = hex_data_len / 2

      else:
        raise ValueError("Data format %s for TLSA of %s not implemented" %
                         (new_tlsa["data_format"],host))

      if "hash_alg" in new_tlsa:
        try:
          dgst_len = {"sha1":20,"sha256":32,"sha512":64}[new_tlsa["hash_alg"]]
        except:
          raise ValueError("Hash algorithm %s for TLSA of %s not implemented" %
                           (new_tlsa["hash_alg"],host))

        if data_len != dgst_len:
          raise ValueError("Invalid %s digest data length for TLSA of %s: "
                          "should be %s bytes" %
                          (new_tlsa["hash_alg"],host,dgst_len))

      res.append(new_tlsa)

    return res

  def _read_policy(self,name,dic):
    """
    Read and validate attributes of a policy.

    Return:
      dictionary with policy attributes

    Raise:
      ValueError, TypeError

    """
    res = {}

    for attr, val in dic.items():
      if attr == "certificate-matching":
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
        res[attr] = self._read_tlsa(name,val)

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

    return res

  def __init__(self, cfg_file_name = "config.json"):
    """
    Raise:
      ValueError
      TypeError
    """
    self.known_tlds = Config.get_tlds_list()

    self.global_policies = {}
    self.tls_policies = {}
    self.author = None
    self.timestamp = None
    self.expires = None

    f = open(cfg_file_name)
    try:
      self.cfg = json.loads(f.read())
    except:
      raise ValueError("Policy definitions not in a valid JSON format")

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
                                                      policy)

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
            self.global_policies[domain_policy["from-global"]]
        else:
          self.tls_policies[domain] = self._read_policy(domain,domain_policy)

          if "mx-hostnames" in domain_policy:
            if type(domain_policy["mx-hostnames"]) != list:
              raise TypeError("%s's mx-hostnames must be a list" % domain)

            for mx_hostname in domain_policy["mx-hostnames"]:
              if type(mx_hostname) not in [str,unicode]:
                raise TypeError("%s' mx-hostnames must contain only strings" %
                                domain)
              if not self.looks_like_a_domain(mx_hostname):
                raise ValueError("Invalid mx-hostname for %s: %s" %
                                 (domain,mx_hostname))

            self.tls_policies[domain]["mx-hostnames"] = \
              domain_policy["mx-hostnames"]

  def to_json(self):
    """
    Return a dictionary, suitable for JSON representation.
    """
    res = {}
    for prop, attr in [(self.author,"author"),
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

  parser.add_argument("-j", action="store_true",
                      help="print JSON configuration on exit",
                      dest="print_json")

  parser.add_argument("policy_def", help="JSON policy definitions file",
                      metavar="policy_defs.json")

  args = parser.parse_args()

  Config.read(args.cfg_path)

  try:
    c = Defs(args.policy_def)
    print("Validation OK")
    if args.print_json:
      print(json.dumps(c.to_json(),indent=2))
  except (ValueError, TypeError) as e:
    print("Validation failure: %s" % str(e))
  except:
    raise


