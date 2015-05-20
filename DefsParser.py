#!/usr/bin/env python

import sys
import json
from datetime import datetime
import string
import argparse

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

        elif attr == "data":
          if val.strip() == "":
            raise ValueError("Invalid %s value for TLSA of %s: %s" %
                             (attr,host,val))
          new_tlsa[attr] = val.lower()

        else:
          #TODO: log warning
          print("Warning: unknown attribute '%s' ignored for TLSA of %s" %
                (attr,host))

      for e in [ "entity", "data" ]:
        if e not in new_tlsa:
          raise ValueError("Missing %s for TLSA of %s" % (e,host))

      if "hash_alg" in new_tlsa:
        dgst_len = {"sha1":40, "sha256":64, "sha512":128}[new_tlsa["hash_alg"]]
        if len(new_tlsa["data"]) != dgst_len:
          raise ValueError("Invalid %s digest data length for TLSA of %s: "
                          "should be %s" %
                          (new_tlsa["hash_alg"],host,dgst_len))
      else:
        if len(new_tlsa["data"]) % 2 != 0:
          raise ValueError("Data lenght for TLSA of %s must be an even number"%
                           host)

      try:
        assert all([c in "0123456789abcdef" for c in new_tlsa["data"]])
      except:
        raise ValueError("Invalid characters in %s hex data for TLSA of %s" %
                         (new_tlsa["hash_alg"],host))

      res.append(new_tlsa)

    return res

  def _read_policy(self,host,dic):
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
        if val not in [ "valid", "TA", "EE" ]:
          raise ValueError("Unknown %s for %s: %s" % (attr,host,val))
        res[attr] = val
        
      elif attr == "log-only":
        if type(val) != bool:
          raise TypeError("Invalid %s type for %s: must be boolean" %
                          (attr,host))
        res[attr] = val

      elif attr == "min-tls-version":
        if val not in [ "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" ]:
          raise ValueError("Unknown %s for %s: %s" %
                           (attr,host,val))
        res[attr] = val

      elif attr == "ee-tlsa" or attr == "ta-tlsa":
        if type(val) != list:
          raise TypeError("Invalid %s type for %s: must be a list" %
                          (attr,host))
        res[attr] = self._read_tlsa(host,val)

    if "ee-tlsa" in res and "certificate-matching" not in res:
      #TODO: improve logging
      print("Warning: EE TLSAs with no certificate-matching - "
            "they will be ignored")
    if "ta-tlsa" in res and "certificate-matching" not in res:
      #TODO: improve loggin
      print("Warning: TA TLSAs with no certificate-matching - "
            "they will be ignored")

    if "certificate-matching" in res:
      if res["certificate-matching"] == "EE" and "ee-tlsa" not in res:
        raise ValueError("Missing EE TLSAs with certificate-matching = EE")
      elif res["certificate-matching"] == "TA" and "ta-tlsa" not in res:
        raise ValueError("Missing TA TLSAs with certificate-matching = TA")

    return res

  def __init__(self, cfg_file_name = "config.json"):
    self.known_tlds = Config.get_tlds_list()

    f = open(cfg_file_name)
    try:
      self.cfg = json.loads(f.read())
    except:
      raise ValueError("Policy definitions not in a valid JSON format")
    self.tls_policies = {}
    self.mx_map = {}
    for atr, val in self.cfg.items():
      # Verify each attribute of the structure
      if atr.startswith("comment"):
        continue
      if atr == "author":
        if type(val) not in [str, unicode]:
          raise TypeError, "Author must be a string: " + `val`
        self.author = val
      elif atr == "timestamp":
        self.timestamp = parse_timestamp(val)
      elif atr == "expires":
        self.expires = parse_timestamp(val)
      elif atr == "tls-policies":
        for domain, policies in self.check_tls_policy_domains(val):
          if type(policies) != dict:
            raise TypeError("%s's policies should be a dict" %domain)
          if not self.looks_like_a_domain(domain):
            raise ValueError("Invalid domain: %s" % domain)
          self.tls_policies[domain] = self._read_policy(domain,policies)
          if "mx-hostnames" in policies:
            if type(policies["mx-hostnames"]) != dict:
              raise TypeError("%s's mx-hostnames should be a dict" %domain)
            self.tls_policies[domain]["mx-hostnames"] = {}
            for mx_hostname, mx_hostname_policies in policies["mx-hostnames"].items():
              mx_hostname_policy = self._read_policy(mx_hostname,mx_hostname_policies)
              self.tls_policies[domain]["mx-hostnames"][mx_hostname] = mx_hostname_policy
      else:
        #TODO: improve logging
        sys.stderr.write("Unknown attribute: " + `atr` + "\n")

  def to_json(self):
    res = {}
    for prop, attr in [(self.author,"author"),
                       (self.timestamp.strftime(TIMESTAMP_FORMAT),"timestamp"),
                       (self.expires.strftime(TIMESTAMP_FORMAT),"expires"),
                       (self.tls_policies,"tls-policies")]:
      res[attr] = prop
    return res

  def get_address_domains(self, mx_hostname):
    labels = mx_hostname.split(".")
    for n in range(1, len(labels)):
      parent = "." + ".".join(labels[n:])
      if parent in self.mx_domain_to_address_domains:
        return self.mx_domain_to_address_domains[parent]
    return None

  def check_tls_policy_domains(self, val):
    if type(val) != dict:
      raise TypeError, "tls-policies should be a dict" + `val`
    for domain, policies in val.items():
      try:
        assert type(domain) == unicode
        d = str(domain) # convert from unicode
      except:
        raise TypeError, "tls-policy domain not a string" + `domain`
      yield (d, policies)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(
    description="STARTTLS policy definitions validator")

  parser.add_argument("-c", "--cfg", default=Config.default_cfg_path,
                      help="general configuration file path", metavar="file",
                      dest="cfg_path")

  parser.add_argument("-j", action="store_true",
                      help="print JSON configuration befor exit",
                      dest="print_json")

  parser.add_argument("policy_def", help="JSON policy definitions file",
                      metavar="policy_defs.json")

  args = parser.parse_args()

  Config.read(args.cfg_path)

  try:
    c = Defs(args.policy_def)
  except:
    print("Validation failure")
    raise
  print("Validation OK")

  if args.print_json:
    print(json.dumps(c.to_json(),indent=2))

