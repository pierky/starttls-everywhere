#!/usr/bin/python
import sys
import os
import smtplib
import subprocess
import re
import json
import argparse
import hashlib
import dns.resolver
import time
import datetime
import platform
import copy
from M2Crypto import X509

from Config import Config
from Errors import *
from Utils import mkdirp, tls_protocols_higher_than, extract_pem_data

CACHE_TIME = 86400  #seconds, 86400 = 1 day
CACHE_DIR = ""

def extract_names(x509_cert):
  """Return a set of DNS subject names from PEM-encoded leaf cert."""

  subj = x509_cert.get_subject()
  # Certs have a "subject" identified by a Distingushed Name (DN).
  # Host certs should also have a Common Name (CN) with a DNS name.
  common_names = subj.get_entries_by_nid(subj.nid["CN"])
  common_names = [name.get_data().as_text().lower() for name in common_names]
  try:
    # The SAN extension allows one cert to cover multiple domains
    # and permits DNS wildcards.
    # http://www.digicert.com/subject-alternative-name.htm
    # The field is a comma delimited list, e.g.:
    # >>> twitter_cert.get_ext('subjectAltName').get_value()
    # 'DNS:www.twitter.com, DNS:twitter.com'
    alt_names = x509_cert.get_ext("subjectAltName").get_value()
    alt_names = alt_names.split(",")
    alt_names = [name.strip().partition(":") for name in alt_names]
    alt_names = [name.lower() for prot, _, name in alt_names if prot == "DNS"]
  except:
    alt_names = []
  return set(common_names + alt_names)

def extract_ski_aki(x509_cert):
  """Return (SKI, AKI keyid, AKI dirname, AKI serial)."""

  ski = None
  aki = None
  aki_keyid = None
  aki_dirname = None
  aki_serial = None
  try:
    ski = x509_cert.get_ext("subjectKeyIdentifier").get_value().strip()
    aki = x509_cert.get_ext("authorityKeyIdentifier").get_value().strip()

    for aki_part in aki.split("\n"):
      if aki_part.lower().startswith("keyid:"):
        _, _, aki_keyid = aki_part.partition(":")
      elif aki_part.startswith("DirName:"):
        _, _, aki_dirname = aki_part.partition(":")
      elif aki_part.startswith("serial:"):
        _, _, aki_serial = aki_part.partition(":")
  except:
    pass

  return (ski,aki_keyid,aki_dirname,aki_serial)

def get_certs_info(openssl_output):
  """
  cert_info defined as:
    {
      "certificate_pem": "PEM_between_BEGIN_END_CERTIFICATE",

      "certificate_fingerprints": {
        "sha1": "data",
        "sha256": "data",
        "sha512": "data"
      },

      "pubkey_pem": "PEM_between_BEGIN_END_PUBLIC_KEY",

      "pubkey_fingerprinsts": {
        "sha1": "data",
        "sha256": "data",
        "sha512": "data"
      }

      "self_signed": boolean
    }

  Return:
    {
      "ee": {

        "names": [],

        <cert_info>,

        "verify_ok": boolean,
        "verify_res": "data",

        "self_issued": boolean
      },

      // optional
      "ta": { <cert_info> }
    }

  Raise:
    SSLCertificatesError
  """

  res = {}

  certs = re.findall("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                     openssl_output, flags=re.DOTALL)

  if len(certs) < 1:
    raise SSLCertificatesError("Can't obtain SSL certificate for %s" % mx_host)

  # used below to collect information that are common to both EE and TA certs
  # list of pairs ( X509_cert, destination_object )
  certs_map = []

  #FIXME: be sure that certs[0] is EE and certs[1] is Intermediate
  EE_pem = certs[0]
  try:
    EE = X509.load_cert_string(EE_pem, X509.FORMAT_PEM)
  except Exception as e:
    raise SSLCertificatesError("Can't load EE certificate for %s: %s" %
                               (mx_host,str(e)))
  res["ee"] = {}
  certs_map = [ ( EE, res["ee"] ) ]

  if len(certs) > 1:
    TA_pem = certs[1]
    try:
      TA = X509.load_cert_string(TA_pem, X509.FORMAT_PEM)
    except:
      raise SSLCertificatesError("Can't load TA certificate for %s: %s" %
                                 (mx_host,str(e)))
    res["ta"] = {}
    certs_map.append( ( TA, res["ta"] ) )

  res["ee"]["names"] = list(extract_names(EE))

  for cert, dest in certs_map:
    dest["certificate_pem"] = extract_pem_data(cert.as_pem())
    dest["certificate_fingerprints"] = {}
    dest["pubkey_pem"] = extract_pem_data(\
      cert.get_pubkey().get_rsa().as_pem(cipher=None))
    dest["pubkey_fingerprints"] = {}
#    dest["self_signed"] = cert.verify(cert.get_pubkey()) == 1

    pubkey = "".join([l for l in dest["pubkey_pem"].split("\n") 
                      if len(l) > 0 and l[0] != "-"])

    for alg in [ "sha1", "sha256", "sha512" ]:
      dest["certificate_fingerprints"][alg] = \
        cert.get_fingerprint(md=alg).lower()
      if len(dest["certificate_fingerprints"][alg]) % 2 != 0:
        dest["certificate_fingerprints"][alg] = "0" + \
          dest["certificate_fingerprints"][alg]

      if alg == "sha1":
        dgst = hashlib.sha1()
      elif alg == "sha256":
        dgst = hashlib.sha256()
      elif alg == "sha512":
        dgst = hashlib.sha512()
      else:
        raise ValueError("Digest not implemented: %s" % alg)

      dgst.update(pubkey)
      dest["pubkey_fingerprints"][alg] = dgst.hexdigest()

  verify_result = re.search("Verify return code:\s+(\d+)\s+\((.+)\)",openssl_output)
  if verify_result:
    res["ee"]["verify_ok"] = verify_result.group(1) == "0"
    res["ee"]["verify_res"] = verify_result.group(2)
  else:
    res["ee"]["verify_ok"] = False
    res["ee"]["verify_res"] = "missing openssl verify result"

#  # self issued EE cert?
#  ski, aki_keyid, aki_dirname, aki_serial = extract_ski_aki(EE)
#
#  if ski and aki_keyid and ski.lower() == aki_keyid.lower():
#    dest["self_issued"] = True
#  #TODO: implement checking AKI dirname/serial with cert 
#  #      subject DN/serial
#  #      Does X509 cert .get_serial_number() return an int?
#  #      Shouldn't sn be a 20 bytes field?
#  #elif aki_dirname and aki_serial:
#  elif EE.get_issuer().as_text() == EE.get_subject().as_text():
#      dest["self_issued"] = True
#  else:
#    res["ee"]["self_issued"] = False
  
  return res

def supports_starttls(mx_host):
  """Check STARTTLS support on mx_host.

  Return:
    True  mx_host supports STARTTLS
    False connection succeeded but mx_host does not support STARTTLS

  Raise:
    CheckSTARTTLSSupportError  connection failed
  """
    
  try:
    smtpserver = smtplib.SMTP(mx_host, 25, timeout = 2)
    smtpserver.ehlo()
  except Exception as e:
    raise CheckSTARTTLSSupportError("Connection to %s failed: %s" %
                                    (mx_host, str(e)))

  try:
    smtpserver.starttls()
    smtpserver.quit()
    return True
  except:
    try:
      smtpserver.quit()
    except:
      pass
    return False

def tls_connect(mx_host, mail_domain, ignore_cache):
  """
  Attempt a STARTTLS connection with openssl and save the output.

  Return:
    None or openssl output

  Raise:
    SSLCertificatesError
  
  """

  cache_file = os.path.join(CACHE_DIR, mail_domain, mx_host)

  if not ignore_cache and os.path.exists(cache_file):
    if os.path.getmtime(cache_file) >= time.time() - CACHE_TIME:
      with open(cache_file, "r") as f:
        res = f.read()
      return res

  if supports_starttls(mx_host):
    # smtplib doesn't let us access certificate information,
    # so shell out to openssl.
    try:
      output = subprocess.check_output("{openssl} s_client "
            "-connect {mx_host}:25 "
            "-starttls smtp "
            "-showcerts "
            "-CApath {capath} "
            "</dev/null "
            "2>/dev/null".format(openssl=Config.get("general","openssl_path"),
                        mx_host=mx_host,
                        capath=Config.get("general","capath")), shell=True)
    except subprocess.CalledProcessError as e:
      raise SSLCertificatesError("Can't get openssl information from %s: %s" %
                                 (mx_host,e.output))

    # Save a copy of the certificate for later analysis
    with open(cache_file, "w") as f:
      f.write(output)

    return output
  return None

def collect(mail_domain, ignore_cache):
  """
  Attempt to connect to each MX hostname for mail_doman and negotiate STARTTLS.
  Store the output in a directory with the same name as mail_domain to make
  subsequent analysis faster.

  Return a set:
    list of failed MX hosts
    dictionary with data
  """

  mkdirp(os.path.join(CACHE_DIR, mail_domain))
  cache_file = os.path.join(CACHE_DIR, mail_domain, "data.json")

  if not ignore_cache and os.path.exists(cache_file):
    if os.path.getmtime(cache_file) >= time.time() - CACHE_TIME:
      with open(cache_file, "r") as f:
        res = json.loads(f.read())
      return [], res

  res = { "mx-hostnames": {} }
  check_ko = []

  try:
    answers = dns.resolver.query(mail_domain, "MX")
  except:
    return [], None

  for rdata in answers:
    mx_host = str(rdata.exchange).rstrip(".")

    mx_host_data = {}

    try:
      openssl_output = tls_connect(mx_host, mail_domain, ignore_cache)
    except ( CheckSTARTTLSSupportError, SSLCertificatesError ) as e:
      check_ko.append( ( mx_host, str(e) ) )
      continue

    if not openssl_output:
      check_ko.append( ( mx_host, "STARTTLS not supported" ) )
      continue

    # TLS protocol version
    protocol = re.findall("Protocol\s+:\s+(.*)", openssl_output)[0]

    if not protocol in [ "TLSv1", "TLSv1.1", "TLSv1.2" ]:
      raise ValueError("Unknown TLS protocol version for %s: %s" %
                       (mx_host,protocol))

    mx_host_data["tls-version"] = protocol
    mx_host_data["certificates"] = get_certs_info(openssl_output)

    res["mx-hostnames"][mx_host] = mx_host_data

  if len(check_ko) == 0:
    with open(cache_file, "w") as f:
      f.write(json.dumps(res,indent=2))
  else:
    if os.path.exists(cache_file):
      os.remove(cache_file)
 
  return check_ko, res

def main():
  DISCLAIMER = """WARNING: the policy herein built is based on a set
                  of common features found among the current layout and
                  configuration of the MX hostnames associated to input
                  mail domains. There is no warranty that the current
                  settings will be kept by mail servers' owners in the
                  future nor that these settings are the correct ones that
                  really identify the recipient domain's mail servers.
                  A bad policy could result in messages delivery failures.
                  USE THIS POLICY DEFINITIONS FILE AT YOUR OWN RISK."""

  parser = argparse.ArgumentParser(
    description="Guess STARTTLS policies on the basis of current MX "
      "hostnames settings.",
    epilog="""Consume a target list of mail domains and output a \
    policy definitions file for those domains. %s""" % DISCLAIMER)

  parser.add_argument("-c", "--cfg", default=Config.default_cfg_path,
                      help="general configuration file path", metavar="file",
                      dest="cfg_path")

  parser.add_argument("inputfile", type=argparse.FileType("r"),
                      default=sys.stdin, metavar="domains_list_file",
                      help="""file containing the list of domains to consume;
                      one domain on each line;
                      use "-" to read from stdin""")

  parser.add_argument("-o", metavar="file", type=argparse.FileType("w"),
                      help="path where policy definitions file will be "
                      "written to; default: stdout", dest="outputfile")

  parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                      help="print some explanatory messages")

  parser.add_argument("--hash-alg", default="sha256",
                      choices=["sha1","sha256","sha512"],
                      help="hash algorithm used for fingerprints matching",
                      dest="hash_alg")

  parser.add_argument("--no-cache", dest="nocache", action="store_true",
                      help="ignore any cached data")

  parser.add_argument("--expires", dest="expires", type=int,
                      metavar="minutes",
                      help="policy expiration time, in minutes "
                      "(default: 10080, 1 week)", default=10080)

  avoid_choices = ["ta", "ee_pubkey", "ee_certificate", "valid"]
  parser.add_argument("--avoid-cert-matching", metavar="policy_type",
                      choices=avoid_choices,
                      dest="avoid",
                      help="do not use these policy types for certificate "
                      "matching; allowed values: " + \
                      ", ".join(avoid_choices), nargs="*")
  args = parser.parse_args()

  Config.read(args.cfg_path)

  global CACHE_DIR
  CACHE_DIR = Config.get("general", "guessstarttlspolicy_cache_dir")

  if not os.path.isdir(CACHE_DIR):
    mkdirp(CACHE_DIR)
  if not os.access(CACHE_DIR, os.W_OK):
    raise InsufficientPermissionError("Insufficient permissions to write "
                                      "into GuessSTARTTLSPolicies cache dir "
                                      "(guessstarttlspolicy_cache_dir): %s" %
                                      CACHE_DIR)

  hash_alg = args.hash_alg

  if args.avoid:
    avoid_cert_matching = args.avoid
  else:
    avoid_cert_matching = []

  check_ko = []

  expires = datetime.datetime.utcnow() + \
            datetime.timedelta(minutes=args.expires)

  output = {
    "version": "0.1",
    "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
    "author": "GuessSTARTTLSPolicies on %s - "
              "USE THIS POLICY AT YOUR OWN RISK" % platform.node(),
    "expires": expires.strftime("%Y-%m-%dT%H:%M:%S"), 
    "tls-policies": {}
  }

  def verbose(s):
    if args.verbose:
      print(s)

  for domain in args.inputfile.readlines():
    mail_domain = domain.strip()

    verbose("Analysing domain %s..." % mail_domain)
    verbose("")

    check_ko, domain_data = collect(mail_domain, args.nocache)

    if len(check_ko) > 0:
      verbose(" One or more MX hosts can't be analysed:")
      for mx_hostname, failure in check_ko:
        verbose("  %s: %s" % (mx_hostname,failure))
      verbose("")
      continue

    if not domain_data:
      verbose(" Can't get information about any MX host for %s" % mail_domain)
      verbose("")
      continue

    common = {}

    # ----------------------------------------------

    verbose(" Highest common TLS version...")
    common["min-tls-version"] = None
    for mx_hostname in domain_data["mx-hostnames"]:
      mx_host = domain_data["mx-hostnames"][mx_hostname]
      tls_ver = mx_host["tls-version"]
      verbose("  %s supports %s" % (mx_hostname,tls_ver))
      if not common["min-tls-version"]:
        common["min-tls-version"] = tls_ver
      else:
        if not tls_ver in tls_protocols_higher_than(common["min-tls-version"]):
          common["min-tls-version"] = tls_ver

    verbose(" min-tls-version: %s" % common["min-tls-version"])
    verbose("")

    # ----------------------------------------------

    common["ta_certificate"] = None
    common["ta_pubkey"] = None
    common["ee_certificate"] = None
    common["ee_pubkey"] = None

    for descr, ee_ta, dest, pem, fp in [("trust anchor certificate",
                                         "ta",
                                         "ta_certificate",
                                         "certificate_pem",
                                         "certificate_fingerprints"),
                                        ("trust anchor public key",
                                         "ta",
                                         "ta_pubkey",
                                         "pubkey_pem",
                                         "pubkey_fingerprints"),
                                        ("leaf certificate",
                                         "ee",
                                         "ee_certificate",
                                         "certificate_pem",
                                         "certificate_fingerprints"),
                                        ("leaf certificate public key",
                                         "ee",
                                         "ee_pubkey",
                                         "pubkey_pem",
                                         "pubkey_fingerprints")]:

      verbose(" Common %s..." % descr)
      for mx_hostname in domain_data["mx-hostnames"]:
        mx_host = domain_data["mx-hostnames"][mx_hostname]
        if not ee_ta in mx_host["certificates"]:
          verbose("  no %s certificate found for %s" % (ee_ta.upper(),
                                                      mx_hostname))
          common[dest] = None
          break

        cert = mx_host["certificates"][ee_ta]
        verbose("  %s %s's fingerprint: %s" % (mx_hostname, descr,
                                             cert[fp][hash_alg]))
        if not common[dest]:
          common[dest] = {}
          common[dest][pem] = cert[pem]
          common[dest][fp] = cert[fp]
        elif common[dest][pem] != cert[pem]:
          common[dest] = None
          break

      if common[dest]:
        verbose(" Common %s found: fingerprint %s" %
              (descr,common[dest][fp][hash_alg]))
      else:
        verbose(" No common %s found" % descr)
      verbose("")

    # ----------------------------------------------

    verbose(" Any invalid EE certificates...")

    common["any-invalid-EE-cert"] = False

    for mx_hostname in domain_data["mx-hostnames"]:
      mx_host = domain_data["mx-hostnames"][mx_hostname]

#      if mx_host["certificates"]["ee"]["self_signed"]:
#        verbose("  %s: not valid (self-signed)" % mx_hostname)
#        common["any-invalid-EE-cert"] = True
#      elif mx_host["certificates"]["ee"]["self_issued"]:
#        verbose("  %s: not valid (self-issued)" % mx_hostname)
#        common["any-invalid-EE-cert"] = True
#      else:
#        verbose("  %s: valid" % mx_hostname)

      if not mx_host["certificates"]["ee"]["verify_ok"]:
        verbose("  %s: not valid (%s)" %
                (mx_hostname, mx_host["certificates"]["ee"]["verify_res"]))
        common["any-invalid-EE-cert"] = True
      else:
        verbose("  %s: valid" % mx_hostname)

    if common["any-invalid-EE-cert"]:
      verbose(" Invalid EE certificates found")
    else:
      verbose(" No invalid EE certificates found")
    verbose("")

    # ----------------------------------------------

    verbose(" Common names in EE certificates...")

    common["shortest_names"] = []

    pdoms = {}

    for mx_hostname in domain_data["mx-hostnames"]:
      mx_host = domain_data["mx-hostnames"][mx_hostname]
      verbose("  %s: %s" % (mx_hostname,
                          ", ".join(mx_host["certificates"]["ee"]["names"])))
      for name in mx_host["certificates"]["ee"]["names"]:
        lbls = name.split(".")

        for dom_len in range(2, len(lbls)+1):
          pdom = ".".join(lbls[-dom_len:])
          if dom_len != len(lbls):
            pdom = "." + pdom

          if not str(dom_len) in pdoms:
            pdoms[str(dom_len)] = {}

          if not pdom in pdoms[str(dom_len)]:
            pdoms[str(dom_len)][pdom] = [mx_hostname]
          elif not mx_hostname in pdoms[str(dom_len)][pdom]:
            pdoms[str(dom_len)][pdom].append(mx_hostname)

    common_names = {}
    for dom_len in pdoms.keys():
      for name in pdoms[dom_len].keys():
        if len(pdoms[dom_len][name]) == len(domain_data["mx-hostnames"]):
          if not dom_len in common_names:
            common_names[dom_len] = []
          common_names[dom_len].append(name)

    if len(common_names.keys()) > 0:
      min_len = sorted([int(x) for x in common_names.keys()])[0]
      common["shortest_names"] = common_names[str(min_len)]
      verbose(" Common shortest names: " + ", ".join(common["shortest_names"]))
    else:
      verbose(" No common names found in EE certificates")

    # ----------------------------------------------
    # Decisions follow

    policy = {}

    def add_tlsas(ee_ta,entity):
      assert(ee_ta in [ "ee", "ta" ])
      assert(entity in [ "pubkey", "certificate" ])

      # add both full entity (base64 PEM) and it's fingerprint
      policy["%s-tlsa" % ee_ta].append({
        "entity": entity,
        "data_format": "b64",
        "data": common["%s_%s" %
                       (ee_ta,entity)]["%s_pem" % entity]
      })
      policy["%s-tlsa" % ee_ta].append({
        "entity": entity,
        "hash_alg": hash_alg,
        "data_format": "hex",
        "data": common["%s_%s" %
                       (ee_ta,entity)]["%s_fingerprints" % entity][hash_alg]
      })

    verbose("")

    if common["ta_certificate"] or common["ta_pubkey"]:

      if len(common["shortest_names"]) > 0:
        if "ta" in avoid_cert_matching:
          verbose(" Common trust anchor found "
                  "but forbidden by user's choice: "
                  "--avoid-cert-matching ta")
        else:
          verbose(" Certificate matching based on common trust anchor.")
          policy["certificate-matching"] = "TA"
          policy["ta-tlsa"] = []

          if common["ta_certificate"]:
            add_tlsas("ta", "certificate")
          if common["ta_pubkey"]:
            add_tlsas("ta", "pubkey")
      else:
        verbose(" WARNING: even if domain's MX hosts share a common "
                "trust anchor it can't be used for certificate "
                "matching because no common EE certificate names have "
                "be found. ")

    if "certificate-matching" not in policy and common["ee_pubkey"]:

      if "ee_pubkey" in avoid_cert_matching:
        verbose(" Common EE certificates' public keys found "
                "but forbidden by user's choice: "
                "--avoid-cert-matching ee_pubkey")
      else:
        verbose(" Certificate matching based on the common EE certificates' "
                "public key.")
        policy["certificate-matching"] = "EE"
        policy["ee-tlsa"] = []

        add_tlsas("ee", "pubkey")

    if "certificate-matching" not in policy and common["ee_certificate"]:

      if "ee_certificate" in avoid_cert_matching:
        verbose(" Common EE certificates found "
                "but forbidden by user's choice: "
                "--avoid-cert-matching ee_certificate")
      else:
        verbose(" Certificate matching based on common EE certificates.")
        policy["certificate-matching"] = "EE"
        policy["ee-tlsa"] = []

        add_tlsas("ee", "certificate")

    if "certificate-matching" not in policy and \
      common["shortest_names"] != [] and not common["any-invalid-EE-cert"]:

      verbose(" No common TA or EE certificate have been found among domain's "
              "MX hosts.")

      if "valid" in avoid_cert_matching:
        verbose(" Certificate matching based on any valid certificate "
                "would be used "
                "but it's forbidden by user's choice: "
                "--avoid-cert-matching valid")
      else:
        verbose(" Certificate matching based on any valid certificate "
                "with a matching name.")
        policy["certificate-matching"] = "valid"
    
    if "certificate-matching" not in policy:
      verbose(" WARNING: no common certificates' trust anchors nor common "
              "EE valid certificates have been found. TLS will be enforced "
              "but no authentication will be provided.")

    if "certificate-matching" in policy:
      if policy["certificate-matching"] in [ "TA", "valid"]:
        policy["allowed-cert-names"] = copy.copy(common["shortest_names"])
        if mail_domain in policy["allowed-cert-names"]:
          policy["allowed-cert-names"].remove(mail_domain)
          if policy["allowed-cert-names"] == []:
            policy.pop("allowed-cert-names", None)

    if common["min-tls-version"]:
      policy["min-tls-version"] = common["min-tls-version"]

    output["tls-policies"][mail_domain] = copy.deepcopy(policy)
    verbose("")

#    print(json.dumps(common,indent=2))
#    print json.dumps(domain_data,indent=2)
#    print(json.dumps(policy,indent=2))

  if args.outputfile:
    args.outputfile.write(json.dumps(output,indent=2))
    verbose("Policy definitions written to the output file.")
    args.outputfile.close()
  else:
    verbose("Policy definitions follow:")
    verbose("")
    print(json.dumps(output,indent=2))
    verbose("")

if __name__ == "__main__":
  try:
    main()
  except (STARTTLSEverywhereCustomError,ValueError,TypeError) as e:
    print(e)
