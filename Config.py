import os
import time
import urllib2
from ConfigParser import SafeConfigParser

from Errors import TLDsListUnavailableError

class STARTTLSEverywhereConfig(SafeConfigParser):
  def __init__(self):
    SafeConfigParser.__init__(self, {
      # general

      "data_dir": "data",
      "certs-observed": "%(data_dir)s/certs-observed",
      "openssl_path": "openssl",
      "capath": "/etc/ssl/certs/",
      "tlds_update_interval": "86400",
      "tlds_url": "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",

      # postfix

      "policy_file": "starttls_everywhere_policy",
      "ca_file": "%{capath}s"
    })

    self.read("distrib/starttls-everywhere.cfg")

  def get_tlds_list(self):
    """Return official TLDs list (lower-case).

    Uses local cached file if not expired (tlds_update_interval),
    otherwise downloads the new one from IANA"""

    tlds = None

    tlds_path = os.path.join(self.get("general","data_dir"),"tlds")

    tlds_url = self.get("general","tlds_url")
    if tlds_url:
      min_tlds_update = self.getint("general","tlds_update_interval")

    from_cache = True

    if os.path.exists(tlds_path):
      if tlds_url == "" or \
        os.path.getmtime(tlds_path) >= time.time() - min_tlds_update:
        with open(tlds_path, "r") as f:
          tlds = f.read()

    if tlds is None:
      if tlds_url == "":
        raise TLDsListUnavailableError()

      from_cache = False

      HTTPRequest = urllib2.Request( tlds_url )
      tlds = urllib2.urlopen( HTTPRequest ).read()

    tlds_list = []

    for line in tlds.split("\n"):
      s = line.strip()
      if s != "":
        if s[0] != "#":
          tlds_list.append(s.lower())

    if not from_cache:
      with open(tlds_path, "w") as f:
        f.write(tlds)

    return tlds_list
        
Config = STARTTLSEverywhereConfig()
