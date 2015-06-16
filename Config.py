import os
import time
import urllib2
from ConfigParser import SafeConfigParser, NoOptionError, NoSectionError
import logging
from logging.handlers import RotatingFileHandler, MemoryHandler, SMTPHandler

from Errors import TLDsListUnavailableError, InsufficientPermissionError

class STARTTLSEverywhereConfig(SafeConfigParser):
  default_cfg_path = "/etc/starttls-everywhere/starttls-everywhere.cfg"

  custom_defaults = {
    "postfix": {
      "cfg_dir": "/etc/postfix",
      "ca_path": "%(capath)s",
      "main_config_file": "main.cf",
      "policy_defs_file": "starttls-everywhere",
      "smtp_tls_policy_maps_type": "btree",
      "postmap_path": "/usr/sbin/postmap",
      "tafile_real_dir": "/var/spool/postfix/etc",
      "tafile_dir": "/etc"
    }
  }

  def __init__(self):
    self.logger = None

    SafeConfigParser.__init__(self, {
      # general

      "data_dir": "/var/lib/starttls-everywhere",
      "guessstarttlspolicy_cache_dir": "%(data_dir)s/guessstarttlspolicy_cache",
      "openssl_path": "openssl",
      "capath": "/etc/ssl/certs/",
      "tlds_update_interval": "86400",
      "tlds_url": "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
      "diff_cmd": "diff -y {new} {old}",
      "failure_threshold_percent": "0.1",
      "log_level": "INFO",
      "log_file_level": "%(log_level)s",
      "log_smtp_level": "ERROR",
      "logwatcher_reports_dir": "%(data_dir)s/logwatcher-reports",
      "logwatcher_reports_fmt": "%%Y-%%m-%%d-%%H-%%M-%%S.log",
      })

  def get(self,section,option,default=None):
    try:
      return SafeConfigParser.get(self,section,option)
    except (NoSectionError, NoOptionError) as e:
      if default is not None:
        return default

      if section in STARTTLSEverywhereConfig.custom_defaults:
        if isinstance(e,NoSectionError):
          self.add_section(section)

        if option in STARTTLSEverywhereConfig.custom_defaults[section]:
          return SafeConfigParser.get(self,section,option,vars={
            option: STARTTLSEverywhereConfig.custom_defaults[section][option]})
      raise
    except:
      raise

  def get_tlds_list(self):
    """Return official TLDs list (lower-case).

    Uses local cached file if not expired (tlds_update_interval),
    otherwise downloads the new one from IANA"""

    tlds = None

    data_dir = Config.get("general","data_dir")
    if not os.path.isdir(data_dir):
      raise MissingFileError("Working directory (data_dir) not found: %s" %
                              data_dir)
    if not os.access(data_dir, os.W_OK):
      raise InsufficientPermissionError("Insufficient permissions to write "
                                        "into working directory (data_dir): "
                                        "%s" % data_dir)

    tlds_path = os.path.join(data_dir,"tlds")

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
        raise TLDsListUnavailableError("Missing tlds_url")

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

  def get_logger(self):
    if self.logger:
      return self.logger
    else:
      log_level = self.get("general","log_level")

      self.logger = logging.getLogger("STARTTLS-Everywhere")

      try:
        self.logger.setLevel(log_level)
      except:
        raise ValueError("Invalid value for log_level: %s" % log_level)

      fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

      stderr_needed = True

      # file logging
      log_file = self.get("general","log_file","")
      log_file_level = self.get("general","log_file_level")

      if log_file != "":
        try:
          hdlr = RotatingFileHandler(log_file,
                                                      maxBytes=1000000,
                                                      backupCount=3)
        except IOError as e:
          if e.errno == 13:
            raise InsufficientPermissionError("Insufficient permissions to "
                                              "write STARTTLS-Everywhere log "
                                              "file (log_file): %s" % log_file)
          else:
            raise

        try:
          hdlr.setLevel(log_file_level)
        except:
          raise ValueError("Invalid value for log_file_level: "
                          "%s" % log_file_level)

        hdlr.setFormatter(fmt)
        self.logger.addHandler(hdlr)
        stderr_needed = False

      # SMTP logging
      log_smtp_server = self.get("general","log_smtp_server","")
      log_smtp_from = self.get("general","log_smtp_from","")
      log_smtp_to = self.get("general","log_smtp_to","")
      log_smtp_subj = self.get("general","log_smtp_subject","")
      log_smtp_user = self.get("general","log_smtp_user","")
      log_smtp_pass = self.get("general","log_smtp_pass","")
      log_smtp_tls = self.get("general","log_smtp_tls","")
      log_smtp_tls_key = self.get("general","log_smtp_tls_key","")
      log_smtp_tls_cert = self.get("general","log_smtp_tls_cert","")
      log_smtp_level = self.get("general","log_smtp_level")

      if log_smtp_server != "":
        if len(log_smtp_server.split(":")) > 2:
          raise ValueError("SMTP logging config: invalid log_smtp_server "
                           "format, should be hostname[:port]")
        if log_smtp_from == "":
          raise ValueError("SMTP logging config: missing log_smtp_from")
        if log_smtp_to == "":
          raise ValueError("SMTP logging config: missing log_smtp_to")
        if log_smtp_subj == "":
          raise ValueError("SMTP logging config: missing log_smtp_subject")

        log_smtp_host = log_smtp_server.split(":")[0]
        if len(log_smtp_server.split(":")) > 1:
          log_smtp_port = log_smtp_server.split(":")[1]
          if not log_smtp_port.isdigit():
            raise ValueError("SMTP logging config: invalid log_smtp_server "
                             "port, should be numeric: %s" %
                             log_smtp_port.isdigit)
        else:
          log_smtp_port = 25
        log_smtp_server_tuple = (log_smtp_host,log_smtp_port)

        log_smtp_to_list = log_smtp_to.split(";")

        log_smtp_usrpwd_tuple = None
        log_smtp_tls_tuple = None

        # TLS only if user/pass are given
        if log_smtp_user != "" and log_smtp_pass != "":
          log_smtp_usrpwd_tuple = (log_smtp_user,log_smtp_pass)

          if log_smtp_tls.lower() in [ "yes", "true", "1" ]:
            log_smtp_tls_tuple = ()
            if log_smtp_tls_key != "":
              if log_smtp_tls_cert != "":
                log_smtp_tls_tuple = (log_smtp_tls_key,log_smtp_tls_cert)
              else:
                log_smtp_tls_tuple = (log_smtp_tls_key)

        smtp_hdlr = SMTPHandler(mailhost=log_smtp_server_tuple,
                                fromaddr=log_smtp_from,
                                toaddrs=log_smtp_to_list,
                                subject=log_smtp_subj,
                                credentials=log_smtp_usrpwd_tuple,
                                secure=log_smtp_tls_tuple)
        smtp_hdlr.setFormatter(fmt)

        hdlr = MemoryHandler(capacity=1000000,flushLevel="CRITICAL")
        hdlr.setTarget(smtp_hdlr)

        try:
          hdlr.setLevel(log_smtp_level)
        except:
          raise ValueError("Invalid value for log_smtp_level: "
                          "%s" % log_smtp_level)

        hdlr.setFormatter(fmt)
        self.logger.addHandler(hdlr)
        stderr_needed = False

      if stderr_needed:
        hdlr = logging.StreamHandler()
        hdlr.setFormatter(fmt)
        self.logger.addHandler(hdlr)

      return self.logger

Config = STARTTLSEverywhereConfig()
