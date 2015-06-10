#!/usr/bin/env python
from __future__ import division
import argparse
import os
import re
import sys
import datetime
import json

import DefsParser
from Config import Config
from Errors import *
from Utils import mkdirp

#TODO: implement a status to match "log-only = true" results
MANDATORY_STATUS_TAGS = [ "sent_ok", "sent_ko", "attempted" ]

class MTALogWatcher():
  def _prepare_re_timestamps_from_lines(self):
    if self.re_timestamps_from_lines:
      return
    self.re_timestamps_from_lines = {}
    for re_str in self.timestamps_from_lines.keys():
      compiled_re = re.compile(re_str)
      self.re_timestamps_from_lines[re_str] = {}
      self.re_timestamps_from_lines[re_str]["compiled"] = compiled_re 
      self.re_timestamps_from_lines[re_str]["strftime_fmt"] = \
        self.timestamps_from_lines[re_str]

  def _prepare_re_status_map(self):
    if self.re_status_map:
      return
    self.re_status_map = {}
    for re_str in self.status_map.keys():
      compiled_re = re.compile(re_str)
      self.re_status_map[re_str] = {}
      self.re_status_map[re_str]["compiled"] = compiled_re
      self.re_status_map[re_str]["status_tags"] = \
        self.status_map[re_str]["status_tags"]
      self.re_status_map[re_str]["mail_domain"] = \
        self.status_map[re_str]["mail_domain"]
 
  def __init__(self,logfilepath,incremental,policy_defs):
    """
    Logfile must exist and must be readable.
    """

    ABBR_MONTHS = [datetime.date(2015,m,1).strftime("%b") for m in range(1,13)]

    # Map between re and log timestamps strftime format.
    # Syntax:
    #   {
    #     "<re1>": "<strftime_fmt1>",
    #     "<reN>": "<strftime_fmtN>"
    #   }
    # Converted in (self.re_timestamps_from_lines):
    #   {
    #     "<re1>": {
    #       "compiled": "<compiled_re_obj>",
    #       "strftime_fmt": "<strftime_fmt1>"
    #     }
    #   }
    # May be integrated with more formats by child classes.
    self.timestamps_from_lines = {
      # format: MMM [D]D [h]h:[m]m:[s]s
      #         May  4 01:14:24
      "^(" + "|".join(ABBR_MONTHS) + ")\s{1,2}"
      "(\d{1,2})\s{1,2}"
      "(\d{1,2}):"
      "(\d{1,2}):"
      "(\d{1,2})": "%b %d %H:%M:%S",

      # format: YYYY/MM/DD hh:mm:ss
      #         2015/05/29 19:34:21
      "^(\d{4})/(\d{2})/(\d{2})\s"
      "(\d{2}):(\d{2}):(\d{2})": "%Y/%m/%d %H:%M:%S",

      # format: YYYY-MM-DD[T]hh:mm:ss
      "^(\d{4})-(\d{2})-(\d{2})[\sT]"
      "(\d{2}):(\d{2}):(\d{2})": "%Y-%m-%d %H:%M:%S",

    }
    self.re_timestamps_from_lines = None
      
    # Map between re and message delivery status.
    # Syntax:
    #   {
    #     "<re1>": {
    #       "status_tags": [ "status1", "status2", "statusN" ],
    #       "mail_domain": <group_index>
    #     }
    #   }
    # Converted in (self.re_status_map):
    #   {
    #     "<re1>": {
    #       "compiled": "<compiled_re_obj>",
    #       "status_tags": [ "status1", "status2", "statusN" ],
    #       "mail_domain": <group_index>
    #     }
    #   }
    # <group_index> is the index of the regexp group that matches the
    # mail domain for which the delivery attempt has been made.
    #
    # Must be filled by child classes.
    self.status_map = {}
    self.re_status_map = None

    self.status_tags = []
    for s in MANDATORY_STATUS_TAGS:
      self.status_tags.append(s)

    self.policy_defs = policy_defs

    self.logfilepath = logfilepath
    self.cursorfile = None

    if self.logfilepath == "-":
      self.is_stdin = True
      self.incremental = False
    else:
      self.is_stdin = False
      self.incremental = incremental

      if not os.path.isfile(self.logfilepath):
        raise FileNotFoundError("Log file not found: %s" % self.logfilepath)
      if not os.access(self.logfilepath, os.R_OK):
        raise InsufficientPermissionError("Insufficient permissions to read "
                                          "logfile %s" % self.logfilepath)

      data_dir = Config.get("general","data_dir")

      if not os.path.isdir(data_dir):
        raise FileNotFoundError("Working directory (data_dir) not found: %s" %
                                data_dir)
      if not os.access(data_dir, os.W_OK):
        raise InsufficientPermissionError("Insufficient permissions to write "
                                          "into working directory (data_dir): "
                                          "%s" % data_dir)

      logfile_inode = os.stat(self.logfilepath).st_ino
      self.cursorfile = os.path.join(data_dir, str(logfile_inode) + ".cur")

  def remove_cursor(self):
    if self.cursorfile:
      if os.path.isfile(self.cursorfile):
        os.remove(self.cursorfile)
        return "Cursor removed"
      else:
        return "Cursor file does not exist"
    else:
      return "Cursor not defined"

  def show_cursor(self):
    if self.cursorfile:
      j = json.dumps(self.read_cursor(),indent=2)
      return "Cursor file: %s\n%s" % (self.cursorfile,j)
    else:
      return "No cursor specified"

  def read_cursor(self):
    cursor = {}
    if os.path.isfile(self.cursorfile):
      with open(self.cursorfile,"r") as cursor_file:
        cursor = json.loads(cursor_file.read())
    return cursor
  
  def write_cursor(self,cursor):
    with open(self.cursorfile,"w") as cursor_file:
      cursor_file.write(json.dumps(cursor))

  def get_ts_from_line(self,line):
    """
    Return the sub-string matching the line's timestamp or None if noone found.
    """
    self._prepare_re_timestamps_from_lines()

    for re_str in self.re_timestamps_from_lines.keys():
      compiled_re = self.re_timestamps_from_lines[re_str]["compiled"]
      match = compiled_re.search(line)
      if match:
        return match.group(0)
    return None

  def get_newlines(self):
    """
    Return the new lines (trailing \n included) from the input log file.
    If input is stdin, return all the lines.
    If input is a log file and the incremental mode is on, return the new
    lines that have not been read yet. A cursor is saved in data_dir to
    keep the state.
    """
    if self.is_stdin:
      return sys.stdin.read().split("\n")

    if not os.path.isfile(self.logfilepath):
      raise FileNotFoundError("Log file not found: %s" % self.logfilepath)
    elif not os.access(self.logfilepath, os.R_OK):
      raise InsufficientPermissionError("Insufficient permissions to read "
                                        "logfile %s" % self.logfilepath)

    if not self.incremental:
      logfile = open(self.logfilepath,"r")
      res = logfile.readlines()
      logfile.close()
    else:
      res = []
      cursor = {}

      # Log file modification time check.
      # If current mtime == old mtime, return an empty list.
      curr_mtime = int(os.path.getmtime(self.logfilepath))

      cursor = self.read_cursor()

      if "mtime" in cursor:
        if curr_mtime <= cursor["mtime"]:
          return []

      # Read content.
      logfile = open(self.logfilepath,"r")
      lines = logfile.readlines()
      logfile.close()

      # Number of lines check.
      # If current number of lines > last known number of lines AND
      # first line's timestamp is equal to the last known first line's
      # timestamp then return new lines only.
      curr_lines_cnt = len(lines)
      curr_first_line_ts = None

      if curr_lines_cnt > 0:
        #TODO: allow first line's null timestamp or not? Look for a valid
        # timestamp on first x lines?
        curr_first_line_ts = self.get_ts_from_line(lines[0])

        if "lines_cnt" in cursor:
          if curr_lines_cnt > cursor["lines_cnt"]:
            if "first_line_ts" in cursor:
              if curr_first_line_ts == cursor["first_line_ts"]:
                res = lines[cursor["lines_cnt"]:]
      
      # If res is still empty, set it to the whole lines.
      if res == []:
        res = lines

      cursor["mtime"] = curr_mtime
      cursor["lines_cnt"] = curr_lines_cnt
      cursor["first_line_ts"] = curr_first_line_ts

      self.write_cursor(cursor)

    return res

  def analyze_lines(self,lines):
    """
    Return the summary of delivery attempts status.

    {
      "matched_lines": [ "<line1>", "<line2>", "<lineN>" ],
      "unmatched_lines": [ "<line1>", "<line2>", "<lineN>" ],
      "domains": {
        "<mail_domain1>": {
          "<status_tag1>": <int>,
          "<status_tagN>": <int>
        },
        "<mail_domainN>": {...}
      },
      "<status_tag1>": {
        "domains": {
          "<mail_domain1>": <int>,
          "<mail_domainN>": <int>
        },
        "cnt": <int>
      },
      "<status_tagN>": {...}
    }
    """

    res = {
      "matched_lines": [],
      "unmatched_lines": [],
      "domains": {}
    }

    self._prepare_re_status_map()

    for line in lines:
      matched = False
      for re_str in self.re_status_map.keys():
        compiled_re = self.re_status_map[re_str]["compiled"]
        match = compiled_re.search(line)
        if match:
          matched = True

          mail_domain_idx = self.re_status_map[re_str]["mail_domain"]
          mail_domain = match.group(mail_domain_idx)

          # Increment counters only if no policy definitions
          # has been provided or if the domain is one of those
          # included in the policy.
          if not self.policy_defs or \
            mail_domain in self.policy_defs.tls_policies.keys():

            if not mail_domain in res["domains"]:
              res["domains"][mail_domain] = {}

            for status in self.re_status_map[re_str]["status_tags"]:
              if not status in res:
                res[status] = {}
                res[status]["cnt"] = 0
                res[status]["domains"] = {}

              res[status]["cnt"] = res[status]["cnt"] + 1

              if not mail_domain in res[status]["domains"]:
                res[status]["domains"][mail_domain] = 0
              res[status]["domains"][mail_domain] = \
                res[status]["domains"][mail_domain] + 1

              if not status in res["domains"][mail_domain]:
                res["domains"][mail_domain][status] = 0
              res["domains"][mail_domain][status] = \
                res["domains"][mail_domain][status] + 1

      if matched:
        res["matched_lines"].append(line)
      else:
        res["unmatched_lines"].append(line)

    return res

class PostfixLogWatcher(MTALogWatcher):

  def __init__(self,logfilepath,incremental,policy_defs):
    MTALogWatcher.__init__(self,logfilepath,incremental,policy_defs)

    self.status_map = {
      "to=<[^@]+@([^>]*)>.* status=deferred.*(TLS|certificate)": {
        "status_tags": [ "sent_ko", "attempted" ],
        "mail_domain": 1
      },
      "to=<[^@]+@([^>]*)>.* status=sent": {
        "status_tags": [ "sent_ok", "attempted" ],
        "mail_domain": 1
      }
    }

if __name__ == "__main__":
  def main():
    parser = argparse.ArgumentParser(
      description="""MTA log watcher""",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog="""
Incremental reading is not available when logfile = "-" (stdin).

If a policy definitions file is supplied (-p argument) the output counters are
incremented only for logfile lines that match one of the mail domains covered
by the policy.

Output type:
- matched-lines: only the lines that have been analysed will be shown.
- unmatched-lines: only the lines that have not been included in the analysis
  will be shown; this option can be useful to evaluate the effectiveness of 
  log parsing patterns and to display log lines that have been ignored.
- domains: all the domains that have been analysed are shown, with counters
  of successful and failed delivery attempts.
- warnings: like for 'domains', but only mail domains with a failure rate that
  is higher than the configured threshold are shown.""")

    parser.add_argument("-c", "--cfg", default=Config.default_cfg_path,
                        help="general configuration file path", metavar="file",
                        dest="cfg_path")

    parser.add_argument("-m", default="Postfix",
                        help="MTA flavor", choices=["Postfix"],
                        dest="mta_flavor")

    parser.add_argument("logfile", help="MTA's log file to analyze; "
                        "a dash ('-') means read from stdin")

    parser.add_argument("-i", "--incremental", action="store_true",
                        dest="incremental", help="read file incrementally")

    parser.add_argument("--remove-cursor", action="store_true",
                        dest="remove_cursor",
                        help="remove the file containing the cursor used for "
                             "incrementally reading the logfile")

    parser.add_argument("--show-cursor", action="store_true",
                        dest="show_cursor",
                        help="show the file containing the cursor used for "
                             "incrementally reading the logfile")

    output_choices = ["warnings", "domains", "summary",
                              "matched-lines", "unmatched-lines"]

    parser.add_argument("-o", default="warnings", dest="output",
                        choices=output_choices,
                        metavar="output-type",
                        help="requested output: " + 
                        " | ".join("'" + c + "'" for c in output_choices))

    parser.add_argument("-p",
                        help="JSON policy definitions file",
                        dest="policy_defs",
                        metavar="policy_defs.json")

    args = parser.parse_args()

    Config.read(args.cfg_path)

    if args.output == "warnings":
      # Reporting facilities initialization

      reports_dir = Config.get("general","logwatcher_reports_dir")
      if not os.path.isdir(reports_dir):
        mkdirp(reports_dir)
        #raise FileNotFoundError("Logwatcher's reports directory "
        #                        "(logwatcher_reports_dir) not found: %s" %
        #                        reports_dir)
      if not os.access(reports_dir, os.W_OK):
        raise InsufficientPermissionError("Insufficient permissions to write "
                                          "into logwatcher's reports "
                                          "directory "
                                          "(logwatcher_reports_dir): %s" %
                                          reports_dir)

      Config.get_logger()

    # failure_threshold = failure_threshold_percent / 100
    #   1 = 100%
    #   0.001 = 0.1%
    failure_threshold = Config.get("general","failure_threshold_percent")
    try:
      failure_threshold = float(failure_threshold)/100
    except:
      raise TypeError("Invalid failure threshold: %s" % failure_threshold)

    if failure_threshold < 0 or failure_threshold > 1:
      raise ValueError("Failure threshold must be between 0 and 100: %s" %
                        failure_threshold)

    if args.logfile == "-":
      if args.incremental:
        print("Can't use incremental reading on stdin.")
        return
      if args.remove_cursor or args.show_cursor:
        print("Can't manage cursors for stdin.")
        return

    if args.policy_defs:
      policy_defs = DefsParser.Defs(args.policy_defs)
    else:
      policy_defs = None

    if args.mta_flavor == "Postfix":
      logwatcher = PostfixLogWatcher(args.logfile,args.incremental,policy_defs)
    else:
      print("Unexpected MTA flavor: {}".format(args.mta_flavor))
      return

    if args.remove_cursor:
      print(logwatcher.remove_cursor())
      return
    if args.show_cursor:
      print(logwatcher.show_cursor())
      return

    res = logwatcher.analyze_lines(logwatcher.get_newlines())

    if args.output == "summary":
      print("Displaying the summary accordingly to logfile parsing results")
      print("")

      for s in logwatcher.status_tags:
        if s in res:
          print("%s:" % s)
          print(json.dumps(res[s],indent=2))
      print("Domains:")
      print(json.dumps(res["domains"],indent=2))

    elif args.output == "matched-lines":
      print("Displaying the logfile's lines that matched configured patterns")
      print("")

      for l in res["matched_lines"]:
        print(l.rstrip("\n"))

    elif args.output == "unmatched-lines":
      print("Displaying the logfile's lines that did not match "
            "configured patterns")
      print("")

      for l in res["unmatched_lines"]:
        print(l.rstrip("\n"))

    elif args.output in [ "domains", "warnings" ]:
      print("Displaying successful/failed delivery attempts for %s" %
            ("every domain" if args.output == "domains" else
             "domains with an high failure rate (%s%%)" %
             (failure_threshold*100)))
      print("")

      warning_domains = []

      for domainname in res["domains"]:
        domain = res["domains"][domainname]
        
        if not "attempted" in domain:
          continue

        #TODO: implement results for "log-only = true" status.
        if "sent_ko" in domain and domain["attempted"] > 0:
          failure_rate = domain["sent_ko"] / domain["attempted"]
        else:
          failure_rate = None

        if args.output == "domains" or \
          ( args.output == "warnings" and failure_rate >= failure_threshold ):
          succeeded = domain["sent_ok"] if "sent_ok" in domain else "none"
          failed = domain["sent_ko"] if "sent_ko" in domain else "none"

          s = "{d}: {t} delivery attempts, {s} succeeded, {f} failed"
          if failure_rate:
            s = s + ", {r:.2%} failure rate"
            if failure_rate >= failure_threshold:
              s = s + " - WARNING"
              warning_domains.append(domainname)

          print(s.format(d=domainname, r=failure_rate,
                         t=domain["attempted"], s=succeeded,
                         f=failed))

      if args.output == "warnings" and len(warning_domains) > 0:
        report_format= Config.get("general","logwatcher_reports_fmt")
        report_filename = datetime.datetime.now().strftime(report_format)
        report_file = "%s/%s" % (reports_dir,report_filename)
        with open(report_file, "w") as r:
          r.write("domainname,attempts,ko,ok\n")
          for domainname in warning_domains:
            r.write("{domainname},{attempted},{sent_ko},{sent_ok}\n".format(
                    domainname=domainname,
                    attempted=res["domains"][domainname]["attempted"],
                    sent_ko=res["domains"][domainname]["sent_ko"],
                    sent_ok=res["domains"][domainname]["sent_ok"]))

        notification_t = "Delivery errors found for {domains} for a " + \
                         "total of {fail} failures over {tot} total " + \
                         "attempts. More details on {report_file}"

        if len(warning_domains) > 3:
          notification_domains = ", ".join(warning_domains[:3]) + \
                                 "and " + str(len(warning_domains)-3) + \
                                 " more domains"
        else:
          notification_domains = ", ".join(warning_domains)

        fail = 0
        tot = 0
        for domainname in warning_domains:
          fail = fail + res["domains"][domainname]["sent_ko"]
          tot = tot + res["domains"][domainname]["attempted"]

        notification = notification_t.format(domains=notification_domains,
                                             fail=fail,
                                             tot=tot,
                                             report_file=report_file)

        Config.get_logger().error(notification)

    #TODO: consider implementing a feature to automatically remove
    # policy enforcement in case of problems (it would require an
    # additional MTAConfigGenerator method to force MTA to reload
    # its configuration).

  try:
    main()
  except Exception as e:
    print(e)
