#!/usr/bin/env python
import argparse
import collections
import os
import re
import sys
import datetime
import json

import DefsParser
from Config import Config
from Errors import *

TIME_FORMAT = "%b %d %H:%M:%S"

ABBR_MONTHS = [datetime.date(2015,m,1).strftime("%b") for m in range(1,13)]

STATUS_TAGS = [ "sent_ok", "sent_ko", "tried" ]

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
      self.re_status_map[re_str]["tags"] = \
        self.status_map[re_str]["tags"]
      if "mail_domain" in self.status_map[re_str]:
        self.re_status_map[re_str]["mail_domain"] = \
          self.status_map[re_str]["mail_domain"]
 
  def __init__(self,logfilepath,incremental):
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
    self.timestamps_from_lines = {
      # May 29 19:30:52
      "^(" + "|".join(ABBR_MONTHS) + ")\s{1,2}"
      "(\d{1,2})\s{1,2}"
      "(\d{1,2}):"
      "(\d{1,2}):"
      "(\d{1,2})\s": "%b %d %H:%M:%S"
    }
    self.re_timestamps_from_lines = None
      
    # Map between re and message delivery status.
    # Syntax:
    #   {
    #     "<re1>": {
    #       "tags": [ "status1", "status2", "statusN" ],
    #       "mail_domain": <group_index>
    #     }
    #   }
    # Converted in (self.re_status_map):
    #   {
    #     "<re1>": {
    #       "compiled": "<compiled_re_obj>",
    #       "tags": [ "status1", "status2", "statusN" ],
    #       "mail_domain": <group_index>
    #     }
    #   }
    self.status_map = {}
    self.re_status_map = None

    self.logfilepath = logfilepath

    if self.logfilepath == "-":
      self.is_stdin = True
      self.incremental = False
      self.cursorfile = None
    else:
      self.is_stdin = False
      self.incremental = incremental
      data_dir = Config.get("general","data_dir")
      self.cursorfile = os.path.join(data_dir,
                                    "cur" + self.logfilepath.replace("/","-"))

      if os.path.isfile(self.logfilepath):
        if not os.access(self.logfilepath, os.R_OK):
          raise InsufficientPermissionError("Insufficient permissions to read "
                                            "logfile %s" % self.logfilepath)


    if self.incremental:
      if not os.path.isdir(data_dir):
        raise FileNotFoundError("Working directory (data_dir) not found: %s" %
                                data_dir)

      if not os.access(data_dir, os.W_OK):
        raise InsufficientPermissionError("Insufficient permissions to write "
                                          "logfile cursor to %s" % data_dir)

  def remove_cursor(self):
    if self.cursorfile:
      if os.path.isfile(self.cursorfile):
        os.remove(self.cursorfile)
        return "Cursor removed"
      else:
        return "Cursor file does not exist"
    else:
      return "Cursor not defined"

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

      if os.path.isfile(self.cursorfile):
        with open(self.cursorfile,"r") as cursor_file:
          cursor = json.loads(cursor_file.read())

      if "mtime" in cursor:
        if curr_mtime <= cursor["mtime"]:
          return []

      # Read content.
      logfile = open(self.logfilepath,"r")
      lines = logfile.readlines()
      logfile.close()

      # Number of lines check.
      # If current number of lines > last known number of lines AND
      # first line's timestamp is equal to last known first line's TS
      # then return new lines only.
      curr_lines_cnt = len(lines)
      curr_first_line_ts = None

      if curr_lines_cnt > 0:
        curr_first_line_ts = self.get_ts_from_line(lines[0])

        if "lines_cnt" in cursor:
          if curr_lines_cnt > cursor["lines_cnt"]:
            if curr_first_line_ts and "first_line_ts" in cursor:
              if curr_first_line_ts == cursor["first_line_ts"]:
                res = lines[cursor["lines_cnt"]:]
      
      # If res is still empty, set it to the whole lines
      if res == []:
        res = lines

      cursor["mtime"] = curr_mtime
      cursor["lines_cnt"] = curr_lines_cnt
      cursor["first_line_ts"] = curr_first_line_ts

      with open(self.cursorfile,"w") as cursor_file:
        cursor_file.write(json.dumps(cursor))

    return res

  def analyze_lines(self,lines):
    """
    Return the summary of delivery attempts status.
    """
    self._prepare_re_status_map()

    res = {
      "matched_lines": [],
      "unmatched_lines": [],
      "domains": {}
    }

    for line in lines:
      matched = False
      for re_str in self.re_status_map.keys():
        compiled_re = self.re_status_map[re_str]["compiled"]
        match = compiled_re.search(line)
        if match:
          matched = True

          if "mail_domain" in self.re_status_map[re_str]:
            mail_domain_idx = self.re_status_map[re_str]["mail_domain"]
            mail_domain = match.group(mail_domain_idx)

            if not mail_domain in res["domains"]:
              res["domains"][mail_domain] = {}
          else:
            mail_domain = None

          for status in self.re_status_map[re_str]["tags"]:
            if not status in res:
              res[status] = {}
              res[status]["cnt"] = 0
              res[status]["domains"] = {}

            res[status]["cnt"] = res[status]["cnt"] + 1

            if mail_domain:
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

  def __init__(self,logfilepath,incremental):
    MTALogWatcher.__init__(self,logfilepath,incremental)

    self.status_map = {
      "to=<[^@]+@([^>]*)>.* status=deferred.*(TLS|certificate)": {
        "tags": [ "sent_ko", "tried" ],
        "mail_domain": 1
      },
      "to=<[^@]+@([^>]*)>.* status=sent": {
        "tags": [ "sent_ok", "tried" ],
        "mail_domain": 1
      }
    }

if __name__ == "__main__":
  def main():
    parser = argparse.ArgumentParser(
      description="""MTA log watcher""")

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
                             "incremental reading")

    parser.add_argument("-o", "--output", default="summary", dest="output",
                        choices=["summary", "matched_lines",
                                 "unmatched_lines"], metavar="output",
                        help="requested output")

    #parser.add_argument("-p", "--policy-defs",
    #                    help="JSON policy definitions file",
    #                    dest="policy_defs",
    #                    metavar="policy_defs.json")

    args = parser.parse_args()

    Config.read(args.cfg_path)

    #if args.policy_defs:
    #  c = DefsParser.Defs(args.policy_def)

    if args.mta_flavor == "Postfix":
      logwatcher = PostfixLogWatcher(args.logfile,args.incremental)
    else:
      print("Unexpected MTA flavor: {}".format(args.mta_flavor))
      return

    if args.remove_cursor:
      print(logwatcher.remove_cursor())
      return

    res = logwatcher.analyze_lines( logwatcher.get_newlines() )

    if args.output == "summary":
      for s in STATUS_TAGS:
        if s in res:
          print("%s:" % s)
          print(json.dumps(res[s],indent=2))
      print("Domains:")
      print(json.dumps(res["domains"],indent=2))
    elif args.output == "matched_lines":
      for l in res["matched_lines"]:
        print(l.rstrip("\n"))
    elif args.output == "unmatched_lines":
      for l in res["unmatched_lines"]:
        print(l.rstrip("\n"))
#    for l in res["unmatched_lines"]:
#      print(l)

  try:
    main()
  except Exception as e:
    raise
    print(e)
