#!/usr/bin/python2.7
import re
import sys
import collections

import ConfigParser

def get_counts(input, config):
  seen_trusted = False

  counts = collections.defaultdict(lambda: collections.defaultdict(int))
  r = re.compile("([A-Za-z]+) TLS connection established to ([^[]*)")
  for line in sys.stdin:
    result = r.search(line)
    if result:
      validation = result.group(1)
      mx_hostname = result.group(2).lower()
      if validation == "Trusted" or validation == "Verified":
        seen_trusted = True
      address_domains = config.get_address_domains(mx_hostname)
      if address_domains:
        for d in address_domains:
          counts[d][validation] += 1
          counts[d]["all"] += 1
  if not seen_trusted:
    print "Didn't see any trusted connections. Need to install some certs?"
  return counts

def print_summary(counts):
  for mx_hostname, validations in counts.items():
    for validation, validation_count in validations.items():
      if validation == "all":
        continue
      print mx_hostname, validation, validation_count / validations["all"], "of", validations["all"]

if __name__ == "__main__":
  config = ConfigParser.Config("starttls-everywhere.json")
  counts = get_counts(sys.stdin, config)
  print_summary(counts)