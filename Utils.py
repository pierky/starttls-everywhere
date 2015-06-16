#!/usr/bin/env python
import os
from errno import EEXIST, EACCES
import re
from Errors import InsufficientPermissionError

def bin_to_hexstr(b):
  """Output: ab12cd34..."""
  return "".join([hex(ord(c))[2:].zfill(2) for c in b])

def hexstr_to_bin(s):
  """Input: ab12cd34..."""
  # for the sake of code readability...
  #   s = "68656c6c6f"
  #   s[0::2] == '66666'
  #   s[1::2] == '85ccf'
  #   zip(s[0::2], s[1::2]) == [('6', '8'), ('6', '5'), ('6', 'c'),
  #                             ('6', 'c'), ('6', 'f')]
  #   [''.join(c) for c in zip(s[0::2], s[1::2])] == ['68', '65', '6c',
  #                                                   '6c', '6f']
  return "".join([chr(int("".join(c), 16)) for c in zip(s[0::2], s[1::2])])

def hexstr_to_hexstr_with_colon(s):
  """Input: ab12cd34...
  Output: ab:12:cd:34:..."""
  # for the sake of code readability...
  #   s = "abcdef"
  #   s[0::2] == 'ace'
  #   s[1::2] == 'bdf'
  #   zip(s[0::2], s[1::2]) == [('a', 'b'), ('c', 'd'), ('e', 'f')]
  #   [b[0] + b[1] for b in zip(s[0::2], s[1::2])] == ['ab', 'cd', 'ef']
  return ":".join([b[0] + b[1] for b in zip(s[0::2], s[1::2])])

def split_string_every_n_char(s,n):
  """Output: list of strings"""
  return [s[i:i+n] for i in range(0, len(s), n)]

def tls_protocols_higher_than(first):
  """
  Return the list of protocols equal or higher than argument.
  """
  protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]

  res = []
  for p in protocols:
    if p == first or len(res) > 0:
      res.append(p)
  return res

def mkdirp(path):
  try:
    os.makedirs(path)
  except OSError as exc:
    if exc.errno == EEXIST and os.path.isdir(path):
      pass
    elif exc.errno == EACCES:
      raise InsufficientPermissionError("Permission denied while creating %s" %
                                        path)
    else:
      raise

def extract_pem_data(pem):
  match = re.search("-----BEGIN .+-----\s([a-zA-Z0-9\+\/\s\=]+)\s-----END ",
                    pem,re.MULTILINE)
  if match:
    return match.group(1)
  else:
    return None
