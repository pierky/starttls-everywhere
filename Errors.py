class STARTTLSEverywhereCustomError(Exception): pass

class TLDsListUnavailableError(STARTTLSEverywhereCustomError): pass

class ExistingConfigError(STARTTLSEverywhereCustomError):
  """
  When an ExistingConfigError exception is raised
  the MTA config generator shows a notice and suggests
  the user to run the program with the --fix argument.
  """
  def __str__(self):
    return self.message + "\n" \
                   "Please consider using the --fix argument to show a new " \
                   "proposal configuration."

class InsufficientPermissionError(STARTTLSEverywhereCustomError):
  """
  When an InsufficientPermissionError exception is raised
  the MTA config generator suggests the user to run the
  program with root permissions.
  """
  def __str__(self):
    return self.message + "\n" \
                   "Please try re-running as root."

class MissingFileError(STARTTLSEverywhereCustomError): pass

class BuildUnchangedConfigFileError(STARTTLSEverywhereCustomError): pass

class PolicyNotImplementedError(STARTTLSEverywhereCustomError):
  """
  Policies that can't be built because of a 
  PolicyNotImplementedError exception can be ignored
  with the --ignore command line argument; to do so:
  - the MTA config generator must raise the exception
    and pass a symbolic tag in ignore_flag;
  - the MTA config generator must have that tag in its
    allowed_ignore_list.
  """
  def __init__(self, message, ignore_flag=None):
    STARTTLSEverywhereCustomError.__init__(self, message)
    self.ignore_flag = ignore_flag

  def __str__(self):
    if self.ignore_flag:
      return self.message + "\n" \
                     "Use the '--ignore %s' argument to ignore those " \
                     "policies that use this unimplemented " \
                     "feature." % self.ignore_flag
    else:
      return self.message

class PolicyBuildingError(STARTTLSEverywhereCustomError):
  """
  Unrecoverable errors.
  """
  pass

class CheckSTARTTLSSupportError(STARTTLSEverywhereCustomError): pass
class SSLCertificatesError(STARTTLSEverywhereCustomError): pass
