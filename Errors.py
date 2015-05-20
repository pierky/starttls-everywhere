class TLDsListUnavailableError(Exception): pass

class ExistingConfigError(ValueError): pass

class InsufficientPermissionError(Exception): pass

try:
  FileNotFoundError
except:
  class FileNotFoundError(Exception): pass

class BuildUnchangedConfigFileError(Exception): pass
class PolicyNotImplementedError(Exception): pass

class CheckSTARTTLSSupportError(Exception): pass
class SSLCertificatesError(Exception): pass
