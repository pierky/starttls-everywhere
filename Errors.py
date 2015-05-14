class TLDsListUnavailableError(Exception): pass

class ExistingConfigError(ValueError): pass

class InsufficientPermissionError(Exception): pass

try:
  FileNotFoundError
except:
  class FileNotFoundError(Exception): pass

class BuildUnchangedConfigFileError(Exception): pass
