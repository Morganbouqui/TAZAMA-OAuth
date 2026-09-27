class TazamaOAuthError(Exception): pass
class ScopeDenied(TazamaOAuthError): pass
class RiskDenied(TazamaOAuthError): pass
class WorkspaceError(TazamaOAuthError): pass
