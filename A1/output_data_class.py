from dataclasses import dataclass


@dataclass()
class ProgramOutput:
    """Class for tracking the support of http2, cookies and password protection"""
    cookies: []
    http2_support: bool = False
    password_protected: bool = False


@dataclass()
class CookieInfo:
    """Class for storing cookie information"""
    name: str
    expires: str = "Not Given"
    domain: str = "Not Given"
