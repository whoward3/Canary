"""
canaryServices

Attacker and Node Custom Services for the simulation canaryScripts using CORE

Additional Custom services that you define can be put in this directory.  Everything
listed in __all__ is automatically loaded when you add this directory to the
custom_services_dir = '/full/path/to/here' core.conf file option.
"""

__all__ = ["attacker","node"]