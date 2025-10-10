"""findmytakeover - A tool to find subdomain takeover vulnerabilities."""

__version__ = "2.0.0"
__author__ = "Original Authors"
__license__ = "GPL-3.0"

from findmytakeover.collector import aws, gcp, msazure

__all__ = ["aws", "gcp", "msazure", "__version__"]
