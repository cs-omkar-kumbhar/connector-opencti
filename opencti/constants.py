"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

INDICATOR_TYPES = {
    "account": "User-Account",
    "domain": "Domain-Name",
    "email": "Email-Addr",
    "file-md5": "StixFile",
    "file-sha1": "StixFile",
    "file-sha256": "StixFile",
    "host": "X-OpenCTI-Hostname",
    "ipv4": "IPv4-Addr",
    "ipv6": "IPv6-Addr",
    "registry key": "Windows-Registry-Key",
    "url": "Url"
}

FILE_TYPES = {
    "file-md5": "file.hashes.md5",
    "file-sha1": "file.hashes.sha-1",
    "file-sha256": "file.hashes.sha-256"
}

UPDATE_FIELDS = {
    "description": "x_opencti_description",
    "score": "x_opencti_score"
}
