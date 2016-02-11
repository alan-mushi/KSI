"""
Available algorithms: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512
Other may be available using OpenSSL.
"""
HASH_ALGO = "sha3_256"
HASH_ALGO_OID = {"sha3_256": "2.16.840.1.101.3.4.2.8",
                 "sha3_384": "2.16.840.1.101.3.4.2.9",
                 "sha3_512": "2.16.840.1.101.3.4.2.10"}

"""
Used by the Identifier, see Identifier's documentation
"""
IDENTIFIER_SEPARATOR = '.'
IDENTIFIER_BASE_NAME = "org" + IDENTIFIER_SEPARATOR + "ksi" + IDENTIFIER_SEPARATOR

"""
Used by SignFactory, see SignFactory's documentation.
"""
SIGN_KEY_LEN = 2048  # Power of 2 >= 1024 and <= 4096
SIGN_KEY_FORMAT = "PEM"  # "PEM" or "DER"

"""
REST API base URL.
"""
API_ROUTE_BASE = '/ksi/api/v0.1/'
API_HOST_PORT = 'http://localhost:5000'
