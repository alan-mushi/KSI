"""
Available algorithms: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512
Other may be available using OpenSSL.
"""
HASH_ALGO = "sha3_256"

"""
Used by the Identifier, see Identifier's documentation
"""
IDENTIFIER_SEPARATOR = '.'
IDENTIFIER_BASE_NAME = "org" + IDENTIFIER_SEPARATOR + "ksi"
