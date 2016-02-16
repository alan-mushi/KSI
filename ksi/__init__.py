from os import getenv

"""
Available algorithms: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512
Other may be available using OpenSSL.
Warning: haraka hash is **experimental**! See haraka for more details. 'alg_name' for Haraka: haraka_512_256, haraka_256_256
"""
HASH_ALGO = getenv("KSI_HASH_ALGO", "sha3_256")
# This is a special flag used to adjust seed/data size for haraka hash functions
HASH_ALGO_DIGEST_SIZE = int(256 / 8)
HASH_ALGO_OID = {"sha3_256": "2.16.840.1.101.3.4.2.8",
                 "sha3_384": "2.16.840.1.101.3.4.2.9",
                 "sha3_512": "2.16.840.1.101.3.4.2.10"}
LIBHARAKA_PATH = getenv("KSI_LIBHARAKA_PATH", "/tmp/")

"""
Used by the Identifier, see Identifier's documentation.
"""
IDENTIFIER_SEPARATOR = '.'
IDENTIFIER_BASE_NAME = "org" + IDENTIFIER_SEPARATOR + "ksi" + IDENTIFIER_SEPARATOR

"""
Used by SignFactory, see SignFactory's documentation.
"""
SIGN_KEY_LEN = int(getenv("KSI_SIGN_KEY_LEN", "2048"))  # Power of 2 >= 1024 and <= 4096
SIGN_KEY_FORMAT = "PEM"  # "PEM" or "DER"

"""
REST API base URL.
"""
API_ROUTE_BASE = '/ksi/api/v0.1/'
API_HOST_PORT = 'http://localhost:5000'

"""
Set to true to perform benchmarks (enable the benchmark decorators).
"""
PERFORM_BENCHMARKS = getenv('KSI_PERFORM_BENCHMARKS', 'False') == 'True'
BENCHMARK_MOTIF = getenv('KSI_BENCHMARK_MOTIF', '')
