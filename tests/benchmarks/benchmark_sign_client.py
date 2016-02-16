import logging
import os
import shelve

from ksi.keys import Keys
from ksi.hash import hash_factory
from ksi.ksi_client import KSIClient
from ksi.ksi_server import KSIServer
from ksi.dao import factory
from ksi.dao_memory import DAOMemoryFactory
from ksi.identifier import Identifier
from ksi.bench_decorator import add_logger, LOGGER_NAME, LOGGER_DIR
from ksi import PERFORM_BENCHMARKS, HASH_ALGO, BENCHMARK_MOTIF, SIGN_KEY_LEN

#
# This benchmark allows us to determine how long it takes to build the hash chain.
# There is _always_ one second delay before the signature is "published".
#


MAX_L_POW = 20
LOGGER_DEFAULT_OUTFILE = LOGGER_DIR + LOGGER_NAME + '.log'
LOGGER_SAVE_OUTFILE = LOGGER_DIR + 'benchmark-{}-{}-{}.log'
KEY_SHELVE_INPUT_FILE = LOGGER_SAVE_OUTFILE[:-4] + '.shelve'


if __name__ == '__main__':
    add_logger()
    logging.basicConfig(level=logging.INFO)
    assert PERFORM_BENCHMARKS is True  # This switch need to be enabled!
    assert BENCHMARK_MOTIF == "ksi.ksi_client"

    l_nums = list(map(lambda i: 2 ** i, [i for i in range(2, MAX_L_POW+1)]))
    _max_l = 2 ** MAX_L_POW
    msg_to_sign = hash_factory(data=b'ABCDEFGHIJKLMNOPQRSTUVWXYZ').digest()

    # We don't generate a private key here
    # ln -s /home/user/ksi_git/tests/output/private.pem /tmp/private.pem

    for l in l_nums:
        keys = None

        # Importing saved keys from Keys benchmark
        with shelve.open(KEY_SHELVE_INPUT_FILE.format("Keys", HASH_ALGO, "l_" + str(l)), flag='r') as save:
            keys = save['keys']  # type: Keys

        assert keys is not None

        open(LOGGER_DEFAULT_OUTFILE, 'w+').close()
        print("l: \t{} / {}".format(l, _max_l))
        dao_factory = factory(DAOMemoryFactory)

        server = KSIServer(Identifier("server"), dao_factory.get_server(), filename_private_key="/tmp/private.pem")
        client = KSIClient(server, dao_factory.get_client(), keys=keys)

        # Benchmark Start
        client.sign(msg_to_sign)
        # Benchmark End

        logger = logging.getLogger(LOGGER_NAME)

        for h in logger.handlers:
            h.flush()
            logger.removeHandler(h)

        os.rename(LOGGER_DEFAULT_OUTFILE, LOGGER_SAVE_OUTFILE.format("KSIClient_Sign_" + HASH_ALGO,
                                                                     "RSA_" + str(SIGN_KEY_LEN),
                                                                     "l_" + str(l)))
