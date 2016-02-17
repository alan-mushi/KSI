import logging
import os
from datetime import datetime

from ksi.signverify import SignVerify
from ksi.ksi_messages import TimestampResponse, KSIErrorCodes
from ksi.hash import hash_factory
from ksi.identifier import Identifier
from ksi.bench_decorator import add_logger, LOGGER_NAME, LOGGER_DIR
from ksi import PERFORM_BENCHMARKS, BENCHMARK_MOTIF

#
# Observe the time spent signing (signverify.sign()) for different key sizes.
#

LOGGER_DEFAULT_OUTFILE = LOGGER_DIR + LOGGER_NAME + '.log'
LOGGER_SAVE_OUTFILE = LOGGER_DIR + 'benchmark-{}-{}-{}.log'

if __name__ == '__main__':
    assert PERFORM_BENCHMARKS is True  # This switch need to be enabled!
    assert BENCHMARK_MOTIF == "ksi.signverify"

    add_logger()
    logging.basicConfig(level=logging.INFO)
    hash = hash_factory(data=b'ABCD')

    for i in [1024, 2048, 4096]:
        open(LOGGER_DEFAULT_OUTFILE, 'w+').close()
        signer = SignVerify()
        signer.generate_keys(i)
        resp = TimestampResponse(hash, Identifier('server'), Identifier('client'), datetime.utcnow(),
                                 KSIErrorCodes.NO_ERROR)
        # Benchmark start
        m, sig = signer.sign(resp)
        assert signer.verify(m, sig) is True
        # Benchmark end

        logger = logging.getLogger(LOGGER_NAME)

        for h in logger.handlers:
            h.flush()
            logger.removeHandler(h)

        os.rename(LOGGER_DEFAULT_OUTFILE, LOGGER_SAVE_OUTFILE.format('Sign', '', 'key-len_' + str(i)))
