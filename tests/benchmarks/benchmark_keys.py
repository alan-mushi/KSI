import logging
import os
import shelve

from ksi.keys import Keys
from ksi.bench_decorator import add_logger, LOGGER_NAME, LOGGER_DIR
from ksi import PERFORM_BENCHMARKS, HASH_ALGO, BENCHMARK_MOTIF


MAX_L_POW = 20
LOGGER_DEFAULT_OUTFILE = LOGGER_DIR + LOGGER_NAME + '.log'
LOGGER_SAVE_OUTFILE = LOGGER_DIR + 'benchmark-{}-{}-{}.log'
KEY_SHELVE_OUTFILE = LOGGER_SAVE_OUTFILE[:-4] + '.shelve'


if __name__ == '__main__':
    add_logger()
    logging.basicConfig(level=logging.INFO)
    assert PERFORM_BENCHMARKS is True  # This switch need to be enabled!
    assert BENCHMARK_MOTIF == "ksi.keys"

    l_nums = list(map(lambda i: 2 ** i, [i for i in range(2, MAX_L_POW+1)]))
    _max_l = 2 ** MAX_L_POW

    for l in l_nums:
        open(LOGGER_DEFAULT_OUTFILE, 'w+').close()
        print("Computing time: \t{} / {}".format(l, _max_l))

        # Benchmark Start
        keys = Keys(l=l)
        # Benchmark End

        logger = logging.getLogger(LOGGER_NAME)

        for h in logger.handlers:
            h.flush()
            logger.removeHandler(h)

        os.rename(LOGGER_DEFAULT_OUTFILE, LOGGER_SAVE_OUTFILE.format("Keys", HASH_ALGO, "l_" + str(l)))

        # Generating keys is quite long, we wish to restore them at a latter time (with the hash function of our choice)
        with shelve.open(KEY_SHELVE_OUTFILE.format("Keys", HASH_ALGO, "l_" + str(l)), flag='c') as save:
            save['keys'] = keys
