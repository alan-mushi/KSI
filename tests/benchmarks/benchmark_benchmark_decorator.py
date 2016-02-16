from ksi.bench_decorator import benchmark_decorator

#
# Observe the bias introduced by the decorator's code. This is a useful information to adjust measures when decorated
# functions call other decorated functions.
#


@benchmark_decorator
@benchmark_decorator
def func():
    pass


if __name__ == '__main__':
    func()
