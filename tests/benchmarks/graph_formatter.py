import os
import json
from datetime import datetime

DIR = '/home/user/ksi_git/tests/benchmarks/benchmarks_output/'
START_EXPR = 'benchmark-Keys-{}-l_'
EXTENSION = '.log'
MOTIF = '__init__'
SEPARATOR = '|'
alg_names = ['haraka_512_256' ,'md5' ,'ripemd160' ,'sha256' ,'sha3_224' ,'sha3_256' ,'sha3_384' ,'sha3_512' ,'whirlpool']

if __name__ == '__main__':
    os.chdir(DIR)
    base_date = datetime.utcnow().isoformat(sep='T').split('T')[0]
    chart_values_all = []

    for alg in alg_names:
        START_EXPR = 'benchmark-Keys-{}-l_'.format(alg)

        files = [f for f in os.listdir(DIR) if os.path.isfile(f) and f.endswith(EXTENSION) and f.startswith(START_EXPR)]
        val = sorted(list(map(lambda f: f[len(START_EXPR):][:-len(EXTENSION)], files)), key=int)
        chart_values = []

        for i in val:
            with open(START_EXPR + i + EXTENSION, 'r') as f:
                for line in f.readlines():
                    if MOTIF in line:
                        time = base_date + 'T0' + line.split(sep=SEPARATOR)[1][:-1]
                        chart_values.append({'time': time, 'value': int(i)})

        chart_values_all.append(chart_values)

    metadata = {}
    metadata['title'] = 'Time spent generating user\'s Keys (Merkle Tree) with various algorithms'
    metadata['description'] = ''
    metadata['x_accessor'] = 'time'
    metadata['x_label'] = 'Time'
    metadata['xax_units'] = ''
    metadata['y_accessor'] = 'value'
    metadata['y_label'] = 'l'
    metadata['yax_units'] = ''
    metadata['y_scale_type'] = 'linear'  # 'log' || 'linear'
    metadata['chart_type'] = 'line'
    metadata['x_rug'] = True
    metadata['y_rug'] = True
    metadata['european_clock'] = False
    metadata['legend'] = alg_names
    metadata['legend_target'] = '#legend'
    metadata['x_mouseover'] = '%M min %S.%L secs for l = '
    metadata['colors'] = ['blue', 'orange', 'green', 'yellow', 'brown', 'black', 'fuchsia', 'cyan', 'red']
    metadata['aggregate_rollover'] = True
    metadata['missing_is_hidden'] = True
    metadata['full_width'] = True

    with open('data.json', 'w+') as outfile:
        outfile.write(json.dumps({'data': chart_values_all, 'metadata': metadata}, indent=4))
