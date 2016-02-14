import os
import json

DIR = '.'
START_EXPR = 'benchmark-Keys-{}-l_'.format('md5')
EXTENSION = '.log'
MOTIF = '__init__'
SEPARATOR = '|'

if __name__ == '__main__':
    files = [f for f in os.listdir(DIR) if os.path.isfile(f) and f.endswith(EXTENSION) and f.startswith(START_EXPR)]
    val = sorted(list(map(lambda f: f[len(START_EXPR):][:-len(EXTENSION)], files)), key=int)

    chart_values = []
    for i in val:
        with open(START_EXPR + i + EXTENSION, 'r') as f:
            for line in f.readlines():
                if MOTIF in line:
                    chart_values.append({'time': line.split(sep=SEPARATOR)[1][:-1], 'value': int(i)})

    metadata = {}
    metadata['title'] = 'Time spent generating user\'s Keys (Merkle Tree) with MD5'
    metadata['description'] = ''
    metadata['x_accessor'] = 'time'
    metadata['x_label'] = 'Time'
    metadata['xax_units'] = ''
    metadata['y_accessor'] = 'value'
    metadata['y_label'] = 'l'
    metadata['yax_units'] = ''
    metadata['y_scale_type'] = 'linear'  # 'log' || 'linear'
    metadata['chart_type'] = 'point'
    metadata['x_rug'] = False
    metadata['y_rug'] = False
    metadata['european_clock'] = False
    metadata['x_rollover_format'] = '%M min %S.%L secs for l = '

    with open('../static/data.json', 'w+') as outfile:
        outfile.write(json.dumps({'data': chart_values, 'metadata': metadata}, indent=4))
