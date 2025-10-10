#!/usr/bin/env python
#----------------------------------------------------------------------------
# rsabench - Copyright (c) 2025, Thierry Lelegard
# BSD 2-Clause License, see LICENSE file.
# A Python module to analyze results files and produce a table.
# The main analyzes results files and produce an analysis in RESULTS.txt.
# With option --pprint, print the data structure instead of creating the file.
#----------------------------------------------------------------------------

import re, os, sys, pprint

GIGA = 1000000000.0
SEPARATOR = '   '

#
# List of CPU cores and corresponding result files.
#
RESULTS = [
    {'cpu': 'i7-8565U',    'frequency': 4.20, 'file': 'intel-i7-8565U-linux-vm.txt'},
    {'cpu': 'i7-13700H',   'frequency': 5.00, 'file': 'intel-i7-13700H-linux-vm.txt'},
    {'cpu': 'Xeon G6242R', 'frequency': 3.10, 'file': 'intel-xeon-gold-6242r-linux.txt'},
    {'cpu': 'Xeon G6348',  'frequency': 2.60, 'file': 'intel-xeon-gold-6348-linux.txt'},
    {'cpu': 'Xeon M9460',  'frequency': 3.50, 'file': 'intel-xeon-max-9460-linux.txt'},
    {'cpu': 'EPYC 7543P',  'frequency': 3.70, 'file': 'amd-epyc-7543p-linux.txt'},
    {'cpu': 'EPYC 9534',   'frequency': 3.70, 'file': 'amd-epyc-9534-linux.txt'},
    {'cpu': 'Cortex A53',  'frequency': 1.20, 'file': 'arm-rpi3-cortex-a53-linux.txt'},
    {'cpu': 'Cortex A72',  'frequency': 1.80, 'file': 'arm-rpi4-cortex-a72-linux.txt'},
    {'cpu': 'Neoverse N1', 'frequency': 3.00, 'file': 'arm-ampere-neoverse-n1-30-linux.txt'},
    {'cpu': 'Neoverse N1', 'frequency': 3.30, 'file': 'arm-ampere-neoverse-n1-33-linux.txt'},
    {'cpu': 'Neoverse V1', 'frequency': 2.60, 'file': 'arm-graviton3-neoverse-v1-linux-vm.txt'},
    {'cpu': 'Neoverse V2', 'frequency': 3.30, 'file': 'arm-grace-neoverse-v2-linux.txt'},
    {'cpu': 'Apple M1',    'frequency': 3.20, 'file': 'arm-apple-m1-macos.txt'},
    {'cpu': 'Apple M3',    'frequency': 4.00, 'file': 'arm-apple-m3-macos.txt'},
    {'cpu': 'Apple M4',    'frequency': 4.40, 'file': 'arm-apple-m4-macos.txt'}
]

#
# Column headers.
#
HEADERS = {'cpu': 'CPU core', 'freq': 'Frequency', 'openssl': 'OpenSSL'}

#
# With asymmetric crypto, we count the number of "operations" (encrypt, decrypt, sign,
# verify) per second. The input data size is not important because the input data are
# always padded to th ekey size. Because the load can be heavy, we count the number of
# operations per REF_SECONDS and per REF_CYCLES.
#
REF_SECONDS = 1
REF_CYCLES  = 1000000

#
# Names of cryptographic operations, names of values to display.
#
OP_NAMES    = ['oaep-encrypt', 'oaep-decrypt', 'pss-sign', 'pss-verify']
VALUE_NAMES = ['oprate', 'opcycle']

##
# Format a float for display.
#
# @param [in] value An integer or float value.
# @return Formatted string.
#
def format_num(value):
    if value == int(value) or value >= 100.0:
        return '{:,}'.format(int(value))
    elif value >= 10.0:
        return '%.1f' % value
    elif value >= 1.0:
        return '%.2f' % value
    else:
        return '%.3f' % value

##
# Load and analyze a "results" structure.
#
# A "results" structure is a list of dictionaries. Each dictionary describes one test.
# In a test dictionary, the two mandatory fields are 'frequency' (in GHz) and 'file'
# (containing the output of aesbench).
#
# @param [in,out] results List of results. Each result is updated with data from the file.
# @param [in] input_dir Base directory for input file names. All file names are updated.
# @return A list of algorithm names.
#
def load_results(results, input_dir):
    algos = []
    index = 0

    # Load all files.
    while index < len(results):
        res = results[index]
        if not os.path.isabs(res['file']):
            res['file'] = os.path.abspath(input_dir + os.path.sep + res['file'])
        if not os.path.exists(res['file']):
            del results[index]
            continue
        res['freq'] = '%.2f GHz' % (res['frequency'])
        if not 'openssl' in res:
            res['openssl'] = ''
        res['data'] = {}
        res['index'] = index
        index += 1
        with open(res['file'], 'r') as input:
            algo = None
            for line in input:
                line = [field.strip() for field in line.split(':')]
                if len(line) >= 2:
                    subop = [field.strip() for field in line[0].split('-')]
                    op = '-'.join(subop[:-1])
                    value = subop[-1]
                    if line[0] == 'algo':
                        algo = line[1]
                        if algo not in algos:
                            algos += [algo]
                        res['data'][algo] = dict()
                        for op in OP_NAMES:
                            res['data'][algo][op] = dict()
                            for value in VALUE_NAMES:
                                res['data'][algo][op][value] = {'value': 0.0, 'string': '', 'rank': 0}
                    elif line[0] == 'openssl' and not res['openssl']:
                        match = re.search(r'([0-9\.]+[a-zA-Z]*)', line[1])
                        if match is not None:
                            res['openssl'] = match.group(1)
                    elif value == 'microsec' and algo is not None:
                        microsec = float(line[1])
                    elif value == 'count' and algo is not None:
                        count = float(line[1])                        
                        oprate = (REF_SECONDS * GIGA * count) / microsec
                        opcycle = (REF_CYCLES * count) / (microsec * res['frequency'])
                        data = res['data'][algo][op]
                        data['oprate']['value'] = oprate
                        data['oprate']['string'] = format_num(oprate)
                        data['opcycle']['value'] = opcycle
                        data['opcycle']['string'] = format_num(opcycle)

    # Build rankings for each operation.
    for algo in algos:
        for op in OP_NAMES:
            for value in VALUE_NAMES:
                dlist = [(res['index'], res['data'][algo][op][value]['value']) for res in results]
                dlist.sort(key=lambda x: x[1], reverse=True)
                for rank in range(len(dlist)):
                    res = next(r for r in results if r['index'] == dlist[rank][0])
                    res['data'][algo][op][value]['rank'] = rank + 1
    for res in results:
        res['width'] = 0
        res['ranks'] = dict()
        for value in VALUE_NAMES:
            res['ranks'][value] = {'min': 1000, 'max': 0}
        for algo in algos:
            for op in OP_NAMES:
                for value in VALUE_NAMES:
                    data = res['data'][algo][op][value]
                    res['ranks'][value]['min'] = min(res['ranks'][value]['min'], data['rank'])
                    res['ranks'][value]['max'] = max(res['ranks'][value]['max'], data['rank'])
        for algo in algos:
            for op in OP_NAMES:
                for value in VALUE_NAMES:
                    data = res['data'][algo][op][value]
                    space = ' '
                    if res['ranks'][value]['min'] < 10 and res['ranks'][value]['max'] >= 10 and data['rank'] < 10:
                        space = '  '
                    data['string'] += '%s(%d)' % (space, data['rank'])
                    res['width'] = max(res['width'], len(data['string']))

    # End of analysis, return the list of algos.
    return algos

##
# Generate a text table of results.
#
# @param [in] results Table results.
# @param [in] algos List of algorithms to display.
# @param [in] headers List of headers, by key from result.
# @param [in] value_name Key of result to display, typically from VALUE_NAMES.
# @param [in] file Output file handler.
# @param [in] colsep Separator between columns.
#
def display_one_table(results, algos, headers, value_name, file, colsep=SEPARATOR):
    # Max width of first column.
    wops = max([len(op) for op in OP_NAMES])
    w0 = max(max([len(s) for s in headers.values()]), max([len(s) for s in algos]) + wops + 1)
    # Max line of each column, depending on headers.
    for res in results:
        res['_width'] = max(res['width'], max([len(res[k]) for k in headers.keys()]))
    # Output headers lines.
    for k in headers.keys():
        line = headers[k].ljust(w0)
        for res in results:
            line += colsep + res[k].rjust(res['_width'])
        print(line.rstrip(), file=file)
    line = w0 * '-'
    for res in results:
        line += colsep + (res['_width'] * '-')
    print(line.rstrip(), file=file)
    # Output one line per operation.
    for algo in algos:
        for op in OP_NAMES:
            line = (algo + ' ' + op).ljust(w0)
            for res in results:
                if algo in res['data'] and op in res['data'][algo]:
                    line += colsep + res['data'][algo][op][value_name]['string'].rjust(res['_width'])
                else:
                    line += colsep + res['_width'] * ' '
            print(line.rstrip(), file=file)

##
# Generate the final text file.
#
# @param [in] results Table results.
# @param [in] algos List of algorithms to display.
# @param [in] headers List of headers, by key from result.
# @param [in] file Output file handler.
# @param [in] colsep Separator between columns.
#
def display_tables(results, algos, headers, file, colsep=SEPARATOR):
    unit = 'SECOND' if REF_SECONDS == 1 else '%d SECONDS' % REF_SECONDS
    print('CRYPTOGRAPHIC OPERATIONS PER %s' % unit, file=file)
    print('', file=file)
    display_one_table(results, algos, headers, 'oprate', file, colsep)
    print('', file=file)
    unit = 'PROCESSOR CYCLE' if REF_CYCLES == 1 else '%d PROCESSOR CYCLES' % REF_CYCLES
    print('CRYPTOGRAPHIC OPERATIONS PER %s' % unit, file=file)
    print('', file=file)
    display_one_table(results, algos, headers, 'opcycle', file, colsep)

#
# Main code.
#
if __name__ == '__main__':
    dir = os.path.dirname(os.path.abspath(__file__))
    algos = load_results(RESULTS, dir + '/results')
    if '--pprint' in sys.argv:
        pprint.pprint(RESULTS, width=132)
    else:
        with open(dir + '/RESULTS.txt', 'w') as output:
            display_tables(RESULTS, algos, HEADERS, output)
