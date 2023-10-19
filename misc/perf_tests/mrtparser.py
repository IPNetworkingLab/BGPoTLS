#!/usr/bin/env python3

import csv
import gzip
import os
import typing
from argparse import ArgumentParser
from pathlib import Path
from typing import Union, TextIO

import mrtparse
from ipaddress import ip_network, IPv4Network, IPv6Network, ip_address, IPv4Address, IPv6Address

import numpy as np
from matplotlib import pyplot as plt
from tqdm import tqdm
from mrtparse import MRT_T, BGP4MP_ST, BGP_MSG_T, BGP_ATTR_T


# import matplotlib

# matplotlib.rcParams['pdf.fonttype'] = 42
# matplotlib.rcParams['ps.fonttype'] = 42

# plt.rcParams.update({
#    "text.usetex": True,
#    "font.family": "serif",
#    "font.serif": ["Palatino"],
# })


def s2us(seconds: int):
    return seconds * 1e+6


def us2ms(microseconds: int) -> float:
    return microseconds / 1000


class Stats:
    def __init__(self) -> None:
        self.pfx_seen: dict[Union[IPv4Network, IPv6Network], list[
            tuple[Union[
                str, IPv4Address, IPv6Address], float]]] = {}  # dict key: pfx. value: list[src BGP speaker, timestamp]
        self.start_eor = -1
        self.errors = 0


def parse_nrli(data) -> list[IPv4Network | IPv6Network]:
    pfxs = []
    for nrli in data['nlri']:
        pfxs.append(ip_network(f"{nrli['prefix']}/{nrli['length']}"))

    return pfxs


def parse_mp_reach(data) -> list[IPv4Network | IPv6Network]:
    mp_reach = data['value']
    return parse_nrli(mp_reach)


def parse_bgp_message(data):
    if BGP_MSG_T['UPDATE'] not in data['type']:
        return None

    mp_reach = [attr for attr in data['path_attributes'] if BGP_ATTR_T['MP_REACH_NLRI'] in attr['type']]
    assert len(mp_reach) <= 1, "Wow! Several MP_REACH attr found in BGP Update"

    if any(mp_reach):
        prefixes = parse_mp_reach(mp_reach[0])
    else:
        prefixes = parse_nrli(data)

    return prefixes if len(prefixes) > 0 else None


def parse_BGP4MP(data, stats):
    if (BGP4MP_ST['BGP4MP_MESSAGE'] not in data['subtype'] and
            BGP4MP_ST['BGP4MP_MESSAGE_AS4'] not in data['subtype'] and
            BGP4MP_ST['BGP4MP_MESSAGE_LOCAL'] not in data['subtype'] and
            BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL'] not in data['subtype']):
        return False
    pfxs = parse_bgp_message(data['bgp_message'])
    if pfxs is None:
        return False

    for prefix in pfxs:
        timestamp = s2us(list(data['timestamp'].keys())[0]) + \
                    (data['microsecond_timestamp'] if 'microsecond_timestamp' in data else 0)
        new_entry = (ip_address(data['peer_ip']), us2ms(timestamp))

        assert 0 <= data['microsecond_timestamp'] < 1000000

        try:
            stats.pfx_seen[prefix].append(new_entry)
        except KeyError:
            stats.pfx_seen[prefix] = [new_entry]


def plot_cdf(times: typing.Iterable, legend: str):
    count1, b_count1 = np.histogram(times, bins=200000)
    pdf1 = count1 / sum(count1)
    cdf1 = np.cumsum(pdf1)
    plt.plot(b_count1[1:], cdf1, label=legend)


def plot_show(x_legend: str, save: Union[str | None]):
    plt.ylabel('CDF')
    plt.xlabel(x_legend)
    plt.legend()
    plt.grid()
    plt.tight_layout()
    if save is not None:
        plt.savefig(save)
        return
    plt.show()


def store_results(data: dict, out_file_path: str):
    with gzip.open(out_file_path, 'wt', newline='') as csvfile:
        fieldnames = ['prefix', 'peer_ip', 'time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for pfx, times in data.items():
            for peer_ip, time in times:
                writer.writerow({'prefix': str(pfx),
                                 'peer_ip': str(peer_ip),
                                 'time': float(time)})


def yield_times(stats: Stats):
    for pfx, times in stats.pfx_seen.items():
        if len(times) >= 2:
            latest = times[-1][1]
            for _, time in times[:-1]:
                yield latest - time


def parse_mrt_dump(mrt_path: str, legend: str, out_store: Union[None, Path] = None):
    stats = Stats()
    tot_length = os.stat(mrt_path).st_size

    with tqdm.wrapattr(open(mrt_path, 'rb'), "read", total=tot_length) as mrt_file:
        rdr = mrtparse.Reader(mrt_file)

        for entry in rdr:
            if entry.err:
                stats.errors += 1
            elif (MRT_T['BGP4MP'] not in entry.data['type'] and
                  MRT_T['BGP4MP_ET'] not in entry.data['type']):
                pass
            else:
                parse_BGP4MP(entry.data, stats)

    print(f"Parsing done: {stats.errors} error(s).\n"
          f"Prefixes seen: {len(stats.pfx_seen)}.")

    if out_store:
        print("storing_results...")
        store_results(stats.pfx_seen, str(out_store))
    # print("Plotting results...")

    # [times[-1][1] - times[0][1] for pfx, times in stats.pfx_seen.items() if len(times) >= 2]
    # plot_cdf(list(yield_times(stats)), legend=legend)
    plot_cdf([times[-1][1] - times[0][1] for pfx, times in stats.pfx_seen.items() if len(times) == 2], legend=legend)


def split_input(entry: str):
    splitted = entry.split(',')
    if len(splitted) != 2:
        raise ValueError("Bad input format. Usage: -i <mrt_file_path>,<legend> "
                         "or -c <csv_file_path>,<legend>.")

    return splitted


def read_csv_file(stats: Stats, reader_io: TextIO):
    fieldnames = ['prefix', 'peer_ip', 'time']
    reader = csv.DictReader(reader_io, fieldnames=fieldnames)
    next(reader)  # skip csv header
    for row in reader:
        prefix = row['prefix']
        peer_ip = row['peer_ip']
        time_us = float(row['time'])

        new_entry = (peer_ip, time_us)
        try:
            stats.pfx_seen[prefix].append(new_entry)
        except KeyError:
            stats.pfx_seen[prefix] = [new_entry]


def parse_csv_file(file_path: str, legend: str):
    stats = Stats()

    try:
        with gzip.open(file_path, 'rt', newline='') as csvfile:
            read_csv_file(stats, csvfile)
    except gzip.BadGzipFile:
        print("[WARN] Not gzip compressed, trying plain csv...")
        with open(file_path, 'r', newline='') as csvfile:
            read_csv_file(stats, csvfile)

    plot_cdf(list(yield_times(stats)), legend=legend)


def get_file_stem(full_path: str):
    return Path(full_path).stem


def main(args):
    out_dir = None
    if args.output:
        out_dir = Path(args.output)
        if not out_dir.is_dir():
            raise NotADirectoryError(f"{out_dir}")

    if args.csvs:
        for record in args.csvs:
            csv_file, legend = split_input(record)
            print(f"Parsing {csv_file} ({legend})")
            parse_csv_file(csv_file, legend)

    if args.inputs:
        for record in args.inputs:
            mrt_file, legend = split_input(record)
            print(f"Parsing {mrt_file} ({legend})")
            dest_file = out_dir.joinpath(f"{get_file_stem(mrt_file)}.csv.gz") if out_dir else None
            parse_mrt_dump(mrt_file, legend, dest_file)

    plot_show("Prefix Latency (ms)", args.save)


if __name__ == '__main__':
    parser = ArgumentParser(description="Plot the prefix latency from one or several MRT dump files")

    parser.add_argument('-i', '--input', dest='inputs', required=False, action='append',
                        help='The MRT files to process. The format of the argument must be '
                             '<mrt_file_path>,<legend>. <mrt_file_path> is the path to the MRT dump. '
                             '<legend> is the description that will be added to the graph')
    parser.add_argument('-o', '--output', dest='output', required=False, type=str,
                        help='Store parsed MRT files in the directory passed to this parameter. '
                             'By default it compress data in .gz')
    parser.add_argument('-c', '--csv', dest='csvs', required=False, action='append',
                        help='Use this CSV (or csv.gz compressed) file instead of parsing MRT file. The '
                             'format is the same as -i argument. <csv_file_path>,<legend>. <csv_file_path> '
                             'is the csv file (or .gz compressed file). <legend> is the description that will '
                             'be added to the graph.')
    parser.add_argument('-s', '--save', dest='save', required=False, type=str, default=None,
                        help="Store the generated graph in the file specified in this argument. "
                             "This command implies no interactive GUI.")
    __args = parser.parse_args()
    main(__args)
