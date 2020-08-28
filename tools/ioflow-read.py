#!/usr/bin/python
# 
# ioflow-read.py        End-to-end IO Flow Tracer for read() syscall. 
# 
# Usage: 
#    ./ioflow-read.py           # Default time threshold to 1ms. 
#    ./ioflow-read.py -t 5      # Print full data if an IO has total latency that exceeds 5ms.
#
#
# Copyright (c) Google LLC
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Aug-2020   Haoning Chen   Created this. 

from __future__ import print_function
from bcc import BPF 
import argparse

# parse arguments
examples = """examples:
    ./ioflow-read.py           # Trace read io flow. Set default time threshold to 1ms. 
    ./ioflow-read.py -t 5      # Trace read io flow. Print full data if an IO has total latency that exceeds 5ms. 
"""
parser = argparse.ArgumentParser(
    description="End-to-end IO Flow Tracer for read IOs",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--threshold", type=float, default=1.,
    help="Set the time threshold in ms. Default to be 1.0ms.")
args = parser.parse_args()

# load BPF program
bpf = BPF(src_file="ioflow-read.c")

# file system layer:
bpf.attach_kprobe(event="vfs_read", fn_name="vfs_read_entry")
bpf.attach_kprobe(event="generic_file_read_iter", fn_name="page_cache_entry")
bpf.attach_kprobe(event="__do_page_cache_readahead", fn_name="read_page_entry")
bpf.attach_kprobe(event="ext4_mpage_readpages", fn_name="ext4_read_page_entry")
# block layer:
bpf.attach_kprobe(event="generic_make_request", fn_name="block_entry")
bpf.attach_kretprobe(event="generic_make_request", fn_name="block_return")
bpf.attach_kprobe(event="bio_split", fn_name="split_entry")
bpf.attach_kretprobe(event="bio_split", fn_name="split_return")
bpf.attach_kprobe(event="bio_attempt_front_merge", fn_name="merge_entry")
bpf.attach_kretprobe(event="bio_attempt_front_merge", fn_name="merge_return")
bpf.attach_kprobe(event="bio_attempt_back_merge", fn_name="merge_entry")
bpf.attach_kretprobe(event="bio_attempt_back_merge", fn_name="merge_return")
bpf.attach_kretprobe(event="vfs_read", fn_name="vfs_read_return")


# header
print("Tracing read I/Os... Hit Ctrl-C to end and display histograms.")
print("IO time threshold: %.1fms." % args.threshold)
print("Any IO that takes time longer than this value gets emitted here (in us):\n")

print("%9s %8s %10s %11s %9s %10s %14s %14s %9s %8s %8s %5s %11s %9s %9s %5s %11s %9s %9s %5s %10s %11s %6s %10s %8s %8s %6s" % (
    "TOTAL_LAT", "VFS_LAT", "PGCACHE_TS", "PGCACHE_LAT", "READPG_TS", "READPG_LAT", "EXT4READPG_TS", "EXT4READPG_LAT", 
    "BLK_START", "BLK_LAT", "BLK_END", "COUNT", "SPLIT_START", "SPLIT_LAT", "SPLIT_END", "COUNT", "MERGE_START", 
    "MERGE_LAT", "MERGE_END", "COUNT", "REQUEST_TS", "REQUEST_LAT", "PID", "COMMAND", "OFFSET", "SIZE", "FILE"))

# process event 
def print_event(cpu, data, size):
    event = bpf["events"].event(data)

    total = float(event.total) / 1000
    if total >= (args.threshold * 1000):
        ts_pgcache = float(event.ts_pgcache - event.ts_vfs) / 1000 if event.ts_pgcache > 0 else 0.
        ts_readpg = float(event.ts_readpg - event.ts_vfs) / 1000 if event.ts_readpg > 0 else 0.
        ts_ext4readpg = float(event.ts_ext4readpg - event.ts_vfs) / 1000 if event.ts_ext4readpg > 0 else 0.
        ts_blk_start = float(event.ts_blk_start - event.ts_vfs) / 1000 if event.ts_blk_start > 0 else 0.
        ts_blk_end = float(event.ts_blk_end - event.ts_vfs) / 1000 if event.ts_blk_end > 0 else 0.
        ts_split_start = float(event.ts_split_start - event.ts_vfs) / 1000 if event.ts_split_start > 0 else 0.
        ts_split_end = float(event.ts_split_end - event.ts_vfs) / 1000 if event.ts_split_end > 0 else 0.
        ts_merge_start = float(event.ts_merge_start - event.ts_vfs) / 1000 if event.ts_merge_start > 0 else 0.
        ts_merge_end = float(event.ts_merge_end - event.ts_vfs) / 1000 if event.ts_merge_end > 0 else 0.
        ts_request = float(event.ts_request - event.ts_vfs) / 1000 if event.ts_request > 0 else 0.

        print("%9.3f %8.3f %10.3f %11.3f %9.3f %10.3f %14.3f %14.3f %9.3f %8.3f %8.3f %5s %11.3f %9.3f %9.3f %5s %11.3f %9.3f %9.3f %5s %10.3f %11.3f %6s %10s %8s %8s %6s" 
            % (total, float(event.vfs)/1000, ts_pgcache, float(event.pgcache)/1000, ts_readpg, float(event.readpg)/1000, 
            ts_ext4readpg, float(event.ext4readpg)/1000, ts_blk_start, float(event.blk)/1000, ts_blk_end, event.cnt_blk, 
            ts_split_start, float(event.split)/1000, ts_split_end, event.cnt_split, ts_merge_start, float(event.merge)/1000, 
            ts_merge_end, event.cnt_merge, ts_request, float(event.request)/1000, event.pid, event.cmd_name, event.offset, 
            event.size, event.file_name))

# loop with callback to print_event
bpf["events"].open_perf_buffer(print_event, page_cnt=128)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

print()
bpf["hist_vfs"].print_log2_hist("VFS (us)")
print()
bpf["hist_pgcache"].print_log2_hist("Page Cache Entry (us)")
print()
bpf["hist_readpg"].print_log2_hist("Read Page (us)")
print()
bpf["hist_ext4readpg"].print_log2_hist("EXT4 Read Page (us)")
print()
bpf["hist_blk"].print_log2_hist("Block Entry (us)")
print()
bpf["hist_split"].print_log2_hist("Bio Split (us)")
print()
bpf["hist_merge"].print_log2_hist("Bio Merge (us)")
print()
bpf["hist_request"].print_log2_hist("Request Handle (us)")
exit()
