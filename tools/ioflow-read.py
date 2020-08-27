#!/usr/bin/python
# 
# ioflow-.py        End-to-end IO Flow Tracer for read() syscall. 
# 
# Usage: 
# 
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

print("%8s %8s %10s %9s %14s %8s %5s %8s %5s %8s %5s %14s %6s %10s %8s %8s %6s" % (
    "TOTAL", "VFS", "PAGE_CACHE", "READ_PAGE", "EXT4_READ_PAGE", "BLOCK", "COUNT", "SPLIT", 
    "COUNT", "MERGE", "COUNT", "REQUEST_HANDLE", "PID", "COMM", "OFFSET", "SIZE", "FILE"))

# process event 
def print_event(cpu, data, size):
    event = bpf["events"].event(data)

    total = float(event.total) / 1000
    if total >= (args.threshold * 1000):
        print("%8.2f %8.2f %10.2f %9.2f %14.2f %8.2f %5s %8.2f %5s %8.2f %5s %14.2f %6s %10s %8s %8s %10s" 
            % (total, float(event.vfs)/1000, float(event.pgcache)/1000, float(event.readpg)/1000, 
            float(event.ext4readpg)/1000, float(event.blk)/1000, event.cnt_blk, float(event.split)/1000, 
            event.cnt_split, float(event.merge)/1000, event.cnt_merge, float(event.request)/1000, 
            event.pid, event.cmd_name, event.offset, event.size, event.file_name))

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
