#!/usr/bin/python
# 
# ioflow-syncwrite.py        End-to-end IO Flow Tracer for synchronous write() syscall. 
#
#
# Copyright (c) Google LLC
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-Aug-2020   Haoning Chen   Created this. 

from __future__ import print_function
from bcc import BPF 
import argparse

# parse arguments
examples = """examples:
    ./ioflow-syncwrite.py           # Trace sync write io flow. Set default time threshold to 1ms. 
    ./ioflow-syncwrite.py -t 5      # Trace sync write io flow. Print full data if an IO has total latency that exceeds 5ms. 
"""
parser = argparse.ArgumentParser(
    description="End-to-end IO Flow Tracer for sync write IOs",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--threshold", type=float, default=1.,
    help="Set the time threshold in ms. Default to be 1.0ms.")
args = parser.parse_args()

# load BPF program
bpf = BPF(src_file="ioflow-syncwrite.c")

# file system layer:
bpf.attach_kprobe(event="vfs_write", fn_name="vfs_write_entry")
bpf.attach_kprobe(event="ext4_file_write_iter", fn_name="ext4_entry")
bpf.attach_kprobe(event="generic_perform_write", fn_name="write_page_entry")
bpf.attach_kprobe(event="ext4_sync_file", fn_name="ext4_sync_entry")
# block layer:
bpf.attach_kprobe(event="generic_make_request", fn_name="block_entry")
bpf.attach_kretprobe(event="generic_make_request", fn_name="block_return")
bpf.attach_kprobe(event="bio_split", fn_name="split_entry")
bpf.attach_kretprobe(event="bio_split", fn_name="split_return")
bpf.attach_kprobe(event="bio_attempt_front_merge", fn_name="merge_entry")
bpf.attach_kretprobe(event="bio_attempt_front_merge", fn_name="merge_return")
bpf.attach_kprobe(event="bio_attempt_back_merge", fn_name="merge_entry")
bpf.attach_kretprobe(event="bio_attempt_back_merge", fn_name="merge_return")
bpf.attach_kretprobe(event="vfs_write", fn_name="vfs_write_return")


# header
print("Tracing sync write I/Os... Hit Ctrl-C to end and display histograms.")
print("IO time threshold: %.1fms." % args.threshold)
print("Any IO that takes time longer than this value gets emitted here (in us):\n")

print("%9s %8s %8s %8s %10s %11s %12s %12s %9s %8s %8s %5s %11s %9s %9s %5s %11s %9s %9s %5s %10s %11s %6s %10s %8s %8s %6s" % (
    "TOTAL_LAT", "VFS_LAT", "EXT4_TS", "EXT4_LAT", "WRITEPG_TS", "WRITEPG_LAT", "EXT4SYNC_TS", "EXT4SYNC_LAT", 
    "BLK_START", "BLK_LAT", "BLK_END", "COUNT", "SPLIT_START", "SPLIT_LAT", "SPLIT_END", "COUNT", "MERGE_START", 
    "MERGE_LAT", "MERGE_END", "COUNT", "REQUEST_TS", "REQUEST_LAT", "PID", "COMMAND", "OFFSET", "SIZE", "FILE"))

# process event 
def print_event(cpu, data, size):
    event = bpf["events"].event(data)

    total = float(event.total) / 1000
    if total >= (args.threshold * 1000):
        ts_ext4 = float(event.ts_ext4 - event.ts_vfs) / 1000 
        ts_writepg = float(event.ts_writepg - event.ts_vfs) / 1000
        ts_ext4sync = float(event.ts_ext4sync - event.ts_vfs) / 1000 if event.ts_ext4sync > 0 else 0.
        ts_blk_start = float(event.ts_blk_start - event.ts_vfs) / 1000 if event.ts_blk_start > 0 else 0.
        ts_blk_end = float(event.ts_blk_end - event.ts_vfs) / 1000 if event.ts_blk_end > 0 else 0.
        ts_split_start = float(event.ts_split_start - event.ts_vfs) / 1000 if event.ts_split_start > 0 else 0.
        ts_split_end = float(event.ts_split_end - event.ts_vfs) / 1000 if event.ts_split_end > 0 else 0.
        ts_merge_start = float(event.ts_merge_start - event.ts_vfs) / 1000 if event.ts_merge_start > 0 else 0.
        ts_merge_end = float(event.ts_merge_end - event.ts_vfs) / 1000 if event.ts_merge_end > 0 else 0.
        ts_request = float(event.ts_request - event.ts_vfs) / 1000 if event.ts_request > 0 else 0.

        print("%9.3f %8.3f %8.3f %8.3f %10.3f %11.3f %12.3f %12.3f %9.3f %8.3f %8.3f %5s %11.3f %9.3f %9.3f %5s %11.3f %9.3f %9.3f %5s %10.3f %11.3f %6s %10s %8s %8s %6s" 
            % (total, float(event.vfs)/1000, ts_ext4, float(event.ext4)/1000, ts_writepg, float(event.writepg)/1000, 
            ts_ext4sync, float(event.ext4sync)/1000, ts_blk_start, float(event.blk)/1000, ts_blk_end, event.cnt_blk, 
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
bpf["hist_ext4"].print_log2_hist("EXT4 (us)")
print()
bpf["hist_writepg"].print_log2_hist("Write Page (us)")
print()
bpf["hist_ext4sync"].print_log2_hist("EXT4 Sync (us)")
print()
bpf["hist_blk"].print_log2_hist("Block Entry (us)")
print()
bpf["hist_split"].print_log2_hist("Bio Split (us)")
print()
bpf["hist_merge"].print_log2_hist("Bio Merge (us)")
print()
bpf["hist_request"].print_log2_hist("Request Handle (us)")
exit()
