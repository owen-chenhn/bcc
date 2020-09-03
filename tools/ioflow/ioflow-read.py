#!/usr/bin/python
# 
# ioflow-read.py        End-to-end IO Flow Tracer for read() syscall. 
# 
# Usage: 
#    ./ioflow-read.py           # Default time threshold: 1ms for syscalls and 0.2ms for requests. 
#    ./ioflow-read.py -t 5      # Print data if syscall latency exceeds 5ms or request latency exceeds 0.2ms.
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
    ./ioflow-read.py              # Trace read io flow. Default time threshold: 1ms for syscalls and 0.2ms for requests.
    ./ioflow-read.py -s 5         # Set syscall threshold to 5ms. Print syscall data if its latency exceeds 5 ms.
    ./ioflow-read.py -s 5 -r 0.5  # Set syscall threshold to 5ms and request threshold to 0.5 ms.
"""
parser = argparse.ArgumentParser(
    description="End-to-end IO Flow Tracer for read IOs",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-s", "--sys_thres", type=float, default=1.,
    help="Set syscall threshold in ms. Default to be 1.0")
parser.add_argument("-r", "--rq_thres", type=float, default=0.2,
    help="Set request threshold in ms. Default to be 0.2")
args = parser.parse_args()


# load Tracer program 
with open("ioflow-read.c") as src_f:
    bpf_text = src_f.read()
with open("ioflow-common.h") as comm_f:
    comm_text = comm_f.read()

# load BPF program
bpf = BPF(text=bpf_text.replace("[IMPORT_COMM]", comm_text, 1))

# file system layer:
bpf.attach_kprobe(event="vfs_read", fn_name="vfs_read_entry")
bpf.attach_kprobe(event="generic_file_read_iter", fn_name="page_cache_entry")
bpf.attach_kprobe(event="__do_page_cache_readahead", fn_name="read_page_entry")
bpf.attach_kprobe(event="ext4_mpage_readpages", fn_name="ext4_read_page_entry")
# block layer:
bpf.attach_kprobe(event="submit_bio", fn_name="block_entry")
bpf.attach_kretprobe(event="submit_bio", fn_name="block_return")
bpf.attach_kprobe(event="bio_split", fn_name="split_entry")
bpf.attach_kretprobe(event="bio_split", fn_name="split_return")
bpf.attach_kprobe(event="bio_attempt_front_merge", fn_name="merge_entry")
bpf.attach_kretprobe(event="bio_attempt_front_merge", fn_name="merge_return")
bpf.attach_kprobe(event="bio_attempt_back_merge", fn_name="merge_entry")
bpf.attach_kretprobe(event="bio_attempt_back_merge", fn_name="merge_return")
# async request handling:
bpf.attach_kprobe(event="blk_account_io_start", fn_name="rq_create")
if BPF.get_kprobe_functions(b'blk_start_request'):
	bpf.attach_kprobe(event="blk_start_request", fn_name="rq_issue")
bpf.attach_kprobe(event="blk_mq_start_request", fn_name="rq_issue")
bpf.attach_kprobe(event="blk_account_io_done", fn_name="rq_done")
# end of IO:
bpf.attach_kretprobe(event="vfs_read", fn_name="vfs_read_return")


# header
print("Tracing read I/Os. Time threshold: %.1f ms for syscalls and %.1f ms for requests. " % (args.sys_thres, args.rq_thres))
print("2 types of emit output with the following formats:\n")

print("[REQUEST] %6s %6s %9s %9s %11s %10s %14s %8s %6s\n" % 
    ("PID", "IO_NUM", "TOTAL_LAT", "CREATE_TS", "QUEUE_LAT", "SERV_LAT", "SECTOR", "LEN", "DISK"))

print("[SYSCALL] %6s %6s %9s %9s %11s %10s %14s %9s %8s %8s %5s %11s %9s %9s %5s %11s %9s %9s %5s %10s %8s %8s %6s\n" % 
    ("PID", "IO_NUM", "TOTAL_LAT", "VFS_LAT", "PGCACHE_LAT", "READPG_LAT", "EXT4READPG_LAT", "BLK_START", 
    "BLK_LAT", "BLK_END", "COUNT", "SPLIT_START", "SPLIT_LAT", "SPLIT_END", "COUNT", "MERGE_START", 
    "MERGE_LAT", "MERGE_END", "COUNT", "COMMAND", "OFFSET", "SIZE", "FILE"))

print("Hit Ctrl-C to end and display histograms.\n")


# process syscall events
def print_syscall_event(cpu, data, size):
    event = bpf["syscall_events"].event(data)
    total = float(event.total) / 1000
    if total >= (args.sys_thres * 1000):
        ts_blk_start = float(event.ts_blk_start - event.ts_vfs) / 1000 if event.ts_blk_start > 0 else 0.
        ts_blk_end = float(event.ts_blk_end - event.ts_vfs) / 1000 if event.ts_blk_end > 0 else 0.
        ts_split_start = float(event.ts_split_start - event.ts_vfs) / 1000 if event.ts_split_start > 0 else 0.
        ts_split_end = float(event.ts_split_end - event.ts_vfs) / 1000 if event.ts_split_end > 0 else 0.
        ts_merge_start = float(event.ts_merge_start - event.ts_vfs) / 1000 if event.ts_merge_start > 0 else 0.
        ts_merge_end = float(event.ts_merge_end - event.ts_vfs) / 1000 if event.ts_merge_end > 0 else 0.

        print("[SYSCALL] %6s %6s %9.3f %9.3f %11.3f %10.3f %14.3f %9.3f %8.3f %8.3f %5s %11.3f %9.3f %9.3f %5s %11.3f %9.3f %9.3f %5s %10s %8s %8s %6s" 
            % (event.pid, event.seq_num, total, float(event.vfs)/1000, float(event.pgcache)/1000, float(event.readpg)/1000, 
            float(event.ext4readpg)/1000, ts_blk_start, float(event.blk)/1000, ts_blk_end, event.cnt_blk, 
            ts_split_start, float(event.split)/1000, ts_split_end, event.cnt_split, ts_merge_start, float(event.merge)/1000, 
            ts_merge_end, event.cnt_merge, event.cmd_name, event.offset, event.size, event.file_name))


# process request events
def print_rq_event(cpu, data, size):
    event = bpf["rq_events"].event(data)
    total = float(event.queue + event.service) / 1000
    if total >= (args.rq_thres * 1000):
        print("[REQUEST] %6s %6s %9.3f %9.3f %11.3f %10.3f %14s %8s %6s" % 
            (event.pid, event.seq_num, total, float(event.ts_create)/1000, float(event.queue)/1000, 
            float(event.service)/1000, event.sector, event.len, event.disk_name))


# loop with callback to print_event
bpf["syscall_events"].open_perf_buffer(print_syscall_event, page_cnt=64)
bpf["rq_events"].open_perf_buffer(print_rq_event, page_cnt=128)
while True:
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
bpf["hist_rq_queue"].print_log2_hist("Request Queue (us)")
print()
bpf["hist_rq_service"].print_log2_hist("Request Service (us)")
exit()
