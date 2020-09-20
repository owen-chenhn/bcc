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
    ./ioflow-syncwrite.py              # Trace sync write io flow. Default time threshold: 1ms for syscalls and 0.2ms for requests.
    ./ioflow-syncwrite.py -s 5         # Set syscall threshold to 5ms. Print syscall data if its latency exceeds 5 ms.
    ./ioflow-syncwrite.py -s 5 -r 0.5  # Set syscall threshold to 5ms and request threshold to 0.5 ms.
    Any syscall data and request data that takes time longer than the corresponding threshold is emitted. 
"""
parser = argparse.ArgumentParser(
    description="End-to-end IO Flow Tracer for sync write IOs",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-s", "--sys_thres", type=float, default=1.,
    help="Set syscall threshold in ms. Emit any syscall data that takes time longer than this threshold. Default to be 1.0")
parser.add_argument("-r", "--rq_thres", type=float, default=0.2,
    help="Set request threshold in ms. Emit any request data that takes time longer than this threshold. Default to be 0.2")
args = parser.parse_args()


# load Tracer program 
with open("ioflow-syncwrite.c") as src_f:
    bpf_text = src_f.read()
with open("ioflow-common.h") as comm_f:
    comm_text = comm_f.read()

sys_thres_flag = "-DSYSCALL_THRESHOLD=%d" % int(args.sys_thres * 1000000)
rq_thres_flag = "-DREQUEST_THRESHOLD=%d" % int(args.rq_thres * 1000000)
# load BPF program
bpf = BPF(text=bpf_text.replace("[IMPORT_COMM]", comm_text, 1), cflags=[sys_thres_flag, rq_thres_flag])

# file system layer:
bpf.attach_kprobe(event="vfs_write", fn_name="vfs_write_entry")
bpf.attach_kprobe(event="ext4_file_write_iter", fn_name="ext4_entry")
bpf.attach_kprobe(event="generic_perform_write", fn_name="write_page_entry")
bpf.attach_kprobe(event="ext4_sync_file", fn_name="ext4_sync_entry")
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
bpf.attach_kretprobe(event="vfs_write", fn_name="vfs_write_return")


# header
print("Tracing sync write I/Os. Time threshold: %.1f ms for syscalls and %.1f ms for requests. Emit data that takes time longer than its threshold." % (args.sys_thres, args.rq_thres))
print("2 types of emit output with the following formats (unit: us):\n")

print("[REQUEST] %6s %6s %9s %9s %9s %11s %12s %8s %6s\n" % 
    ("PID", "IO_NUM", "TOTAL_LAT", "CREATE_TS", "QUEUE_LAT", "SERV_LAT", "SECTOR", "LEN", "DISK"))

print("[SYSCALL] %6s %6s %9s %9s %9s %11s %12s %9s %8s %8s %5s %11s %9s %9s %5s %11s %9s %9s %5s %10s %8s %8s %6s\n" % 
    ("PID", "IO_NUM", "TOTAL_LAT", "VFS_LAT", "EXT4_LAT", "WRITEPG_LAT", "EXT4SYNC_LAT", "BLK_START", 
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

        print("[SYSCALL] %6s %6s %9.3f %9.3f %9.3f %11.3f %12.3f %9.3f %8.3f %8.3f %5s %11.3f %9.3f %9.3f %5s %11.3f %9.3f %9.3f %5s %10s %8s %8s %6s" 
            % (event.pid, event.seq_num, total, float(event.vfs)/1000, float(event.ext4)/1000, float(event.writepg)/1000, 
            float(event.ext4sync)/1000, ts_blk_start, float(event.blk)/1000, ts_blk_end, event.cnt_blk, 
            ts_split_start, float(event.split)/1000, ts_split_end, event.cnt_split, ts_merge_start, float(event.merge)/1000, 
            ts_merge_end, event.cnt_merge, event.cmd_name, event.offset, event.size, event.file_name))


# process request events
def print_rq_event(cpu, data, size):
    event = bpf["rq_events"].event(data)
    total = float(event.queue + event.service) / 1000
    if total >= (args.rq_thres * 1000):
        print("[REQUEST] %6s %6s %9.3f %9.3f %9.3f %11.3f %12s %8s %6s" % 
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
bpf["hist_rq_queue"].print_log2_hist("Request Queue (us)")
print()
bpf["hist_rq_service"].print_log2_hist("Request Service (us)")
exit()
