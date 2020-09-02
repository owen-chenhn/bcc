#!/usr/bin/python
# 
# biosplitmerge.py      Block layer tracer that traces bio struct's 
#                       split and merge. Whenever a split/merge event
#                       happens, the full data of the event is emitted.
# 
# Usage: 
# Trace both split and merge event:  ./biosplitmerge.py
# Trace split events only:           ./biosplitmerge.py -S
# Trace merge events only:           ./biosplitmerge.py -M
#
#
# Copyright (c) Google LLC
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Aug-2020   Haoning Chen   Created this. 
# 09-Aug-2020   Haoning Chen   Seperated the eBPF C code to a single .c file.

from __future__ import print_function
from bcc import BPF 
import argparse

# parse arguments
examples = """examples:
    ./biosplitmerge.py       # trace both split and merge events
    ./biosplitmerge.py -S    # trace split events
    ./biosplitmerge.py -M    # trace merge events
"""
parser = argparse.ArgumentParser(
	description="Bio split/merge event tracer",
	formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog=examples)
parser.add_argument("-S", "--split", action="store_true",
	help="trace split events")
parser.add_argument("-M", "--merge", action="store_true",
	help="trace merge events")
args = parser.parse_args()


# load BPF program
bpf = BPF(src_file="biosplitmerge.c")

if args.split or not args.merge:
	bpf.attach_kprobe(event="bio_split", fn_name="split_entry") 
	bpf.attach_kretprobe(event="bio_split", fn_name="split_return") 

if args.merge or not args.split:
	bpf.attach_kprobe(event="bio_attempt_front_merge", fn_name="front_merge_entry")
	bpf.attach_kprobe(event="bio_attempt_back_merge", fn_name="back_merge_entry")
	bpf.attach_kprobe(event="bio_attempt_discard_merge", fn_name="discard_merge_entry")

	bpf.attach_kretprobe(event="bio_attempt_front_merge", fn_name="merge_return")
	bpf.attach_kretprobe(event="bio_attempt_back_merge", fn_name="merge_return")
	bpf.attach_kretprobe(event="bio_attempt_discard_merge", fn_name="merge_return")


# header
print("%-11s %-13s %-14s %-6s %-7s %-1s %10s %10s %10s %10s" % (
	"TIME(s)", "EVENT", "COMMAND", "PID", "DISK", "T", "IN-SECTOR", 
	"IN-BYTES", "OUT-SECTOR", "OUT-BYTES"))

start_ts = 0
type_map = {
	0: "Split",
	1: "Front Merge",
	2: "Back Merge",
	3: "Discard Merge"
}

# process event 
def print_event(cpu, data, size): 
	event = bpf["events"].event(data)

	global start_ts 
	if start_ts == 0: 
		start_ts = event.ts 
	ts = float(event.ts - start_ts) / 1000000000    # in sec
	rwflag = 'W' if event.rwflag == 1 else 'R'
	event_type = type_map[event.type]

	print("%-11.4f %-13s %-14.14s %-6s %-7s %-1s %10s %10s %10s %10s" % (
		ts, event_type, event.cmd_name, event.pid, event.disk_name, rwflag,  
		event.in_sector, event.in_len, event.out_sector, event.out_len))

# loop with callback to print_event
bpf["events"].open_perf_buffer(print_event, page_cnt=128)
while True:
	try:
		bpf.perf_buffer_poll()
	except KeyboardInterrupt:
		exit()
