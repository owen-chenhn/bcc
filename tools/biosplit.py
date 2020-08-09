#!/usr/bin/python
# 
# biosplit.py      description here ...
#                  next line ...
# 
# Usage: 
#
#
# Copyright (c) Google LLC
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Aug-2020   Haoning Chen   Created this. 
# 09-Aug-2020   Haoning Chen   Seperated the eBPF C code to a single .c file.

from __future__ import print_function
from bcc import BPF 
import sys 

# load BPF program
bpf = BPF(src_file="splitmerge.c")

bpf.attach_kprobe(event="bio_split", fn_name="split_entry") 
bpf.attach_kretprobe(event="bio_split", fn_name="split_return") 


# header
print("%-11s %-14s %-7s %-1s %10s %10s %10s %10s %7s" % (
	"TIME(s)", "COMM", "DISK", "T", "IN-SECTOR", "IN-BYTES", "OUT-SECTOR", "OUT-BYTES", "LATENCY(us)")) 

start_ts = 0

# process event 
def print_event(cpu, data, size): 
	event = bpf["events"].event(data)

	global start_ts 
	if start_ts == 0: 
		start_ts = event.ts 
	ts = float(event.ts - start_ts) / 1000000000    # in sec
	lat = float(event.lat) / 1000		# in usec
	rwflag = 'W' if event.rwflag == 1 else 'R'

	print("%-11.4f %-14.14s %-7s %-1s %10s %10s %10s %10s %7.2f" % (
		ts, event.cmd_name, event.disk_name, rwflag,  
		event.in_sector, event.in_len, event.out_sector, event.out_len, 
		lat))


# loop with callback to print_event
bpf["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
	try:
		bpf.perf_buffer_poll()
	except KeyboardInterrupt:
		exit()
