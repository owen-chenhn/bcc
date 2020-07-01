#!/usr/bin/python
#
# bitehist.py	Block I/O size histogram.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of using histograms to show a distribution.
#
# A Ctrl-C will print the gathered histogram then exit.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Aug-2015	Brendan Gregg	Created this.
# 03-Feb-2019   Xiaozhou Liu    added linear histogram.

from __future__ import print_function
from bcc import BPF
from time import sleep
import os

# check "blk_account_io_completion" against /proc/kallsyms
string = os.popen('cat /proc/kallsyms | ' + 
			'grep "blk_account_io_completion"'
			).read()
if len(string.strip()) > 0: 
    event = "blk_account_io_completion"
else: 
    event = "blk_account_io_done"

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(dist_linear);
int kprobe_blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
	dist.increment(bpf_log2l(req->__data_len / 1024));
	dist_linear.increment(req->__data_len / 1024);
	return 0;
}
""")
b.attach_kprobe(event=event, fn_name='kprobe_blk_account_io_completion')

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

# output
print("log2 histogram")
print("~~~~~~~~~~~~~~")
b["dist"].print_log2_hist("kbytes")

print("\nlinear histogram")
print("~~~~~~~~~~~~~~~~")
b["dist_linear"].print_linear_hist("kbytes")
