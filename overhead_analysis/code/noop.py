#!/usr/bin/python
#
# This script is used for performance overhead analysis tests of eBPF. 
# It essentially load an empty eBPF program to the kernel. 
#
# Copyright (c) Google LLC
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Jun-2020   Haoning Chen   Created this. 

from __future__ import print_function
from time import sleep
from bcc import BPF

# BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

int trace_rq_creation(struct pt_regs *ctx, struct request *req) {
	return 0;
}

int trace_rq_start(struct pt_regs *ctx, struct request *req) {
	return 0;
}

int trace_rq_completion(struct pt_regs *ctx, struct request *req) {
	return 0;
}
"""

bpf = BPF(text=bpf_text)

bpf.attach_kprobe(event="blk_account_io_start", fn_name="trace_rq_creation")
if BPF.get_kprobe_functions(b'blk_start_request'):
	bpf.attach_kprobe(event="blk_start_request", fn_name="trace_rq_start")
bpf.attach_kprobe(event="blk_mq_start_request", fn_name="trace_rq_start")
bpf.attach_kprobe(event="blk_account_io_done", fn_name="trace_rq_completion")


# header
print("Tracing I/O requests... Hit Ctrl-C to end.")

# trace until keyboard interrupt
try:
	sleep(99999999)
except KeyboardInterrupt:
	print("BCC script finished.")

# output
exit() 
