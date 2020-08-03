#!/usr/bin/python
# 
# blkrqhist.py		Instrument two time periods of block layer's I/O requests: queuing time and  
#			service time. One histograme is generated for each. Here queuing time is defined 
#			as the time of an I/O request being queued in kernel, and service time is the 
#			duration the I/O request being handled by device drivers, up to its completion. 
# 
# 
# Usage: 
# To run with Kprobe implementation (by default):	./blkrqhist.py
# With Raw tracepoint implementation: 			./blkrqhist.py T 
#
#
# Copyright (c) Google LLC
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Jun-2020   Haoning Chen   Created this. 
# 03-Aug-2020   Haoning Chen   Added raw tracepoint implementation. 

from __future__ import print_function
from time import sleep
from bcc import BPF 
import sys 

# BPF program
bpf_text_head = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(creation, struct request *);
BPF_HASH(start, struct request *);
BPF_HISTOGRAM(que_hist);
BPF_HISTOGRAM(serv_hist);

static int rq_insert(struct request *req) {
	// stash creation timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();
	creation.update(&req, &ts);
	return 0;
}

static int rq_issue(struct request *req) {
	// stash start timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();
	start.update(&req, &ts);
	return 0;
}

static int rq_complete(struct request *req) {
	u64 *create_tsp, *start_tsp, que_delta, serv_delta;
	create_tsp = creation.lookup(&req);
	start_tsp  = start.lookup(&req);
	if (create_tsp != NULL && start_tsp != NULL) {
		que_delta = *start_tsp - *create_tsp;
		serv_delta = bpf_ktime_get_ns() - *start_tsp;

		que_hist.increment(bpf_log2l(que_delta / 1000));
		serv_hist.increment(bpf_log2l(serv_delta / 1000));

		creation.delete(&req);
		start.delete(&req);
	}
	return 0;
}

"""

bpf_text_kprobe = """
int trace_rq_insert(struct pt_regs *ctx, struct request *req) {
	return rq_insert(req);
}

int trace_rq_issue(struct pt_regs *ctx, struct request *req) {
	return rq_issue(req);
}

int trace_rq_complete(struct pt_regs *ctx, struct request *req) {
	return rq_complete(req);
}
"""

bpf_text_tracepoint = """ 
RAW_TRACEPOINT_PROBE(block_rq_insert) {
	// TP_PROTO(struct request_queue *q, struct request *rq) 
	return rq_insert((struct request *) ctx->args[1]); 
}

RAW_TRACEPOINT_PROBE(block_rq_issue) {
	// TP_PROTO(struct request_queue *q, struct request *rq) 
	return rq_issue((struct request *) ctx->args[1]); 
}

RAW_TRACEPOINT_PROBE(block_rq_complete) {
	// TP_PROTO(struct request *rq, int error, unsigned int nr_bytes) 
	return rq_complete((struct request *) ctx->args[0]); 
}
"""


if len(sys.argv) > 1 and sys.argv[1] == 'T': 	# use tracepoint 
	bpf = BPF(text=bpf_text_head+bpf_text_tracepoint) 

else:		# default: use kprobe
	bpf = BPF(text=bpf_text_head+bpf_text_kprobe) 

	bpf.attach_kprobe(event="blk_account_io_start", fn_name="trace_rq_insert")
	if BPF.get_kprobe_functions(b'blk_start_request'):
		bpf.attach_kprobe(event="blk_start_request", fn_name="trace_rq_issue")
	bpf.attach_kprobe(event="blk_mq_start_request", fn_name="trace_rq_issue")
	bpf.attach_kprobe(event="blk_account_io_done", fn_name="trace_rq_complete")


# header
print("Tracing I/O requests... Hit Ctrl-C to end.")

# trace until keyboard interrupt
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

# output
bpf["que_hist"].print_log2_hist("Queuing time (us)")
print(end="\n\n")
bpf["serv_hist"].print_log2_hist("Service time (us)")

