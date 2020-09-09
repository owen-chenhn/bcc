/* 
 * ioflow-syncwrite.c        C source code for sync write tracer. 
 *
 *
 * Copyright (c) Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 27-Aug-2020   Haoning Chen   Created this.
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/fs.h>

#define IO_FLOW_SYNCWRITE 1
// Use python string replacement to import common header code
[IMPORT_COMM]

BPF_HASH(syscall_map, u64, struct val_t);    // Map of syscall data, with pid as key
BPF_HASH(request_map, struct request *, struct rqval_t);    // Map of request info for asynchronous request handling

BPF_HISTOGRAM(hist_vfs);
BPF_HISTOGRAM(hist_ext4);
BPF_HISTOGRAM(hist_writepg);
BPF_HISTOGRAM(hist_ext4sync);
BPF_HISTOGRAM(hist_blk);
BPF_HISTOGRAM(hist_split);
BPF_HISTOGRAM(hist_merge);
BPF_HISTOGRAM(hist_rq_queue);
BPF_HISTOGRAM(hist_rq_service);

BPF_PERF_OUTPUT(syscall_events);
BPF_PERF_OUTPUT(rq_events);


int vfs_write_entry(struct pt_regs *ctx, struct file *file) {
    // Filter asyc and direct IO
    if (!(file->f_op->write_iter) || file->f_flags & O_DIRECT)
        return 0;
    
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t val = {0};
    comm_vfs_entry(&val, file);
    syscall_map.update(&pid, &val);
    return 0;
}

int ext4_entry(struct pt_regs *ctx) {
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp && valp->ts_ext4 == 0)
        valp->ts_ext4 = bpf_ktime_get_ns();
    return 0;
}

int write_page_entry(struct pt_regs *ctx) {
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp && valp->ts_writepg == 0)
        valp->ts_writepg = bpf_ktime_get_ns();
    return 0;
}

int ext4_sync_entry(struct pt_regs *ctx) {
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp && valp->ts_ext4sync == 0)
        valp->ts_ext4sync = bpf_ktime_get_ns();
    return 0;
}

/* BLock layer */
int block_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp) {
        comm_block_entry(valp, ts);
    }
    return 0;
}

int block_return(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp) {
        comm_block_return(valp, ts);
    }
    return 0;
}

int split_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp) {
        comm_split_entry(valp, ts);
    }
    return 0;
}

int split_return(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp) {
        comm_split_return(valp, ts);
    }
    return 0;
}

int merge_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp) {
        comm_merge_entry(valp, ts);
    }
    return 0;
}

int merge_return(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp) {
        comm_merge_return(valp, ts);
    }
    return 0;
}

// Async request handling
int rq_create(struct pt_regs *ctx, struct request *rq) {
    // Still in the syscall process's context now. 
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp) {
        struct rqval_t rqval = {0};
        comm_rq_create(&rqval, valp, rq, pid >> 32, ts);
        request_map.insert(&rq, &rqval);
    }
    return 0;
}

// The request is issued to device driver.
int rq_issue(struct pt_regs *ctx, struct request *rq) {
    // Async to the syscall process now. 
    u64 ts = bpf_ktime_get_ns();
    struct rqval_t *rqvalp = request_map.lookup(&rq);
    comm_rq_issue(rqvalp, ts);
    return 0;
}

// The request is done.
int rq_done(struct pt_regs *ctx, struct request *rq) {
    u64 ts = bpf_ktime_get_ns();
    struct rqval_t *rqvalp = request_map.lookup(&rq);
    if (rqvalp) {
        struct rqdata_t rqdata = {0};
        comm_rq_done(&rqdata, rqvalp, ts);
        rq_events.perf_submit(ctx, &rqdata, sizeof(rqdata));

        hist_rq_queue.increment(bpf_log2l(rqdata.queue / 1000));
        hist_rq_service.increment(bpf_log2l(rqdata.service / 1000));
        
        request_map.delete(&rq);
    }
    return 0;
}

// The end of the write IO
int vfs_write_return(struct pt_regs *ctx) {
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    ssize_t size = (ssize_t) PT_REGS_RC(ctx);
    u64 pid =  bpf_get_current_pid_tgid();

    struct val_t *valp = syscall_map.lookup(&pid);
    if (!valp) 
        return 0;
    if (!valp->ts_ext4 || !valp->ts_writepg) {
        // filter out non-buffered wirtes
        syscall_map.delete(&pid);
        return 0;
    }

    /* Note: the async (normal) writes aren't filtered. In those 
    *  cases, timestamp fields starting from ext4sync are all 0. 
    */

    // Populate output data struct.
    u64 ts_end = bpf_ktime_get_ns();
    struct data_t data = {0};
    comm_vfs_return(&data, valp, pid >> 32, ts_end, size);
    
    data.vfs = valp->ts_ext4 - valp->ts_vfs;
    data.ext4 = valp->ts_writepg - valp->ts_ext4;
    if (valp->ts_ext4sync > valp->ts_writepg)
        data.writepg = valp->ts_ext4sync - valp->ts_writepg;
    else
        data.writepg = ts_end - valp->ts_writepg;

    if (valp->ts_ext4sync != 0 && valp->ts_blk_start > valp->ts_ext4sync)
        data.ext4sync = valp->ts_blk_start - valp->ts_ext4sync;
    else if (valp->ts_ext4sync != 0) 
        data.ext4sync = ts_end - valp->ts_ext4sync;

    syscall_events.perf_submit(ctx, &data, sizeof(data));
    syscall_map.delete(&pid);

    // update histograms
    if (data.vfs)
        hist_vfs.increment(bpf_log2l(data.vfs / 1000));
    if (data.ext4)
        hist_ext4.increment(bpf_log2l(data.ext4 / 1000));
    if (data.writepg)
        hist_writepg.increment(bpf_log2l(data.writepg / 1000));
    if (data.ext4sync)
        hist_ext4sync.increment(bpf_log2l(data.ext4sync / 1000));
    if (data.blk)
        hist_blk.increment(bpf_log2l(data.blk / 1000));
    if (data.split)
        hist_split.increment(bpf_log2l(data.split / 1000));
    if (data.merge)
        hist_merge.increment(bpf_log2l(data.merge / 1000));
    
    return 0;
}