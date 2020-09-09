/* 
 * ioflow-read.c        C source code for read tracer. 
 *
 *
 * Copyright (c) Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 25-Aug-2020   Haoning Chen   Created this.
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/fs.h>

#define IO_FLOW_READ 1
// Use python string replacement to import common header code
[IMPORT_COMM]

BPF_HASH(syscall_map, u64, struct val_t);    // Map of syscall data, with pid as key
BPF_HASH(request_map, struct request *, struct rqval_t);    // Map of request info for asynchronous request handling

BPF_HISTOGRAM(hist_vfs);
BPF_HISTOGRAM(hist_pgcache);
BPF_HISTOGRAM(hist_readpg);
BPF_HISTOGRAM(hist_ext4readpg);
BPF_HISTOGRAM(hist_blk);
BPF_HISTOGRAM(hist_split);
BPF_HISTOGRAM(hist_merge);
// Async request handling histograms
BPF_HISTOGRAM(hist_rq_queue);
BPF_HISTOGRAM(hist_rq_service);

BPF_PERF_OUTPUT(syscall_events);
BPF_PERF_OUTPUT(rq_events);


int vfs_read_entry(struct pt_regs *ctx, struct file *file) {
    // Filter asyc and direct IO
    if (!(file->f_op->read_iter))
        return 0;
    
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t val = {0};
    comm_vfs_entry(&val, file);
    syscall_map.update(&pid, &val);
    return 0;
}

int page_cache_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp && valp->ts_pgcache == 0)
        valp->ts_pgcache = bpf_ktime_get_ns();
    return 0;
}

int read_page_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp && valp->ts_readpg  == 0)
        valp->ts_readpg = bpf_ktime_get_ns();
    return 0;
}

int ext4_read_page_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = syscall_map.lookup(&pid);
    if (valp && valp->ts_ext4readpg  == 0)
        valp->ts_ext4readpg = bpf_ktime_get_ns();
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

// The end of the read IO
int vfs_read_return(struct pt_regs *ctx) {
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    ssize_t size = (ssize_t) PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();

    struct val_t *valp = syscall_map.lookup(&pid);
    if (!valp) 
        return 0;
    if (valp->ts_pgcache == 0) {
        syscall_map.delete(&pid);
        return 0;
    }
    
    // Populate output struct 
    u64 ts_end = bpf_ktime_get_ns();
    struct data_t data = {0};
    comm_vfs_return(&data, valp, pid >> 32, ts_end, size);

    if (valp->ts_pgcache > valp->ts_vfs) 
        data.vfs = valp->ts_pgcache - valp->ts_vfs;
    else 
        // Direct IO. Directly falls to block layer. 
        data.vfs = data.ts_blk_start - valp->ts_vfs;
    
    if (valp->ts_readpg > valp->ts_pgcache)
        data.pgcache = valp->ts_readpg - valp->ts_pgcache;
    else if (data.ts_blk_start > valp->ts_pgcache)
        data.pgcache = data.ts_blk_start - valp->ts_pgcache;
    else 
        data.pgcache = ts_end - valp->ts_pgcache;

    if (valp->ts_readpg != 0 && valp->ts_ext4readpg > valp->ts_readpg)
        data.readpg = valp->ts_ext4readpg - valp->ts_readpg;

    if (valp->ts_ext4readpg != 0 && data.ts_blk_start > valp->ts_ext4readpg)
        data.ext4readpg = data.ts_blk_start - valp->ts_ext4readpg;
    
    syscall_events.perf_submit(ctx, &data, sizeof(data));
    syscall_map.delete(&pid);

    // update histograms
    if (data.vfs)
        hist_vfs.increment(bpf_log2l(data.vfs / 1000));
    if (data.pgcache)
        hist_pgcache.increment(bpf_log2l(data.pgcache / 1000));
    if (data.readpg)
        hist_readpg.increment(bpf_log2l(data.readpg / 1000));
    if (data.ext4readpg)
        hist_ext4readpg.increment(bpf_log2l(data.ext4readpg / 1000));
    if (data.blk)
        hist_blk.increment(bpf_log2l(data.blk / 1000));
    if (data.split)
        hist_split.increment(bpf_log2l(data.split / 1000));
    if (data.merge)
        hist_merge.increment(bpf_log2l(data.merge / 1000));
    
    return 0;
}
