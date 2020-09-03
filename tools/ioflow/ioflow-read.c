/* 
 * ioflow-read.c        description ...
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

/* Value of the bpf map. */
struct val_t {
    u64 seq_num;    // Sequence number of a pid
    // Timestamp when entering each section in file-system layer.
    u64 ts_vfs;
    u64 ts_pgcache;
    u64 ts_readpg;
    u64 ts_ext4readpg;

    // Block layer. Updated each time to calc accumulated time.
    u64 ts_blk;
    u64 ts_split;
    u64 ts_merge;
    // Start and end time in block layer
    u64 ts_blk_start;
    u64 ts_blk_end;
    u64 ts_split_start;
    u64 ts_split_end;
    u64 ts_merge_start;
    u64 ts_merge_end;
    
    // Accumulated latency for each section in the block layer
    u64 lat_blk;
    u64 lat_split;
    u64 lat_merge;
    // Number of times the section is entered
    u64 cnt_blk;
    u64 cnt_split;
    u64 cnt_merge;
    //u64 cnt_request;
    
    s64 offset;    // file offset
    char file_name[DNAME_INLINE_LEN];
};


/* Output data of syscall IO, sent from kernel to user space. */
struct data_t {
    // Latency in each stage
    u64 vfs;
    u64 pgcache;
    u64 readpg;
    u64 ext4readpg;
    // Accumulated latency of each stage in Block layer
    u64 blk;
    u64 split;
    u64 merge;
    // Total latency
    u64 total;

    // Timestamps
    u64 ts_vfs;
    u64 ts_pgcache;
    u64 ts_readpg;
    u64 ts_ext4readpg;
    u64 ts_blk_start;
    u64 ts_blk_end;
    u64 ts_split_start;
    u64 ts_split_end;
    u64 ts_merge_start;
    u64 ts_merge_end;

    u64 cnt_blk;
    u64 cnt_split;
    u64 cnt_merge;
    
    // File info
    u64 pid;    // PID (upper 32 bits) and Kernel ThreadID (lower 32 bits)
    u64 seq_num;
    s64 offset;
    u64 size;
    char file_name[DNAME_INLINE_LEN];
    char cmd_name[TASK_COMM_LEN];
};


/* Value type for request map. It stores info of request struct. */
struct rqval_t {
    u64 pid;
    u64 seq_num;
    // Timestamps
    u64 ts_vfs;    // Start time of the VFS syscall that creates this request. 
    u64 ts_rqcreate;
    u64 ts_rqissue;

    // IO info
    u64 sector;
    u64 len;
    char disk_name[DISK_NAME_LEN];
};


/* Output data of async requests. */
struct rqdata_t {
    u64 pid;        // PID and Kernel ThreadID
    u64 seq_num;
    u64 ts_vfs;     // Used to calc creation timestamp
    u64 ts_rqcreate;
    u64 queue;      // Queuing latency
    u64 service;    // Handle lantency by device driver
    u64 total;

    // IO info
    u64 sector;
    u64 len;
    char disk_name[DISK_NAME_LEN];
};


BPF_HASH(seq, u64);    // sequence number of a pid
BPF_HASH(map, u64, struct val_t);    // Map of syscall data, with pid as key
BPF_HASH(rqmap, struct request *, struct rqval_t);    // Map of request info for aync request handling

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


// Probe to vfs_read() or new_sync_read()
int vfs_read_entry(struct pt_regs *ctx, struct file *file) {
    // Filter asyc and direct IO
    if (!(file->f_op->read_iter) || file->f_flags & O_DIRECT)
        return 0;
    
    u64 pid = bpf_get_current_pid_tgid();
    u64 zero = 0, *seq_num;
    seq_num = seq.lookup_or_try_init(&pid, &zero);
    if (!seq_num)
        return 0;
    struct val_t val = {0};
    val.seq_num = (*seq_num)++;
    val.ts_vfs = bpf_ktime_get_ns();
    val.offset = file->f_pos;

    struct dentry *de = file->f_path.dentry;
    bpf_probe_read_kernel(&val.file_name, sizeof(val.file_name), &de->d_iname);
    
    map.update(&pid, &val);
    return 0;
}

int page_cache_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp && valp->ts_pgcache == 0)
        valp->ts_pgcache = bpf_ktime_get_ns();
    return 0;
}

int read_page_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp && valp->ts_readpg <= valp->ts_pgcache)
        valp->ts_readpg = bpf_ktime_get_ns();
    return 0;
}

int ext4_read_page_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp && valp->ts_ext4readpg <= valp->ts_readpg)
        valp->ts_ext4readpg = bpf_ktime_get_ns();
    return 0;
}

/* BLock layer */
int block_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->ts_blk = ts;
        if (valp->ts_blk_start == 0)
            valp->ts_blk_start = ts;
    }
    return 0;
}

int block_return(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->lat_blk += ts - valp->ts_blk;
        valp->ts_blk_end = ts;
    }
    return 0;
}

int split_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->cnt_split++;
        valp->ts_split = ts;
        if (valp->ts_split_start == 0)
            valp->ts_split_start = ts;
    }
    return 0;
}

int split_return(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->lat_split += ts - valp->ts_split;
        valp->ts_split_end = ts;
    }
    return 0;
}

int merge_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->cnt_merge++;
        valp->ts_merge = ts;
        if (valp->ts_merge_start == 0)
            valp->ts_merge_start = ts;
    }
    return 0;
}

int merge_return(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->lat_merge += ts - valp->ts_merge;
        valp->ts_merge_end = ts;
    }
    return 0;
}

// Async request handling
int rq_create(struct pt_regs *ctx, struct request *rq) {
    // Still in the syscall process's context now. 
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->cnt_blk++;
        struct rqval_t rqval = {0};
        rqval.pid = pid;
        rqval.seq_num = valp->seq_num;
        rqval.ts_vfs = valp->ts_vfs;
        rqval.ts_rqcreate = ts;

        rqval.sector = rq->__sector;
        rqval.len    = rq->__data_len;
        struct gendisk *disk = rq->rq_disk;
        bpf_probe_read_kernel(&rqval.disk_name, sizeof(rqval.disk_name), 
            disk->disk_name);

        rqmap.insert(&rq, &rqval);
    }
    return 0;
}

// The request is issued to device driver.
int rq_issue(struct pt_regs *ctx, struct request *rq) {
    // Async to the syscall process now. 
    struct rqval_t *rqvalp = rqmap.lookup(&rq);
    if (rqvalp) {
        rqvalp->ts_rqissue = bpf_ktime_get_ns();
    }
    return 0;
}

// The request is done.
int rq_done(struct pt_regs *ctx, struct request *rq) {
    u64 ts = bpf_ktime_get_ns();
    struct rqval_t *rqvalp = rqmap.lookup(&rq);
    if (rqvalp) {
        struct rqdata_t rqdata = {0};
        rqdata.pid = rqvalp->pid;
        rqdata.seq_num = rqvalp->seq_num;
        rqdata.ts_vfs = rqvalp->ts_vfs;
        rqdata.ts_rqcreate = rqvalp->ts_rqcreate;
        rqdata.queue = rqvalp->ts_rqissue - rqvalp->ts_rqcreate;
        rqdata.service = ts - rqvalp->ts_rqissue;
        rqdata.total = rqdata.queue + rqdata.service;
        rqdata.sector = rqvalp->sector;
        rqdata.len = rqvalp->len;
        bpf_probe_read_kernel(&rqdata.disk_name, sizeof(rqdata.disk_name), 
            &rqvalp->disk_name);
        rq_events.perf_submit(ctx, &rqdata, sizeof(rqdata));

        hist_rq_queue.increment(bpf_log2l(rqdata.queue / 1000));
        hist_rq_service.increment(bpf_log2l(rqdata.service / 1000));
        
        rqmap.delete(&rq);
    }
    return 0;
}

// The end of the read IO
int vfs_read_return(struct pt_regs *ctx) {
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    ssize_t size = (ssize_t) PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();

    struct val_t *valp = map.lookup(&pid);
    if (!valp) 
        return 0;
    if (valp->ts_pgcache == 0) {
        map.delete(&pid);
        return 0;
    }

    // Populate output data struct.
    u64 ts_end = bpf_ktime_get_ns();
    struct data_t data = {0};
    data.pid = pid;
    data.seq_num = valp->seq_num;
    data.ts_vfs = valp->ts_vfs;
    data.ts_pgcache = valp->ts_pgcache;
    data.ts_readpg = valp->ts_readpg;
    data.ts_ext4readpg = valp->ts_ext4readpg;
    data.ts_blk_start = valp->ts_blk_start;
    data.ts_blk_end = valp->ts_blk_end;
    data.ts_split_start = valp->ts_split_start;
    data.ts_split_end = valp->ts_split_end;
    data.ts_merge_start = valp->ts_merge_start;
    data.ts_merge_end = valp->ts_merge_end;

    data.total = ts_end - valp->ts_vfs;
    data.vfs = valp->ts_pgcache - valp->ts_vfs;
    if (valp->ts_readpg > valp->ts_pgcache)
        data.pgcache = valp->ts_readpg - valp->ts_pgcache;
    else 
        data.pgcache = ts_end - valp->ts_pgcache;

    if (valp->ts_readpg != 0 && valp->ts_ext4readpg > valp->ts_readpg)
        data.readpg = valp->ts_ext4readpg - valp->ts_readpg;

    if (valp->ts_ext4readpg != 0 && valp->ts_blk_start > valp->ts_ext4readpg)
        data.ext4readpg = valp->ts_blk_start - valp->ts_ext4readpg;

    data.blk = valp->lat_blk;
    data.split = valp->lat_split;
    data.merge = valp->lat_merge;

    // Copy other info:
    data.cnt_blk = valp->cnt_blk;
    data.cnt_split = valp->cnt_split;
    data.cnt_merge = valp->cnt_merge;
    data.offset = valp->offset;
    data.size = size;
    bpf_probe_read_kernel(&data.file_name, sizeof(data.file_name), &valp->file_name);
    bpf_get_current_comm(&data.cmd_name, sizeof(data.cmd_name));

    syscall_events.perf_submit(ctx, &data, sizeof(data));
    map.delete(&pid);

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
