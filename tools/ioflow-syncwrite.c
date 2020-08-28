/* 
 * ioflow-syncwrite.c        description ...
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

/* Value of the bpf map. */
struct val_t {
    // Timestamp when entering each section in file-system layer.
    u64 ts_vfs;
    u64 ts_ext4;
    u64 ts_writepg;
    u64 ts_ext4sync;

    // Block layer. Updated each time.
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

    u64 ts_request;     // The first time when a request is submitted to request queue. 
    
    // Accumulated latency for each section in the block layer
    u64 lat_blk;
    u64 lat_split;
    u64 lat_merge;
    // Number of times the section is entered
    u64 cnt_blk;
    u64 cnt_split;
    u64 cnt_merge;
    
    s64 offset;    // file offset
    char file_name[DNAME_INLINE_LEN];
};


/* Output data sent from kernel to user space. */
struct data_t {
    // Latency in each stage
    u64 vfs;
    u64 ext4;
    u64 writepg;
    u64 ext4sync;
    // Accumulated latency of each stage in Block layer
    u64 blk;
    u64 split;
    u64 merge;
    u64 request;
    // Total latency
    u64 total;

    // Timestamps
    u64 ts_vfs;
    u64 ts_ext4;
    u64 ts_writepg;
    u64 ts_ext4sync;
    u64 ts_blk_start;
    u64 ts_blk_end;
    u64 ts_split_start;
    u64 ts_split_end;
    u64 ts_merge_start;
    u64 ts_merge_end;
    u64 ts_request;

    u64 cnt_blk;
    u64 cnt_split;
    u64 cnt_merge;
    
    // File info
    u64 pid;
    s64 offset;
    u64 size;
    char file_name[DNAME_INLINE_LEN];
    char cmd_name[TASK_COMM_LEN];
};


BPF_HASH(map, u64, struct val_t);    // use pid as hash key

BPF_HISTOGRAM(hist_vfs);
BPF_HISTOGRAM(hist_ext4);
BPF_HISTOGRAM(hist_writepg);
BPF_HISTOGRAM(hist_ext4sync);
BPF_HISTOGRAM(hist_blk);
BPF_HISTOGRAM(hist_split);
BPF_HISTOGRAM(hist_merge);
BPF_HISTOGRAM(hist_request);

BPF_PERF_OUTPUT(events); 


// Probe to vfs_write() or new_sync_write()
int vfs_write_entry(struct pt_regs *ctx, struct file *file) {
    // Filter asyc and direct IO
    if (!(file->f_op->read_iter) || file->f_flags & O_DIRECT)
        return 0;
    
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t val = {0};
    val.ts_vfs = bpf_ktime_get_ns();
    val.offset = file->f_pos;

    struct dentry *de = file->f_path.dentry;
    bpf_probe_read_kernel(&val.file_name, sizeof(val.file_name), &de->d_iname);
    
    map.update(&pid, &val);
    return 0;
}

int ext4_entry(struct pt_regs *ctx) {
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp && valp->ts_ext4 == 0)
        valp->ts_ext4 = bpf_ktime_get_ns();
    return 0;
}

int write_page_entry(struct pt_regs *ctx) {
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp && valp->ts_writepg <= valp->ts_ext4)
        valp->ts_writepg = bpf_ktime_get_ns();
    return 0;
}

int ext4_sync_entry(struct pt_regs *ctx) {
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp && valp->ts_ext4sync <= valp->ts_writepg)
        valp->ts_ext4sync = bpf_ktime_get_ns();
    return 0;
}

/* BLock layer */
int block_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->cnt_blk++;
        valp->ts_blk = ts;
        if (valp->ts_blk_start == 0)
            valp->ts_blk_start = ts;
    }
    return 0;
}

int block_return(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->lat_blk += ts - valp->ts_blk;
        valp->ts_blk_end = ts;
        // stash the request timestamp for the first submitted request
        if (valp->ts_request == 0)
            valp->ts_request = ts;
    }
    return 0;
}

int split_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid =  bpf_get_current_pid_tgid();
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
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->lat_split += ts - valp->ts_split;
        valp->ts_split_end = ts;
    }
    return 0;
}

int merge_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid =  bpf_get_current_pid_tgid();
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
    u64 pid =  bpf_get_current_pid_tgid();
    struct val_t *valp = map.lookup(&pid);
    if (valp) {
        valp->lat_merge += ts - valp->ts_merge;
        valp->ts_merge_end = ts;
    }
    return 0;
}

// The end of the read IO
int vfs_write_return(struct pt_regs *ctx) {
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    ssize_t size = (ssize_t) PT_REGS_RC(ctx);
    u64 pid =  bpf_get_current_pid_tgid();

    struct val_t *valp = map.lookup(&pid);
    if (!valp) 
        return 0;
    if (!valp->ts_ext4 || !valp->ts_writepg) {
        // filter out non-buffered wirtes
        map.delete(&pid);
        return 0;
    }

    /* Note: the async (normal) writes aren't filtered. In those 
    *  cases, timestamp fields starting from ext4sync are all 0. 
    */

    // Populate output data struct.
    u64 ts_end = bpf_ktime_get_ns();
    struct data_t data = {0};
    data.ts_vfs = valp->ts_vfs;
    data.ts_ext4 = valp->ts_ext4;
    data.ts_writepg = valp->ts_writepg;
    data.ts_ext4sync = valp->ts_ext4sync;
    data.ts_blk_start = valp->ts_blk_start;
    data.ts_blk_end = valp->ts_blk_end;
    data.ts_split_start = valp->ts_split_start;
    data.ts_split_end = valp->ts_split_end;
    data.ts_merge_start = valp->ts_merge_start;
    data.ts_merge_end = valp->ts_merge_end;
    data.ts_request = valp->ts_request;

    data.total = ts_end - valp->ts_vfs;
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

    if (valp->ts_request != 0)
        data.request = ts_end - valp->ts_request;

    data.blk = valp->lat_blk;
    data.split = valp->lat_split;
    data.merge = valp->lat_merge;

    // Copy other info:
    data.cnt_blk = valp->cnt_blk;
    data.cnt_split = valp->cnt_split;
    data.cnt_merge = valp->cnt_merge;
    data.offset = valp->offset;
    
    data.pid = pid >> 32;
    data.size = size;
    bpf_probe_read_kernel(&data.file_name, sizeof(data.file_name), &valp->file_name);
    bpf_get_current_comm(&data.cmd_name, sizeof(data.cmd_name));

    events.perf_submit(ctx, &data, sizeof(data));
    map.delete(&pid);

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
    if (data.request)
        hist_request.increment(bpf_log2l(data.request / 1000));
    
    return 0;
}