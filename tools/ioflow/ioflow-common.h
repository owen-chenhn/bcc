/* 
 * ioflow-common.h    Common data structures and helper functions shared by both read and 
 *                    write tracers. Due to errors with bpf verifiers, this file is not 
 *                    imported via "include" directive, but directly injected to tracer 
 *                    source text using string replacement in the Python script. 
 *
 * Copyright (c) Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 1-Sep-2020   Haoning Chen   Created this.
 */

/* Value of the bpf map. */
struct val_t {
    u32 seq_num;
    // Timestamp of file-system sections.
    u64 ts_vfs;
# ifdef IO_FLOW_READ
    u64 ts_pgcache;
    u64 ts_readpg;
    u64 ts_ext4readpg;
#elif defined(IO_FLOW_SYNCWRITE)
    u64 ts_ext4;
    u64 ts_writepg;
    u64 ts_ext4sync;
#endif

    // Timestamps
    u64 ts_blk;
    u64 ts_split;
    u64 ts_merge;
    // The first entry time and the last leave time
    u64 ts_blk_start;
    u64 ts_blk_end;
    u64 ts_split_start;
    u64 ts_split_end;
    u64 ts_merge_start;
    u64 ts_merge_end;

    // Accumulated latency of each stage in Block layer
    u64 blk;
    u64 split;
    u64 merge;

    u32 cnt_blk;
    u32 cnt_split;
    u32 cnt_merge;
    
    // File info
    s64 offset;
    char file_name[DNAME_INLINE_LEN];
};


/* Output data of syscall IO, sent from kernel to user space. */
struct data_t {
    u32 pid;
    u32 seq_num;
    // Latency in each stage
    u64 vfs;
# ifdef IO_FLOW_READ
    u64 pgcache;
    u64 readpg;
    u64 ext4readpg;
#elif defined(IO_FLOW_SYNCWRITE)
    u64 ext4;
    u64 writepg;
    u64 ext4sync;
#endif

    // Accumulated latency of each stage in Block layer
    u64 blk;
    u64 split;
    u64 merge;
    // Total latency
    u64 total;

    // Timestamps
    u64 ts_vfs;
    u64 ts_blk_start;
    u64 ts_blk_end;
    u64 ts_split_start;
    u64 ts_split_end;
    u64 ts_merge_start;
    u64 ts_merge_end;

    u32 cnt_blk;
    u32 cnt_split;
    u32 cnt_merge;

    // File info
    s64 offset;
    s32 size;
    char file_name[DNAME_INLINE_LEN];
    char cmd_name[TASK_COMM_LEN];
};


/* Value type for request map. It stores info of request struct. */
struct rqval_t {
    u32 pid;
    u32 seq_num;
    // Timestamps
    u64 ts_vfs;    // Start time of the VFS syscall that creates this request. 
    u64 ts_rqcreate;
    u64 ts_rqissue;

    // IO info
    u64 sector;
    u32 len;
    char disk_name[DISK_NAME_LEN];
};


/* Output data of async requests. */
struct rqdata_t {
    u32 pid;
    u32 seq_num;
    u64 ts_create;  // Create time (from the start of vfs call)
    u64 queue;      // Queuing latency
    u64 service;    // Handle lantency by device driver

    // IO info
    u64 sector;
    u32 len;
    char disk_name[DISK_NAME_LEN];
};


/* Common helper functions used by read and write tracers */
static inline void comm_vfs_entry(struct val_t *val, u32 seq_num, struct file *file) {
    val->ts_vfs = bpf_ktime_get_ns();
    val->seq_num = seq_num;
    val->offset = file->f_pos;

    struct dentry *de = file->f_path.dentry;
    bpf_probe_read_kernel(&val->file_name, sizeof(val->file_name), &de->d_iname);
}

static inline void comm_block_entry(struct val_t *val, u64 ts) {
    val->ts_blk = ts;
    if (val->ts_blk_start == 0)
        val->ts_blk_start = ts;
}

static inline void comm_block_return(struct val_t *val, u64 ts) {
    val->blk += ts - val->ts_blk;
    val->ts_blk_end = ts;
}

static inline void comm_split_entry(struct val_t *val, u64 ts) {
    val->cnt_split++;
    val->ts_split = ts;
    if (val->ts_split_start == 0)
        val->ts_split_start = ts;
}

static inline void comm_split_return(struct val_t *val, u64 ts) {
    val->split += ts - val->ts_split;
    val->ts_split_end = ts;
}

static inline void comm_merge_entry(struct val_t *val, u64 ts) {
    val->cnt_merge++;
    val->ts_merge = ts;
    if (val->ts_merge_start == 0)
        val->ts_merge_start = ts;
}

static inline void comm_merge_return(struct val_t *val, u64 ts) {
    val->merge += ts - val->ts_merge;
    val->ts_merge_end = ts;
}

static inline void comm_rq_create(struct rqval_t *rqval, struct val_t *val, 
                                  struct request *rq, u32 pid, u64 ts) {
    val->cnt_blk++;
    
    rqval->pid = pid;
    rqval->seq_num = val->seq_num;
    rqval->ts_vfs = val->ts_vfs;
    rqval->ts_rqcreate = ts;
    rqval->sector = rq->__sector;
    rqval->len = rq->__data_len;
    struct gendisk *disk = rq->rq_disk;
    bpf_probe_read_kernel(&rqval->disk_name, sizeof(rqval->disk_name), 
        disk->disk_name);
}

static inline void comm_rq_issue(struct rqval_t *rqval, u64 ts) {
    if (rqval) {
        rqval->ts_rqissue = ts;
    }
}

static inline void comm_rq_done(struct rqdata_t *rqdata, struct rqval_t *rqval, u64 ts) {
    rqdata->pid = rqval->pid;
    rqdata->seq_num = rqval->seq_num;
    rqdata->ts_create = rqval->ts_rqcreate - rqval->ts_vfs;
    if (rqval->ts_rqissue) {
        rqdata->queue = rqval->ts_rqissue - rqval->ts_rqcreate;
        rqdata->service = ts - rqval->ts_rqissue;
    }
    else {
        rqdata->queue = 0;
        rqdata->service = ts - rqval->ts_rqcreate;
    }
    
    rqdata->sector = rqval->sector;
    rqdata->len = rqval->len;
    bpf_probe_read_kernel(&rqdata->disk_name, sizeof(rqdata->disk_name), 
        &rqval->disk_name);
}

static inline void comm_vfs_return(struct data_t *data,  struct val_t *val, u32 pid, 
                                   u64 ts, ssize_t size) {
    data->pid = pid;
    data->seq_num = val->seq_num;
    data->total = ts - val->ts_vfs;

    data->ts_vfs = val->ts_vfs;
    data->ts_blk_start = val->ts_blk_start;
    data->ts_blk_end = val->ts_blk_end;
    data->ts_split_start = val->ts_split_start;
    data->ts_split_end = val->ts_split_end;
    data->ts_merge_start = val->ts_merge_start;
    data->ts_merge_end = val->ts_merge_end;
    data->blk = val->blk;
    data->split = val->split;
    data->merge = val->merge;
    data->cnt_blk = val->cnt_blk;
    data->cnt_split = val->cnt_split;
    data->cnt_merge = val->cnt_merge;
    data->offset = val->offset;
    data->size = size;
    bpf_probe_read_kernel(&data->file_name, sizeof(data->file_name), &val->file_name);
    bpf_get_current_comm(&data->cmd_name, sizeof(data->cmd_name));
}
