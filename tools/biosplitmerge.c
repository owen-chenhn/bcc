/* 
 * biosplitmerge.c      The eBPF C source file for split and merge tracer. 
 *                      Functions in this file are imported and used by 
 *                      biosplitmerge.py. 
 *
 *
 * Copyright (c) Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 09-Aug-2020   Haoning Chen   Created this.
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/version.h>

/* Split/Merge event type. */
enum type { Split = 0, Fmerge, Bmerge, Dmerge };


/* Value of the bpf map */
struct val_t {
	u64 ts; 
	u64 sector;
	u64 len;
	u8 type;
};


/* Output data type sent from kernel to user space */
struct data_t {
	u64 ts; 
	u64 in_sector;
	u64 in_len;
	u64 out_sector1; 
	u64 out_len1;
	u64 out_sector2;    // The remaining bio for split
	u64 out_len2; 
	u8 rwflag;
	u8 type;
	u32 pid;
	char disk_name[DISK_NAME_LEN];
	char cmd_name[TASK_COMM_LEN];
};


BPF_HASH(input, u64, struct val_t);    // use pid as hash key
BPF_PERF_OUTPUT(events); 


/* Common actions performed when probe function is entered. */
static inline void do_entry(enum type event_type, struct bio *bio) {
	u64 pid = bpf_get_current_pid_tgid();
	// put the input bio's data to map 
	struct bvec_iter bi_iter;
	bpf_probe_read_kernel(&bi_iter, sizeof(bi_iter), &bio->bi_iter); 

	struct val_t val = {0};
	val.ts     = bpf_ktime_get_ns();
	val.sector = bi_iter.bi_sector;
	val.len    = bi_iter.bi_size;
	val.type   = (u8) event_type;

	input.update(&pid, &val);
}


/* Function probed to entry of bio_split(). */
int split_entry(struct pt_regs *ctx, struct bio *bio) {
	do_entry(Split, bio);
	return 0;
}


/* Function probed to entry of bio_attempt_front_merge(). */
int front_merge_entry(struct pt_regs *ctx) {
	// obtain the second param of the function
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	struct bio *bio = (struct bio *)PT_REGS_PARM2(ctx);
#else 
	struct bio *bio = (struct bio *)PT_REGS_PARM3(ctx);
#endif
	do_entry(Fmerge, bio);
	return 0;
}

/* Function probed to entry of bio_attempt_back_merge(). */
int back_merge_entry(struct pt_regs *ctx) {
	// obtain the bio argument of the function
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	struct bio *bio = (struct bio *)PT_REGS_PARM2(ctx);
#else 
	struct bio *bio = (struct bio *)PT_REGS_PARM3(ctx);
#endif
	do_entry(Bmerge, bio);
	return 0;
}


/* Function probed to entry of bio_attempt_discard_merge(). */
int discard_merge_entry(struct pt_regs *ctx) {
	struct bio *bio = (struct bio *)PT_REGS_PARM3(ctx);
	do_entry(Dmerge, bio);
	return 0;
}


/* Function probed to return of bio_split(). */
int split_return(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	struct bio *split = (struct bio *)PT_REGS_RC(ctx); 
	
	struct val_t *valp = input.lookup(&pid); 
	if (valp == NULL) 
		return 0; 

	// verify the split event and construct output data struct
	if (split == NULL) {
		input.delete(&pid);
		return 0; 
	}

	struct bvec_iter bi_iter;
	bpf_probe_read_kernel(&bi_iter, sizeof(bi_iter), &split->bi_iter); 

	struct data_t out_data = {0};
	out_data.ts = valp->ts;
	out_data.in_sector = valp->sector;
	out_data.in_len    = valp->len;
	out_data.out_sector1 = bi_iter.bi_sector;
	out_data.out_len1    = bi_iter.bi_size;
	out_data.out_sector2 = out_data.in_sector + (bi_iter.bi_size >> 9);
	out_data.out_len2    = out_data.in_len - bi_iter.bi_size;
	out_data.type = valp->type;
	out_data.pid  = pid >> 32;

	// fill remaining fields and emit output data to user space
	bpf_get_current_comm(&out_data.cmd_name, sizeof(out_data.cmd_name));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	struct gendisk *disk = split->bi_disk;
#else
	struct gendisk *disk = split->bi_bdev->bd_disk;
#endif
	bpf_probe_read_kernel(&out_data.disk_name, sizeof(out_data.disk_name),
			disk->disk_name); 

	// obtain r/w flag 
#ifdef REQ_WRITE      // kernel version < 4.8.0
	out_data.rwflag = split->bi_rw & REQ_WRITE;
#elif defined(REQ_OP_SHIFT)
	out_data.rwflag = (split->bi_opf >> REQ_OP_SHIFT) & REQ_OP_WRITE;
#else
	out_data.rwflag = (split->bi_opf & REQ_OP_MASK) & REQ_OP_WRITE;
#endif
	events.perf_submit(ctx, &out_data, sizeof(out_data));
	
	input.delete(&pid);
	return 0; 
}


/* Common function probed to return of the merge functions. */
int merge_return(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	struct request *req = (struct request *)PT_REGS_PARM1(ctx);

	struct val_t *valp = input.lookup(&pid); 
	if (valp == NULL) 
		return 0;

	// verify the event via return value and construct output data struct
	if ( !PT_REGS_RC(ctx) ) {
		input.delete(&pid); 
		return 0; 
	}

	struct data_t out_data = {0};
	out_data.ts = valp->ts;
	out_data.in_sector = valp->sector;
	out_data.in_len    = valp->len;
	out_data.out_sector1 = req->__sector;
	out_data.out_len1    = req->__data_len;
	out_data.type = valp->type;
	out_data.pid  = pid >> 32;

	// fill remaining fields and emit output data to user space
	bpf_get_current_comm(&out_data.cmd_name, sizeof(out_data.cmd_name));
	struct gendisk *disk = req->rq_disk; 
	bpf_probe_read_kernel(&out_data.disk_name, sizeof(out_data.disk_name),
			disk->disk_name);

	// obtain r/w flag 
#ifdef REQ_WRITE
	out_data.rwflag = req->cmd_flags & REQ_WRITE;
#elif defined(REQ_OP_SHIFT)
	out_data.rwflag = (req->cmd_flags >> REQ_OP_SHIFT) & REQ_OP_WRITE;
#else
	out_data.rwflag = (req->cmd_flags & REQ_OP_MASK) & REQ_OP_WRITE;
#endif
	events.perf_submit(ctx, &out_data, sizeof(out_data));
	
	input.delete(&pid); 
	return 0; 
}
