/* 
 * splitmerge.c      The eBPF C source file for split and merge tracer. 
 *                   Functions in this file are imported and used by 
 *                   biosplit.py and biomerge.py. 
 *
 *
 * Copyright (c) Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 09-Aug-2020   Haoning Chen   Created this.
 */


#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct val_t {      // value type of the bpf map
	u64 ts; 
	u64 sector;
	u64 len;
};

struct data_t { 	// output data type sent from kernel to user space
	u64 ts; 
	u64 lat;
	u64 in_sector;
	u64 in_len;
	u64 out_sector; 
	u64 out_len; 
	u64 rwflag; 
	char disk_name[DISK_NAME_LEN];
	char cmd_name[TASK_COMM_LEN];
};

BPF_HASH(input, struct bio *, struct val_t);
BPF_PERF_OUTPUT(events); 

int split_entry(struct pt_regs *ctx, struct bio *bio) {
	// put the input bio's data to map 
	struct bvec_iter bi_iter;
	bpf_probe_read_kernel(&bi_iter, sizeof(bi_iter), &bio->bi_iter); 

	struct val_t val = { 
        .ts 	= bpf_ktime_get_ns(), 
		.sector = bi_iter.bi_sector, 
		.len 	= bi_iter.bi_size
    }; 
	input.update(&bio, &val); 
	
	return 0;
}

int split_return(struct pt_regs *ctx) {
	// verify split event happened and send output to user space
	struct bio *split = (struct bio *)PT_REGS_RC(ctx); 
	struct bio *bio   = (struct bio *)PT_REGS_PARM1(ctx); 
	
	struct val_t *valp = input.lookup(&bio); 
	if (valp == NULL) 
		return 0; 

	// verify the split event and construct output data struct
	if (split != NULL) {
		struct bvec_iter bi_iter;
		bpf_probe_read_kernel(&bi_iter, sizeof(bi_iter), &split->bi_iter); 

		struct data_t out_data = {
			.ts  = valp->ts, 
			.lat = bpf_ktime_get_ns() - valp->ts,
			.in_sector = valp->sector, 
			.in_len    = valp->len,
			.out_sector = bi_iter.bi_sector,
			.out_len    = bi_iter.bi_size
		};
		bpf_get_current_comm(&out_data.cmd_name, sizeof(out_data.cmd_name));
		struct gendisk *disk = bio->bi_disk; 
		bpf_probe_read_kernel(&out_data.disk_name, sizeof(out_data.disk_name),
				disk->disk_name); 

		// obtain r/w flag 
#ifdef REQ_WRITE
    	out_data.rwflag = !!(bio->bi_opf & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    	out_data.rwflag = !!((bio->bi_opf >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    	out_data.rwflag = !!((bio->bi_opf & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

		// submit output data to user space
		events.perf_submit(ctx, &out_data, sizeof(out_data));
	}

	input.delete(&bio); 
	return 0; 
}
