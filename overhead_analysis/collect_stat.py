import os 
import sys
import json
from datetime import datetime
import csv 


# compute the increment in percent of target from compare
def cmpr(target, compare): 
    if compare == 0: 
        return "0 (0)" 
    inc = (target - compare) / compare * 100 
    formatstr = "%d (%+.2f%%)" if isinstance(target, int) \
                else "%.2f (%+.2f%%)"
    return formatstr % (target, inc) 
    

mode_map = {
    "output": "no-trace", 
    "output-ebpf": "ebpf", 
    "output-blkhist": "blkhist"
}
stat = dict() 

for outdir in ["output", "output-ebpf", "output-blkhist"]: 
    if not os.path.exists(outdir): 
        print("Output directory not found: %s" % outdir) 
        exit() 
    for out_file in os.listdir(outdir): 
        file_path = os.path.join(outdir, out_file)
        job_name, out_format = out_file.split('.')
        job_stat = stat.setdefault(job_name, dict()) \
                        .setdefault(mode_map[outdir], dict()) 
        if out_format == "out": 
            with open(file_path, 'r') as fio_f:
                fio_json = json.load(fio_f) 
            fio_job = fio_json["jobs"][0] 
            r_stat, w_stat = fio_job["read"], fio_job["write"]
            job_stat["lat"] = {
                "r": {
                    "mean": round(r_stat["lat"]["mean"], 2),
                    "50p": r_stat["clat"]["percentile"]["50.000000"], 
                    "90p": r_stat["clat"]["percentile"]["90.000000"],
                    "99p": r_stat["clat"]["percentile"]["99.990000"]
                }, 
                "w": {
                    "mean": round(w_stat["lat"]["mean"], 2),
                    "50p": w_stat["clat"]["percentile"]["50.000000"], 
                    "90p": w_stat["clat"]["percentile"]["90.000000"],
                    "99p": w_stat["clat"]["percentile"]["99.990000"]
                }
            }
            job_stat["bw"] = {
                "r": r_stat["bw"], 
                "w": w_stat["bw"]
            }
        else: 
            cpu = os.popen("cat %s | grep 'cpu-clock'" % file_path) \
                    .read().strip().split(' ')[0]
            job_stat["cpu"] = round(float(cpu))


# whether format output data with analysis 
if len(sys.argv) > 1 and sys.argv[1] == '1': 
    analyflag = True 
else: 
    analyflag = False 

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
with open("stats/stat-%s.json" % timestamp, "w") as json_w: 
    json.dump(stat, json_w, indent=2) 

with open("stats/stat-%s.csv" % timestamp, "w") as csv_w: 
    writer = csv.writer(csv_w) 
    writer.writerow(["Job name", "Lat(us)-R-NoTrace", "50 Percentile", "90 Percentile", "99 Percentile",  
            "Lat(us)-W-NoTrace", "50 Percentile", "90 Percentile", "99 Percentile", 
            "BW(KB/s)-R-NoTrace", "BW(KB/s)-W-NoTrace", "CPU-NoTrace", 
            "Lat(us)-R-eBpf", "50 Percentile", "90 Percentile", "99 Percentile", 
            "Lat(us)-W-eBpf", "50 Percentile", "90 Percentile", "99 Percentile", 
            "BW(KB/s)-R-eBpf", "BW(KB/s)-W-eBpf", "CPU-eBpf", 
            "Lat(us)-R-Blkhist", "50 Percentile", "90 Percentile", "99 Percentile", 
            "Lat(us)-W-Blkhist", "50 Percentile", "90 Percentile", "99 Percentile", 
            "BW(KB/s)-R-Blkhist", "BW(KB/s)-W-Blkhist", "CPU-Blkhist"])

    for job_name in sorted(stat.keys()): 
        nt_stat, ebpf_stat, blkhist_stat = stat[job_name]["no-trace"], stat[job_name]["ebpf"], stat[job_name]["blkhist"]

        nt_lat_r, nt_lat_w = nt_stat["lat"]["r"], nt_stat["lat"]["w"]
        nt_bw_r, nt_bw_w = nt_stat["bw"]["r"], nt_stat["bw"]["w"] 
        nt_cpu = nt_stat["cpu"]

        ebpf_lat_r, ebpf_lat_w = ebpf_stat["lat"]["r"], ebpf_stat["lat"]["w"]
        ebpf_bw_r, ebpf_bw_w = ebpf_stat["bw"]["r"], ebpf_stat["bw"]["w"] 
        ebpf_cpu = ebpf_stat["cpu"]

        blkhist_lat_r, blkhist_lat_w = blkhist_stat["lat"]["r"], blkhist_stat["lat"]["w"]
        blkhist_bw_r, blkhist_bw_w = blkhist_stat["bw"]["r"], blkhist_stat["bw"]["w"] 
        blkhist_cpu = blkhist_stat["cpu"]

        if analyflag: 
            writer.writerow([job_name, nt_lat_r["mean"], nt_lat_r["50p"], nt_lat_r["90p"], nt_lat_r["99p"], 
                    nt_lat_w["mean"], nt_lat_w["50p"], nt_lat_w["90p"], nt_lat_w["99p"], 
                    nt_bw_r, nt_bw_w, nt_cpu, 
                    cmpr(ebpf_lat_r["mean"], nt_lat_r["mean"]), ebpf_lat_r["50p"], ebpf_lat_r["90p"], ebpf_lat_r["99p"], 
                    cmpr(ebpf_lat_w["mean"], nt_lat_w["mean"]), ebpf_lat_w["50p"], ebpf_lat_w["90p"], ebpf_lat_w["99p"], 
                    cmpr(ebpf_bw_r, nt_bw_r), cmpr(ebpf_bw_w, nt_bw_w), cmpr(ebpf_cpu, nt_cpu), 
                    cmpr(blkhist_lat_r["mean"], nt_lat_r["mean"]), blkhist_lat_r["50p"], blkhist_lat_r["90p"], blkhist_lat_r["99p"], 
                    cmpr(blkhist_lat_w["mean"], nt_lat_w["mean"]), blkhist_lat_w["50p"], blkhist_lat_w["90p"], blkhist_lat_w["99p"], 
                    cmpr(blkhist_bw_r, nt_bw_r), cmpr(blkhist_bw_w, nt_bw_w), cmpr(blkhist_cpu, nt_cpu)])  
        else: 
            writer.writerow([job_name, nt_lat_r["mean"], nt_lat_r["50p"], nt_lat_r["90p"], nt_lat_r["99p"], 
                    nt_lat_w["mean"], nt_lat_w["50p"], nt_lat_w["90p"], nt_lat_w["99p"], 
                    nt_bw_r, nt_bw_w, nt_cpu, 
                    ebpf_lat_r["mean"], ebpf_lat_r["50p"], ebpf_lat_r["90p"], ebpf_lat_r["99p"], 
                    ebpf_lat_w["mean"], ebpf_lat_w["50p"], ebpf_lat_w["90p"], ebpf_lat_w["99p"], 
                    ebpf_bw_r, ebpf_bw_w, ebpf_cpu, 
                    blkhist_lat_r["mean"], blkhist_lat_r["50p"], blkhist_lat_r["90p"], blkhist_lat_r["99p"], 
                    blkhist_lat_w["mean"], blkhist_lat_w["50p"], blkhist_lat_w["90p"], blkhist_lat_w["99p"], 
                    blkhist_bw_r, blkhist_bw_w, blkhist_cpu]) 
