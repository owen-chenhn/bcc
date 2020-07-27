import os 
import sys
import json
from datetime import datetime
import csv 


# function to compute increment in percent of target from compare
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
            fio_stat = fio_job["read"] 
            if fio_stat["bw"] == 0: 
                fio_stat = fio_job["write"]
            job_stat["lat"] = {
                "mean": round(fio_stat["lat"]["mean"], 2),
                "50p": fio_stat["clat"]["percentile"]["50.000000"], 
                "90p": fio_stat["clat"]["percentile"]["90.000000"],
                "99p": fio_stat["clat"]["percentile"]["99.990000"]
            }
            job_stat["bw"] = fio_stat["bw"] 
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
    writer.writerow(["Job name", "Lat(us)-NoTrace", "50 Percentile", "90 Percentile", "99 Percentile",  
            "BW(KB/s)-NoTrace", "CPU-NoTrace", 
            "Lat(us)-eBpf", "50 Percentile", "90 Percentile", "99 Percentile",  
            "BW(KB/s)-eBpf", "CPU-eBpf", 
            "Lat(us)-BlkHist", "50 Percentile", "90 Percentile", "99 Percentile",  
            "BW(KB/s)-BlkHist", "CPU-BlkHist"])

    for job_name in sorted(stat.keys()): 
        nt_stat, ebpf_stat, blkhist_stat = stat[job_name]["no-trace"], stat[job_name]["ebpf"], stat[job_name]["blkhist"]

        nt_lat, nt_bw, nt_cpu = nt_stat["lat"], nt_stat["bw"], nt_stat["cpu"]
        ebpf_lat, ebpf_bw, ebpf_cpu = ebpf_stat["lat"], ebpf_stat["bw"], ebpf_stat["cpu"]
        blkhist_lat, blkhist_bw, blkhist_cpu = blkhist_stat["lat"], blkhist_stat["bw"], blkhist_stat["cpu"]

        if analyflag: 
            writer.writerow([job_name, nt_lat["mean"], nt_lat["50p"], nt_lat["90p"], nt_lat["99p"], nt_bw, nt_cpu, 
                    cmpr(ebpf_lat["mean"], nt_lat["mean"]), ebpf_lat["50p"], ebpf_lat["90p"], ebpf_lat["99p"], 
                    cmpr(ebpf_bw, nt_bw), cmpr(ebpf_cpu, nt_cpu), 
                    cmpr(blkhist_lat["mean"], nt_lat["mean"]), blkhist_lat["50p"], blkhist_lat["90p"], blkhist_lat["99p"], 
                    cmpr(blkhist_bw, nt_bw), cmpr(blkhist_cpu, nt_cpu)]) 
        else: 
            writer.writerow([job_name, nt_lat["mean"], nt_lat["50p"], nt_lat["90p"], nt_lat["99p"], nt_bw, nt_cpu, 
                    ebpf_lat["mean"], ebpf_lat["50p"], ebpf_lat["90p"], ebpf_lat["99p"], ebpf_bw, ebpf_cpu, 
                    blkhist_lat["mean"], blkhist_lat["50p"], blkhist_lat["90p"], blkhist_lat["99p"], blkhist_bw, blkhist_cpu]) 
