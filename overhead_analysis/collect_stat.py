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


if not os.path.exists("stats"):
    os.mkdir("stats")

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
statdir = os.path.join("stats", timestamp)
os.mkdir(statdir)
print("Collecting stat and save to dir: %s" % statdir)

for outdir in os.listdir("."): 
    if outdir[:6] == "output": 
        stat = dict()
        task = outdir[7:]
        if not task:
            task = "baseline"
        
        for out_file in os.listdir(outdir): 
            job_name, out_format = out_file.split('.')
            job_stat = stat.setdefault(job_name, dict())
            file_path = os.path.join(outdir, out_file)
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
            else:   # .perf 
                with open(file_path, 'r') as perf_f:
                    job_stat["cpu"] = perf_f.readline().strip().split()

        with open(os.path.join(statdir, task + ".json"), "w") as json_w: 
            json.dump(stat, json_w, indent=2) 

        with open(os.path.join(statdir, task + ".csv"), "w") as csv_w: 
            writer = csv.writer(csv_w) 
            writer.writerow(["Job name", "Lat(us)", "50 Percentile", "90 Percentile", "99 Percentile", "BW(KB/s)",
                    "CPU-user", "CPU-nice", "CPU-system", "CPU-idle", "CPU-iowait", "CPU-irq", "CPU-softirq", 
                    "CPU-steal", "CPU-guest", "CPU-guest_nice", "CPU-total", "CPU-per-io"])

            for job_name in sorted(stat.keys()): 
                job_stat = stat[job_name]
                cpu_util = sum(job_stat["cpu"][:3] + job_stat["cpu"][5:])
                writer.writerow([job_name, job_stat["lat"]["mean"], job_stat["lat"]["50p"], job_stat["lat"]["90p"], 
                        job_stat["lat"]["99p"], job_stat["bw"]] + job_stat["cpu"] + [cpu_util, cpu_util*4./job_stat["bw"]])
