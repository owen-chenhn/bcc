import os 

srcdir = "job_files"
destdir = "single_jobs"

if not os.path.exists(destdir):
    os.mkdir(destdir)

for fname in os.listdir(srcdir): 
    f_op = open(os.path.join(srcdir, fname), 'r')
    while True:
        line = f_op.readline()
        if not line: 
            break 
        if line == '\n': 
            continue
        
        line = line.strip() 
        if line == "[global]": 
            global_params = "[global]\n"
            while True: 
                line = f_op.readline()
                if not line.strip(): 
                    break 
                global_params += line 
            global_params += "\n" 
        
        else: 
            job_name = line[1:-1] 
            f_w = open(destdir + '/' + job_name + '.fio', 'w')
            f_w.write(global_params)
            f_w.write("[%s]\n" % job_name)             
            while True: 
                line = f_op.readline()
                if not line or line == '\n': 
                    break 
                f_w.write(line) 
            f_w.close() 

    f_op.close() 
