# Run fio tests on different modes: 0 - blockhisto disabled; 1 - blockhisto enabled
# Place the fio job files in directory "job_files"
# Modify the varible BCC_script in this file to point to the bcc script that is going to run

BCC_script=~/bcc/tools/blkrqhist.py

if [ ! -d "job_files" ]; then 
    echo "Directory job_files not exist" 
    exit 1 
done 
if [ ! -d "single_jobs" ]
then 
    echo "Split job files ..."
    python3 split_jobs.py
fi 


function do_test {
    if [ "$(ls -A ./job_files/)" ] 
    then 
        mkdir -p $outdir 
        for jobfile in ./single_jobs/*      # jobfile=./single_jobs/xxx.fio
        do 
            echo "Run job file: $jobfile"
            filename=${jobfile##*/}
            sudo perf stat -a -o $outdir/${filename%fio}perf -- fio $jobfile --output=$outdir/${filename%fio}out --output-format="json" --idle-prof=system
        done
    else 
        echo "No job files in dir job_files/" 
        exit 1
    fi 
}


if [ -z $1 ]
then 
    echo "Please input mode: 0 - blockhisto disabled; 1 - blockhisto enabled" 
    exit 1
fi 

for cnt in 1 2
do 
    if [ $cnt -eq 1 -a $1 -eq 0 ]
    then 
        outdir=./output
        echo "Run without tracing"

    elif [ $cnt -eq 1 -a $1 -eq 1 ] 
    then
        outdir=./output-blkhist
        echo "Run with block histogram enabled"

    elif [ $cnt -eq 2 -a $1 -eq 0 ]
    then
        outdir=./output-ebpf
        echo "Run with eBpf tracing"
        sudo python $BCC_script &  # run ebpf script at backgroud 
        pid=$!
        sleep 3     # ensure tracing tool has started

    else
        outdir=""
    fi 

    if [ ! -z $outdir ] 
    then 
        do_test
    fi

    if [ $cnt -eq 2 -a $1 -eq 0 ]
    then
        # kill ebpf tracing script at background 
        sudo kill -s 2 $pid
        echo "EBpf tracing stoped." 
    fi 

    echo "Current run of tests finished."
done

if [ -d ./output -a -d ./output-ebpf -a -d ./output-blkhist ]
then 
    mkdir -p stats 
    echo "Collecting stat ..."
    python3 collect_stat.py
    echo "Tests finished. Stats are stored in directory stats/"
    echo "To obtain analysis results, run again the python script with analysis mode on:"
    echo "$ python3 collect_stat.py 1"
fi
