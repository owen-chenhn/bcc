# Run fio tests on different modes: 0 - blockhisto disabled; 1 - blockhisto enabled
# Place the fio job files in directory "job_files", and remove directory "single_jobs" so as to create one .fio file per job 
BCC=../bcc


function do_test {
    mkdir -p $outdir 
    for jobfile in ./job_files/*; do      # jobfile=./job_files/xxx.fio 
        for job in $(grep -o "\[.*\]" $jobfile | awk -F "[\[\]]" '{print $2}'); do
            if [ $job != "global" ]; then
                echo "Run job: $job at file: $jobfile"
                sudo perf stat -a -o $outdir/${job}.perf -- fio $jobfile --section=$job --output=$outdir/${job}.out --output-format="json" --idle-prof=system
            fi
        done
    done
}


if [ -z $1 ]
then 
    echo "Please input mode: 0 - blockhisto disabled; 1 - blockhisto enabled" 
    exit 
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
        sudo python ~/bcc/tools/blkrqhist.py &  # run ebpf script at backgroud 
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

if [ -d ./output -a -d ./output-ebpf -a -d ./output-blkhist ]; then
    echo "Collecting stat ..."
    python3 collect_stat.py
    echo "Tests finished. Stats are stored in directory stats/"
fi 