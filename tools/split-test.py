"""
The unit test program for testing the split tracer. It performs one direct write to the device specified
by users, with the size that is 8 times greater than the maximum bio sector size supported by the device. 
The submitted bio should be split in 7 times, resulting in 7 lines of output records in the split tracer. 
The test checks that the number of lines of split output produced by the process is 7. 

It requires the path to the target device as input that the test writes to. It also requires the maximum 
bio sector size (in KB) supported by the device (which can be checked via /sys/block/sdX/queue/max_sectors_kb).
"""

import argparse
import os
from subprocess import Popen, PIPE
from signal import SIGINT
from time import sleep


def unit_test(target, size):
    """
    The unit testing function. It @target device that perform the test to, 
    and requires the maximum bio sector @size of the device. 
    """
    tracer_proc = Popen(["./biosplitmerge.py", "-S"], stdout=PIPE)
    sleep(5)

    comm = "dd if=/dev/zero of=%s bs=%dK count=1" % (args.device, 8*args.size)
    os.system(comm)

    print("Write finished. Sending Ctrl-C to tracer.")
    tracer_proc.send_signal(SIGINT)
    sleep(5)
    if tracer_proc.poll() is None:
        print("Tracer not terminated. Kill the tracer.")
        tracer_proc.kill()

    pid = str(os.getpid())
    count = 0
    for line in tracer_proc.stdout.readlines():
        if line.split()[3] == pid:
            count += 1
    assert count == 7


examples = """examples:
    sudo python split-test.py /dev/sdc 16    # Perform the test on disk /dev/sdc. The max sector size the device supports is 16KB. 
"""
parser = argparse.ArgumentParser(
    description="Unit test for Split/Merge tracer",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("device", type=str,
    help="The device that perform sample direct write to.")
parser.add_argument("size", type=int,
    help="Maximum bio sector size (in KB) the machine supports.")

args = parser.parse_args()


unit_test(args.device, args.size)

