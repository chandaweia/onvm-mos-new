#! /bin/bash

min=$1
max=$2
online=$3

for ((c=$min; c<=$max; ++c))
do
        CPU_PATH=/sys/devices/system/cpu/cpu$c
        echo $online > $CPU_PATH/online
done

