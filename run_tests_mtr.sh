#!/bin/bash

INTERFACE="eno2"
GATEWAY="149.43.152.1"
TSTAMP=`date +%Y%m%d%H%M%S`

euid=`id -u`
if [[ $euid != "0" ]]; then
    echo "Gotta be root"
    exit
fi

NDTHOSTS="ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-lga03.measurement-lab.org"
#NDTHOSTS="ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-sin01.measurement-lab.org ndt-iupui-mlab1-nbo01.measurement-lab.org ndt-iupui-mlab1-vie01.measurement-lab.org ndt-iupui-mlab1-dub01.measurement-lab.org ndt-iupui-mlab1-ams03.measurement-lab.org ndt-iupui-mlab1-mia03.measurement-lab.org ndt-iupui-mlab1-sea03.measurement-lab.org ndt-iupui-mlab1-dfw03.measurement-lab.org ndt-iupui-mlab1-akl01.measurement-lab.org"

python3 ./someta_testapi/eppt.py -q -I pass -l -f eppt_${TSTAMP} -i ${INTERFACE} ${NDTHOSTS} &
ebpfpid=$!

for host in $NDTHOSTS; do
    code=`echo ${host} | perl -ne '/mlab\d+-(\w{3})\d{2}/; print $1'`
    ./mtr/mtr -i 0.2 -l ${host} -c 3600 >> ${code}_mtr_${TSTAMP}.txt &
    mtrpid=$!
    ./go/bin/someta -v -f ${code} -M=cpu -M=rtt,interface=${INTERFACE},type=ping,dest=${GATEWAY} -c "./go/bin/ndt7-client -hostname ${host}"
    kill -TERM $mtrpid
    echo "done with ${code} ${TSTAMP}"
    echo "sleeping 30 seconds"
    sleep 30
done

kill -INT $ebpfpid
echo "all done!"
