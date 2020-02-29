#!/bin/bash

CLOUDLABSITE="utah"
INTERFACE="eno49"
GATEWAY="128.110.152.1"
XHOME="/users/jsommers"
TSTAMP=`date +%Y%m%d%H%M%S`

euid=`id -u`
if [[ $euid != "0" ]]; then
    echo "Gotta be root"
    exit
fi

pushd $XHOME
NDTHOSTS="ndt-iupui-mlab1-lga03.measurement-lab.org ndt-iupui-mlab1-sin01.measurement-lab.org ndt-iupui-mlab1-nbo01.measurement-lab.org ndt-iupui-mlab1-vie01.measurement-lab.org ndt-iupui-mlab1-dub01.measurement-lab.org ndt-iupui-mlab1-ams03.measurement-lab.org ndt-iupui-mlab1-mia03.measurement-lab.org ndt-iupui-mlab1-sea03.measurement-lab.org ndt-iupui-mlab1-dfw03.measurement-lab.org ndt-iupui-mlab1-akl01.measurement-lab.org"

/usr/bin/python3 ${XHOME}/someta_testapi/someta_ebpf.py -q -l -f ${CLOUDLABSITE}_ebpf_${TSTAMP} -i ${INTERFACE} ${NDTHOSTS} &
ebpfpid=$!

for host in $NDTHOSTS; do
    code=`echo ${host} | /usr/bin/perl -ne '/mlab\d+-(\w{3})\d{2}/; print $1'`
    ${XHOME}/go/bin/someta -v -f ${CLOUDLABSITE}_${code} -M=cpu -M=rtt,interface=${INTERFACE},type=ping,dest=${GATEWAY} -c "${XHOME}/go/bin/ndt7-client -hostname ${host}"
    echo "done with ${code} ${TSTAMP}"
    echo "sleeping 30 seconds"
    sleep 30
done

kill -INT $ebpfpid
echo "all done!"
popd
