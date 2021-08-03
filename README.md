# ELF: eBPF teLemetry Framework

ELF is a framework for active and passive measurement using the extended
Berkeley Packet Filter (eBPF).   The active measurement component can
be invoked (once dependencies are installed -- see `CLOUDLAB.md`) with
`elfprobe.py`.

# Installation

See `CLOUDLAB.md` for installation instructions for an Ubuntu 18.04 or 20.04 host.  These instructions were originally designed for our cloudlab experiments, but work for any standard Ubuntu host.

# Running

A minimal example of running ELF and injecting probes within packet streams created with a binary named `speedtest` is as follows:

```bash
$ sudo python3 elfprobe.py -i eno2 -a speedtest 
```

With the above command line, ELF will instrument any ICMP/TCP/UDP flows initiated with `speedtest`.  Probe results will be stored, by default, in `elf.csv`.  See the `-f` option to change the output file name.  

If there are specific destination addresses (v4 or v6) for which you want to instrument any flows, you can drop the `-a` option and list those names or addresses at the end of the `elfprobe.py` command line.

ELF will dump quite a bit of information to the console while it runs.  You can redirect this chatter to a logfile with `-l` and turn off console chatter with `-q`.  To increase the chatter, add `-d` (debug) option.

The full set of command line options are as follows (use `-h` to get the same):
```
$ sudo python3 elfprobe.py -h
usage: elfprobe.py [-h] [-I {pass,drop}] [-l] [-f FILEBASE] [-d] [-p PROBEINT]
                   [-P PID] [-a APP] [-r {g,global,h,perhop}] -i INTERFACE
                   [-T] [-e {ethernet,ipinip,ip6inip}] [-q]
                   [addresses [addresses ...]]

positional arguments:
  addresses             IP addresses of interest

optional arguments:
  -h, --help            show this help message and exit
  -I {pass,drop}, --ingress {pass,drop}
                        Specify how ingress ICMP time exceeded messages should
                        be handled: pass through to OS or drop in XDP
  -l, --logfile         Turn on logfile output
  -f FILEBASE, --filebase FILEBASE
                        Configure base name for log and data output files
  -d, --debug           Turn on debug logging
  -p PROBEINT, --probeint PROBEINT
                        Minimum probe interval (milliseconds)
  -P PID, --pid PID     Add PID for process of interest
  -a APP, --app APP     Add app name of interest
  -r {g,global,h,perhop}, --ratetype {g,global,h,perhop}
                        Probe rate type: global or per hop; default is per hop
                        => longer path for per-hop type implies higher
                        measurement probe rate
  -i INTERFACE, --interface INTERFACE
                        Interface/device to use
  -T, --notrunc         Don't truncate probe payload
  -e {ethernet,ipinip,ip6inip}, --encapsulation {ethernet,ipinip,ip6inip}
                        How packets are encapsulated on the wire
  -q, --quiet           Turn off logging to stdout (implies -l)
```

# Extending

See `elfhooks.c` for entrypoints that can be overridden to include your own code.  In `elfhooks.c` you could also define your own BPF map(s) and use them in your hooks.  The egress hooks are invoked just before recording information about the outgoing probe, but _after_ any probe modifications (and after emitting the original application packet).  The ingress hooks are invoked _after_ inspecting packet contents and prior to recording information in ELF's BPF maps.  See `elfprobe.c` for additional context for where those hooks are invoked.

# License

Copyright 2021 Joel Sommers and Ramakrishnan Durairajan.  All rights reserved.

The ELF software is distributed under terms of the GNU General Public License, version 3.  See below for the standard GNU GPL v3 copying text.


    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
