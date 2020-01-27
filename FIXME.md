# fixme list

 - name
   bandaid
   bpfinjector

 - output format: do csv; add metadata as comments at the top
   change filename stuff just `base.log` and `base.csv`.
   - easier import and analysis, and metadata is pretty simple
   - logfile can also have some metadata in it???
 - not clear whether it is avoiding probing non-responsive hops correctly
   (see cloudlab/utah results)

# done
 - parameterize probe rate
 - tcp ip4
 - icmp ip4
 - udp ipv4 
 - tcp ip6
 - udp ip6
 - icmp ip6
 - option to change return code for ingress (to allow icmp to pass to OS or to get dropped in XDP)
