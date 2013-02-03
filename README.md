# l7-in-nfqueue

As [l7](http://l7-filter.clearfoundation.com/start) for iptables is not updated for a long time,and I don't like to patch both kernel and iptables,so I try to write this script,which reads l7 pattern file and apply to layer 7 payloads,then decide whether to drop or accept.

This script is not and maybe won't be tested widely.

## Usage:

First install [NetfilterQueue](http://pypi.python.org/pypi/NetfilterQueue),a python bindings for libnetfilter_queue,then run this script as root:

\# ./l7-in-nfqueue.py /path/to/your/l7_pattern_file

then use iptables' NFQUEUE to feed the script with certain packets,for example:

\# iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 1
\# iptables -A FORWARD -p udp -j NFQUEUE --queue-num 1

There are some limitations in regex for l7 kernel version,if you want to use regex similar to userspace version(the regex you may be more familliar with,see more in [pattern writing howto](http://l7-filter.clearfoundation.com/docs/pattern_writing_howto)),add -P option:

\# ./l7-in-nfqueue.py -P /path/to/your/l7_pattern_file

When package dropped,some information of the package will be printed,like this:
packet dropped,from 127.0.0.1:7070 to 127.0.0.1:55023 with length 79

## TODO

* ~~Seems I need to get more familiar with l7 patterns,at the moment script could only parse pattern files with only one pattern~~(seems familliar now?)
* ~~Maybe I should support more than TCP and UDP?And also TCP and UDP header length are not always fixed,this should be considered~~(supporting for TCP and UDP seems enough at the moment.IP and TCP headers' length are read from headers now.)
* ~~Print more information when dropping packets~~(Done)
* Read multiple pattern files once.(maybe won't be done because I'm too lazy)
