# l7-in-nfqueue

As [l7](http://l7-filter.clearfoundation.com/start) for iptables is not updated for a long time,and I don't like to patch both kernel and iptables,so I try to write this script,which reads l7 pattern file and apply to layer 7 payloads,then decide whether to drop or accept.

This script is not tested widely at the moment,but at least could read qq.pat and forbid qq from logining.

## Usage:

First install [NetfilterQueue](http://pypi.python.org/pypi/NetfilterQueue),a python bindings for libnetfilter_queue,then run this script as root:

\# ./l7-in-nfqueue.py /path/to/your/l7_pattern_file

then use iptables' NFQUEUE to feed the script with certain packets,for example:

\# iptablles -A FORWARD -p tcp -j NFQUEUE --queue-num 1

## TODO

* Seems I need to get more familiar with l7 patterns,at the moment script could only parse pattern files with only one pattern
* Maybe I should support more than TCP and UDP?And also TCP and UDP header length are not always fixed,this should be considered.
* Print more information when dropping packets
* The most important:I shouldn't be so lazy,please clean TODOs above in one month(orz...).
