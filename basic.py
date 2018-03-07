import dpkt

from snortunsock import snort_listener

for msg in snort_listener.start_recv("/tmp/snort_alert"):
    print('alertmsg: %s' % ''.join(msg.alertmsg))
    buf = msg.pkt

    # buf is a raw packet which can use dpkt library to parsing it

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)