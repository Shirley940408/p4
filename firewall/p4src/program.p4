/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    macAddr_t senderMac;
    ip4Addr_t senderIp;
    macAddr_t targetMac;
    ip4Addr_t targetIp;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(4096) counters;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dst_mac, bit<9> egress_port) {
        hdr.ethernet.dstAddr = dst_mac;
        standard_metadata.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action arp_forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    action ids_drop() {
        bit<32> index = (bit<32>)hdr.ipv4.srcAddr ^ ((bit<32>)hdr.ipv4.dstAddr << 8) ^ ((bit<32>)hdr.ipv4.protocol << 24);
        bit<16> flow_idx = (bit<16>)(index[11:0]);
        bit<32> count;
        counters.read(count, (bit<32>)flow_idx);
        count = count + 1;
        counters.write((bit<32>)flow_idx, count);
        mark_to_drop(standard_metadata);
    }

    table ip_filter {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            ids_drop;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop;
    }

    table arp_table {
        key = {
            hdr.arp.targetIp: exact;
        }
        actions = {
            arp_forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        if (hdr.arp.isValid()) {
            arp_table.apply();
        } else if (hdr.ipv4.isValid()) {
            if (ip_filter.apply().hit) {
                // IDS matched; packet is dropped and counter updated.
            } else {
                ipv4_lpm.apply();
            }
        } else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;