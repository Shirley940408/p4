#!/usr/bin/env python3
import threading
import time

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff


class Controller(object):
    def __init__(self, sw_name="s1"):
        self.topo = load_topo("topology.json")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        self.cpu_port_iface = self._get_cpu_iface()
        self.init()

    def _get_cpu_iface(self):
        try:
            # 1. 优先使用 p4utils 官方提供的获取 CPU 接口名称的 API
            if hasattr(self.topo, "get_cpu_port_intf"):
                iface = self.topo.get_cpu_port_intf(self.sw_name)
                if iface:
                    return iface

            # 2. 备用逻辑：使用正确的 get_nodes() 方法遍历节点
            for node in self.topo.get_nodes():
                # 判断节点名称是否匹配
                node_name = getattr(node, "name", None) or (
                    node.get("name") if isinstance(node, dict) else None
                )
                if node_name == self.sw_name:
                    iface = getattr(node, "cpu_port_iface", None) or (
                        node.get("cpu_port_iface")
                        if isinstance(node, dict)
                        else None
                    )
                    if iface:
                        return iface
        except Exception as e:
            print(f"[WARN] Failed to automatically resolve cpu iface: {e}")

        # 默认回退接口名称 (在 Linux 下与 CPU port 对应)
        return f"{self.sw_name}-cpu-eth0"

    def init(self):
        self.controller.reset_state()

    def fill_table(self):
        try:
            self.controller.table_add("ip_filter", "ids_drop", ["10.0.0.1", "0x06"], [])
        except Exception:
            pass

        # 补全 IPv4 LPM
        try:
            self.controller.table_add("ipv4_lpm", "ipv4_forward", ["10.0.0.1/32"], ["00:00:0a:00:00:01", "1"])
            self.controller.table_add("ipv4_lpm", "ipv4_forward", ["10.0.0.2/32"], ["00:00:0a:00:00:02", "2"])
            self.controller.table_add("ipv4_lpm", "ipv4_forward", ["10.0.0.3/32"], ["00:00:0a:00:00:03", "3"])
            self.controller.table_add("ipv4_lpm", "ipv4_forward", ["10.0.0.4/32"], ["00:00:0a:00:00:04", "4"])
        except Exception:
            pass

        # 补全 ARP 表（非常关键！）
        try:
            self.controller.table_add("arp_table", "arp_forward", ["10.0.0.1"], ["1"])
            self.controller.table_add("arp_table", "arp_forward", ["10.0.0.2"], ["2"])
            self.controller.table_add("arp_table", "arp_forward", ["10.0.0.3"], ["3"])
            self.controller.table_add("arp_table", "arp_forward", ["10.0.0.4"], ["4"])
        except Exception:
            pass
            
    def dump_table(self):
        for table_name in ["ip_filter", "ipv4_lpm", "signatures", "flows"]:
            try:
                print(f"=== Dumping {table_name} table ===")
                self.controller.table_dump(table_name)
            except Exception:
                pass

    def _handle_cpu_packet(self, pkt):
        ether = pkt.getlayer(Ether)
        if ether is None:
            print("[ALERT] received non-Ethernet packet on CPU port")
            return

        print(
            "[ALERT] intrusion packet received: "
            f"src={ether.src}, dst={ether.dst}, type=0x{ether.type:04x}, len={len(bytes(pkt))}"
        )
        print(pkt.summary())

    def listen_alerts(self):
        print(f"[INFO] listening for IDS alerts on {self.cpu_port_iface}")
        sniff(
            iface=self.cpu_port_iface,
            prn=self._handle_cpu_packet,
            store=False,
        )

    def run(self):
        self.fill_table()
        self.dump_table()

        # t = threading.Thread(target=self.listen_alerts, daemon=True)
        # t.start()

        print("[INFO] controller is running")


if __name__ == "__main__":
    Controller("s1").run()