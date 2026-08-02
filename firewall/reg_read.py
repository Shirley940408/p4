#!/usr/bin/env python3
import time

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


FLOW_ENTRIES = 4096
REGISTER_NAME = "counters"


class RegReader:
    def __init__(self, sw_name="s1"):
        self.topo = load_topo("topology.json")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.client = SimpleSwitchThriftAPI(self.thrift_port)

    def read_register(self, reg_name, index):
        if hasattr(self.client, "register_read"):
            return self.client.register_read(reg_name, index)
        if hasattr(self.client, "read_register"):
            return self.client.read_register(reg_name, index)
        raise AttributeError("No register read API found in SimpleSwitchThriftAPI")

    def dump_nonzero(self):
        print(f"Reading register {REGISTER_NAME} from switch {self.sw_name}")
        for i in range(FLOW_ENTRIES):
            try:
                value = self.read_register(REGISTER_NAME, i)
                if isinstance(value, list):
                    value = value[0]
                if value != 0:
                    print(f"flow[{i}] = {value}")
            except Exception:
                pass

    def watch(self, interval=2):
        while True:
            self.dump_nonzero()
            time.sleep(interval)


if __name__ == "__main__":
    RegReader("s1").watch()