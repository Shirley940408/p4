from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


class Controller(object):

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        self.init()

    def init(self):
        self.controller.reset_state()

    def fill_table(self):
        # 1. 防火墙规则：阻止来自 h1 (00:00:0a:00:00:01) 的所有流量
        self.controller.table_add("smac", "drop", ['00:00:0a:00:00:01'], [])

        # 2. 转发规则：所有主机 (包括 h1) 的目的 MAC 转发映射
        self.controller.table_add("dmac", "forward", ['00:00:0a:00:00:01'], ['1'])
        self.controller.table_add("dmac", "forward", ['00:00:0a:00:00:02'], ['2'])
        self.controller.table_add("dmac", "forward", ['00:00:0a:00:00:03'], ['3'])
        self.controller.table_add("dmac", "forward", ['00:00:0a:00:00:04'], ['4'])
    
    def dump_table(self):
        # 打印 smac 和 dmac 两个表的内容
        print("=== Dumping smac table ===")
        self.controller.table_dump("smac")
        print("\n=== Dumping dmac table ===")
        self.controller.table_dump("dmac")
        return None


if __name__ == "__main__":
    import sys
    sw_name = 's1'
    controller = Controller(sw_name)
    controller.fill_table()
    controller.dump_table()