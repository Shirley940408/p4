from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('info')

# Network definition
net.addP4Switch('s1', device_id=1)
net.addP4Switch('s2', device_id=2)
net.addP4Switch('s3', device_id=3)
net.setP4Source('s1', './p4src/program.p4')
net.setP4Source('s2', './p4src/program.p4')
net.setP4Source('s3', './p4src/program.p4')
net.enableCpuPort('s1')
net.addHost('h1')
net.addHost('h2')
net.addHost('h3')
net.addHost('h4')
net.addLink('s1', 'h1', port1=1, port2=0)
net.addLink('s1', 's3', port1=2, port2=1)
net.addLink('s1', 's2', port1=3, port2=1)
net.addLink('s2', 'h2', port1=2, port2=0)
net.addLink('s3', 'h3', port1=2, port2=0)
net.addLink('s3', 'h4', port1=3, port2=0)

# Assignment strategy
net.l2()

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()
net.startNetwork()
