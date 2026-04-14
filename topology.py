from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink


def create_topology():
    #  IMPORTANT: specify OVSSwitch
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    #  Controller (Ryu default port = 6653)
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    # Switch (OpenFlow13 REQUIRED)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # Hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    # Links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    net.start()

    print("*** Network started")
    print("*** Controller should now connect")
    print("*** H4 (10.0.0.4) is blocked by firewall")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    create_topology()