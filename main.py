import os
from subprocess import PIPE, Popen
from dpkt import *
from socket import inet_ntop
from PyQt5.QtWidgets import QPushButton, QApplication, QMainWindow
import xlrd

protocol = {}
freq = {}


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    try:
        return inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return inet_ntop(socket.AF_INET6, inet)


class GUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.tcpdump = None
        self.active = False

        self.initUI()

    def initUI(self):
        startButton = QPushButton("Start", self)
        stopButton = QPushButton("Stop", self)

        startButton.clicked.connect(self.start)
        stopButton.clicked.connect(self.stop)

        startButton.move(270, 300)
        stopButton.move(380, 300)

        self.statusBar().showMessage('Press start to start capturing')

        self.setGeometry(500, 500, 500, 350)
        self.setWindowTitle('Layer-7 Classification')
        self.show()

    def start(self):
        if not self.active:
            self.active = True
            self.tcpdump = Popen(['tcpdump', '-i', 'wlp2s0', '-w', 'cap.pcap'], stdout=PIPE)
            self.statusBar().showMessage('Capturing live packets using tcpdump. Press stop to display results')

    def stop(self):
        if self.active:
            self.active = False
            if self.tcpdump.poll() is None:
                self.tcpdump.terminate()
                self.statusBar().showMessage('Analysing packet capture')
                analyse_packets("cap.pcap")
                os.remove("cap.pcap")
                self.statusBar().showMessage('Press start to start capturing')


def make_gui():
    app = QApplication(sys.argv)
    ex = GUI()
    sys.exit(app.exec_())


def get_protocols():
    global protocol

    file = xlrd.open_workbook('Protocols.xlsx')
    sheet = file.sheet_by_index(0)

    for i in range(sheet.nrows):
        if i == 0:
            continue

        port = sheet.cell(i, 1).value
        if '-' in str(port):
            (start, dash, end) = port.partition('-')
            start = int(start)
            end = int(end)
            while start <= end:
                protocol[start] = sheet.cell(i, 3).value.lower()
                start += 1
        else:
            port = sheet.cell(i, 1).value
            if port != '':
                port = int(port)
                if sheet.cell(i, 0).value == '':
                    protocol[port] = sheet.cell(i, 3).value.lower()
                else:
                    protocol[port] = sheet.cell(i, 0).value


def analyse_packets(file):
    global freq, protocol

    f = open(file, 'rb')
    packets = pcap.Reader(f)
    for timestamp, packet in packets:
        eth = ethernet.Ethernet(packet)

        # ignore if no IP protocol
        if eth.type != ethernet.ETH_TYPE_IP:
            continue

        iproto = eth.data

        # ignore ICMP packets
        if isinstance(iproto.data, icmp.ICMP) or isinstance(iproto.data, igmp.IGMP):
            continue

        port = iproto.data.sport

        if port not in protocol.keys():
            if 'others' not in freq.keys():
                freq['others'] = 1
            else:
                freq['others'] += 1
        else:
            prot = protocol[port]
            if prot not in freq.keys():
                freq[prot] = 1
            else:
                freq[prot] += 1


def plot_graph(npackets):
    global freq

    import matplotlib.pyplot as plt
    import numpy as np

    sizes = []
    for val in freq.values():
        sizes.append(str(round(((val / npackets) * 100), 2)) + '%')
    label = list(freq.keys())
    labels = []
    z = zip(label, sizes)
    for tup in z:
        labels.append(' - '.join(tup))

    # Data to plot
    cmap = plt.get_cmap('viridis')
    labels = tuple(labels)
    sizes = list(freq.values())
    colors = cmap(np.linspace(0, 1, len(labels)))

    patches, texts = plt.pie(sizes, colors=colors, shadow=True, startangle=90)
    plt.axis('equal')
    plt.tight_layout()
    plt.legend(patches, labels, loc="best")
    plt.show()


if __name__ == '__main__':
    get_protocols()
    # make_gui()
    analyse_packets("cap.pcap")
    plot_graph(2740)
