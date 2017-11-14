import sys
from subprocess import PIPE, Popen
import os
from dpkt import *
from socket import inet_ntop
from PyQt5.QtWidgets import QWidget, QPushButton, QHBoxLayout, QVBoxLayout, QApplication, QMainWindow


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
                # analyse_packets()
                self.statusBar().showMessage('Press start to start capturing')


def make_gui():
    app = QApplication(sys.argv)
    ex = GUI()
    sys.exit(app.exec_())


def analyse_packets():
    f = open("cap.pcap", 'rb')
    packets = pcap.Reader(f)
    for timestamp, packet in packets:
        eth = ethernet.Ethernet(packet)
        iproto = eth.data

        print(mac_addr(eth.src))
        print(inet_to_str(iproto.src))
        print(inet_to_str(iproto.dst))

        if type(iproto.data) == tcp.TCP:
            print("TCP")

        break
    os.remove("cap.pcap")


if __name__ == '__main__':
    make_gui()
    # analyse_packets()
