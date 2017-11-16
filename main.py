import os
import xlrd
from subprocess import PIPE, Popen
from dpkt import *
from socket import inet_ntop
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTableWidgetItem, QFrame, \
    QHBoxLayout, QWidget, QDialog, QLabel, QLineEdit, QTableWidget
from PyQt5.QtCore import QCoreApplication, QRect, QMetaObject
import matplotlib.pyplot as plt
import numpy as np

protocol = {}


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    try:
        return inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return inet_ntop(socket.AF_INET6, inet)


class GUI(QDialog):
    def __init__(self):
        super().__init__()
        self.resize(570, 370)

        self.tcpdump = None
        self.active = False
        self.file = False

        self.horizontalLayoutWidget = QWidget(self)
        self.horizontalLayoutWidget.setGeometry(QRect(290, 280, 261, 61))
        self.horizontalLayout = QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.startButton = QPushButton(self.horizontalLayoutWidget)
        self.stopButton = QPushButton(self.horizontalLayoutWidget)
        self.fileName = QLineEdit(self)
        self.fileName.setGeometry(QRect(10, 300, 271, 21))
        self.table = QTableWidget(self)
        self.table.setGeometry(QRect(10, 10, 541, 271))

        # self.startButton.setStyleSheet("background-color: rgb(5,103,219)")
        # self.stopButton.setStyleSheet("background-color: rgb(20,99,222)")
        self.horizontalLayout.addWidget(self.startButton)
        self.horizontalLayout.addWidget(self.stopButton)
        self.startButton.clicked.connect(self.start)
        self.stopButton.clicked.connect(self.stop)

        self.line_2 = QFrame(self)
        self.line_2.setFrameShape(QFrame.HLine)
        self.line_2.setFrameShadow(QFrame.Sunken)
        self.line_2.setGeometry(QRect(10, 330, 541, 20))
        self.status = QLabel(self)
        self.status.setGeometry(QRect(10, 340, 541, 30))

        self.retranslateUi(self)
        QMetaObject.connectSlotsByName(self)

        self.show()

    def retranslateUi(self, Dialog):
        _translate = QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Internet Traffic Classifier"))
        self.startButton.setText(_translate("Dialog", "Start"))
        self.stopButton.setText(_translate("Dialog", "Stop"))
        self.status.setText(_translate("Dialog", "Press \'Start\' to start live capturing or enter \'.pcap\' file "
                                                 "path for offline analysis"))

    def start(self):
        if not self.active:
            self.active = True

            name = str(self.fileName.text())
            if name or len(name) != 0:
                self.file = True

                # Clearing table
                for i in reversed(range(self.table.rowCount())):
                    self.table.removeRow(i)

                self.fileName.setText("")
                if os.path.exists(name):
                    if name[-5:] == ".pcap":
                        freq, npackets = analyse_packets(name)
                        self.fill_table(freq=freq, npackets=npackets)

                        self.status.setText("Press \'Start\' to start live capturing or enter \'.pcap\' file "
                                            "path for offline analysis")
                    else:
                        self.status.setText("Not a valid \'.pcap\' file")
                else:
                    self.status.setText("Not a valid path")

                self.file = False
                self.active = False
            else:
                self.tcpdump = Popen(['tcpdump', '-i', 'wlp2s0', '-w', 'cap.pcap'], stdout=PIPE)

                self.startButton.setText("Capturing...")
                self.status.setText('Capturing live packets using tcpdump. Press stop to display results')

    def stop(self):
        if self.active and not self.file:
            self.active = False
            if self.tcpdump and self.tcpdump.poll() is None:
                self.tcpdump.terminate()
            self.startButton.setText("Analysing...")
            self.status.setText('Analysing packet capture')
            analyse_packets("cap.pcap")
            os.remove("cap.pcap")

            # Analysing Packets
            freq, npackets = analyse_packets("cap.pcap")
            self.fill_table(freq=freq, npackets=npackets)

            self.startButton.setText("Start")
            self.status.setText("Press \'Start\' to start live capturing or enter \'.pcap\' file "
                                "path for offline analysis")

    def fill_table(self, freq, npackets):
        print("Filling table")

        sizes = []
        for val in freq.values():
            sizes.append(str(round(((val / npackets) * 100), 2)) + '%')

        keys = list(freq.keys())
        rows = [list(a) for a in zip(keys, sizes)]

        # self.table = QTableWidget(len(rows), 2)

        self.table.insertColumn(0)
        self.table.insertColumn(1)

        header_labels = ['Protocol', 'Percentage']
        self.table.setHorizontalHeaderLabels(header_labels)
        for row in rows:
            inx = rows.index(row)
            self.table.insertRow(inx)
            self.table.setItem(inx, 0, QTableWidgetItem(str(row[0])))
            self.table.setItem(inx, 0, QTableWidgetItem(str(row[0])))
            self.table.setItem(inx, 0, QTableWidgetItem(str(row[0])))

        plot_graph(freq=freq, npackets=npackets)


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
    global protocol

    freq = {}
    f = open(file, 'rb')
    packets = pcap.Reader(f)
    totalPackets = 0
    for timestamp, packet in packets:
        totalPackets += 1

        eth = ethernet.Ethernet(packet)

        # ignore if no IP protocol
        if eth.type != ethernet.ETH_TYPE_IP:
            continue

        iproto = eth.data

        # ignore ICMP & IGMP packets
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
    return freq, totalPackets


def plot_graph(freq, npackets):
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
    plt.title("Protocol Percentages")
    plt.axis('equal')
    plt.tight_layout()
    plt.legend(patches, labels, loc="best")
    plt.show()


if __name__ == '__main__':
    get_protocols()
    make_gui()
