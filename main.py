import os

import time
import xlrd
from subprocess import PIPE, Popen
from PyQt5.QtWidgets import QApplication, QPushButton, QTableWidgetItem, QFrame, \
    QHBoxLayout, QWidget, QDialog, QLabel, QLineEdit, QTableWidget, QHeaderView
from PyQt5.QtCore import QCoreApplication, QRect, QMetaObject
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import *
from scapy.layers.inet import UDP, TCP

protocol = {}


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

        self.table.insertColumn(0)
        self.table.insertColumn(1)
        header_labels = ['Protocol', 'Percentage']
        self.table.setHorizontalHeaderLabels(header_labels)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

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

            # Clearing table
            for i in reversed(range(self.table.rowCount())):
                self.table.removeRow(i)

            name = str(self.fileName.text())
            if name or len(name) != 0:
                self.file = True

                self.fileName.setText("")
                if os.path.exists(name):
                    if name[-5:] == ".pcap":
                        self.startButton.setText("Analysing...")
                        self.status.setText('Analysing packet capture')

                        freq, npackets = analyse_packets(name)
                        self.fill_table(freq=freq, npackets=npackets)
                        # plot_graph(freq=freq, npackets=npackets)

                        self.startButton.setText("Start")
                        self.status.setText("Press \'Start\' to start live capturing or enter \'.pcap\' file "
                                            "path for offline analysis")
                    else:
                        self.status.setText("Not a valid \'.pcap\' file")
                else:
                    self.status.setText("Not a valid path")

                time.sleep(2)

                self.file = False
                self.active = False
        else:
            self.tcpdump = Popen(['tcpdump', '-i', 'wlp2s0', '-w', 'cap.pcap'], stdout=PIPE)

            self.startButton.setText("Capturing...")
            self.status.setText('Capturing live packets using tcpdump. Press stop to display results')

    def stop(self):
        if self.active and not self.file:

            self.startButton.setText("Analysing...")
            self.status.setText('Analysing packet capture')

            time.sleep(2)

            self.active = False
            if self.tcpdump and self.tcpdump.poll() is None:
                self.tcpdump.terminate()

            # Analysing Packets
            freq, npackets = analyse_packets("cap.pcap")
            self.fill_table(freq=freq, npackets=npackets)
            # plot_graph(freq=freq, npackets=npackets)

            self.startButton.setText("Start")
            self.status.setText("Press \'Start\' to start live capturing or enter \'.pcap\' file "
                                "path for offline analysis")

            os.remove("cap.pcap")

    def fill_table(self, freq, npackets):
        sizes = []
        for val in freq.values():
            sizes.append(str(round(((val / npackets) * 100), 2)) + '%')

        keys = list(freq.keys())
        rows = [list(a) for a in zip(keys, sizes)]

        for row in rows:
            inx = rows.index(row)
            self.table.insertRow(inx)
            self.table.setItem(inx, 0, QTableWidgetItem(str(row[0])))
            self.table.setItem(inx, 1, QTableWidgetItem(str(row[1])))


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
    totalPackets = 0

    with PcapReader(file) as packets:
        for packet in packets:
            totalPackets += 1
            if packet.haslayer(UDP) or packet.haslayer(TCP):
                port = packet.sport

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
