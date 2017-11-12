from tkinter import *
import subprocess
from dpkt import *
from socket import inet_ntop
from applications import get_applications

tcpdump = 0
active = False
apps = {}


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    try:
        return inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return inet_ntop(socket.AF_INET6, inet)


class GUI(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.grid()
        self.create_buttons()

    def create_buttons(self):
        label = Label(self, text="Press Start/Stop for Network Classification to Work")
        label.grid()

        startButton = Button(self, text="Start", command=start)
        startButton.grid()

        stopButton = Button(self, text="Stop", command=stop)
        stopButton.grid()


def create_gui():
    root = Tk()
    root.title("Internet Traffic Classifier")
    root.geometry("400x200")

    app = GUI(root)

    root.mainloop()


# TCPDump -> Capture Packets -> <maths> -> Identify Packets
# start capturing packets
def start():
    global tcpdump, active, apps

    if not active:
        active = True
        apps = get_applications()
        tcpdump = subprocess.Popen(['tcpdump', '-i', 'wlp2s0', '-w', 'cap.pcap'], stdout=subprocess.PIPE)


# What % packets (TCP/UDP -etc-) belong to which application over given time?
# stop capturing packets
def stop():
    global tcpdump, active

    if active:
        active = False
        tcpdump.terminate()
        analyse_packets()


"""
[LINK LAYER]                ->
[ETHERNET LAYER]            -> src, dst, type, data
[INTERNET PROTOCOL LAYER]   -> src, dst, data, p (protocol)

[TCP]   -> data, sport, dport, ack, seq
[UDP]   -> data, sport, dport
"""


def analyse_packets():
    global apps

    apps = get_applications()

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


if __name__ == "__main__":
    # create_gui()
    analyse_packets()
