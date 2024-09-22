#!/usr/bin/env python3
import sys
import subprocess
from ipaddress import ip_network, summarize_address_range, ip_address
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget
from PyQt5 import QtCore

class SimpleApp(QMainWindow):
    """
    A simple PyQt5 application for managing IP blocking using iptables.
    """
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.blocked_ips = {}  # Dictionary to track blocked IPs for each file

        self.ams1_ips_blocked = False  # State variable to track if AMS1 IPs are blocked
        self.gan3_ips_blocked = False  # State variable to track if GAN3 IPs are blocked
        self.gbr1_ips_blocked = False  # State variable to track if GBR1 IPs are blocked
        self.gen1_ips_blocked = False  # State variable to track if GEN1 IPs are blocked
        self.gsg1_ips_blocked = False  # State variable to track if GSG1 IPs are blocked
        self.gtk1_ips_blocked = False  # State variable to track if GTK1 IPs are blocked
        self.guw2_ips_blocked = False  # State variable to track if GUW2 IPs are blocked
        self.icn1_ips_blocked = False  # State variable to track if ICN1 IPs are blocked
        self.las1_ips_blocked = False  # State variable to track if LAS1 IPs are blocked
        self.gmec1_ips_blocked = False  # State variable to track if GMEC1 IPs are blocked
        self.gmec2_ips_blocked = False  # State variable to track if GMEC2 IPs are blocked
        self.ord1_ips_blocked = False  # State variable to track if ORD1 IPs are blocked
        self.syd2_ips_blocked = False  # State variable to track if SYD2 IPs are blocked
        self.tpe1_ips_blocked = False  # State variable to track if TPE1 IPs are blocked

        self.clear_iptables()

    def init_ui(self):
        """
        Initializes the UI components of the application.
        """
        self.setWindowTitle('Overwatch Server Selector')
        self.setGeometry(100, 100, 400, 300)
        self.setFixedSize(300, 600)

        # Create a central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create a layout
        layout = QVBoxLayout()

        # Create a label
        self.label = QLabel('Select an Option below', self)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.label)

        self.block_ams1_button = QPushButton('EU Netherlands (ams1)', self)
        self.block_ams1_button.clicked.connect(self.toggle_ams1_ips)
        layout.addWidget(self.block_ams1_button)

        self.block_gan3_button = QPushButton('AS South Korea 3 (gan3)', self)
        self.block_gan3_button.clicked.connect(self.toggle_gan3_ips)
        layout.addWidget(self.block_gan3_button)

        self.block_gbr1_button = QPushButton('Brazil (gbr1)', self)
        self.block_gbr1_button.clicked.connect(self.toggle_gbr1_ips)
        layout.addWidget(self.block_gbr1_button)

        self.block_gen1_button = QPushButton('EU Finland (gen1)', self)
        self.block_gen1_button.clicked.connect(self.toggle_gen1_ips)
        layout.addWidget(self.block_gen1_button)

        self.block_gmec1_button = QPushButton('ME Qatar (gmec1)', self)
        self.block_gmec1_button.clicked.connect(self.toggle_gmec1_ips)
        layout.addWidget(self.block_gmec1_button)

        self.block_gmec2_button = QPushButton('ME KSA (gmec2)', self)
        self.block_gmec2_button.clicked.connect(self.toggle_gmec2_ips)
        layout.addWidget(self.block_gmec2_button)

        # Create a button to block/unblock IP addresses for GSG1
        self.block_gsg1_button = QPushButton('AS Singapore (gsg1)', self)
        self.block_gsg1_button.clicked.connect(self.toggle_gsg1_ips)
        layout.addWidget(self.block_gsg1_button)

        self.block_gtk1_button = QPushButton('AS Japan (gtk1)', self)
        self.block_gtk1_button.clicked.connect(self.toggle_gtk1_ips)
        layout.addWidget(self.block_gtk1_button)

        self.block_guw2_button = QPushButton('US West 2 (guw2)', self)
        self.block_guw2_button.clicked.connect(self.toggle_guw2_ips)
        layout.addWidget(self.block_guw2_button)

        self.block_icn1_button = QPushButton('AS South Korea 1 (icn1)', self)
        self.block_icn1_button.clicked.connect(self.toggle_icn1_ips)
        layout.addWidget(self.block_icn1_button)

        self.block_las1_button = QPushButton('US West (las1)', self)
        self.block_las1_button.clicked.connect(self.toggle_las1_ips)
        layout.addWidget(self.block_las1_button)

        self.block_ord1_button = QPushButton('US Central (ord1)', self)
        self.block_ord1_button.clicked.connect(self.toggle_ord1_ips)
        layout.addWidget(self.block_ord1_button)

        self.block_syd2_button = QPushButton('AU East (syd2)', self)
        self.block_syd2_button.clicked.connect(self.toggle_syd2_ips)
        layout.addWidget(self.block_syd2_button)

        self.block_tpe1_button = QPushButton('AS Taiwan (tpe1)', self)
        self.block_tpe1_button.clicked.connect(self.toggle_tpe1_ips)
        layout.addWidget(self.block_tpe1_button)

        # Create a button to clear all iptables rules
        self.clear_button = QPushButton('Clear All Rules', self)
        self.clear_button.clicked.connect(self.clear_iptables)
        layout.addWidget(self.clear_button)

        # Set the layout to the central widget
        central_widget.setLayout(layout)

    def toggle_ams1_ips(self):
        """
        Toggles the blocking/unblocking of AMS1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/AMS1.txt')
        if not self.ams1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('EU Netherlands (ams1) Selected.')
            self.block_ams1_button.setText('Unblock AMS1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('AMS1 IPs Unblocked!')
            self.block_ams1_button.setText('EU Netherlands (ams1)')
        self.ams1_ips_blocked = not self.ams1_ips_blocked

    def toggle_gan3_ips(self):
        """
        Toggles the blocking/unblocking of GAN3 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GAN3.txt')
        if not self.gan3_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('AS South Korea 3 (gan3) Selected.')
            self.block_gan3_button.setText('Unblock GAN3 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GAN3 IPs Unblocked!')
            self.block_gan3_button.setText('AS South Korea 3 (gan3)')
        self.gan3_ips_blocked = not self.gan3_ips_blocked

    def toggle_gbr1_ips(self):
        """
        Toggles the blocking/unblocking of GBR1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GBR1.txt')
        if not self.gbr1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('Brazil (gbr1) Selected.')
            self.block_gbr1_button.setText('Unblock GBR1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GBR1 IPs Unblocked!')
            self.block_gbr1_button.setText('Brazil (gbr1)')
        self.gbr1_ips_blocked = not self.gbr1_ips_blocked

    def toggle_gen1_ips(self):
        """
        Toggles the blocking/unblocking of GEN1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GEN1.txt')
        if not self.gen1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('EU Finland (gen1) Selected.')
            self.block_gen1_button.setText('Unblock GEN1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GEN1 IPs Unblocked!')
            self.block_gen1_button.setText('EU Finland (gen1)')
        self.gen1_ips_blocked = not self.gen1_ips_blocked

    def toggle_gmec1_ips(self):
        """
        Toggles the blocking/unblocking of GMEC1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GMEC1.txt')
        if not self.gmec1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('ME Qatar (gmec1) Selected.')
            self.block_gmec1_button.setText('Unblock GMEC1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GMEC1 IPs Unblocked!')
            self.block_gmec1_button.setText('ME Qatar (gmec1)')
        self.gmec1_ips_blocked = not self.gmec1_ips_blocked

    def toggle_gmec2_ips(self):
        """
        Toggles the blocking/unblocking of GMEC2 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GMEC2.txt')
        if not self.gmec2_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('ME KSA (gmec2) Selected.')
            self.block_gmec2_button.setText('Unblock GMEC2 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GMEC2 IPs Unblocked!')
            self.block_gmec2_button.setText('ME KSA (mec2)')
        self.gmec2_ips_blocked = not self.gmec2_ips_blocked

    def toggle_gsg1_ips(self):
        """
        Toggles the blocking/unblocking of GSG1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GSG1.txt')
        if not self.gsg1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('AS Singapore (gsg1) Selected.')
            self.block_gsg1_button.setText('Unblock GSG1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GSG1 IPs Unblocked!')
            self.block_gsg1_button.setText('AS Singapore (gsg1)')
        self.gsg1_ips_blocked = not self.gsg1_ips_blocked

    def toggle_gtk1_ips(self):
        """
        Toggles the blocking/unblocking of GTK1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GTK1.txt')
        if not self.gtk1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('AS Japan (gtk1) Selected.')
            self.block_gtk1_button.setText('Unblock GTK1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GTK1 IPs Unblocked!')
            self.block_gtk1_button.setText('AS Japan (gtk1)')
        self.gtk1_ips_blocked = not self.gtk1_ips_blocked

    def toggle_guw2_ips(self):
        """
        Toggles the blocking/unblocking of GUW2 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/GUW2.txt')
        if not self.guw2_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('US West 2 (guw2) Selected.')
            self.block_guw2_button.setText('Unblock GUW2 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('GUW2_IPs Unblocked!')
            self.block_guw2_button.setText('US West 2 (guw2)')
        self.guw2_ips_blocked = not self.guw2_ips_blocked

    def toggle_icn1_ips(self):
        """
        Toggles the blocking/unblocking of ICN1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/ICN1.txt')
        if not self.icn1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('AS South Korea (icn1) Selected.')
            self.block_icn1_button.setText('Unblock ICN1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('ICN1 IPs Unblocked!')
            self.block_icn1_button.setText('AS South Korea (icn1)')
        self.icn1_ips_blocked = not self.icn1_ips_blocked

    def toggle_las1_ips(self):
        """
        Toggles the blocking/unblocking of LAS1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/LAS1.txt')
        if not self.las1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('US West (las1) Selected.')
            self.block_las1_button.setText('Unblock LAS1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('LAS1 IPs Unblocked!')
            self.block_las1_button.setText('US West (las1)')
        self.las1_ips_blocked = not self.las1_ips_blocked

    def toggle_ord1_ips(self):
        """
        Toggles the blocking/unblocking of ORD1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/ORD1.txt')
        if not self.ord1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('US Central (ord1) Selected.')
            self.block_ord1_button.setText('Unblock ORD1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('ORD1 IPs Unblocked!')
            self.block_ord1_button.setText('US Central (ord1)')
        self.ord1_ips_blocked = not self.ord1_ips_blocked

    def toggle_syd2_ips(self):
        """
        Toggles the blocking/unblocking of SYD2 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/SYD2.txt')
        if not self.syd2_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('AU East (syd2) Selected.')
            self.block_syd2_button.setText('Unblock SYD2 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('SYD2 IPs Unblocked!')
            self.block_syd2_button.setText('AU East (syd2)')
        self.syd2_ips_blocked = not self.syd2_ips_blocked

    def toggle_tpe1_ips(self):
        """
        Toggles the blocking/unblocking of TPE1 IP addresses using iptables.
        """
        ip_list = self.read_ips_from_file('/home/zel/Scripts/ip_addresses/block/TPE1.txt')
        if not self.tpe1_ips_blocked:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('AS Taiwan (tpe1) Selected.')
            self.block_tpe1_button.setText('Unblock TPE1 IPs')
        else:
            for ip in ip_list:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            self.label.setText('TPE1 IPs Unblocked!')
            self.block_tpe1_button.setText('AS Taiwan (tpe1)')
        self.tpe1_ips_blocked = not self.tpe1_ips_blocked

    def read_ips_from_file(self, file_path):
        """
        Reads IP addresses from a file and returns them as a list.
        
        Args:
            file_path (str): The path to the file containing IP addresses.
        
        Returns:
            list: A list of IP addresses.
        """
        ip_list = []
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if '-' in line:
                    start_ip, end_ip = line.split('-')
                    start_ip = ip_address(start_ip.strip())
                    end_ip = ip_address(end_ip.strip())
                    for net in summarize_address_range(start_ip, end_ip):
                        ip_list.append(str(net))
                else:
                    ip_list.append(line)
        return ip_list

    def clear_iptables(self):
        """Clears all iptables rules and resets the UI state."""
        subprocess.run(['sudo', 'iptables', '-F'])

        self.label.setText('All Rules Cleared!')
        self.block_ams1_button.setText('EU Netherlands (ams1)')
        self.block_gan3_button.setText('AS South Korea 3 (gan3)')
        self.block_gbr1_button.setText('Brazil (gbr1)')
        self.block_gen1_button.setText('EU Finland (gen1)')
        self.block_gmec1_button.setText('ME KSA (gmec1)')
        self.block_gmec2_button.setText('ME Qatar (gmec2)')
        self.block_gsg1_button.setText('AS Singapore (gsg1)')
        self.block_gtk1_button.setText('AS Japan (gtk1)')
        self.block_guw2_button.setText('EU East (guw2)')
        self.block_icn1_button.setText('AS Korea (icn1)')
        self.block_las1_button.setText('US West (las1)')
        self.block_ord1_button.setText('US Central (ord1)')
        self.block_syd2_button.setText('AU East (syd2)')
        self.block_tpe1_button.setText('AS Taiwan (tpe1)')

        # Reset all state variables
        self.ams1_ips_blocked = False
        self.gan3_ips_blocked = False
        self.gbr1_ips_blocked = False
        self.gen1_ips_blocked = False
        self.gmec1_ips_blocked = False
        self.gmec2_ips_blocked = False
        self.gsg1_ips_blocked = False
        self.gtk1_ips_blocked = False
        self.guw2_ips_blocked = False
        self.icn1_ips_blocked = False
        self.las1_ips_blocked = False
        self.ord1_ips_blocked = False
        self.syd2_ips_blocked = False
        self.tpe1_ips_blocked = False

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SimpleApp()
    ex.show()
    sys.exit(app.exec_())
