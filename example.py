# example.py
# by: Madeleine Duke
# purpose: this program will send a message when a specific dash button is
#          pressed

from scapy.all import *

def arp_detect(pkt):
        if pkt.haslayer(ARP):
                if pkt[ARP].op == 1: #network request
                        # the following line will be used when finding the MAC
                        # address of the button
                        #
                        # for the first part, all that has to be done is run
                        # the program with the following line, an then see
                        # which MAC address is printed when the button is
                        # pressed while the program is running
                        #
                        # print pkt[ARP].hwsrc


                        # the following lines can be commented out while
                        # finding the MAC address, and then returned to
                        # the usable code once the MAC address has been
                        # found
                        #
                        # for a more complicated program, where "Button
                        # Pressed" is returned, more can be done, including
                        # packet manipulation and spoofing
                        if pkt[ARP].hwsrc == "78:e1:03:72:63:ae": # MAC address
                                return "Button Pressed"           # my button

print sniff(prn=arp_detect, filter="arp", store=0, count=0)
                                                                     
