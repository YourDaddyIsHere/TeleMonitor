from scapy.all import *
import atexit


class TSniffer(object):

    port_filter_string = ""
    #we only sniff the ports in the list
    dst_port_list = []
    src_port_list = []
    packets_to_write = []
    #how many packets per pcap file
    file_packet_size = 500

    #when the buffer_size reach file_packet_size, write it to file
    buffer_size = 0
    #the number of file we already create
    file_number = 0
    #start the sniffer
    #we sniff ALL PORTS, but only store those packets with ports in dst_port_list into pcap file
    def run(self):
        #we don't need a filter, we get down all packets we see
        sniff(prn=self.packet_handler, filter="", store=0)
    def add_dst_port(self,port):
        if port not in self.dst_port_list:
            print "add port "+str(port)
            self.dst_port_list.append(port)
            print "after adding, the dst port list is: "
            print self.dst_port_list
    def delete_dst_port(self,port):
        if port in self.dst_port_list:
            print "delete port "+str(port)
            self.dst_port_list.remove(port)
            print "after deleting, the dst port list is: "
            print self.dst_port_list
    def add_src_port(self,port):
        if port not in self.src_port_list:
            print "add port "+str(port)
            self.src_port_list.append(port)
            print "after adding, the src port list is: "
            print self.src_port_list
    def delete_src_port(self,port):
        if port in self.src_port_list:
            print "delete port "+str(port)
            self.src_port_list.remove(port)
            print "after deleting, the src port list is: "
            print self.src_port_list
    def packet_handler(self,pkt):
        #we first check is the packet coming from debugger
        #command packets are sent through UDP protocol so we only check UDP here
        if UDP in pkt:
            if str(pkt["UDP"]).find("T debugger add dst port:")>-1:
                #we receive an ADD dst port command
                prefix_index = str(pkt["UDP"]).find("T debugger add dst port:")
                index = prefix_index + len("T debugger add dst port:")
                port = int(str(pkt["UDP"])[index:index+5])
                self.add_dst_port(port)
            if str(pkt["UDP"]).find("T debugger delete dst port:")>-1:
                #we receive an delete dst port command
                prefix_index = str(pkt["UDP"]).find("T debugger delete dst port:")
                index = prefix_index + len("T debugger delete dst port:")
                port = int(str(pkt["UDP"])[index:index+5])
                self.delete_dst_port(port)
            if str(pkt["UDP"]).find("T debugger add src port:")>-1:
                #we receive an ADD SRC port command
                prefix_index = str(pkt["UDP"]).find("T debugger add src port:")
                index = prefix_index + len("T debugger add src port:")
                port = int(str(pkt["UDP"])[index:index+5])
                self.add_src_port(port)
            if str(pkt["UDP"]).find("T debugger delete src port:")>-1:
                #we receive an DELETE SRC port command
                prefix_index = str(pkt["UDP"]).find("T debugger delete src port:")
                index = prefix_index + len("T debugger delete src port:")
                port = int(str(pkt["UDP"])[index:index+5])
                self.delete_src_port(port)

        #OK, if we arrive here, that means the packet does not come from debugger
        src_port = None
        dest_port = None
        if UDP in pkt:
            dest_port = pkt["UDP"].dport 
            src_port = pkt["UDP"].sport 
        if TCP in pkt:
            dest_port = pkt["TCP"].dport
            src_port = pkt["TCP"].sport 
        if dest_port in self.dst_port_list or src_port in self.src_port_list: 
        #if True:
            #print "write packet to buffer"
            self.packets_to_write.append(pkt)
            self.buffer_size = self.buffer_size+1
            print self.buffer_size
            if self.buffer_size>self.file_packet_size:
                print "create a new file"
                wrpcap("testpcap"+str(self.file_number)+".pcap",self.packets_to_write)
                self.packets_to_write = []
                self.buffer_size=0
                self.file_number = self.file_number+1


def exit_handler(sn):
    print 'My application is ending!'
    wrpcap("testpcap"+str(sn.file_number)+".pcap",sn.packets_to_write)

if __name__ == '__main__':
    sniffer = TSniffer()
    sniffer.run()
    atexit.register(exit_handler,sniffer)


