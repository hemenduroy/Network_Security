from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' New imports here ... '''
import csv
import argparse
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
priority = 50000

l2config = "l2firewall.config"
l3config = "l3firewall.config"


class Firewall (EventMixin):

	def __init__ (self,l2config,l3config):
		self.listenTo(core.openflow)
		#self.disbaled_MAC_pair = [] # Shore a tuple of MAC pair which will be installed into the flow table of each switch.
        #self.fwconfig = list()
                #Port Security Implementation
                self.RecordTable = dict ()    # a list of mac addresses,ips and ports as described in the project document
                self.BannedTable = dict ()     # a list of blocked transactions



		if l2config == "":
			l2config="l2firewall.config"
			
		if l3config == "":
			l3config="l3firewall.config" 
		with open(l2config, 'rb') as rules:
			csvreader = csv.DictReader(rules) # Map into a dictionary
			for line in csvreader:
				# Read MAC address. Convert string to Ethernet address using the EthAddr() function.
                                if line['mac_0'] != 'any':
				    mac_0 = EthAddr(line['mac_0'])
                                else:
                                    mac_0 = None

                                if line['mac_1'] != 'any':
        				mac_1 = EthAddr(line['mac_1'])
                                else:
                                    mac_1 = None
				# Append to the array storing all MAC pair.
				#self.disbaled_MAC_pair.append((mac_0,mac_1))

		with open(l3config) as csvfile:
			log.debug("Reading log file !")
			self.rules = csv.DictReader(csvfile)
			for row in self.rules:
				log.debug("Saving individual rule parameters in rule dict !")
				currPrio = row['priority']
				sourcemac = row['src_mac']
				destmac = row['dst_mac']
				s_ip = row['src_ip']
				d_ip = row['dst_ip']
				s_port = row['src_port']
				d_port = row['dst_port']
				nw_proto = row['nw_proto']
				print "src_ip, dst_ip, src_port, dst_port", s_ip,d_ip,s_port,d_port
                                if s_ip == "any" and sourcemac != "any" and destmac == "any" and d_port == "any" and d_ip != "any" and s_port == "any" and nw_proto == "any":
                                    self.RecordTable [sourcemac] = [s_ip, d_ip, 'any']
                                if d_ip != "any" and sourcemac == "any" and destmac == "any" and s_ip != "any" and nw_proto == "any" and s_port == "any" and d_port == "any":
                                    self.RecordTable [sourcemac] = [s_ip, d_ip, 'any']
                                

		log.debug("Enabling Firewall Module")

	def replyToARP(self, packet, match, event):
		r = arp()
		r.opcode = arp.REPLY
		r.hwdst = match.dl_src
		r.protosrc = match.nw_dst
		r.protodst = match.nw_src
		r.hwsrc = match.dl_dst
		e = ethernet(type=packet.ARP_TYPE, src = r.hwsrc, dst=r.hwdst)
		e.set_payload(r)
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
		msg.in_port = event.port
		event.connection.send(msg)

	def allowOther(self, event, action=None):
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		#action = of.ofp_action_output(port = of.OFPP_NORMAL)
		msg.actions.append(action)
		event.connection.send(msg)

	def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		if(srcip != None):
			match.nw_src = IPAddr(srcip)
		if(dstip != None):
			match.nw_dst = IPAddr(dstip)	
                if(nwproto):
                        match.nw_proto = int(nwproto)
		match.dl_src = srcmac
		match.dl_dst = dstmac
		match.tp_src = sport
		match.tp_dst = dport
		match.dl_type = pkt.ethernet.IP_TYPE
		msg.match = match
		msg.hard_timeout = 0
		msg.idle_timeout = 200
                if priority + offset <= 65535:
                    msg.priority = priority + offset		
                else:
                    msg.priority = 65535

		event.connection.send(msg)

	def replyToIP(self, packet, match, event):
		srcmac = str(match.dl_src)
		dstmac = str(match.dl_src)
		sport = str(match.tp_src)
		dport = str(match.tp_dst)
		nwproto = str(match.nw_proto)

                with open(l3config) as csvfile:
                    self.rules = csv.DictReader(csvfile)
                    for row in self.rules:
                        currPrio = row['priority']
                        srcmac = row['src_mac']
                        dstmac = row['dst_mac']
                        s_ip = row['src_ip']
                        d_ip = row['dst_ip']
                        s_port = row['src_port']
                        d_port = row['dst_port']
                        nw_proto = row['nw_proto']
                        
                        srcmac1 = EthAddr(srcmac) if srcmac != 'any' else None
                        dstmac1 = EthAddr(dstmac) if dstmac != 'any' else None
                        s_ip1 = s_ip if s_ip != 'any' else None
                        d_ip1 = d_ip if d_ip != 'any' else None
                        s_port1 = int(s_port) if s_port != 'any' else None
                        d_port1 = int(d_port) if d_port != 'any' else None
                        prio1 = int(currPrio) if currPrio != None else priority
                        if nw_proto == "tcp":
                            nw_proto1 = pkt.ipv4.TCP_PROTOCOL
                        elif nw_proto == "icmp":
                            nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
                            s_port1 = None
                            d_port1 = None
                        elif nw_proto == "udp":
                            nw_proto1 = pkt.ipv4.UDP_PROTOCOL
                        else:
                            nw_proto1 = None
                        print (prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
                        self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)


	def _handle_ConnectionUp (self, event):
		''' Add your logic here ... '''

		'''
		Iterate through the disbaled_MAC_pair array, and for each
		'''
		self.connection = event.connection

		#for (source, destination) in self.disbaled_MAC_pair:

                for new_mac, new_records in self.RecordTable.items():

                        srcmac = new_mac
                        srcip = new_records[0]
                        dstip = new_records[1]
                        
			message = of.ofp_flow_mod()     
			match = of.ofp_match()          
                        if srcmac == 'any':
                            match.dl_src = None         
                        else:
                            match.dl_src = srcmac       
                        if srcip == 'any':
                            match.nw_src = None         
                        else:
                            match.nw_src = IPAddr(srcip)    
                        if dstip == 'any':
                            match.nw_dst = None         
                        else:
                            match.nw_dst = IPAddr(dstip)    
			message.priority = 65535 
                        match.dl_type = ethernet.IP_TYPE
			message.match = match			
                        
			event.connection.send(message) 

		#log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

        def addRuleToCSV(self, srcmac='any', srcip='any', dstip='any'):
            
            #log.debug("Entered addRuleToCSV")

            

            to_add = True
            for new_mac, new_records in self.BannedTable.items():
                if new_mac == str(srcmac) and new_records[0] == str(srcip) and new_records[1] == str(dstip):
                    log.debug("Duplicate entry")
                    to_add = False
                    break

            if to_add: 
                self.BannedTable [str(srcmac)] = [str(srcip), str(dstip)]
                # Open in append mode
                with open(l3config, 'a') as csvfile:
                    log.debug("new log entered")

                    csvwriter = csv.DictWriter(csvfile, fieldnames=[
                        'priority','src_mac','dst_mac','src_ip','dst_ip','src_port','dst_port','nw_proto',])
                    log.debug("added to dict")
                    csvwriter.writerow({
                        'priority': 32768,
                        'src_mac' : str(srcmac),
                        'dst_mac' : 'any',
                        'src_ip'  : str(srcip),
                        'dst_ip'  : str(dstip),
                        'src_port': 'any',
                        'dst_port': 'any',
                        'nw_proto': 'any',
                        })

        def checkSecPort(self, packet, match=None, event=None):

            log.debug("Inside checkSecPort function")

            srcmac = None
            srcip = None
            dstip = None

            if packet.type == packet.IP_TYPE:
                ip_packet = packet.payload
                if ip_packet.srcip == None or ip_packet.dstip == None:
                    log.debug("dont need this packet")
                    return True
                if packet.src not in self.RecordTable:        
                    for new_mac, new_records in self.RecordTable.items():
                        
                        if str(new_records[0]) == str(ip_packet.srcip):
                            log.debug("Duplicate MAC detected! IP %s  MAC %s port %s, start %s %s " %
                                (str(ip_packet.srcip), str(new_mac), str(new_records[1]), str(packet.src), str(event.port)))
                            
                            srcmac = None
                            srcip = str(ip_packet.srcip)
                            dstip = str(ip_packet.dstip)
                            self.addRuleToCSV ('any', srcip, dstip)
                            
                    self.RecordTable [packet.src] = [ip_packet.srcip, ip_packet.dstip, event.port]
                    log.debug("New entry is: %s, %s, %s, %s" %
                        (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                    return True
                else:                                           
                    if self.RecordTable.get(packet.src) == [ip_packet.srcip, ip_packet.dstip, event.port]:
                        log.debug("added: %s, %s, %s, %s" %
                            (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                        return True
                    else:
                        
                        newip = self.RecordTable.get(packet.src)[0]
                        newport = self.RecordTable.get(packet.src)[1]
                        
                        if newip != ip_packet.srcip:
                            log.debug("Fake IP! MAC %s IP %s port %s, start %s %s " %
                                (str(packet.src), str(newip), str(newport), str(ip_packet.dstip), str(event.port)))
                            
                            srcmac = str(packet.src)
                            srcip = None
                            dstip = str(ip_packet.dstip)
                            self.addRuleToCSV (srcmac, 'any', dstip)
                            
                        if newport != event.port:
                            log.debug("newport != event.port %s, MAC %s old: IP %s  %s], want %s " %
                                (str(newport), str(packet.src), str(ip_packet.srcip), str(event.port), str(ip_packet.dstip)))
                            return True

                        
                        return True

            if packet.type == packet.ARP_TYPE:
                
                return True

            srcmac = srcmac
            dstmac = None
            sport = None
            dport = None
            nwproto = str(match.nw_proto)

            
            self.installFlow(event, 32768, srcmac, None, srcip, dstip, None, None, nw_proto) #32768 prio least

            return False


	def _handle_PacketIn(self, event):

		packet = event.parsed
		match = of.ofp_match.from_packet(packet)

		if(match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST):

		    self.replyToARP(packet, match, event)

		if(match.dl_type == packet.IP_TYPE):

                    # Port Security check
                    if self.checkSecPort(packet, match, event):
                        log.debug("Safe...proceeding flow")
                    else:
                        log.debug("Under attack! halting flow...")


   
		    self.replyToIP(packet, match, event)


def launch (l2config="l2firewall.config",l3config="l3firewall.config"):
	'''
	Starting the Firewall module
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument('--l2config', action='store', dest='l2config',
					help='Layer 2 config file', default='l2firewall.config')
	parser.add_argument('--l3config', action='store', dest='l3config',
					help='Layer 3 config file', default='l3firewall.config')
	core.registerNew(Firewall,l2config,l3config)
