import java.net.InetAddress;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

public class Packets {
	public static Packet buildArpPacket(ArpOperation type, InetAddress srcIP, InetAddress dstIP,MacAddress srcMac,MacAddress dstMac){
		
		ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
		arpBuilder
		.hardwareType(ArpHardwareType.ETHERNET)
		.protocolType(EtherType.IPV4)
		.hardwareAddrLength((byte)MacAddress.SIZE_IN_BYTES)
		.protocolAddrLength((byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
		.operation(type)
		.srcHardwareAddr(srcMac)
		.srcProtocolAddr(srcIP)
		.dstHardwareAddr(dstMac)
		.dstProtocolAddr(dstIP);
	      
		EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
		etherBuilder
		.dstAddr(dstMac)
		.srcAddr(srcMac)
		.type(EtherType.ARP)
		.payloadBuilder(arpBuilder)
		.paddingAtBuild(true);

		return etherBuilder.build();
	}
	
	public static Packet doEvil(Packet sourcePacket) {
		return sourcePacket;
	}
	
}
