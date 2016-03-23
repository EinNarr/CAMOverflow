import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

class Sender implements Runnable {
	Thread sender;
	PcapHandle handle;
	InetAddress srcIP;
	InetAddress dstIP;
	MacAddress srcMac;
	MacAddress dstMac;
	int cap = 0;
	boolean sleep = false;
	Sender(PcapHandle handle, InetAddress srcIP, InetAddress dstIP, MacAddress srcMac, MacAddress dstMac) {
		sender = new Thread(this, "Sender Thread");
		this.handle = handle;
		this.srcIP = srcIP;
		this.dstIP = dstIP;
		this.srcMac = srcMac;
		this.dstMac = dstMac;
		sender.start();
	}

	public void run() {
		while (true) {
			try {
				handle.sendPacket(Packets.buildArpPacket(ArpOperation.REPLY, srcIP, dstIP, srcMac, dstMac));
				cap++;
			} catch (PcapNativeException | NotOpenException e) {}
			if(sleep) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {}
			}
		}
	}

}

class RandomSender implements Runnable {
	Thread sender;
	PcapHandle handle;
	int cap = 0;
	boolean sleep = false;
	RandomSender(PcapHandle handle) {
		sender = new Thread(this, "Sender Thread");
		this.handle = handle;
		sender.start();
	}

	public void run() {
		while (true) {
			try {
				handle.sendPacket(Packets.buildArpPacket(ArpOperation.REPLY, GetAddress.randomIPAddress(), GetAddress.randomIPAddress(), GetAddress.randomMACAddress(), GetAddress.randomMACAddress()));
				cap++;
			} catch (PcapNativeException | NotOpenException | UnknownHostException e) {}
			if(sleep) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {}
			}
		}
	}

}

class Listener implements Runnable {
	Thread listener;
	PcapHandle handle;
	boolean run = true;
	Listener(PcapHandle handle) {
		listener = new Thread(this, "Sender Thread");
		this.handle = handle;
		listener.start();
	}
	
	public void stop() {
		run = false;
	}

	public void run() {
		while(run){
			Packet packet = null;
			try {
				packet = handle.getNextPacket();
			} catch (NotOpenException e) {}
			if (packet == null) continue;
			ArpPacket arp = packet.get(ArpPacket.class);
            if(arp.getHeader().getOperation().equals(ArpOperation.REPLY)){
            	InetAddress ip = arp.getHeader().getSrcProtocolAddr();
            	MacAddress mac = arp.getHeader().getSrcHardwareAddr();
            	CAMOverflow.ip2Mac.put(ip, mac);
            	CAMOverflow.mac2IP.put(mac, ip);
            }
		}
	}
}