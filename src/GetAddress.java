import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.Random;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

public class GetAddress {
	public static String getMacString(MacAddress mac){
	    StringBuilder sb = new StringBuilder(18);
	    for (byte b : mac.getAddress()) {
	        if (sb.length() > 0)
	            sb.append(':');
	        sb.append(String.format("%02x", b));
	    }
	    return sb.toString();
	}

	public static MacAddress getLocalMac(InetAddress ip) throws IOException {
		NetworkInterface inter = null;
		while((inter=NetworkInterface.getByInetAddress(ip))==null);
		byte[] mac = inter.getHardwareAddress();
		return MacAddress.getByAddress(mac);
	}
	
	public static MacAddress getMac(PcapHandle handle, InetAddress localIP, MacAddress localMac, InetAddress ip) throws IOException, PcapNativeException, NotOpenException {
		handle.sendPacket(Packets.buildArpPacket(ArpOperation.REQUEST, localIP, ip, localMac, MacAddress.ETHER_BROADCAST_ADDRESS));
		while(true){
			Packet packet = handle.getNextPacket();
			if (packet == null) continue;
			ArpPacket arp = packet.get(ArpPacket.class);
            if(arp.getHeader().getSrcProtocolAddr().equals(ip)&&arp.getHeader().getOperation().equals(ArpOperation.REPLY)){
                return arp.getHeader().getSrcHardwareAddr();
            }
		}
	}
	
	public static InetAddress getGateWayIP(String localIP) throws IOException{
        Process result = Runtime.getRuntime().exec("ipconfig");
        
        BufferedReader output = new BufferedReader(new InputStreamReader(result.getInputStream()));
        String str = new String();
        while ((str = output.readLine()) != null){
        	if(str.indexOf(localIP)>=0){
        		str = output.readLine();
        		str = output.readLine();
        		int length = str.length();
        		for(int i=0;i<length;i++){
        			if(str.charAt(i)>='0'&&str.charAt(i)<='9'){
        				str=str.substring(i);
        				return InetAddress.getByName(str);
        			}
        		}
        	}
        }
        return InetAddress.getByName(str);
	}
	
	public static InetAddress randomIPAddress() throws UnknownHostException{
	    Random rand = new Random();
	    StringBuffer str = new StringBuffer("192.168.");
	    str.append(rand.nextInt(255));
	    str.append(".");
	    str.append(rand.nextInt(255));
	    return InetAddress.getByName(str.toString());
	}
	
	
	public static MacAddress randomMACAddress(){
	    Random rand = new Random();
	    byte[] macAddr = new byte[6];
	    rand.nextBytes(macAddr);
	    macAddr[0] = (byte)(macAddr[0] & (byte)254); 
	    return MacAddress.getByAddress(macAddr);
	}
	
	public static void findAllDevices(PcapHandle handle, PcapHandle handleSend, InetAddress localIP, MacAddress localMac) throws UnknownHostException, PcapNativeException, NotOpenException{
		int timeout=1000;
		Listener listener = new Listener(handle);
		for(int i=0;i<255;i++)
			for(int i1=0;i1<255;i1++)
			{
				InetAddress ip = InetAddress.getByName("192.168."+i+'.'+i1);
				handleSend.sendPacket(Packets.buildArpPacket(ArpOperation.REQUEST, localIP, ip, localMac, MacAddress.ETHER_BROADCAST_ADDRESS));
			}
		System.out.println("Sent");
		while(timeout-->0);
		listener.stop();
	}
}
