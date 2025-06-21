from scapy.all import sniff, IP, TCP
import time

def test_packet_callback(packet):
    """Simple test callback"""
    if IP in packet:
        print(f"Captured packet: {packet[IP].src} -> {packet[IP].dst}")
        return True
    return False

def test_packet_capture():
    """Test basic packet capture functionality"""
    print("Testing packet capture...")
    print("Make sure you have Npcap installed and are running as Administrator")
    
    try:
        # Try to capture a few packets
        print("Capturing packets for 10 seconds...")
        packets = sniff(count=5, timeout=10, prn=test_packet_callback)
        
        if packets:
            print(f"Successfully captured {len(packets)} packets!")
            return True
        else:
            print("No packets captured. This might indicate:")
            print("1. Npcap is not installed")
            print("2. You're not running as Administrator")
            print("3. No network traffic on the interface")
            return False
            
    except Exception as e:
        print(f"Error during packet capture: {str(e)}")
        print("Please ensure Npcap is installed and you have administrative privileges")
        return False

if __name__ == "__main__":
    test_packet_capture() 