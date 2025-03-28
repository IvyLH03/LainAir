from scapy.all import rdpcap
import matplotlib.pyplot as plt


class FlowSpecifier:
  """
  Classify a flow based on source IP, destination IP, source port, destination port, and protocol (TCP/UDP).
  """
  def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
    self.src_ip = src_ip
    self.dst_ip = dst_ip
    self.src_port = src_port
    self.dst_port = dst_port
    self.protocol = protocol

  def __hash__(self):
    return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

  def __eq__(self, other):
    return (self.src_ip == other.src_ip and 
            self.dst_ip == other.dst_ip and 
            self.src_port == other.src_port and 
            self.dst_port == other.dst_port and 
            self.protocol == other.protocol)

  def __str__(self):
    """
    String representation of the FlowSpecifier object.
    This method returns a string that represents the flow specifier in a readable format.
    """
    return f"{self.protocol} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
  

class Flow:
  """
  define a Flow class to represent a flow that shares the same source ip, destination ip, source port, and destination port.
  """
  def __init__(self, flow_specifier: FlowSpecifier):
    self.flow_specifier = flow_specifier  # FlowSpecifier object to identify the flow
    self.src_ip = flow_specifier.src_ip  # Source IP address 
    self.dst_ip = flow_specifier.dst_ip  # Destination IP address
    self.src_port = flow_specifier.src_port  # Source port number
    self.dst_port = flow_specifier.dst_port  # Destination port number
    self.packets = []  # list to store packets in the flow
    
if __name__ == "__main__":
  pkts = rdpcap("captures/01/cap1.cap")  # read pcap file
  flows = {}
  print(pkts)
  for pkt in pkts:
    if 'TCP' in pkt:
      if 'IP' in pkt:
        flow_specifier = FlowSpecifier(
          src_ip=pkt['IP'].src,
          dst_ip=pkt['IP'].dst,
          src_port=pkt['TCP'].sport,
          dst_port=pkt['TCP'].dport,
          protocol='TCP'
        )
        print(pkt['TCP'].sport, pkt['TCP'].dport, pkt['IP'].src, pkt['IP'].dst)
      elif 'IPv6' in pkt:
        flow_specifier = FlowSpecifier(
          src_ip=pkt['IPv6'].src,
          dst_ip=pkt['IPv6'].dst,
          src_port=pkt['TCP'].sport,
          dst_port=pkt['TCP'].dport,
          protocol='TCP'
        )
        print(pkt['TCP'].sport, pkt['TCP'].dport, pkt['IPv6'].src, pkt['IPv6'].dst)
      else:
        print("TCP Packet does not contain IP layer information")
    elif 'UDP' in pkt:
      if 'IP' in pkt:
        flow_specifier = FlowSpecifier(
          src_ip=pkt['IP'].src,
          dst_ip=pkt['IP'].dst,
          src_port=pkt['UDP'].sport,
          dst_port=pkt['UDP'].dport,
          protocol='UDP'
        )
        print(pkt['UDP'].sport, pkt['UDP'].dport, pkt['IP'].src, pkt['IP'].dst)
      elif 'IPv6' in pkt:
        flow_specifier = FlowSpecifier(
          src_ip=pkt['IPv6'].src,
          dst_ip=pkt['IPv6'].dst,
          src_port=pkt['UDP'].sport,
          dst_port=pkt['UDP'].dport,
          protocol='UDP'
        )
        print(pkt['UDP'].sport, pkt['UDP'].dport, pkt['IPv6'].src, pkt['IPv6'].dst)
      else:
        print("UDP Packet does not contain IP layer information")
    else:
      # Handle other protocols (e.g., ICMP)
      print("Packet does not contain TCP or UDP layer information")
      continue
    if flow_specifier not in flows:
      # Create a new flow if it doesn't exist
      flows[flow_specifier] = Flow(flow_specifier)
    # Append the packet to the corresponding flow
    flows[flow_specifier].packets.append(pkt)
    for spec in flows:
      flow = flows[spec]
      print(f"{flow.flow_specifier} : Packets in flow: {len(flow.packets)}")
    
  # plot the distribution of the number of packets in each flow - number of packets and number of flows
  fig, ax = plt.subplots()
  # Extract the number of packets in each flow
  packet_counts = [len(flow.packets) for flow in flows.values()]
  # Create a histogram to visualize the distribution of packet counts
  ax.hist(packet_counts, bins=range(1, max(packet_counts) + 2), align='left', color='blue', alpha=0.7)
  ax.set_xlabel('Number of Packets in Flow')  # X-axis label
  ax.set_ylabel('Number of Flows')  # Y-axis label
  ax.set_title('Distribution of Packet Counts in Flows')  # Title of the plot
  ax.set_xticks(range(1, max(packet_counts) + 1))  # Set x-ticks to match the range of packet counts
  ax.grid(axis='y', alpha=0.75)  # Add grid lines for better readability
  plt.show()  # Display the plot

    
