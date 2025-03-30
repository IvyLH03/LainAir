from scapy.all import rdpcap
import matplotlib.pyplot as plt


class FlowSpecifier:
  """
  Classify a flow based on source IP, destination IP, source port, destination port, and protocol (TCP/UDP).
  """
  def __init__(self, ip_1, ip_2, port_1, port_2, protocol):
    # ipv4 private address
    if ip_2.startswith("192.168") or ip_2.startswith("10.") or ip_2.startswith("172.16"):
      ip_1, ip_2 = ip_2, ip_1
      port_1, port_2 = port_2, port_1


    # ipv6 private address
    if ip_2.startswith("fd") or ip_2.startswith("fc"):
      ip_1, ip_2 = ip_2, ip_1
      port_1, port_2 = port_2, port_1

    self.ip_1 = ip_1
    self.ip_2 = ip_2
    self.port_1 = port_1
    self.port_2 = port_2
    self.protocol = protocol

  def __hash__(self):
    return hash((self.ip_1, self.ip_2, self.port_1, self.port_2, self.protocol))

  # two are equal if two ip,port pairs are equal, no matter the order of 1 or 2
  def __eq__(self, other):
    return (
      (self.ip_1 == other.ip_1 and self.ip_2 == other.ip_2 and self.port_1 == other.port_1 and self.port_2 == other.port_2 and self.protocol == other.protocol) or
      (self.ip_1 == other.ip_2 and self.ip_2 == other.ip_1 and self.port_1 == other.port_2 and self.port_2 == other.port_1 and self.protocol == other.protocol)
    )

  def __str__(self):
    """
    String representation of the FlowSpecifier object.
    This method returns a string that represents the flow specifier in a readable format.
    """
    return f"{self.protocol} {self.ip_1}:{self.port_1} <-> {self.ip_2}:{self.port_2}"
  

class Flow:
  """
  define a Flow class to represent a flow that shares the same source ip, destination ip, source port, and destination port.
  """
  def __init__(self, flow_specifier: FlowSpecifier):
    self.flow_specifier = flow_specifier  # FlowSpecifier object to identify the flow
    self.ip_1 = flow_specifier.ip_1  # Source IP address 
    self.ip_2 = flow_specifier.ip_2  # Destination IP address
    self.port_1 = flow_specifier.port_1  # Source port number
    self.port_2 = flow_specifier.port_2  # Destination port number
    self.packets = []  # list to store packets in the flow

  def get_incoming_packets(self):
    """
    Return a list of incoming packets in the flow.
    """
    if 'TCP' in self.packets[0]:
      return [pkt['TCP'] for pkt in self.packets if pkt['IP'].src == self.ip_2]
    elif 'UDP' in self.packets[0]:
      return [pkt['UDP'] for pkt in self.packets if pkt['IP'].src == self.ip_2]
    else:
      return []
  
  def plot(self, plot_first_n_packets=None):
    """
    Plot the time series of the packet length of incoming packets in the flow.
    """
    # choose incoming packets
    incoming_packets = self.get_incoming_packets()
    if plot_first_n_packets:
      incoming_packets = incoming_packets[:plot_first_n_packets]

    packet_lengths = [len(pkt) for pkt in incoming_packets]
    packet_time = [pkt.time for pkt in incoming_packets]
    first_packet_time = packet_time[0]
    inter_arrival_times = [pkt.time - first_packet_time for pkt in incoming_packets]

    # plot the time series of packet length
    plt.plot(inter_arrival_times, packet_lengths)
    plt.xlabel("Time (s)")
    plt.ylabel("Packet Length (bytes)")
    plt.title(f"Packet Length of Flow {self.flow_specifier}")

    # mark the arrival time of the packets with red dots
    for i in range(len(inter_arrival_times)):
      plt.scatter(inter_arrival_times[i], packet_lengths[i], color='red', s=10)


    plt.show()

  

def classify_flows(packets):
  """
  classify flows based on the packets
  return a list of flows sorted by the number of packets in descending order
  """    
  flows = {}
  for pkt in pkts:
    if 'TCP' in pkt:
      if 'IP' in pkt:
        flow_specifier = FlowSpecifier(
          ip_1=pkt['IP'].src,
          ip_2=pkt['IP'].dst,
          port_1=pkt['TCP'].sport,
          port_2=pkt['TCP'].dport,
          protocol='TCP'
        )
        # print(pkt['TCP'].sport, pkt['TCP'].dport, pkt['IP'].src, pkt['IP'].dst)
      elif 'IPv6' in pkt:
        flow_specifier = FlowSpecifier(
          ip_1=pkt['IPv6'].src,
          ip_2=pkt['IPv6'].dst,
          port_1=pkt['TCP'].sport,
          port_2=pkt['TCP'].dport,
          protocol='TCP'
        )
        # print(pkt['TCP'].sport, pkt['TCP'].dport, pkt['IPv6'].src, pkt['IPv6'].dst)
      else:
        print("TCP Packet does not contain IP layer information")
    elif 'UDP' in pkt:
      if 'IP' in pkt:
        flow_specifier = FlowSpecifier(
          ip_1=pkt['IP'].src,
          ip_2=pkt['IP'].dst,
          port_1=pkt['UDP'].sport,
          port_2=pkt['UDP'].dport,
          protocol='UDP'
        )
        # print(pkt['UDP'].sport, pkt['UDP'].dport, pkt['IP'].src, pkt['IP'].dst)
      elif 'IPv6' in pkt:
        flow_specifier = FlowSpecifier(
          ip_1=pkt['IPv6'].src,
          ip_2=pkt['IPv6'].dst,
          port_1=pkt['UDP'].sport,
          port_2=pkt['UDP'].dport,
          protocol='UDP'
        )
        # print(pkt['UDP'].sport, pkt['UDP'].dport, pkt['IPv6'].src, pkt['IPv6'].dst)
      else:
        print("UDP Packet does not contain IP layer information")
    else:
      # Handle other protocols (e.g., ICMP)
      print("Packet does not contain TCP or UDP layer information")
      print(pkt.summary())
      continue
    if flow_specifier not in flows:
      # Create a new flow if it doesn't exist
      flows[flow_specifier] = Flow(flow_specifier)
    # Append the packet to the corresponding flow
    flows[flow_specifier].packets.append(pkt)

  sorted_flows = sorted(flows.values(), key=lambda x: len(x.packets), reverse=True)
  return sorted_flows



if __name__ == "__main__":
  pkts = rdpcap("captures/04/youtube-streaming.pcapng")  # read pcap file
  print(pkts)

  sorted_flows = classify_flows(pkts)
  
  # print the top 5 flows by the number of packets
  for flow in sorted_flows[:5]:
    print(f"{flow.flow_specifier} : Packets in flow: {len(flow.packets)}")
  

  # plot the inter-arrival times of packets in the flow with the most packets
  sorted_flows[0].plot(plot_first_n_packets = 100) 
  
    
