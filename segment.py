from scapy.all import rdpcap
import matplotlib.pyplot as plt
import datetime
import time

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
    self.protocol = flow_specifier.protocol  # Protocol (TCP/UDP)
    self.packets = []  # list to store packets in the flow

  def append(self, pkt):
    """
    Append a packet to the flow.
    """
    # calculate packet interarrival time
    pkt.iat = (pkt.time - self.packets[-1].time) if self.packets else 0

    # append the packet
    self.packets.append(pkt)

  def get_incoming_packets(self, pkts=None):
    """
    Return a list of incoming packets in the flow.
    """
    if not pkts:
      pkts = self.packets
    if 'TCP' in pkts[0]:
      return [pkt['TCP'] for pkt in pkts if pkt['IP'].dst == self.ip_1]
    elif 'UDP' in self.packets[0]:
      return [pkt['UDP'] for pkt in pkts if pkt['IP'].dst == self.ip_1]
    else:
      return []

  
  def get_outgoing_packets(self, pkts=None):
    """
    Return a list of outgoing packets in the flow.
    """
    if not pkts:
      pkts = self.packets
    if 'TCP' in pkts[0]:
      return [pkt['TCP'] for pkt in pkts if pkt['IP'].src == self.ip_1]
    elif 'UDP' in self.packets[0]:
      return [pkt['UDP'] for pkt in pkts if pkt['IP'].src == self.ip_1]
    else:
      return []
  
  def plot(self, plot_first_n_packets=None):
    """
    Plot the time series of the packet length of incoming packets in the flow.
    """
    if not plot_first_n_packets:
      pkts = self.packets
    else:
      pkts = self.packets[:plot_first_n_packets]
    # choose incoming packets
    incoming_packets = self.get_incoming_packets(pkts=pkts)
    
    incoming_packets_lengths = [len(pkt) for pkt in incoming_packets]
    incoming_packets_time = [pkt.time for pkt in incoming_packets]

    # get all the outgoing packets that are sent prior to the last incoming packet
    last_incoming_packet_time = incoming_packets[-1].time
    outgoing_packets = self.get_outgoing_packets(pkts=pkts)
    outgoing_packets = [pkt for pkt in outgoing_packets if pkt.time < last_incoming_packet_time]
    outgoing_packets_lengths = [len(pkt) for pkt in outgoing_packets]
    outgoing_packets_time = [pkt.time for pkt in outgoing_packets]

    # calculate the arrival time offset
    first_packet_time = min(incoming_packets_time[0], outgoing_packets_time[0])
    incoming_packets_time = [t - first_packet_time for t in incoming_packets_time]
    outgoing_packet_time = [t - first_packet_time for t in outgoing_packets_time]


    # plot the time series of packet length
    plt.plot(incoming_packets_time, incoming_packets_lengths)
    plt.xlabel("Time (s)")
    plt.ylabel("Packet Length (bytes)")
    plt.title(f"Packet Length of Flow {self.flow_specifier}")

    # mark the arrival time of the packets with red dots
    for i in range(len(incoming_packets_time)):
      plt.scatter(incoming_packets_time[i], incoming_packets_lengths[i], color='red', s=10)

    # plot the time series of packet length of outgoing packets
    plt.plot(outgoing_packet_time, outgoing_packets_lengths, color='green')
    for i in range(len(outgoing_packet_time)):
      plt.scatter(outgoing_packet_time[i], outgoing_packets_lengths[i], color='yellow', s=10)


    plt.show()

  def print_packets(self, n=None):
    """
    Print all packets in the flow.
    """
    print(f"Flow {self.flow_specifier}")
    if not n:
      n = len(self.packets)
    else:
      n = min(n, len(self.packets))
    
    for i in range(n):
      pkt = self.packets[i]

      pkt_timestamp_float = float(str(pkt.time))
      packet_time = datetime.datetime.fromtimestamp(pkt_timestamp_float).strftime('%H:%M:%S.%f')

      if self.protocol == 'UDP':
          # print if the packet is incoming or outgoing, packet size, time in format of "HH:MM:SS"
          if pkt['IP'].src == self.ip_1:
            print(f"Outgoing Packet: {len(pkt['UDP'].payload)} bytes {packet_time}") 
          else:
            print(f"Incoming Packet: {len(pkt['UDP'].payload)} bytes {packet_time}")
      elif self.protocol == 'TCP':
        for pkt in self.packets:
          # print if the packet is incoming or outgoing, packet size, time in format of "HH:MM:SS", and TCP flags
          if pkt['IP'].src == self.ip_1:
            print(f"Outgoing Packet: {len(pkt['TCP'].payload)} bytes {packet_time} {pkt['TCP'].flags}  seq: {pkt['TCP'].seq}")
          else:
            print(f"Incoming Packet: {len(pkt['TCP'].payload)} bytes {packet_time} {pkt['TCP'].flags}  seq: {pkt['TCP'].seq}")
      else:
        print("Protocol not supported")
        return
      
  def get_per_flow_features(self):
    # calculate per-flow features
    per_flow_features = {
      'packet_length': {
        # min Minimum
        'min': min(len(p['IP']) for p in self.packets), 
        # max Maximum
        'max': max(len(p['IP']) for p in self.packets),
        # mean Arithmetic mean
        'mean': sum(len(p['IP']) for p in self.packets) / len(self.packets),
        # std Standard deviation
        'std': (sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 0.5,
        # var Variance
        'var': sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets),
        # mad Mean absolute deviation
        'mad': sum(abs(len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) for p in self.packets) / len(self.packets),
        # skew Unbiased sample skewness
        'skew': (sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 3 for p in self.packets) / len(self.packets)) / ((sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 1.5),
        # kurtosis Unbiased Fisher kurtosis
        'kurtosis': (sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 4 for p in self.packets) / len(self.packets)) / ((sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 2),
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(len(p['IP']) for p in self.packets)[int(len(self.packets) * i / 100)] for i in range(10, 100, 10)},
      },
      'inter_arrival_time':{
        # min Minimum
        'min': float(min(p.iat for p in self.packets)),
        # max Maximum
        'max': float(max(p.iat for p in self.packets)),
        # mean Arithmetic mean
        'mean': float(sum(p.iat for p in self.packets) / len(self.packets)),
        # std Standard deviation
        'std': float((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 0.5),
        # var Variance
        'var': float(sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)),
        # mad Mean absolute deviation
        'mad': float(sum(abs(p.iat - sum(p.iat for p in self.packets) / len(self.packets)) for p in self.packets) / len(self.packets)),
        # skew Unbiased sample skewness
        'skew': float((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 3 for p in self.packets) / len(self.packets)) / ((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 1.5)),
        # kurtosis Unbiased Fisher kurtosis
        'kurtosis': float((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 4 for p in self.packets) / len(self.packets)) / ((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 2)),
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(float(p.iat) for p in self.packets)[int(len(self.packets) * i / 100)] for i in range(10, 100, 10)},
      }
    }
    
    self.per_flow_features = per_flow_features
    return per_flow_features
  
  def get_features(self):
    """
    Return the features of the flow.
    """
    return {
      self.flow_specifier: self.get_per_flow_features()
    }





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
    flows[flow_specifier].append(pkt)

  sorted_flows = sorted(flows.values(), key=lambda x: len(x.packets), reverse=True)
  return sorted_flows



if __name__ == "__main__":
  pkts = rdpcap("captures/01/cap1.pcapng")  # read pcap file
  print(pkts)

  sorted_flows = classify_flows(pkts)
  
  # print the top 5 flows by the number of packets
  # for flow in sorted_flows[:5]:
  #   print(f"{flow.flow_specifier} : Packets in flow: {len(flow.packets)}")
  

  # plot the inter-arrival times of packets in the flow with the most packets
  sorted_flows[0].print_packets(n=400)
  # sorted_flows[0].plot(plot_first_n_packets = 400) 
  print(sorted_flows[0].get_per_flow_features())

    
