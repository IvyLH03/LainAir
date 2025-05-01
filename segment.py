from scapy.all import rdpcap
import matplotlib.pyplot as plt
import datetime
import time
import argparse


class FlowSpecifier:
  """
  Classify a flow based on source IP, destination IP, source port, destination port, and protocol (TCP/UDP).
  """
  def __init__(self, ip_1, ip_2, port_1, port_2, protocol, label=None):
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
    self.label = label

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
    return [pkt for pkt in pkts if pkt['IP'].dst == self.ip_1]

  
  def get_outgoing_packets(self, pkts=None):
    """
    Return a list of outgoing packets in the flow.
    """
    if not pkts:
      pkts = self.packets
    return [pkt for pkt in pkts if pkt['IP'].src == self.ip_1]
  
  def plot(self, plot_first_n_packets=None, plot_first_n_seconds=None, plot_length=True, plot_arrival_time=True):
    """
    Plot the time series of the packet length of incoming packets in the flow.
    """
    if not plot_first_n_packets:
      pkts = self.packets
    else:
      pkts = self.packets[:plot_first_n_packets]
    
    if plot_first_n_seconds:
      pkts = [pkt for pkt in pkts if pkt.time - pkts[0].time <= plot_first_n_seconds]

    print(pkts[0].time, pkts[-1].time, pkts[-1].time - pkts[0].time)
    print(pkts[0])
    print(self.ip_1, self.ip_2)


    # choose incoming packets
    incoming_packets = self.get_incoming_packets(pkts=pkts)
    incoming_packets_lengths = [len(pkt) for pkt in incoming_packets]
    incoming_packets_time = [pkt.time for pkt in incoming_packets]

    outgoing_packets = self.get_outgoing_packets(pkts=pkts)
    outgoing_packets_lengths = [len(pkt) for pkt in outgoing_packets]
    outgoing_packets_time = [pkt.time for pkt in outgoing_packets]

    # calculate the arrival time offset
    first_packet_time = min(incoming_packets_time[0], outgoing_packets_time[0])
    print(first_packet_time)


    print("first incoming: ", incoming_packets_time[0]) 
    print("first outgoing: ", outgoing_packets_time[0])


    print("last incoming: ", incoming_packets_time[-1], incoming_packets_time[-1] - first_packet_time)
    print("last outgoing: ", outgoing_packets_time[-1], outgoing_packets_time[-1] - first_packet_time)

    incoming_packets_time = [t - first_packet_time for t in incoming_packets_time]
    outgoing_packets_time = [t - first_packet_time for t in outgoing_packets_time]

    print(incoming_packets_time[-1], outgoing_packets_time[-1])

    # plot the time series of packet length
    plt.xlabel("Time (s)")
    plt.ylabel("Packet Length (bytes)")
    plt.title(f"Packet Length of Flow {self.flow_specifier}")

    # if plot_length:
    #   plt.plot(incoming_packets_time, incoming_packets_lengths)
    #   plt.plot(outgoing_packets_time, outgoing_packets_lengths, color='green')

    # if plot_first_n_seconds is provides, then fix the x axis to the first n seconds
    if plot_first_n_seconds:
      plt.xlim(0, plot_first_n_seconds)

    if plot_arrival_time:
      # mark the arrival time of the packets with red dots
      for i in range(len(incoming_packets_time)):
        if plot_length:
          plt.scatter(incoming_packets_time[i], incoming_packets_lengths[i], color='red', s=10)
        else:
          plt.scatter(incoming_packets_time[i], 0, color='red', s=10)
      # plot the time series of packet length of outgoing packets
      for i in range(len(outgoing_packets_time)):
        if plot_length:
          plt.scatter(outgoing_packets_time[i], outgoing_packets_lengths[i], color='green', s=10)
        else:
          # mark the arrival time of the packets with yellow dots
          plt.scatter(outgoing_packets_time[i], 1, color='green', s=10)


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

    pkt_len_sum = sum(len(p['IP']) for p in self.packets)  # packet length sum
    pkt_len_mean = pkt_len_sum / len(self.packets)  # packet length mean
    pkt_len_std = (sum((len(p['IP']) - pkt_len_mean) ** 2 for p in self.packets) / len(self.packets)) ** 0.5  # packet length std
    
    outgoing_packets = self.get_outgoing_packets()
    outgoing_pkt_len_sum = sum(len(p['IP']) for p in outgoing_packets)  # outgoing packet length sum
    outgoing_pkt_len_mean = outgoing_pkt_len_sum / len(outgoing_packets)  # outgoing packet length mean
    outgoing_pkt_len_std = (sum((len(p['IP']) - outgoing_pkt_len_mean) ** 2 for p in outgoing_packets) / len(outgoing_packets)) ** 0.5  # outgoing packet length std

    incoming_packets = self.get_incoming_packets()
    incoming_pkt_len_sum = sum(len(p['IP']) for p in incoming_packets)  # incoming packet length sum
    incoming_pkt_len_mean = incoming_pkt_len_sum / len(incoming_packets)  # incoming packet length mean
    incoming_pkt_len_std = (sum((len(p['IP']) - incoming_pkt_len_mean) ** 2 for p in incoming_packets) / len(incoming_packets)) ** 0.5  # incoming packet length std

    iat_sum = sum(p.iat for p in self.packets)  # inter-arrival time sum
    iat_mean = iat_sum / len(self.packets)  # inter-arrival time mean
    iat_std = (sum((p.iat - iat_mean) ** 2 for p in self.packets) / len(self.packets)) ** 0.5  # inter-arrival time std

    incoming_pkt_iat_sum = sum(p.iat for p in incoming_packets)  # inter-arrival time sum
    incoming_pkt_iat_mean = incoming_pkt_iat_sum / len(incoming_packets)  # inter-arrival time mean
    incoming_pkt_iat_std = (sum((p.iat - incoming_pkt_iat_mean) ** 2 for p in incoming_packets) / len(incoming_packets)) ** 0.5  # inter-arrival time std

    outgoing_pkt_iat_sum = sum(p.iat for p in outgoing_packets)  # inter-arrival time sum
    outgoing_pkt_iat_mean = outgoing_pkt_iat_sum / len(outgoing_packets)  # inter-arrival time mean
    outgoing_pkt_iat_std = (sum((p.iat - outgoing_pkt_iat_mean) ** 2 for p in outgoing_packets) / len(outgoing_packets)) ** 0.5  # inter-arrival time std

    per_flow_features = {
      'flow': {
        'ip_1': self.ip_1,
        'ip_2': self.ip_2,
        'port_1': self.port_1,
        'port_2': self.port_2,
        'protocol': self.protocol,
        'label': self.flow_specifier.label,
      },
      'packet_length': {
        # min Minimum
        'min': min(len(p['IP']) for p in self.packets), 
        # max Maximum
        'max': max(len(p['IP']) for p in self.packets),
        # mean Arithmetic mean
        'mean': pkt_len_mean,
        # std Standard deviation
        'std': pkt_len_std,
        # # var Variance
        # 'var': sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets),
        # # mad Mean absolute deviation
        # 'mad': sum(abs(len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) for p in self.packets) / len(self.packets),
        # # skew Unbiased sample skewness
        # 'skew': (sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 3 for p in self.packets) / len(self.packets)) / ((sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 1.5),
        # # kurtosis Unbiased Fisher kurtosis
        # 'kurtosis': (sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 4 for p in self.packets) / len(self.packets)) / ((sum((len(p['IP']) - sum(len(p['IP']) for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 2),
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(len(p['IP']) for p in self.packets)[int(len(self.packets) * i / 100)] for i in range(10, 100, 10)},
      },
      'incoming_packet_length':{
        # min Minimum
        'min': min(len(p['IP']) for p in incoming_packets),
        # max Maximum
        'max': max(len(p['IP']) for p in incoming_packets),
        # mean Arithmetic mean
        'mean': incoming_pkt_len_mean,
        # std Standard deviation
        'std': incoming_pkt_len_std,
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(len(p['IP']) for p in incoming_packets)[int(len(incoming_packets) * i / 100)] for i in range(10, 100, 10)},
      },
      'outgoing_packet_length':{
        # min Minimum
        'min': min(len(p['IP']) for p in outgoing_packets),
        # max Maximum
        'max': max(len(p['IP']) for p in outgoing_packets),
        # mean Arithmetic mean
        'mean': outgoing_pkt_len_mean,
        # std Standard deviation
        'std': outgoing_pkt_len_std,
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(len(p['IP']) for p in outgoing_packets)[int(len(outgoing_packets) * i / 100)] for i in range(10, 100, 10)},
      },
      'inter_arrival_time':{
        # min Minimum
        'min': float(min(p.iat for p in self.packets)),
        # max Maximum
        'max': float(max(p.iat for p in self.packets)),
        # mean Arithmetic mean
        'mean': float(iat_mean),
        # std Standard deviation
        'std': float(iat_std),
        # # var Variance
        # 'var': float(sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)),
        # # mad Mean absolute deviation
        # 'mad': float(sum(abs(p.iat - sum(p.iat for p in self.packets) / len(self.packets)) for p in self.packets) / len(self.packets)),
        # # skew Unbiased sample skewness
        # 'skew': float((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 3 for p in self.packets) / len(self.packets)) / ((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 1.5)),
        # # kurtosis Unbiased Fisher kurtosis
        # 'kurtosis': float((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 4 for p in self.packets) / len(self.packets)) / ((sum((p.iat - sum(p.iat for p in self.packets) / len(self.packets)) ** 2 for p in self.packets) / len(self.packets)) ** 2)),
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(float(p.iat) for p in self.packets)[int(len(self.packets) * i / 100)] for i in range(10, 100, 10)},
      },
      'incoming_inter_arrival_time':{
        # min Minimum
        'min': float(min(p.iat for p in incoming_packets)),
        # max Maximum
        'max': float(max(p.iat for p in incoming_packets)),
        # mean Arithmetic mean
        'mean': float(incoming_pkt_iat_mean),
        # std Standard deviation
        'std': float(incoming_pkt_iat_std),
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(float(p.iat) for p in incoming_packets)[int(len(incoming_packets) * i / 100)] for i in range(10, 100, 10)},
      },
      'outgoing_inter_arrival_time':{
        # min Minimum
        'min': float(min(p.iat for p in outgoing_packets)),
        # max Maximum
        'max': float(max(p.iat for p in outgoing_packets)),
        # mean Arithmetic mean
        'mean': float(outgoing_pkt_iat_mean),
        # std Standard deviation
        'std': float(outgoing_pkt_iat_std),
        # q_percentile qth percentile (q ∈ [10 : 10 : 90])
        'q_percentile': {i: sorted(float(p.iat) for p in outgoing_packets)[int(len(outgoing_packets) * i / 100)] for i in range(10, 100, 10)},
      }

    }
    
    self.per_flow_features = per_flow_features
    return per_flow_features
  
  def get_all_inter_arrival_times(self):
    """
    Return a list of inter-arrival times of packets in the flow.
    """
    return [float(str(pkt.iat)) for pkt in self.packets]
  
  def plot_iat_distribution(self):
    """
    Plot the distribution of inter-arrival times of packets in the flow.
    """
    iat = self.get_all_inter_arrival_times()
    plt.hist(iat, bins=100)
    plt.xlabel("Inter-arrival time (s)")
    plt.ylabel("Frequency")
    plt.title(f"Inter-arrival time distribution of Flow {self.flow_specifier}")
    plt.show()
  
  def get_features(self):
    """
    Return the features of the flow.
    """
    return {
      self.flow_specifier: self.get_per_flow_features()
    }
  
  def separate_flow_by_time_interval(self, time_interval):
    """
    Separate the flow into multiple flows. Each flow contains packets that are sent within time_interval seconds after the first packet. 
    """
    separated_flows = []
    
    flow = Flow(self.flow_specifier)

    for pkt in self.packets:
      # if the flow is empty, add the packet to the flow
      if not flow.packets:
        flow.append(pkt)

      # check if the packet is within the time interval

      else:
        if pkt.time - flow.packets[0].time <= time_interval:
          flow.append(pkt)
        else:
          # add the flow to the list of separated flows
          separated_flows.append(flow)
          # create a new flow
          flow = Flow(self.flow_specifier)
          flow.append(pkt)

    separated_flows.append(flow)
    return separated_flows
  
  def separate_flow_by_packet_count(self, packet_count):
    """
    Separate the flow into multiple flows. Each flow contains packets that are sent within packet_count packets after the first packet. 
    """
    separated_flows = []
    
    flow = Flow(self.flow_specifier)

    for pkt in self.packets:
      # if the flow is empty, add the packet to the flow
      if not flow.packets:
        flow.append(pkt)

      # check if the separated flow has less than packet_count packets
      else:
        if len(flow.packets) < packet_count:
          flow.append(pkt)
        else:
          # add the flow to the list of separated flows
          separated_flows.append(flow)
          # create a new flow
          flow = Flow(self.flow_specifier)
          flow.append(pkt)

    separated_flows.append(flow)
    return separated_flows
  
  def get_time_series_data(self):
    """
    Return the time series data of the flow.
    """
    time_series_data = []
    for pkt in self.packets:
      # time_series_data.append({
      #   'direction': 1 if pkt['IP'].dst == self.ip_1 else 0, # 1 for incoming, 0 for outgoing
      #   'length': len(pkt['IP']),
      #   'iat': float(str(pkt.iat)),
      # })
      time_series_data.append((1 if pkt['IP'].dst == self.ip_1 else 0, len(pkt['IP']), float(str(pkt.iat))))
    return time_series_data
  
  def get_ramdom_forest_features(self):
    """
    return the features of the flow for random forest
    [
      incoming_length_mean, incoming_length_median, incoming_length_std, 
      outgoing_length_mean, outgoing_length_median, outgoing_length_std, 
      iat_mean, iat_median, iat_std, iat_tail_mean,
      in_count, out_count
    ]
    """

    incoming_packets = self.get_incoming_packets()
    outgoing_packets = self.get_outgoing_packets()

    incoming_length_sum = sum(len(p['IP']) for p in incoming_packets)  # incoming packet length sum
    incoming_length_mean = incoming_length_sum / len(incoming_packets)  # incoming packet length mean
    incoming_length_median = sorted(len(p['IP']) for p in incoming_packets)[len(incoming_packets) // 2]  # incoming packet length median
    incoming_length_std = (sum((len(p['IP']) - incoming_length_mean) ** 2 for p in incoming_packets) / len(incoming_packets)) ** 0.5  # incoming packet length std

    outgoing_length_sum = sum(len(p['IP']) for p in outgoing_packets)  # outgoing packet length sum
    outgoing_length_mean = outgoing_length_sum / len(outgoing_packets)  # outgoing packet length mean
    outgoing_length_median = sorted(len(p['IP']) for p in outgoing_packets)[len(outgoing_packets) // 2]  # outgoing packet length median
    outgoing_length_std = (sum((len(p['IP']) - outgoing_length_mean) ** 2 for p in outgoing_packets) / len(outgoing_packets)) ** 0.5  # outgoing packet length std

    iat_sum = sum(float(p.iat) for p in self.packets)  # inter-arrival time sum
    iat_mean = iat_sum / len(self.packets)  # inter-arrival time mean
    iat_median = sorted(float(p.iat) for p in self.packets)[len(self.packets) // 2]  # inter-arrival time median
    iat_std = (sum((float(p.iat) - iat_mean) ** 2 for p in self.packets) / len(self.packets)) ** 0.5  # inter-arrival time std

    iat_outlier_threshold = 0.1 # packets that has iat > 0.1s are considered outliers (off times)
    iat_outlier_count = sum(1 for p in self.packets if float(p.iat) > iat_outlier_threshold)  # inter-arrival time outlier count
    iat_outlier_ratio = iat_outlier_count / len(self.packets)  # inter-arrival time outlier ratio
    
    # define tail mean = the mean of the largest 20 packets
    iat_tail_mean = sum(sorted(float(p.iat) for p in self.packets)[-20:]) / 20 if len(self.packets) >= 20 else iat_mean

    return [
      incoming_length_mean, incoming_length_median, incoming_length_std,
      outgoing_length_mean, outgoing_length_median, outgoing_length_std,
      iat_mean, iat_median, iat_std, iat_tail_mean,
      len(incoming_packets), len(outgoing_packets)
    ]





def classify_flows(pkts, label=None):
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
          protocol='TCP',
          label=label
        )
        # print(pkt['TCP'].sport, pkt['TCP'].dport, pkt['IP'].src, pkt['IP'].dst)
      elif 'IPv6' in pkt:
        flow_specifier = FlowSpecifier(
          ip_1=pkt['IPv6'].src,
          ip_2=pkt['IPv6'].dst,
          port_1=pkt['TCP'].sport,
          port_2=pkt['TCP'].dport,
          protocol='TCP',
          label=label
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
          protocol='UDP',
          label=label
        )
        # print(pkt['UDP'].sport, pkt['UDP'].dport, pkt['IP'].src, pkt['IP'].dst)
      elif 'IPv6' in pkt:
        flow_specifier = FlowSpecifier(
          ip_1=pkt['IPv6'].src,
          ip_2=pkt['IPv6'].dst,
          port_1=pkt['UDP'].sport,
          port_2=pkt['UDP'].dport,
          protocol='UDP',
          label=label
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

def parse_args():
  """
  Parse command line arguments.
  """
  parser = argparse.ArgumentParser()
  parser.add_argument("-f", "--filename", type=str, required=True, help="Path to the pcap file")
  parser.add_argument("-l", "--label", type=str, required=True, help="Label for the flow") 
  parser.add_argument("-o", "--output", type=str, help="Path to the output file")
  return parser.parse_args()


if __name__ == "__main__":
  args = parse_args()

  filename = args.filename
  label = args.label

  # filename = "captures/youtube/01.pcapng"
  # label = "youtube"
  # output_file = "data/zoom_01.json"

  pkts = rdpcap(filename)  # read pcap file

  sorted_flows = classify_flows(pkts, label)

  largest_flow = sorted_flows[0]
  # largest_flow.plot_iat_distribution()

  # largest_flow.plot(plot_first_n_seconds=10, plot_length=True, plot_arrival_time=True)


  largest_flow_separated = largest_flow.separate_flow_by_time_interval(120)
  print(f"Largest flow: {largest_flow.flow_specifier} with {len(largest_flow.packets)} packets, {len(largest_flow_separated)} flows after separation")
  data = []
  for flow in largest_flow_separated:
    data.append(flow.get_ramdom_forest_features())

  print(data[:5])

  if args.output:
    with open(args.output, "w") as f:
      import json
      json.dump(data, f, indent=4)


  # largest_flow_separated = largest_flow.separate_flow_by_packet_count(300)
  # print(f"Largest flow: {largest_flow.flow_specifier} with {len(largest_flow.packets)} packets, {len(largest_flow_separated)} flows after separation")
  # data = []
  # for flow in largest_flow_separated:
  #   data.append(flow.get_time_series_data())
  
  # if args.output:
  #   with open(args.output, "w") as f:
  #     import json
  #     json.dump(data, f, indent=4)

  
  # print the top 5 flows by the number of packets
  # for flow in sorted_flows[:5]:
  #   print(f"{flow.flow_specifier} : Packets in flow: {len(flow.packets)}")
  

  # plot the inter-arrival times of packets in the flow with the most packets
  # sorted_flows[0].print_packets(n=400)
  # sorted_flows[0].plot(plot_first_n_packets = 400) 
  # print(sorted_flows[0].get_per_flow_features())

    
