# LainAir - Machine Learning-Based Encrypted Network Traffic Classifier

<img width="8000" height="6000" alt="poster" src="https://github.com/user-attachments/assets/8d3be644-5af8-4d99-b857-a94b0631674d" />

# Network Traffic Classification Using Time Series and Statistical Features
Author: Ivy Zhu (University of Wisconsin‑Madison, hzhu298@wisc.edu)

## Abstract
Network traffic classification provides essential insights for Quality of Service (QoS), security, and network management. However, the adoption of encryption protocols and increasing complex layering in the internet structure has limited the useful information in packet headers and payloads. This project tested whether the application type of the traffic flows can still be classified using only behavioral metadata (direction, packet length, and interarrival time) without accessing any header information or payload data. We built a pipeline for capturing and labeling flow data from multiple application types, and evaluated two machine learning approaches: a Random Forest classifier using per‑flow statistical summary and an LSTM model using per‑packet time series data. The Random Forest classifier reached 100% accuracy on a small dataset due to the significant differences across the selected application types, while the LSTM model achieved 90.97% accuracy but showed some confusion on protocol level behavior. This highlights the potential for building efficient, privacy‑preserving traffic classifiers with future enhancements in model architecture and data diversity.

## Overview
Traffic classification is essential for Quality of Service (QoS) optimization, local network management, and security. ISPs and network managers need effective methods for load balancing and traffic prioritization. In addition, understanding what information attackers can infer from intercepted packets is crucial to defending against potential threats.

Traditional methods rely on inspecting the addresses and ports in packet headers to identify hosts and applications. However, the growing use of techniques like reverse proxies and NAT has made these identifiers less reliable. The increasing adoption of encryption protocols further limits payload inspection, making these expert‑made matching approaches ineffective.

In response, machine learning methods have emerged as powerful tools for traffic classification. Recent research often uses patterns in packet headers or encrypted payloads to classify traffic. In contrast, we focus on only using behavioral metadata—such as packet length, interarrival time, and direction—to classify traffic flows, without inspecting any specific information in header and payload.

These features are available even when the header and payload information are altered, so they can still provide insights of application types for purposes like management and QoS enforcement. Additionally, by avoiding using identifiable header information or sensitive packet content, this approach not only addresses privacy concerns but also provides greater potential for generalization in different contexts.

In addition, we compare different classification methods to explore whether utilizing the sequential nature of traffic data will provide advantages over methods that use the statistical summary of the entire flow.

**Research question**: Can we classify application type of network flows using only IP and transport layer metadata, without looking into any header and payload information? Does statistical summary of the entire flow suffice, or does time series of packet‑level behavior provide more advantages?

## Related Work
### Network traffic classification: Techniques, datasets, and challenges [1]
Provides a high-level overview of methods in network traffic classification and the challenges of different methods. Port-based identification is limited by reverse proxies, NAT, encryption, and ethical concerns. It also surveys recent machine learning approaches and their data and computation challenges.

### Algorithms for packet classification [2]
Describes traditional expert-designed algorithms that focus on packet header inspection and regex-rule classifiers. Although outdated, the introduced metrics—classification speed, storage requirements, scalability, update time, flexibility—remain relevant.

### Deep packet: a novel approach for encrypted traffic classification using deep learning [3]
Proposes a deep learning method that classifies encrypted packets by application type without decryption by learning features from pseudo-random generators in encrypted packets.

### Demographic Information Inference through Meta-Data Analysis of Wi‑Fi Traffic [4]
Uses Wi-Fi packet header metadata to predict user demographics, collected on a campus network with access to user information. Discusses both privacy risks and methods to mitigate them.

### Deep Learning for Encrypted Traffic Classification: An Overview [5]
Overviews deep learning applied to traffic classification, focusing on data collection, feature selection, and different types of features (payload, header, statistical, time series).

### Network Traffic Classifier With Convolutional and Recurrent Neural Networks for Internet of Things [6]
Proposes a hybrid CNN‑RNN model trained with raw features from the first 20 packets of flows (e.g., source/dest ports, bytes per packet), avoiding handcrafted features.

### MIRAGE: Mobile‑app Traffic Capture and Ground‑truth Creation [7]
Describes an architecture for dataset creation by recording real user activities on Android devices using Wi‑Fi AP captures and logging system calls to map network flows to apps.

## Methodology
### Data collection
Collected custom traffic data in a local Wi‑Fi setting, focusing on three video categories: buffered video (YouTube), live video streaming (Twitch), and video conferencing (Zoom). Each application ran independently on a mobile device. Traffic capture used Wireshark, saved as .pcapng.
Flows were grouped by 5‑tuple, selecting the flow with the largest packet count per session, labeling it by active app and discarding background traffic. Extracted features: packet direction, length, interarrival time, then computed statistical summaries per flow segment.

### Classification Models
Chose lightweight models for real-world applicability (low-latency, limited resource deployment): a Random Forest (baseline) and a simplified LSTM model. The goal was to compare statistical summary vs. sequence-based modeling without assuming heavy tuning.

### Data
Raw Packet Data
For each packet in a flow: recorded IP packet byte count, arrival timestamp, and source IP.

### Time-Series Construction
Calculated interarrival time and labeled direction (based on private-range source IP assumption). Time series segmented into non-overlapping chunks of 300 packets, each as a tuple of (packet_length, direction, interarrival_time), without normalization.

### Statistical Summary Features
Computed features for each 2-minute flow segment: mean, median, standard deviation of packet length by direction; incoming/outgoing packet counts; mean, median, std dev of interarrival times; and a custom “tail mean” (average of top‑20 interarrival times) to capture bursty OFF‑time behavior—yielding a 12‑dimensional feature vector for Random Forest.

## Results
### Flow Patterns Differences between Application Types

**Video streaming**: frequent large incoming packets and small ACKs; stable, short interarrival times.

**Buffered video**: similar to streaming during activity, but shows periodic OFF‑time intervals.

**Video conferencing**: frequent bi‑directional traffic with variable packet sizes and no OFF‑time bursts.

### Classification Model Performance
Random Forest achieved 100% accuracy on this dataset, likely due to distinct flow patterns. Generalization to more similar app types remains to be tested.

LSTM reached 90.97% accuracy, with confusion mainly between YouTube and Zoom. Protocol-level similarities (e.g. UDP vs TCP behaviors) may mislead sequence-based models absent tuning.

## Conclusion
Application types can be classified using only packet length, direction, and interarrival time, without inspecting headers or payloads. When application types differ significantly, statistical summary features—modeled via Random Forest—outperform sequence-based models, especially on small datasets. Lower LSTM accuracy indicates a risk that sequential models may latch on to protocol-level cues rather than application behavior unless specifically tuned.

Future work: scale up data diversity, compare finer-grained app types, evaluate online/real‑time classification performance, and explore enhanced models and architectures.

## References
[1] Ahmad Azab et al., Network traffic classification: Techniques, datasets, and challenges, Digital Communications and Networks, vol. 10, no. 3, 2024, pp. 676‑692.

[2] Pankaj Gupta & Nick McKeown, Algorithms for packet classification, IEEE Network, 2001.

[3] Mohammad Lotfollahi et al., Deep packet: a novel approach for encrypted traffic classification using deep learning, Soft Computing, 2020.

[4] Huaxin Li et al., Demographic Information Inference through Meta‑Data Analysis of Wi‑Fi Traffic, IEEE Transactions on Mobile Computing, 2017.

[5] Shahbaz Rezaei & Xin Liu, Deep Learning for Encrypted Traffic Classification: An Overview, IEEE Communications Magazine, 2019.

[6] Manuel Lopez‑Martin et al., Network Traffic Classifier With CNN and RNN for IoT, IEEE Access, 2017.

[7] Giuseppe Aceto et al., MIRAGE: Mobile‑app Traffic Capture and Ground‑truth Creation, ICCCS 2019.
