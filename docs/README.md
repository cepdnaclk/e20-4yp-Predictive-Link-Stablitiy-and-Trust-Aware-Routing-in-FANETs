---
layout: home
permalink: index.html

# Please update this with your repository name and title
repository-name: eYY-4yp-project-template
title:
---

[comment]: # "This is the standard layout for the project, but you can clean this and use your own template"

# Predictive Link Stability and Trust-Aware Routing in FANETs

#### Team

- E/20/035, K.C.H.N.A.W.M.R.C.J.N. Bandara, [email](mailto:e20035@eng.pdn.ac.lk)
- E/20/173, P.A.S.V. Jayasooriya, [email](mailto:e20173@eng.pdn.ac.lk)
- E/20/178, N.K.D.P. Jayawardena, [email](mailto:e20178@eng.pdn.ac.lk)

#### Supervisors

- Dr. Suneth Namal Karunarathna, [email](mailto:namal@eng.pdn.ac.lk)
- Dr. Upul Jayasinghe, [email](mailto:upuljm@eng.pdn.ac.lk)


#### Table of content

1. [Abstract](#abstract)
2. [Related works](#related-works)
3. [Methodology](#methodology)
4. [Experiment Setup and Implementation](#experiment-setup-and-implementation)
5. [Results and Analysis](#results-and-analysis)
6. [Conclusion](#conclusion)
7. [Publications](#publications)
8. [Links](#links)

---

<!-- 
DELETE THIS SAMPLE before publishing to GitHub Pages !!!
This is a sample image, to show how to add images to your page. To learn more options, please refer [this](https://projects.ce.pdn.ac.lk/docs/faq/how-to-add-an-image/)
![Sample Image](./images/sample.png) 
-->


## Abstract
Efficient routing in Flying Ad Hoc Networks remains a critical challenge due to time-varying link quality, node mobility, and unpredictable network topology changes. Traditional routing protocols like OLSR and AODV rely on static metrics and fixed decision rules, which often fail to adapt to rapidly changing conditions. This paper proposes QBR (Q-Learning Based Routing), a novel machine learning-driven routing protocol that leverages Q-Learning with Quantile Regression to make intelligent routing decisions on demand. Unlike conventional protocols, QBR adapts its path selection in real-time by learning from network feedback, including link quality metrics (SNR, packet loss), latency, and throughput. We evaluate QBR against established protocols (OLSR and AODV) in a simulated 40-node wireless network using NS-3. Experimental results demonstrate that QBR achieves higher Packet Delivery Ratio (PDR) and improved throughput while maintaining competitive latency, particularly in scenarios with fluctuating link quality. The findings illustrate the potential of reinforcement learning-based approaches to enhance routing performance in dynamic wireless networks.

## Related works
Traditional ad-hoc routing protocols can be broadly categorized into reactive (on-demand) and proactive (table-driven) approaches. AODV and DSR are prominent reactive protocols that discover routes only when needed, while OLSR is a proactive protocol that maintains routing tables periodically. These conventional approaches typically use simple metrics such as hop count, which often prove inadequate in dynamic environments with fluctuating link quality. Recent research has explored machine learning applications in networking. Q-Learning and other reinforcement learning techniques have been successfully applied to congestion control, resource allocation, and load balancing. Some studies have investigated learning-based routing for mobile networks; however, limited work exists on distributional Q-Learning approaches that capture link quality uncertainty. Our work extends this domain by combining Q-Learning with Quantile Regression to provide risk-aware routing decisions that consider both expected performance and uncertainty in link metrics.

## Methodology
QBR operates at the network layer by applying Q-Learning to continuously improve routing decisions based on network conditions. The protocol maintains a Q-Table where each state represents a combination of destination and neighboring nodes, and actions correspond to selecting the next hop for packet forwarding. Routing decisions are made using an ε-greedy strategy, which balances exploration of new paths and exploitation of known high-quality routes. The reward mechanism is designed using real-time link metrics such as signal-to-noise ratio (SNR), packet delivery success, and delay, enabling the protocol to learn from network feedback. Additionally, Quantile Regression is incorporated to estimate the distribution of Q-values, allowing the model to account for uncertainty in link quality and make risk-aware decisions. As packets are transmitted, the protocol dynamically updates its knowledge and progressively converges toward optimal routing paths under changing network conditions.

## Experiment Setup and Implementation
We evaluate QBR using NS-3, a discrete-event network simulator, with the following configuration:

1. Network Topology: 40 mobile nodes deployed in a 1000 m × 1000 m area
2. Mobility Model: Random Waypoint Model with velocity 0.5–10 m/s and pause time 5 seconds
3. Physical Layer: 802.11g WiFi with 54 Mbps data rate
4. Communication: CBR (Constant Bit Rate) traffic: 10 flows, 512-byte packets, 5 packets/second
5. Simulation Duration: 300 seconds
6. Q-Learning Parameters: Learning rate α = 0.1, discount factor γ = 0.95, ε = 0.1 (decaying)
7. Comparison Protocols: OLSR (proactive), AODV (reactive), QBR (learning-based)
8. Evaluation Metrics:
        PDR (Packet Delivery Ratio): Percentage of successfully delivered packets
        Average Latency: Mean end-to-end delay
        Throughput: Goodput in Kbps
Performance is recorded every 1 second, and results are aggregated for statistical analysis.

## Results and Analysis

## Conclusion
This work demonstrates that reinforcement learning-based routing can effectively address limitations of traditional routing protocols in dynamic wireless networks. QBR leverages Q-Learning and Quantile Regression to learn adaptive routing policies that improve Packet Delivery Ratio and throughput compared to OLSR and AODV. The experimental evaluation confirms that the protocol rapidly converges to optimal routing decisions as network conditions evolve. However, scalability to larger networks, computational overhead, and Q-Table memory requirements merit further investigation. Future work should explore hierarchical Q-Learning for large-scale networks, integration of multi-agent reinforcement learning for cooperative routing, and deployment on real wireless testbeds to validate simulation findings. The results suggest that machine learning approaches offer promising avenues for developing more intelligent and adaptive routing protocols in next-generation wireless networks.

## Publications
[//]: # "Note: Uncomment each once you uploaded the files to the repository"

<!-- 1. [Semester 7 report](./) -->
<!-- 2. [Semester 7 slides](./) -->
<!-- 3. [Semester 8 report](./) -->
<!-- 4. [Semester 8 slides](./) -->
<!-- 5. Author 1, Author 2 and Author 3 "Research paper title" (2021). [PDF](./). -->


## Links

[//]: # ( NOTE: EDIT THIS LINKS WITH YOUR REPO DETAILS )

- [Project Repository](https://github.com/cepdnaclk/e20-4yp-Predictive-Link-Stability-and-Trust-Aware-Routing-in-FANETs)
- [Project Page](https://cepdnaclk.github.io/repository-name)
- [Department of Computer Engineering](http://www.ce.pdn.ac.lk/)
- [University of Peradeniya](https://eng.pdn.ac.lk/)

[//]: # "Please refer this to learn more about Markdown syntax"
[//]: # "https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet"
