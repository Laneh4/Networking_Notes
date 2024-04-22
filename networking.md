 ## Day 1 networking

    https://net.cybbh.io/public/networking/latest/index.html
    https://miro.com/app/board/o9J_klSqCSY=/
    http://networking-ctfd-2.server.vta:8000/

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


  


    


     


     


  


      
    
  



     




   

           
  

 
        
      
  



    
     

        
      
     
    
 

    

    


   
     

    
     

       
     




    
  

      


     



    
    
