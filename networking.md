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

    
     

       
     




    
  

      


     



    
    
