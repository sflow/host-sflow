/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

/*
////////////////////////////////////////////////////////////////////////////////
////////////////////// sFlow Sampling Packet Data Types ////////////////////////
////////////////////////////////////////////////////////////////////////////////
*/

#ifndef SFLOW_H
#define SFLOW_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef _WIN32
#include <windows.h>
#define u_char UCHAR
#define uchar UCHAR

#define u_int8_t UCHAR
#define uint8_t UCHAR
#define int8_t CHAR

#define u_int16_t WORD
#define uint16_t WORD
#define int16_t WORD

#define u_int32_t UINT32
#define uint32_t UINT32
#define int32_t INT32

#define u_int64_t UINT64
#define uint64_t UINT64
#define int64_t INT64
#endif /*_WIN32 */

typedef struct {
    uint32_t addr;
} SFLIPv4;

typedef struct {
    u_char addr[16];
} SFLIPv6;

typedef union _SFLAddress_value {
    SFLIPv4 ip_v4;
    SFLIPv6 ip_v6;
} SFLAddress_value;

enum SFLAddress_type {
  SFLADDRESSTYPE_UNDEFINED = 0,
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef struct _SFLAddress {
    uint32_t type;           /* enum SFLAddress_type */
    SFLAddress_value address;
} SFLAddress;

enum SFL_DSCLASS {
  SFL_DSCLASS_IFINDEX=0,
  SFL_DSCLASS_VLAN=1,
  SFL_DSCLASS_PHYSICAL_ENTITY=2,
  SFL_DSCLASS_LOGICAL_ENTITY=3
};

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400
#define SFL_DEFAULT_POLLING_INTERVAL 30

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
  SFLHEADER_ETHERNET_ISO8023     = 1,
  SFLHEADER_ISO88024_TOKENBUS    = 2,
  SFLHEADER_ISO88025_TOKENRING   = 3,
  SFLHEADER_FDDI                 = 4,
  SFLHEADER_FRAME_RELAY          = 5,
  SFLHEADER_X25                  = 6,
  SFLHEADER_PPP                  = 7,
  SFLHEADER_SMDS                 = 8,
  SFLHEADER_AAL5                 = 9,
  SFLHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  SFLHEADER_IPv4                 = 11,
  SFLHEADER_IPv6                 = 12,
  SFLHEADER_MPLS                 = 13
};

/* raw sampled header */

typedef struct _SFLSampled_header {
  uint32_t header_protocol;            /* (enum SFLHeader_protocol) */
  uint32_t frame_length;               /* Original length of packet before sampling */
  uint32_t stripped;                   /* header/trailer bytes stripped by sender */
  uint32_t header_length;              /* length of sampled header bytes to follow */
  uint8_t *header_bytes;               /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
  uint32_t eth_len;       /* The length of the MAC packet excluding 
                             lower layer encapsulations */
  uint8_t src_mac[8];    /* 6 bytes + 2 pad */
  uint8_t dst_mac[8];
  uint32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
  uint32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  uint32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv4 src_ip; /* Source IP Address */
  SFLIPv4 dst_ip; /* Destination IP Address */
  uint32_t src_port;    /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;   /* TCP flags */
  uint32_t tos;         /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */

typedef struct _SFLSampled_ipv6 {
  uint32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  uint32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv6 src_ip; /* Source IP Address */
  SFLIPv6 dst_ip; /* Destination IP Address */
  uint32_t src_port;     /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;    /* TCP flags */
  uint32_t priority;     /* IP priority */
} SFLSampled_ipv6;

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
  uint32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  uint32_t src_priority;   /* The 802.1p priority */
  uint32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  uint32_t dst_priority;   /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
  SFLAddress nexthop;               /* IP address of next hop router */
  uint32_t src_mask;               /* Source address prefix mask bits */
  uint32_t dst_mask;               /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
  SFLEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  SFLEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};
  
typedef struct _SFLExtended_as_path_segment {
  uint32_t type;   /* enum SFLExtended_as_path_segment_type */
  uint32_t length; /* number of AS numbers in set/sequence */
  union {
    uint32_t *set;
    uint32_t *seq;
  } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
  SFLAddress nexthop;                       /* Address of the border router that should
                                               be used for the destination network */
  uint32_t as;                             /* AS number for this gateway */
  uint32_t src_as;                         /* AS number of source (origin) */
  uint32_t src_peer_as;                    /* AS number of source peer */
  uint32_t dst_as_path_segments;           /* number of segments in path */
  SFLExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  uint32_t communities_length;             /* number of communities */
  uint32_t *communities;                   /* set of communities */
  uint32_t localpref;                      /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
  uint32_t len;
  char *str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
  uint32_t src_charset;  /* MIBEnum value of character set used to encode a string - See RFC 2978
			     Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
			     of zero indicates an unknown encoding. */
  SFLString src_user;
  uint32_t dst_charset;
  SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
  SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
  uint32_t direction;   /* enum SFLExtended_url_direction */
  SFLString url;         /* URL associated with the packet flow.
			    Must be URL encoded */
  SFLString host;        /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
  uint32_t depth;
  uint32_t *stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
  SFLAddress nextHop;        /* Address of the next hop */ 
  SFLLabelStack in_stack;
  SFLLabelStack out_stack;
} SFLExtended_mpls;

  /* Extended NAT data
     Packet header records report addresses as seen at the sFlowDataSource.
     The extended_nat structure reports on translated source and/or destination
     addesses for this packet. If an address was not translated it should 
     be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
  SFLAddress src;    /* Source address */
  SFLAddress dst;    /* Destination address */
} SFLExtended_nat;

  /* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
   SFLString tunnel_lsp_name;  /* Tunnel name */
   uint32_t tunnel_id;        /* Tunnel ID */
   uint32_t tunnel_cos;       /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
   SFLString vc_instance_name; /* VC instance name */
   uint32_t vll_vc_id;        /* VLL/VC instance ID */
   uint32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
    - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
   SFLString mplsFTNDescr;
   uint32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
    - Definition from MPLS-LDP-STD-MIB mplsFecTable
    Note: mplsFecAddrType, mplsFecAddr information available
          from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
   uint32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information 
   Record outer VLAN encapsulations that have 
   been stripped. extended_vlantunnel information 
   should only be reported if all the following conditions are satisfied: 
     1. The packet has nested vlan tags, AND 
     2. The reporting device is VLAN aware, AND 
     3. One or more VLAN tags have been stripped, either 
        because they represent proprietary encapsulations, or 
        because switch hardware automatically strips the outer VLAN 
        encapsulation. 
   Reporting extended_vlantunnel information is not a substitute for 
   reporting extended_switch information. extended_switch data must 
   always be reported to describe the ingress/egress VLAN information 
   for the packet. The extended_vlantunnel information only applies to 
   nested VLAN tags, and then only when one or more tags has been 
   stripped. */ 

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel { 
  SFLVlanStack stack;  /* List of stripped 802.1Q TPID/TCI layers. Each 
			  TPID,TCI pair is represented as a single 32 bit 
			  integer. Layers listed from outermost to 
			  innermost. */ 
} SFLExtended_vlan_tunnel;

/* Extended tunnel information structures that allow a tunnel end
   point to export information related to the tunnel. 
   Network virtualization protocols such as VxLAN, NVGRE and GRE
   have been developed to virtualize networking by encapsulating 
   layer 2 frames in layer 3 and layer 4 tunnels.
   Extended tunnel structures allow sFlow agents in ingress and 
   egress switches to describe outer headers that are added 
   or removed as packets transit the switch.*/

typedef struct _SFLExtended_l2_tunnel {
	SFLSampled_ethernet header;
} SFLExtended_l2_tunnel;

typedef struct _SFLExtended_ipv4_tunnel {
	SFLSampled_ipv4 header;
} SFLExtended_ipv4_tunnel;

typedef struct _SFLExtended_ipv6_tunnel {
	SFLSampled_ipv6 header;
} SFLExtended_ipv6_tunnel;

typedef struct _SFLExtended_decapsulate {
   uint32_t inner_header_offset;
} SFLExtended_decapsulate;

typedef struct _SFLExtended_vni {
   uint32_t vni;            /* virtual network identifier */
} SFLExtended_vni;

/* TCP connection state */
/* Based on struct tcp_info in /usr/include/linux/tcp.h */
/* opaque = flow_data; enterprise=0; format=2209 */

typedef enum  {
  PKTDIR_unknown  = 0,
  PKTDIR_received = 1,
  PKTDIR_sent     = 2
} EnumPktDirection;

typedef struct  _SFLExtended_TCP_info {
  uint32_t dirn;        /* EnumPktDirection: Sampled packet direction */
  uint32_t snd_mss;     /* Cached effective mss, not including SACKS */
  uint32_t rcv_mss;     /* Max. recv. segment size */
  uint32_t unacked;     /* Packets which are "in flight" */
  uint32_t lost;        /* Lost packets */
  uint32_t retrans;     /* Retransmitted packets */
  uint32_t pmtu;        /* Last pmtu seen by socket */
  uint32_t rtt;         /* smoothed RTT (microseconds) */
  uint32_t rttvar;      /* RTT variance (microseconds) */
  uint32_t snd_cwnd;    /* Sending congestion window */
  uint32_t reordering;  /* Reordering */
  uint32_t min_rtt;     /* Minimum RTT (microseconds) */
} SFLExtended_TCP_info;

#define  XDRSIZ_SFLEXTENDED_TCP_INFO 48

/* Physical or virtual host description */
/* opaque = flow_data; enterprise = 0; format = 2210 */
/* Set Data source to all zeroes if unknown */
typedef struct _SFLExtended_entities {
  uint32_t src_dsClass; /* Data Source associated with packet source */
  uint32_t src_dsIndex;
  uint32_t dst_dsClass; /* Data Source associated with packet destination */
  uint32_t dst_dsIndex;
} SFLExtended_entities;

#define XDRSIZ_SFLEXTENDED_ENTITIES 16
  
/* Extended socket information,
   Must be filled in for all application transactions associated with a network socket
   Omit if transaction associated with non-network IPC  */

/* IPv4 Socket */
/* opaque = flow_data; enterprise = 0; format = 2100 */
typedef struct _SFLExtended_socket_ipv4 {
  uint32_t protocol;         /* IP Protocol (e.g. TCP = 6, UDP = 17) */
  SFLIPv4 local_ip;          /* local IP address */
  SFLIPv4 remote_ip;         /* remote IP address */
  uint32_t local_port;       /* TCP/UDP local port number or equivalent */
  uint32_t remote_port;      /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv4;

#define XDRSIZ_SFLEXTENDED_SOCKET4 20 

/* IPv6 Socket */
/* opaque = flow_data; enterprise = 0; format = 2101 */
typedef struct _SFLExtended_socket_ipv6 {
  uint32_t protocol;         /* IP Protocol (e.g. TCP = 6, UDP = 17) */
  SFLIPv6 local_ip;          /* local IP address */
  SFLIPv6 remote_ip;         /* remote IP address */
  uint32_t local_port;       /* TCP/UDP local port number or equivalent */
  uint32_t remote_port;      /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv6;

#define XDRSIZ_SFLEXTENDED_SOCKET6 44

/* Enterprise Status codes */

/* The status enumeration may be expanded over time.
   Applications receiving sFlow must be prepared to receive
   enterprise_operation structures with unknown status values.

   The authoritative list of machine types will be maintained
   at www.sflow.org */

typedef enum {
  SFLAPP_SUCCESS         = 0,
  SFLAPP_OTHER           = 1,
  SFLAPP_TIMEOUT         = 2,
  SFLAPP_INTERNAL_ERROR  = 3,
  SFLAPP_BAD_REQUEST     = 4,
  SFLAPP_FORBIDDEN       = 5,
  SFLAPP_TOO_LARGE       = 6,
  SFLAPP_NOT_IMPLEMENTED = 7,
  SFLAPP_NOT_FOUND       = 8,
  SFLAPP_UNAVAILABLE     = 9,
  SFLAPP_UNAUTHORIZED    = 10,
} EnumSFLAPPStatus;

/* Operation context */
typedef struct {
  SFLString application;
  SFLString operation;    /* type of operation (e.g. authorization, payment) */
  SFLString attributes;   /* specific attributes associated operation */
} SFLSampled_APP_CTXT;

#define SFLAPP_MAX_APPLICATION_LEN 32
#define SFLAPP_MAX_OPERATION_LEN 32
#define SFLAPP_MAX_ATTRIBUTES_LEN 255

/* Sampled Enterprise Operation */
/* opaque = flow_data; enterprise = 0; format = 2202 */
typedef struct {
  SFLSampled_APP_CTXT context; /* attributes describing the operation */
  SFLString status_descr;      /* additional text describing status (e.g. "unknown client") */
  uint64_t req_bytes;          /* size of request body (exclude headers) */
  uint64_t resp_bytes;         /* size of response body (exclude headers) */
  uint32_t duration_uS;        /* duration of the operation (microseconds) */
  EnumSFLAPPStatus status;     /* status code */
} SFLSampled_APP;

#define SFLAPP_MAX_STATUS_LEN 32

typedef struct {
  SFLString actor;
} SFLSampled_APP_ACTOR;

#define SFLAPP_MAX_ACTOR_LEN 64

/* Selected egress queue */
/* Output port number must be provided in enclosing structure */
/* opaque = flow_data; enterprise = 0; format = 1036 */
typedef struct {
  unsigned int queue;  /* eqress queue number selected for sampled packet */
} SFLExtended_egress_queue;
#define XDRSIZ_SFLEXTENDED_EGRESS_Q 4

/* Software function */
/* Name of software function generating this event */
/* opaque = flow_data; enterprise = 0; format = 1038 */
typedef struct _SFLExtended_function {
  SFLString symbol;
} SFLExtended_function;
#define SFL_MAX_FUNCTION_SYMBOL_LEN 64

  // Devlink Trap Name
  // opaque = flow_data; enterprise = 0; format = 1041
  // https://www.kernel.org/doc/html/latest/networking/devlink/devlink-trap.html
  // XDR spec:
  //  struct extended_hw_trap {
  //    string group<>; /* NET_DM_ATTR_HW_TRAP_GROUP_NAME */
  //    string trap<>; /* NET_DM_ATTR_HW_TRAP_NAME */
  //  }
typedef struct _SFLExtended_hw_trap {
  SFLString group;
  SFLString trap;
} SFLExtended_hw_trap;
#define SFL_MAX_HW_TRAP_LEN 64

  // Linux drop_monitor reason
  // opaque = flow_data; enterprise = 0; format = 1042
  // https://github.com/torvalds/linux/blob/master/include/net/dropreason.h
  // XDR spec:
  //  struct extended_linux_drop_reason {
  //    string reason<>; /* NET_DM_ATTR_REASON */
  //  }
typedef struct _SFLExtended_linux_reason {
  SFLString reason;
} SFLExtended_linux_reason;
#define SFL_MAX_LINUX_REASON_LEN 64

/* Delay for sampled packet traversing switch */
/* opaque = flow_data; enterprise = 0; format = 1039 */
typedef struct {
  unsigned int delay; /* transit delay in nanoseconds
			 0xffffffff indicates value >= 0xffffffff */
} SFLExtended_transit_delay;
#define XDRSIZ_SFLEXTENDED_TRANSIT 4

/* Queue depth for sampled packet traversing switch */
/* extended_egress_queue structure must be included */
/* opaque = flow_data; enterprise = 0; format = 1040 */
typedef struct {
  unsigned int depth;   /* queue depth in bytes */
} SFLExtended_queue_depth;
#define XDRSIZ_SFLEXTENDED_Q_DEPTH 4

enum SFLFlow_type_tag {
  /* enterprise = 0, format = ... */
  SFLFLOW_HEADER    = 1,      /* Packet headers are sampled */
  SFLFLOW_ETHERNET  = 2,      /* MAC layer information */
  SFLFLOW_IPV4      = 3,      /* IP version 4 data */
  SFLFLOW_IPV6      = 4,      /* IP version 6 data */
  SFLFLOW_EX_SWITCH    = 1001,      /* Extended switch information */
  SFLFLOW_EX_ROUTER    = 1002,      /* Extended router information */
  SFLFLOW_EX_GATEWAY   = 1003,      /* Extended gateway router information */
  SFLFLOW_EX_USER      = 1004,      /* Extended TACAS/RADIUS user information */
  SFLFLOW_EX_URL       = 1005,      /* Extended URL information */
  SFLFLOW_EX_MPLS      = 1006,      /* Extended MPLS information */
  SFLFLOW_EX_NAT       = 1007,      /* Extended NAT information */
  SFLFLOW_EX_MPLS_TUNNEL  = 1008,   /* additional MPLS information */
  SFLFLOW_EX_MPLS_VC      = 1009,
  SFLFLOW_EX_MPLS_FTN     = 1010,
  SFLFLOW_EX_MPLS_LDP_FEC = 1011,
  SFLFLOW_EX_VLAN_TUNNEL  = 1012,   /* VLAN stack */
  SFLFLOW_EX_L2_TUNNEL_EGRESS    = 1021,
  SFLFLOW_EX_L2_TUNNEL_INGRESS   = 1022,
  SFLFLOW_EX_IPV4_TUNNEL_EGRESS  = 1023,
  SFLFLOW_EX_IPV4_TUNNEL_INGRESS = 1024,
  SFLFLOW_EX_IPV6_TUNNEL_EGRESS  = 1025,
  SFLFLOW_EX_IPV6_TUNNEL_INGRESS = 1026,
  SFLFLOW_EX_DECAP_EGRESS        = 1027,
  SFLFLOW_EX_DECAP_INGRESS       = 1028,
  SFLFLOW_EX_VNI_EGRESS          = 1029,
  SFLFLOW_EX_VNI_INGRESS         = 1030,
  SFLFLOW_EX_EGRESS_Q            = 1036,
  SFLFLOW_EX_FUNCTION            = 1038,
  SFLFLOW_EX_TRANSIT             = 1039,
  SFLFLOW_EX_Q_DEPTH             = 1040,
  SFLFLOW_EX_HW_TRAP             = 1041,
  SFLFLOW_EX_LINUX_REASON        = 1042,
  SFLFLOW_EX_SOCKET4        = 2100, /* server socket */
  SFLFLOW_EX_SOCKET6        = 2101, /* server socket */
  SFLFLOW_EX_PROXY_SOCKET4  = 2102, /* back-end (client) socket */
  SFLFLOW_EX_PROXY_SOCKET6  = 2103, /* back-end (client) socket */
  SFLFLOW_APP               = 2202, /* transaction sample */
  SFLFLOW_APP_CTXT          = 2203, /* enclosing server context */
  SFLFLOW_APP_ACTOR_INIT    = 2204, /* initiator */
  SFLFLOW_APP_ACTOR_TGT     = 2205, /* target */
  SFLFLOW_EX_TCP_INFO       = 2209,
  SFLFLOW_EX_ENTITIES       = 2210
};

typedef union _SFLFlow_type {
  SFLSampled_header header;
  SFLSampled_ethernet ethernet;
  SFLSampled_ipv4 ipv4;
  SFLSampled_ipv6 ipv6;
  SFLExtended_switch sw;
  SFLExtended_router router;
  SFLExtended_gateway gateway;
  SFLExtended_user user;
  SFLExtended_url url;
  SFLExtended_mpls mpls;
  SFLExtended_nat nat;
  SFLExtended_mpls_tunnel mpls_tunnel;
  SFLExtended_mpls_vc mpls_vc;
  SFLExtended_mpls_FTN mpls_ftn;
  SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
  SFLExtended_vlan_tunnel vlan_tunnel;
  SFLExtended_l2_tunnel tunnel_l2;
  SFLExtended_ipv4_tunnel tunnel_ipv4;
  SFLExtended_ipv6_tunnel tunnel_ipv6;
  SFLExtended_decapsulate tunnel_decap;
  SFLExtended_vni tunnel_vni;
  SFLSampled_APP app;
  SFLSampled_APP_CTXT context;
  SFLSampled_APP_ACTOR actor;
  SFLExtended_socket_ipv4 socket4;
  SFLExtended_socket_ipv6 socket6;
  SFLExtended_TCP_info tcp_info;
  SFLExtended_entities entities;
  SFLExtended_function function;
  SFLExtended_egress_queue egress_queue;
  SFLExtended_queue_depth queue_depth;
  SFLExtended_transit_delay transit_delay;
  SFLExtended_hw_trap hw_trap;
  SFLExtended_linux_reason linux_reason;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element *nxt;
  uint32_t tag;  /* SFLFlow_type_tag */
  uint32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
  SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
  SFLCOUNTERS_SAMPLE_EXPANDED = 4, /* enterprise = 0 : format = 4 */
  SFLEVENT_DISCARDED_PACKET = 5    /* enterprise = 0 : format = 5 */
};
  
/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* uint32_t length; */
  uint32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  uint32_t source_id;            /* fsSourceId */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  uint32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  uint32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
#define SFL_INTERNAL_INTERFACE 0x3FFFFFFF
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample;

  /* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
  /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* uint32_t length; */
  uint32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  uint32_t ds_class;             /* EXPANDED */
  uint32_t ds_index;             /* EXPANDED */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  uint32_t inputFormat;          /* EXPANDED */
  uint32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  uint32_t outputFormat;         /* EXPANDED */
  uint32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known. */
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
  uint32_t ifIndex;
  uint32_t ifType;
  uint64_t ifSpeed;
  uint32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  uint32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  uint64_t ifInOctets;
  uint32_t ifInUcastPkts;
  uint32_t ifInMulticastPkts;
  uint32_t ifInBroadcastPkts;
  uint32_t ifInDiscards;
  uint32_t ifInErrors;
  uint32_t ifInUnknownProtos;
  uint64_t ifOutOctets;
  uint32_t ifOutUcastPkts;
  uint32_t ifOutMulticastPkts;
  uint32_t ifOutBroadcastPkts;
  uint32_t ifOutDiscards;
  uint32_t ifOutErrors;
  uint32_t ifPromiscuousMode;
} SFLIf_counters;

#define SFLSTATUS_ADMIN_UP 1
#define SFLSTATUS_OPER_UP 2

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
  uint32_t dot3StatsAlignmentErrors;
  uint32_t dot3StatsFCSErrors;
  uint32_t dot3StatsSingleCollisionFrames;
  uint32_t dot3StatsMultipleCollisionFrames;
  uint32_t dot3StatsSQETestErrors;
  uint32_t dot3StatsDeferredTransmissions;
  uint32_t dot3StatsLateCollisions;
  uint32_t dot3StatsExcessiveCollisions;
  uint32_t dot3StatsInternalMacTransmitErrors;
  uint32_t dot3StatsCarrierSenseErrors;
  uint32_t dot3StatsFrameTooLongs;
  uint32_t dot3StatsInternalMacReceiveErrors;
  uint32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
  uint32_t dot5StatsLineErrors;
  uint32_t dot5StatsBurstErrors;
  uint32_t dot5StatsACErrors;
  uint32_t dot5StatsAbortTransErrors;
  uint32_t dot5StatsInternalErrors;
  uint32_t dot5StatsLostFrameErrors;
  uint32_t dot5StatsReceiveCongestions;
  uint32_t dot5StatsFrameCopiedErrors;
  uint32_t dot5StatsTokenErrors;
  uint32_t dot5StatsSoftErrors;
  uint32_t dot5StatsHardErrors;
  uint32_t dot5StatsSignalLoss;
  uint32_t dot5StatsTransmitBeacons;
  uint32_t dot5StatsRecoverys;
  uint32_t dot5StatsLobeWires;
  uint32_t dot5StatsRemoves;
  uint32_t dot5StatsSingles;
  uint32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
  uint32_t dot12InHighPriorityFrames;
  uint64_t dot12InHighPriorityOctets;
  uint32_t dot12InNormPriorityFrames;
  uint64_t dot12InNormPriorityOctets;
  uint32_t dot12InIPMErrors;
  uint32_t dot12InOversizeFrameErrors;
  uint32_t dot12InDataErrors;
  uint32_t dot12InNullAddressedFrames;
  uint32_t dot12OutHighPriorityFrames;
  uint64_t dot12OutHighPriorityOctets;
  uint32_t dot12TransitionIntoTrainings;
  uint64_t dot12HCInHighPriorityOctets;
  uint64_t dot12HCInNormPriorityOctets;
  uint64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
  uint32_t vlan_id;
  uint64_t octets;
  uint32_t ucastPkts;
  uint32_t multicastPkts;
  uint32_t broadcastPkts;
  uint32_t discards;
} SFLVlan_counters;

/* Processor Information */
/* opaque = counter_data; enterprise = 0; format = 1001 */

typedef struct _SFLProcessor_counters {
   uint32_t five_sec_cpu;  /* 5 second average CPU utilization */
   uint32_t one_min_cpu;   /* 1 minute average CPU utilization */
   uint32_t five_min_cpu;  /* 5 minute average CPU utilization */
   uint64_t total_memory;  /* total memory (in bytes) */
   uint64_t free_memory;   /* free memory (in bytes) */
} SFLProcessor_counters;


enum SFLMachine_type {
  SFLMT_unknown = 0,
  SFLMT_other   = 1,
  SFLMT_x86     = 2,
  SFLMT_x86_64  = 3,
  SFLMT_ia64    = 4,
  SFLMT_sparc   = 5,
  SFLMT_alpha   = 6,
  SFLMT_powerpc = 7,
  SFLMT_m68k    = 8,
  SFLMT_mips    = 9,
  SFLMT_arm     = 10,
  SFLMT_hppa    = 11,
  SFLMT_s390    = 12
};

enum SFLOS_name {
  SFLOS_unknown   = 0,
  SFLOS_other     = 1,
  SFLOS_linux     = 2,
  SFLOS_windows   = 3,
  SFLOS_darwin    = 4,
  SFLOS_hpux      = 5,
  SFLOS_aix       = 6,
  SFLOS_dragonfly = 7,
  SFLOS_freebsd   = 8,
  SFLOS_netbsd    = 9,
  SFLOS_openbsd   = 10,
  SFLOS_osf       = 11,
  SFLOS_solaris   = 12
};

typedef struct _SFLMacAddress {
  uint8_t mac[8];
} SFLMacAddress;

typedef struct _SFLAdaptor {
  uint32_t ifIndex;
  char *deviceName;
  uint32_t ifDirection;
  uint64_t ifSpeed;
  uint32_t promiscuous;

  /* convenience hooks for clients */
  uint32_t marked;
  uint32_t peer_ifIndex;
  void *userData;

  uint32_t num_macs;
  SFLMacAddress macs[1];
} SFLAdaptor;

typedef struct _SFLAdaptorList {
  uint32_t capacity;
  uint32_t num_adaptors;
  SFLAdaptor **adaptors;
} SFLAdaptorList;

typedef struct _SFLHost_par_counters {
  uint32_t dsClass;       /* sFlowDataSource class */
  uint32_t dsIndex;       /* sFlowDataSource index */
} SFLHost_par_counters;

#define SFL_MAX_HOSTNAME_CHARS 64
#define SFL_MAX_OSRELEASE_CHARS 32

typedef struct _SFLHost_hid_counters {
  SFLString hostname;
  u_char uuid[16];
  uint32_t machine_type; /* enum SFLMachine_type */
  uint32_t os_name;      /* enum SFLOS_name */
  SFLString os_release;  /* max len 32 bytes */
} SFLHost_hid_counters;

typedef struct _SFLHost_nio_counters {
  uint64_t bytes_in;
  uint32_t pkts_in;
  uint32_t errs_in;
  uint32_t drops_in;
  uint64_t bytes_out;
  uint32_t pkts_out;
  uint32_t errs_out;
  uint32_t drops_out;
} SFLHost_nio_counters;

typedef struct _SFLHost_cpu_counters {
  float load_one;      /* 1 minute load avg. */
  float load_five;     /* 5 minute load avg. */
  float load_fifteen;  /* 15 minute load avg. */
  uint32_t proc_run;   /* running threads */
  uint32_t proc_total; /* total threads */
  uint32_t cpu_num;    /* # CPU cores */
  uint32_t cpu_speed;  /* speed in MHz of CPU */
  uint32_t uptime;     /* seconds since last reboot */
  uint32_t cpu_user;   /* time executing in user mode processes (ms) */
  uint32_t cpu_nice;   /* time executing niced processs (ms) */
  uint32_t cpu_system; /* time executing kernel mode processes (ms) */
  uint32_t cpu_idle;   /* idle time (ms) */
  uint32_t cpu_wio;    /* time waiting for I/O to complete (ms) */
  uint32_t cpu_intr;   /* time servicing interrupts (ms) */
  uint32_t cpu_sintr;  /* time servicing softirqs (ms) */
  uint32_t interrupts; /* interrupt count */
  uint32_t contexts;   /* context switch count */
  uint32_t cpu_steal;  /* time spent in other OS instances (virtual env) (ms) */
  uint32_t cpu_guest;  /* time spent running vcpu for guest OS */
  uint32_t cpu_guest_nice;  /* time spent running vcpu for "niced" guest OS */
} SFLHost_cpu_counters;

typedef struct _SFLHost_mem_counters {
  uint64_t mem_total;    /* total bytes */
  uint64_t mem_free;     /* free bytes */
  uint64_t mem_shared;   /* shared bytes */
  uint64_t mem_buffers;  /* buffers bytes */
  uint64_t mem_cached;   /* cached bytes */
  uint64_t swap_total;   /* swap total bytes */
  uint64_t swap_free;    /* swap free bytes */
  uint32_t page_in;      /* page in count */
  uint32_t page_out;     /* page out count */
  uint32_t swap_in;      /* swap in count */
  uint32_t swap_out;     /* swap out count */
} SFLHost_mem_counters;

typedef struct _SFLHost_dsk_counters {
  uint64_t disk_total;
  uint64_t disk_free;
  uint32_t part_max_used;   /* as percent * 100, so 100==1% */
  uint32_t reads;           /* reads issued */
  uint64_t bytes_read;      /* bytes read */
  uint32_t read_time;       /* read time (ms) */
  uint32_t writes;          /* writes completed */
  uint64_t bytes_written;   /* bytes written */
  uint32_t write_time;      /* write time (ms) */
} SFLHost_dsk_counters;


/* Virtual Node Statistics */
/* opaque = counter_data; enterprise = 0; format = 2100 */

typedef struct _SFLHost_vrt_node_counters {
   uint32_t mhz;           /* expected CPU frequency */
   uint32_t cpus;          /* the number of active CPUs */
   uint64_t memory;        /* memory size in bytes */
   uint64_t memory_free;   /* unassigned memory in bytes */
   uint32_t num_domains;   /* number of active domains */
} SFLHost_vrt_node_counters;

/* Virtual Domain CPU Statistics */
/* opaque = counter_data; enterprise = 0; format = 2101 */

/* virDomainState imported from libvirt.h */
enum SFLVirDomainState {
     SFL_VIR_DOMAIN_NOSTATE = 0, /* no state */
     SFL_VIR_DOMAIN_RUNNING = 1, /* the domain is running */
     SFL_VIR_DOMAIN_BLOCKED = 2, /* the domain is blocked on resource */
     SFL_VIR_DOMAIN_PAUSED  = 3, /* the domain is paused by user */
     SFL_VIR_DOMAIN_SHUTDOWN= 4, /* the domain is being shut down */
     SFL_VIR_DOMAIN_SHUTOFF = 5, /* the domain is shut off */
     SFL_VIR_DOMAIN_CRASHED = 6  /* the domain is crashed */
} ;

typedef struct _SFLHost_vrt_cpu_counters {
   uint32_t state;       /* SFLVirDomainState */
   uint32_t cpuTime;     /* the CPU time used in mS */
   uint32_t nrVirtCpu;   /* number of virtual CPUs for the domain */
} SFLHost_vrt_cpu_counters;

/* Virtual Domain Memory statistics */
/* opaque = counter_data; enterprise = 0; format = 2102 */

typedef struct _SFLHost_vrt_mem_counters {
  uint64_t memory;      /* memory in bytes used by domain */
  uint64_t maxMemory;   /* memory in bytes allowed */
} SFLHost_vrt_mem_counters;

/* Virtual Domain Disk statistics */
/* opaque = counter_data; enterprise = 0; format = 2103 */

typedef struct _SFLHost_vrt_dsk_counters {
   uint64_t capacity;   /* logical size in bytes */
   uint64_t allocation; /* current allocation in bytes */
   uint64_t available;  /* remaining free bytes */
   uint32_t rd_req;     /* number of read requests */
   uint64_t rd_bytes;   /* number of read bytes */
   uint32_t wr_req;     /* number of write requests */
   uint64_t wr_bytes;   /* number of  written bytes */
   uint32_t errs;       /* read/write errors */
} SFLHost_vrt_dsk_counters;

/* Virtual Domain Network statistics */
/* opaque = counter_data; enterprise = 0; format = 2104 */

/* for now this is exactly the same as the nio_counters
   so just use a #define for the type */
#define SFLHost_vrt_nio_counters SFLHost_nio_counters

/* NVML statistics */
/* opaque = counter_data; enterprise = 5703, format=1 */
typedef struct _SFLHost_gpu_nvml {
  uint32_t device_count;  /* see nvmlGetDeviceCount */  
  uint32_t processes;     /* see nvmlDeviceGetComputeRunningProcesses */
  uint32_t gpu_time;      /* total milliseconds in which one or more kernels was executing on GPU */
  uint32_t mem_time;      /* total milliseconds during which global device memory was being read/written */
  uint64_t mem_total;     /* bytes. see nvmlDeviceGetMemoryInfo */
  uint64_t mem_free;      /* bytes. see nvmlDeviceGetMemoryInfo */
  uint32_t ecc_errors;    /* see nvmlDeviceGetTotalEccErrors */
  uint32_t energy;        /* mJ. see nvmlDeviceGetPowerUsage */
  uint32_t temperature;   /* C. maximum across devices - see nvmlDeviceGetTemperature */
  uint32_t fan_speed;     /* %. maximum across devices - see nvmlDeviceGetFanSpeed */
} SFLHost_gpu_nvml;

///////////// TCP/UDP/ICMP from MIB-II ///////////////////////

/* IP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2007 */

typedef struct _SFLHost_ip_counters {
  uint32_t ipForwarding;
  uint32_t ipDefaultTTL;
  uint32_t ipInReceives;
  uint32_t ipInHdrErrors;
  uint32_t ipInAddrErrors;
  uint32_t ipForwDatagrams;
  uint32_t ipInUnknownProtos;
  uint32_t ipInDiscards;
  uint32_t ipInDelivers;
  uint32_t ipOutRequests;
  uint32_t ipOutDiscards;
  uint32_t ipOutNoRoutes;
  uint32_t ipReasmTimeout;
  uint32_t ipReasmReqds;
  uint32_t ipReasmOKs;
  uint32_t ipReasmFails;
  uint32_t ipFragOKs;
  uint32_t ipFragFails;
  uint32_t ipFragCreates;
} SFLHost_ip_counters;

#define SFLHOST_NUM_IP_COUNTERS 19
#define XDRSIZ_IP_COUNTERS (SFLHOST_NUM_IP_COUNTERS * sizeof(uint32_t))

/* ICMP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2008 */
  
typedef struct _SFLHost_icmp_counters {
  uint32_t icmpInMsgs;
  uint32_t icmpInErrors;
  uint32_t icmpInDestUnreachs;
  uint32_t icmpInTimeExcds;
  uint32_t icmpInParamProbs;
  uint32_t icmpInSrcQuenchs;
  uint32_t icmpInRedirects;
  uint32_t icmpInEchos;
  uint32_t icmpInEchoReps;
  uint32_t icmpInTimestamps;
  uint32_t icmpInAddrMasks;
  uint32_t icmpInAddrMaskReps;
  uint32_t icmpOutMsgs;
  uint32_t icmpOutErrors;
  uint32_t icmpOutDestUnreachs;
  uint32_t icmpOutTimeExcds;
  uint32_t icmpOutParamProbs;
  uint32_t icmpOutSrcQuenchs;
  uint32_t icmpOutRedirects;
  uint32_t icmpOutEchos;
  uint32_t icmpOutEchoReps;
  uint32_t icmpOutTimestamps;
  uint32_t icmpOutTimestampReps;
  uint32_t icmpOutAddrMasks;
  uint32_t icmpOutAddrMaskReps;
} SFLHost_icmp_counters;

#define SFLHOST_NUM_ICMP_COUNTERS 25
#define XDRSIZ_ICMP_COUNTERS (SFLHOST_NUM_ICMP_COUNTERS * sizeof(uint32_t))

/* TCP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2009 */

typedef struct _SFLHost_tcp_counters {
  uint32_t tcpRtoAlgorithm;
  uint32_t tcpRtoMin;
  uint32_t tcpRtoMax;
  uint32_t tcpMaxConn;
  uint32_t tcpActiveOpens;
  uint32_t tcpPassiveOpens;
  uint32_t tcpAttemptFails;
  uint32_t tcpEstabResets;
  uint32_t tcpCurrEstab;
  uint32_t tcpInSegs;
  uint32_t tcpOutSegs;
  uint32_t tcpRetransSegs;
  uint32_t tcpInErrs;
  uint32_t tcpOutRsts;
  uint32_t tcpInCsumErrors;
} SFLHost_tcp_counters;

#define SFLHOST_NUM_TCP_COUNTERS 15
#define XDRSIZ_TCP_COUNTERS (SFLHOST_NUM_TCP_COUNTERS * sizeof(uint32_t))

/* UDP Group - see MIB-II */
/* opaque = counter_data; enterprise = 0; format = 2010 */

typedef struct _SFLHost_udp_counters {
  uint32_t udpInDatagrams;
  uint32_t udpNoPorts;
  uint32_t udpInErrors;
  uint32_t udpOutDatagrams;
  uint32_t udpRcvbufErrors;
  uint32_t udpSndbufErrors;
  uint32_t udpInCsumErrors;
} SFLHost_udp_counters;

#define SFLHOST_NUM_UDP_COUNTERS 7
#define XDRSIZ_UDP_COUNTERS (SFLHOST_NUM_UDP_COUNTERS * sizeof(uint32_t))

/* Broadcom switch ASIC table utilizations */
/* opaque = counter_data; enterprise = 4413 (Broadcom); format = 3 */
typedef struct {
  uint32_t bcm_host_entries;
  uint32_t bcm_host_entries_max;
  uint32_t bcm_ipv4_entries;
  uint32_t bcm_ipv4_entries_max;
  uint32_t bcm_ipv6_entries;
  uint32_t bcm_ipv6_entries_max;
  uint32_t bcm_ipv4_ipv6_entries;
  uint32_t bcm_ipv4_ipv6_entries_max;
  uint32_t bcm_long_ipv6_entries;
  uint32_t bcm_long_ipv6_entries_max;
  uint32_t bcm_total_routes;
  uint32_t bcm_total_routes_max;
  uint32_t bcm_ecmp_nexthops;
  uint32_t bcm_ecmp_nexthops_max;
  uint32_t bcm_mac_entries;
  uint32_t bcm_mac_entries_max;
  uint32_t bcm_ipv4_neighbors;
  uint32_t bcm_ipv6_neighbors;
  uint32_t bcm_ipv4_routes;
  uint32_t bcm_ipv6_routes;
  uint32_t bcm_acl_ingress_entries;
  uint32_t bcm_acl_ingress_entries_max;
  uint32_t bcm_acl_ingress_counters;
  uint32_t bcm_acl_ingress_counters_max;
  uint32_t bcm_acl_ingress_meters;
  uint32_t bcm_acl_ingress_meters_max;
  uint32_t bcm_acl_ingress_slices;
  uint32_t bcm_acl_ingress_slices_max;
  uint32_t bcm_acl_egress_entries;
  uint32_t bcm_acl_egress_entries_max;
  uint32_t bcm_acl_egress_counters;
  uint32_t bcm_acl_egress_counters_max;
  uint32_t bcm_acl_egress_meters;
  uint32_t bcm_acl_egress_meters_max;
  uint32_t bcm_acl_egress_slices;
  uint32_t bcm_acl_egress_slices_max;
} SFLBCM_tables;

#define XDRSIZ_BCM_TABLES 144

/* Enterprise counters */
/* opaque = counter_data; enterprise = 0; format = 2202 */
typedef struct {
  SFLString application;
  uint32_t status_OK;
  uint32_t errors_OTHER;
  uint32_t errors_TIMEOUT;
  uint32_t errors_INTERNAL_ERROR;
  uint32_t errors_BAD_REQUEST;
  uint32_t errors_FORBIDDEN;
  uint32_t errors_TOO_LARGE;
  uint32_t errors_NOT_IMPLEMENTED;
  uint32_t errors_NOT_FOUND;
  uint32_t errors_UNAVAILABLE;
  uint32_t errors_UNAUTHORIZED;
} SFLAPPCounters;

/* Enterprise resource counters */
/* opaque = counter_data; enterprise = 0; format = 2203 */
typedef struct {
  uint32_t user_time;   /* in milliseconds */
  uint32_t system_time; /* in milliseconds */
  uint64_t mem_used;
  uint64_t mem_max;
  uint32_t fd_open;
  uint32_t fd_max;
  uint32_t conn_open;
  uint32_t conn_max;
} SFLAPPResources;

/* Enterprise application workers */
/* opaque = counter_data; enterprise = 0; format = 2206 */

typedef struct {
  uint32_t workers_active;
  uint32_t workers_idle;
  uint32_t workers_max;
  uint32_t req_delayed;
  uint32_t req_dropped;
} SFLAPPWorkers;

  /* LAG Port Statistics - see IEEE8023-LAG-MIB */
  /* opaque = counter_data; enterprise = 0; format = 7 */
typedef  union _SFLLACP_portState {
    uint32_t all;
    struct {
      uint8_t actorAdmin;
      uint8_t actorOper;
      uint8_t partnerAdmin;
      uint8_t partnerOper;
    } v;
} SFLLACP_portState;

typedef struct _SFLLACP_counters {
  uint8_t actorSystemID[8]; // 6 bytes + 2 pad
  uint8_t partnerSystemID[8]; // 6 bytes + 2 pad
  uint32_t attachedAggID;
  SFLLACP_portState portState;
  uint32_t LACPDUsRx;
  uint32_t markerPDUsRx;
  uint32_t markerResponsePDUsRx;
  uint32_t unknownRx;
  uint32_t illegalRx;
  uint32_t LACPDUsTx;
  uint32_t markerPDUsTx;
  uint32_t markerResponsePDUsTx;
} SFLLACP_counters;

#define XDRSIZ_LACP_COUNTERS 56

/* port name */
/* opaque = counter_data; enterprise = 0; format = 1005 */
typedef struct {
  SFLString portName;
} SFLPortName;

#define SFL_MAX_PORTNAME_LEN 255

/* Optical SFP/QSFP metrics */
/* opaque = counter_data; enterprise = 0; format = 10 */

typedef struct {
  uint32_t lane_index;      /* index of lane in module - starting from 1 */
  uint32_t tx_bias_current; /* microamps */
  uint32_t tx_power;        /* microwatts */
  uint32_t tx_power_min;    /* microwatts */
  uint32_t tx_power_max;    /* microwatts */
  uint32_t tx_wavelength;   /* nanometers */
  uint32_t rx_power;        /* microwatts */
  uint32_t rx_power_min;    /* microwatts */
  uint32_t rx_power_max;    /* microwatts */
  uint32_t rx_wavelength;   /* nanometers */
} SFLLane;

#define XDRSIZ_LANE_COUNTERS 40

typedef struct {
  uint32_t module_id;
  uint32_t module_total_lanes; /* total lanes in module */
  uint32_t module_supply_voltage; /* millivolts */
  int32_t module_temperature; /* signed - in oC / 1000 */
  uint32_t num_lanes; /* number of active lane structs to come */
  SFLLane *lanes;
} SFLSFP_counters;
  
/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_GENERIC       = 1,
  SFLCOUNTERS_ETHERNET      = 2,
  SFLCOUNTERS_TOKENRING     = 3,
  SFLCOUNTERS_VG            = 4,
  SFLCOUNTERS_VLAN          = 5,
  SFLCOUNTERS_80211         = 6,
  SFLCOUNTERS_LACP          = 7,
  SFLCOUNTERS_SFP           = 10,
  SFLCOUNTERS_PROCESSOR     = 1001,
  SFLCOUNTERS_RADIO         = 1002,
  SFLCOUNTERS_PORTNAME      = 1005,
  SFLCOUNTERS_HOST_HID      = 2000, /* host id */
  SFLCOUNTERS_ADAPTORS      = 2001, /* host adaptors */
  SFLCOUNTERS_HOST_PAR      = 2002, /* host parent */
  SFLCOUNTERS_HOST_CPU      = 2003, /* host cpu  */
  SFLCOUNTERS_HOST_MEM      = 2004, /* host memory  */
  SFLCOUNTERS_HOST_DSK      = 2005, /* host storage I/O  */
  SFLCOUNTERS_HOST_NIO      = 2006, /* host network I/O */
  SFLCOUNTERS_HOST_IP       = 2007,
  SFLCOUNTERS_HOST_ICMP     = 2008,
  SFLCOUNTERS_HOST_TCP      = 2009,
  SFLCOUNTERS_HOST_UDP      = 2010,
  SFLCOUNTERS_HOST_VRT_NODE = 2100, /* host virt node */
  SFLCOUNTERS_HOST_VRT_CPU  = 2101, /* host virt cpu */
  SFLCOUNTERS_HOST_VRT_MEM  = 2102, /* host virt mem */
  SFLCOUNTERS_HOST_VRT_DSK  = 2103, /* host virt storage */
  SFLCOUNTERS_HOST_VRT_NIO  = 2104, /* host virt network I/O */
  SFLCOUNTERS_APP           = 2202,
  SFLCOUNTERS_APP_RESOURCES = 2203,
  SFLCOUNTERS_APP_WORKERS   = 2206,
  SFLCOUNTERS_HOST_GPU_NVML = (5703 << 12) + 1, /* = 23359489 */
  SFLCOUNTERS_BCM_TABLES    = (4413 << 12) + 3,
};

typedef union _SFLCounters_type {
  SFLIf_counters generic;
  SFLEthernet_counters ethernet;
  SFLTokenring_counters tokenring;
  SFLVg_counters vg;
  SFLVlan_counters vlan;
  SFLProcessor_counters processor;
  SFLHost_par_counters host_par;
  SFLHost_hid_counters host_hid;
  SFLAdaptorList *adaptors;
  SFLHost_cpu_counters host_cpu;
  SFLHost_mem_counters host_mem;
  SFLHost_dsk_counters host_dsk;
  SFLHost_nio_counters host_nio;
  SFLHost_ip_counters host_ip;
  SFLHost_icmp_counters host_icmp;
  SFLHost_tcp_counters host_tcp;
  SFLHost_udp_counters host_udp;
  SFLHost_vrt_node_counters host_vrt_node;
  SFLHost_vrt_cpu_counters host_vrt_cpu;
  SFLHost_vrt_mem_counters host_vrt_mem;
  SFLHost_vrt_dsk_counters host_vrt_dsk;
  SFLHost_vrt_nio_counters host_vrt_nio;
  SFLHost_gpu_nvml host_gpu_nvml;
  SFLBCM_tables bcm_tables;
  SFLAPPCounters app;
  SFLAPPResources appResources;
  SFLAPPWorkers appWorkers;
  SFLLACP_counters lacp;
  SFLPortName portName;
  SFLSFP_counters sfp;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element *nxt; /* linked list */
  uint32_t tag; /* SFLCounters_type_tag */
  uint32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* uint32_t length; */
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t source_id;          /* fsSourceId */
  uint32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
  /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* uint32_t length; */
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t ds_class;           /* EXPANDED */
  uint32_t ds_index;           /* EXPANDED */
  uint32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFL_DROP(name, code) SFLDrop_ ## name=code,
typedef enum {
#include "sflow_drop.h"
} EnumSFLDropReason;
#undef SFL_DROP

typedef struct _SFLEvent_discarded_packet {
  uint32_t sequence_number;
  uint32_t ds_class; /* EXPANDED */
  uint32_t ds_index; /* EXPANDED */
  uint32_t drops;
  uint32_t input; /* ifIndex */
  uint32_t output; /* ifIndex */
  EnumSFLDropReason reason;
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLEvent_discarded_packet;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); (_sm)->num_elements++; } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  uint32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;        /* IP address of sampling agent */
  uint32_t sub_agent_id;          /* Used to distinguishing between datagram
                                      streams from separate agent sub entities
                                      within an device. */
  uint32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  uint32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  uint32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 8192
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_H */
