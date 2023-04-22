#include <linux/pci.h>
#include <linux/if_vlan.h>

#define MAX_MSIX_ENTRIES 10
#define MAX_Q_VECTORS		8

enum e1000_bus_type {
	e1000_bus_type_unknown = 0,
	e1000_bus_type_pci,
	e1000_bus_type_pcix,
	e1000_bus_type_pci_express,
	e1000_bus_type_reserved
};

enum e1000_bus_speed {
	e1000_bus_speed_unknown = 0,
	e1000_bus_speed_33,
	e1000_bus_speed_66,
	e1000_bus_speed_100,
	e1000_bus_speed_120,
	e1000_bus_speed_133,
	e1000_bus_speed_2500,
	e1000_bus_speed_5000,
	e1000_bus_speed_reserved
};

enum e1000_bus_width {
	e1000_bus_width_unknown = 0,
	e1000_bus_width_pcie_x1,
	e1000_bus_width_pcie_x2,
	e1000_bus_width_pcie_x4 = 4,
	e1000_bus_width_pcie_x8 = 8,
	e1000_bus_width_32,
	e1000_bus_width_64,
	e1000_bus_width_reserved
};

struct e1000_bus_info {
	enum e1000_bus_type type;
	enum e1000_bus_speed speed;
	enum e1000_bus_width width;

	u32 snoop;

	u16 func;
	u16 pci_cmd_word;
};

struct e1000_hw {
	void *back;

	u8 __iomem *hw_addr;
	u8 __iomem *flash_address;
	unsigned long io_base;

    struct e1000_bus_info bus;
	u16 device_id;
	u16 subsystem_vendor_id;
	u16 subsystem_device_id;
	u16 vendor_id;

	u8  revision_id;
};

/* Transmit Descriptor - Advanced */
union e1000_adv_tx_desc {
	struct {
		__le64 buffer_addr;    /* Address of descriptor's data buf */
		__le32 cmd_type_len;
		__le32 olinfo_status;
	} read;
	struct {
		__le64 rsvd;       /* Reserved */
		__le32 nxtseq_seed;
		__le32 status;e1000_adv_tx_desc
	} wb;
};

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer
 */
struct igb_tx_buffer {
	union  *next_to_watch;
	unsigned long time_stamp;
	struct sk_buff *skb;
	unsigned int bytecount;
	u16 gso_segs;
	__be16 protocol;

	//DEFINE_DMA_UNMAP_ADDR(dma);
	//DEFINE_DMA_UNMAP_LEN(len);
	u32 tx_flags;
};

/* HW board specific private data structure */
struct igbk_adapter {
    struct net_device *netdev;
    struct pci_dev *pdev;
    unsigned int num_q_vectors;
    u8 __iomem *ioaddr;
    struct msix_entry msix_entries[MAX_MSIX_ENTRIES];
	unsigned long state;
	unsigned int flags;

	/* Interrupt Throttle Rate */
	u32 rx_itr_setting;
	u32 tx_itr_setting;
	u16 tx_itr;
	u16 rx_itr;

    /* TX */
    u16 tx_work_limit;
    u32 tx_timeout_count;
    int num_tx_queues;
    struct igbk_ring *tx_ring[16];

    /* RX */
    int num_rx_queues;
    struct igbk_ring *rx_ring[16];

	u16 tx_ring_count;
	u16 rx_ring_count;

	u32 max_frame_size;
	u32 min_frame_size;

	struct igbk_q_vector *q_vector[MAX_Q_VECTORS];
	struct e1000_hw hw;
};

/* TX/RX descriptor defines */
#define IGBK_DEFAULT_TXD		256
#define IGBK_DEFAULT_RXD		256
#define IGBK_DEFAULT_ITR		3
#define IGBK_DEFAULT_TX_WORK	128
#define IGBK_ETH_PKT_HDR_PAD	(ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define IGBK_FLAG_HAS_MSIX		BIT(13)
#define MAX_MSIX_ENTRIES	10

struct igbk_tx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 restart_queue;
	u64 restart_queue2;
};

struct igbk_rx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 csum_err;
	u64 alloc_failed;
};

struct igbk_ring {
	struct igbk_q_vector *q_vector;	/* backlink to q_vector */
	struct net_device *netdev;	/* back pointer to net_device */
	struct bpf_prog *xdp_prog;
	struct device *dev;		/* device pointer for dma mapping */
	union {				/* array of buffer info structs */
		struct igbk_tx_buffer *tx_buffer_info;
		struct igbk_rx_buffer *rx_buffer_info;
	};
	void *desc;			/* descriptor ring memory */
	unsigned long flags;		/* ring specific flags */
	void __iomem *tail;		/* pointer to ring tail register */
	dma_addr_t dma;			/* phys address of the ring */
	unsigned int  size;		/* length of desc. ring in bytes */

	u16 count;			/* number of desc. in the ring */
	u8 queue_index;			/* logical index of the ring*/
	u8 reg_idx;			/* physical index of the ring */
	bool launchtime_enable;		/* true if LaunchTime is enabled */
	bool cbs_enable;		/* indicates if CBS is enabled */
	s32 idleslope;			/* idleSlope in kbps */
	s32 sendslope;			/* sendSlope in kbps */
	s32 hicredit;			/* hiCredit in bytes */
	s32 locredit;			/* loCredit in bytes */

	/* everything past this point are written often */
	u16 next_to_clean;
	u16 next_to_use;
	u16 next_to_alloc;

	union {
		/* TX */
		struct {
			struct igbk_tx_queue_stats tx_stats;
			struct u64_stats_sync tx_syncp;
			struct u64_stats_sync tx_syncp2;
		};
		/* RX */
		struct {
			struct sk_buff *skb;
			struct igbk_rx_queue_stats rx_stats;
			struct u64_stats_sync rx_syncp;
		};
	};
	struct xdp_rxq_info xdp_rxq;
} ____cacheline_internodealigned_in_smp;

struct igbk_ring_container {
	struct igbk_ring *ring;		/* pointer to linked list of rings */
	unsigned int total_bytes;	/* total bytes processed this int */
	unsigned int total_packets;	/* total packets processed this int */
	u16 work_limit;			/* total work allowed per interrupt */
	u8 count;			/* total number of rings in vector */
	u8 itr;				/* current ITR setting for ring */
};

struct igbk_q_vector {
	struct igbk_adapter *adapter;	/* backlink */
	int cpu;			/* CPU for DCA */
	u32 eims_value;			/* EIMS mask value */

	u16 itr_val;
	u8 set_itr;
	void __iomem *itr_register;

	struct igbk_ring_container rx, tx;

	struct napi_struct napi;
	struct rcu_head rcu;	/* to avoid race with update stats on free */
	char name[IFNAMSIZ + 9];

	/* for dynamic allocation of rings associated with this q_vector */
	struct igbk_ring ring[] ____cacheline_internodealigned_in_smp;
};

/* igbk_desc_unused - calculate if we have unused descriptors */
static inline int igbk_desc_unused(struct igbk_ring *ring)
{
	if (ring->next_to_clean > ring->next_to_use)
		return ring->next_to_clean - ring->next_to_use - 1;

	return ring->count + ring->next_to_clean - ring->next_to_use - 1;
}