#include <linux/pci.h>

#define MAX_MSIX_ENTRIES 10

struct igbk_adapter {
    struct net_device *netdev;
    struct pci_dev *pdev;
    unsigned int num_q_vectors;
    u8 __iomem *ioaddr;
    struct msix_entry msix_entries[MAX_MSIX_ENTRIES];
    /* TX */
    u16 tx_work_limit;
    u32 tx_timeout_count;
    int num_tx_queues;
    struct igb_ring *tx_ring[16];

    /* RX */
    int num_rx_queues;
    struct igb_ring *rx_ring[16];
};

struct e1000_bus_info {
	enum e1000_bus_type type;
	enum e1000_bus_speed speed;
	enum e1000_bus_width width;

	u32 snoop;

	u16 func;
	u16 pci_cmd_word;
};

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