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
