/* dummy.c: a dummy net-driver */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>
#include <linux/net_tstamp.h>
#include <net/rtnetlink.h>
#include <linux/u64_stats_sync.h>
#include <linux/ethtool.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include "igbk.h"
#include "e1000_regs.h"

/* Protocol specific headers */
#include <linux/ip.h>
#include <linux/icmp.h>

#define DRV_NAME		"dummy-eth"
#define DRV_VERSION		"1.0"
#define DRV_AUTHOR		"Kyung Min Park"

#undef pr_fmt
#define pr_fmt(fmt)	DRV_NAME ": " fmt

#define PRIV_BUF_LEN		128
#define IGB_VENDOR_ID		0x8086
#define IGB_DEVICE_ID		0x10C9

#define IGBK_SET_FLAG(_input, _flag, _result) \
	((_flag <= _result) ? \
	 ((u32)(_input & _flag) * (_result / _flag)) : \
	 ((u32)(_input & _flag) / (_flag / _result)))

static int __igbk_maybe_stop_tx(struct igbk_ring *tx_ring, const u16 size)
{
	struct net_device *netdev = tx_ring->netdev;

	netif_stop_subqueue(netdev, tx_ring->queue_index);

	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it.
	 */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available.
	 */
	if (igbk_desc_unused(tx_ring) < size)
		return -EBUSY;

	/* A reprieve! */
	netif_wake_subqueue(netdev, tx_ring->queue_index);

	u64_stats_update_begin(&tx_ring->tx_syncp2);
	tx_ring->tx_stats.restart_queue2++;
	u64_stats_update_end(&tx_ring->tx_syncp2);

	return 0;
}

static inline int igbk_maybe_stop_tx(struct igbk_ring *tx_ring, const u16 size)
{
	if (igbk_desc_unused(tx_ring) >= size)
		return 0;
	return __igbk_maybe_stop_tx(tx_ring, size);
}

static void igbk_tx_olinfo_status(struct igbk_ring *tx_ring,
				 union e1000_adv_tx_desc *tx_desc,
				 u32 tx_flags, unsigned int paylen)
{
	u32 olinfo_status = paylen << E1000_ADVTXD_PAYLEN_SHIFT;

	/* 82575 requires a unique index per ring */
	if (test_bit(IGBK_RING_FLAG_TX_CTX_IDX, &tx_ring->flags))
		olinfo_status |= tx_ring->reg_idx << 4;

	/* insert L4 checksum */
	olinfo_status |= IGBK_SET_FLAG(tx_flags,
				      IGBK_TX_FLAGS_CSUM,
				      (E1000_TXD_POPTS_TXSM << 8));

	/* insert IPv4 checksum */
	olinfo_status |= IGBK_SET_FLAG(tx_flags,
				      IGBK_TX_FLAGS_IPV4,
				      (E1000_TXD_POPTS_IXSM << 8));

	tx_desc->read.olinfo_status = cpu_to_le32(olinfo_status);
}

static u32 igbk_tx_cmd_type(struct sk_buff *skb, u32 tx_flags)
{
	/* set type for advanced descriptor with frame checksum insertion */
	u32 cmd_type = E1000_ADVTXD_DTYP_DATA |
		       E1000_ADVTXD_DCMD_DEXT |
		       E1000_ADVTXD_DCMD_IFCS;

	/* set HW vlan bit if vlan is present */
	cmd_type |= IGBK_SET_FLAG(tx_flags, IGBK_TX_FLAGS_VLAN,
				 (E1000_ADVTXD_DCMD_VLE));

	/* set segmentation bits for TSO */
	cmd_type |= IGBK_SET_FLAG(tx_flags, IGBK_TX_FLAGS_TSO,
				 (E1000_ADVTXD_DCMD_TSE));

	/* set timestamp bit if present */
	cmd_type |= IGBK_SET_FLAG(tx_flags, IGBK_TX_FLAGS_TSTAMP,
				 (E1000_ADVTXD_MAC_TSTAMP));

	/* insert frame checksum */
	cmd_type ^= IGBK_SET_FLAG(skb->no_fcs, 1, E1000_ADVTXD_DCMD_IFCS);

	return cmd_type;
}

static void igbk_ring_irq_enable(struct igbk_q_vector *q_vector)
{
	struct igbk_adapter *adapter = q_vector->adapter;
	struct e1000_hw *hw = &adapter->hw;

	/* TODO: set the ITR (interrupt throttle rate) here */

	if (!test_bit(__IGBK_DOWN, &adapter->state)) {
		wr32(E1000_EIMS, q_vector->eims_value);
	}
}

static void igbk_free_q_vector(struct igbk_adapter *adapter, int v_idx)
{
	struct igbk_q_vector *q_vector = adapter->q_vector[v_idx];

	adapter->q_vector[v_idx] = NULL;

	/* igb_get_stats64() might access the rings on this vector,
	 * we must wait a grace period before freeing it.
	 */
	if (q_vector)
		kfree_rcu(q_vector, rcu);
}

static bool igbk_clean_rx_irq(struct igbk_q_vector *q_vector, int napi_budget)
{
	return 0;
}

static bool igbk_clean_tx_irq(struct igbk_q_vector *q_vector, int napi_budget)
{
	struct igbk_adapter *adapter = q_vector->adapter;
	struct igbk_ring *tx_ring = q_vector->tx.ring;
	struct igbk_tx_buffer *tx_buffer;
	union e1000_adv_tx_desc *tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = q_vector->tx.work_limit;
	unsigned int i = tx_ring->next_to_clean;

	if (test_bit(__IGBK_DOWN, &adapter->state))
		return true;

	tx_buffer = &tx_ring->tx_buffer_info[i];
	tx_desc = IGBK_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	do {
		union e1000_adv_tx_desc *eop_desc = tx_buffer->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		/* if DD is not set pending work has not been completed */
		if (!(eop_desc->wb.status & cpu_to_le32(E1000_TXD_STAT_DD)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buffer->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buffer->bytecount;
		total_packets += tx_buffer->gso_segs;

		/* free the skb */
		napi_consume_skb(tx_buffer->skb, napi_budget);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);

		/* clear tx_buffer data */
		dma_unmap_len_set(tx_buffer, len, 0);

		/* clear last DMA location and unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buffer = tx_ring->tx_buffer_info;
				tx_desc = IGBK_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buffer, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buffer, dma),
					       dma_unmap_len(tx_buffer, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buffer, len, 0);
			}
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buffer++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buffer = tx_ring->tx_buffer_info;
			tx_desc = IGBK_TX_DESC(tx_ring, 0);
		}

		/* issue prefetch for next Tx descriptor */
		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	netdev_tx_completed_queue(txring_txq(tx_ring),
				  total_packets, total_bytes);
	i += tx_ring->count;
	tx_ring->next_to_clean = i;
	u64_stats_update_begin(&tx_ring->tx_syncp);
	tx_ring->tx_stats.bytes += total_bytes;
	tx_ring->tx_stats.packets += total_packets;
	u64_stats_update_end(&tx_ring->tx_syncp);
	q_vector->tx.total_bytes += total_bytes;
	q_vector->tx.total_packets += total_packets;

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(total_packets &&
	    netif_carrier_ok(tx_ring->netdev) &&
	    igbk_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD)) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (__netif_subqueue_stopped(tx_ring->netdev,
					     tx_ring->queue_index) &&
		    !(test_bit(__IGBK_DOWN, &adapter->state))) {
			netif_wake_subqueue(tx_ring->netdev,
					    tx_ring->queue_index);

			u64_stats_update_begin(&tx_ring->tx_syncp);
			tx_ring->tx_stats.restart_queue++;
			u64_stats_update_end(&tx_ring->tx_syncp);
		}
	}

	return !!budget;
}

static int igbk_poll(struct napi_struct *napi, int budget)
{
	struct igbk_q_vector *q_vector = container_of(napi,
						     struct igbk_q_vector,
						     napi);
	bool clean_complete = true;
	int work_done = 0;

	if (q_vector->tx.ring)
		clean_complete = igbk_clean_tx_irq(q_vector, budget);

	if (q_vector->rx.ring) {
		int cleaned = igbk_clean_rx_irq(q_vector, budget);

		work_done += cleaned;
		if (cleaned >= budget)
			clean_complete = false;
	}

	/* If all work not completed, return budget and keep polling */
	if (!clean_complete)
		return budget;

	/* Exit the polling mode, but don't re-enable interrupts if stack might
	 * poll us due to busy-polling
	 */
	if (likely(napi_complete_done(napi, work_done)))
		igbk_ring_irq_enable(q_vector);

	return work_done;
}

static void igbk_add_ring(struct igbk_ring *ring,
			 struct igbk_ring_container *head)
{
	head->ring = ring;
	head->count++;
}

static int igbk_alloc_q_vector(struct igbk_adapter *adapter,
			      int v_count, int v_idx,
			      int txr_count, int txr_idx,
			      int rxr_count, int rxr_idx)
{
	struct igbk_q_vector *q_vector;
	struct igbk_ring *ring;
	int ring_count;
	size_t size;

	/* igb only supports 1 Tx and/or 1 Rx queue per vector */
	if (txr_count > 1 || rxr_count > 1)
		return -ENOMEM;

	ring_count = txr_count + rxr_count;
	size = struct_size(q_vector, ring, ring_count);

	/* allocate q_vector and rings */
	q_vector = adapter->q_vector[v_idx];
	if (!q_vector) {
		q_vector = kzalloc(size, GFP_KERNEL);
	} else if (size > ksize(q_vector)) {
		struct igbk_q_vector *new_q_vector;

		new_q_vector = kzalloc(size, GFP_KERNEL);
		if (new_q_vector)
			kfree_rcu(q_vector, rcu);
		q_vector = new_q_vector;
	} else {
		memset(q_vector, 0, size);
	}
	if (!q_vector)
		return -ENOMEM;

	/* initialize NAPI */
	netif_napi_add(adapter->netdev, &q_vector->napi, igbk_poll, 64);

	/* tie q_vector and adapter together */
	adapter->q_vector[v_idx] = q_vector;
	q_vector->adapter = adapter;

	/* initialize work limits */
	q_vector->tx.work_limit = adapter->tx_work_limit;

	/* initialize ITR configuration */
	q_vector->itr_register = adapter->ioaddr + E1000_EITR(0);
	q_vector->itr_val = IGBK_START_ITR;

	/* initialize pointer to rings */
	ring = q_vector->ring;

	/* intialize ITR */
	if (rxr_count) {
		/* rx or rx/tx vector */
		if (!adapter->rx_itr_setting || adapter->rx_itr_setting > 3)
			q_vector->itr_val = adapter->rx_itr_setting;
	} else {
		/* tx only vector */
		if (!adapter->tx_itr_setting || adapter->tx_itr_setting > 3)
			q_vector->itr_val = adapter->tx_itr_setting;
	}

	if (txr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		igbk_add_ring(ring, &q_vector->tx);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_count;
		ring->queue_index = txr_idx;

		ring->cbs_enable = false;
		ring->idleslope = 0;
		ring->sendslope = 0;
		ring->hicredit = 0;
		ring->locredit = 0;

		u64_stats_init(&ring->tx_syncp);
		u64_stats_init(&ring->tx_syncp2);

		/* assign ring to adapter */
		adapter->tx_ring[txr_idx] = ring;

		/* push pointer to next ring */
		ring++;
	}

	if (rxr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Rx values */
		igbk_add_ring(ring, &q_vector->rx);

		/* set flag indicating ring supports SCTP checksum offload */
		//set_bit(IGBK_RING_FLAG_RX_SCTP_CSUM, &ring->flags);

		/* On i350, i354, i210, and i211, loopback VLAN packets
		 * have the tag byte-swapped.
		 */
		//set_bit(IGB_RING_FLAG_RX_LB_VLAN_BSWAP, &ring->flags);

		/* apply Rx specific ring traits */
		ring->count = adapter->rx_ring_count;
		ring->queue_index = rxr_idx;

		u64_stats_init(&ring->rx_syncp);

		/* assign ring to adapter */
		adapter->rx_ring[rxr_idx] = ring;
	}

	return 0;
}

static int igbk_alloc_q_vectors(struct igbk_adapter *adapter)
{
	int q_vectors = adapter->num_q_vectors;
	int rxr_remaining = adapter->num_rx_queues;
	int txr_remaining = adapter->num_tx_queues;
	int rxr_idx = 0, txr_idx = 0, v_idx = 0;
	int err;

	if (q_vectors >= (rxr_remaining + txr_remaining)) {
		for (; rxr_remaining; v_idx++) {
			err = igbk_alloc_q_vector(adapter, q_vectors, v_idx,
						 0, 0, 1, rxr_idx);

			if (err)
				goto err_out;

			/* update counts and index */
			rxr_remaining--;
			rxr_idx++;
		}
	}

	for (; v_idx < q_vectors; v_idx++) {
		int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors - v_idx);
		int tqpv = DIV_ROUND_UP(txr_remaining, q_vectors - v_idx);

		err = igbk_alloc_q_vector(adapter, q_vectors, v_idx,
					 tqpv, txr_idx, rqpv, rxr_idx);

		if (err)
			goto err_out;

		/* update counts and index */
		rxr_remaining -= rqpv;
		txr_remaining -= tqpv;
		rxr_idx++;
		txr_idx++;
	}

	return 0;

err_out:
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		igbk_free_q_vector(adapter, v_idx);

	return -ENOMEM;
}

static int igbk_tx_map(struct igbk_ring *tx_ring,
		      struct igbk_tx_buffer *first,
		      const u8 hdr_len)
{
	struct sk_buff *skb = first->skb;
	struct igbk_tx_buffer *tx_buffer;
	union e1000_adv_tx_desc *tx_desc;
	skb_frag_t *frag;
	dma_addr_t dma;
	unsigned int data_len, size;
	u32 tx_flags = first->tx_flags;
	u32 cmd_type = igbk_tx_cmd_type(skb, tx_flags);
	u16 i = tx_ring->next_to_use;

	tx_desc = IGBK_TX_DESC(tx_ring, i);

	igbk_tx_olinfo_status(tx_ring, tx_desc, tx_flags, skb->len - hdr_len);

	size = skb_headlen(skb);
	data_len = skb->data_len;

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buffer = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buffer, len, size);
		dma_unmap_addr_set(tx_buffer, dma, dma);

		tx_desc->read.buffer_addr = cpu_to_le64(dma);

		while (unlikely(size > IGBK_MAX_DATA_PER_TXD)) {
			tx_desc->read.cmd_type_len =
				cpu_to_le32(cmd_type ^ IGBK_MAX_DATA_PER_TXD);

			i++;
			tx_desc++;
			if (i == tx_ring->count) {
				tx_desc = IGBK_TX_DESC(tx_ring, 0);
				i = 0;
			}
			tx_desc->read.olinfo_status = 0;

			dma += IGBK_MAX_DATA_PER_TXD;
			size -= IGBK_MAX_DATA_PER_TXD;

			tx_desc->read.buffer_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type ^ size);

		i++;
		tx_desc++;
		if (i == tx_ring->count) {
			tx_desc = IGBK_TX_DESC(tx_ring, 0);
			i = 0;
		}
		tx_desc->read.olinfo_status = 0;

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0,
				       size, DMA_TO_DEVICE);

		tx_buffer = &tx_ring->tx_buffer_info[i];
	}

	/* write last descriptor with RS and EOP bits */
	cmd_type |= size | IGBK_TXD_DCMD;
	tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);

	netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount);

	/* set the timestamp */
	first->time_stamp = jiffies;

	skb_tx_timestamp(skb);

	/* Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.  (Only applicable for weak-ordered
	 * memory model archs, such as IA-64).
	 *
	 * We also need this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	dma_wmb();

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	i++;
	if (i == tx_ring->count)
		i = 0;

	tx_ring->next_to_use = i;

	/* Make sure there is space in the ring for the next send. */
	igbk_maybe_stop_tx(tx_ring, DESC_NEEDED);

	if (netif_xmit_stopped(txring_txq(tx_ring)) || !netdev_xmit_more()) {
		writel(i, tx_ring->tail);
	}
	return 0;

dma_error:
	dev_err(tx_ring->dev, "TX DMA map failed\n");
	tx_buffer = &tx_ring->tx_buffer_info[i];

	/* clear dma mappings for failed tx_buffer_info map */
	while (tx_buffer != first) {
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_page(tx_ring->dev,
				       dma_unmap_addr(tx_buffer, dma),
				       dma_unmap_len(tx_buffer, len),
				       DMA_TO_DEVICE);
		dma_unmap_len_set(tx_buffer, len, 0);

		if (i-- == 0)
			i += tx_ring->count;
		tx_buffer = &tx_ring->tx_buffer_info[i];
	}

	if (dma_unmap_len(tx_buffer, len))
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);
	dma_unmap_len_set(tx_buffer, len, 0);

	dev_kfree_skb_any(tx_buffer->skb);
	tx_buffer->skb = NULL;

	tx_ring->next_to_use = i;

	return -1;
}

netdev_tx_t igbk_xmit_frame_ring(struct sk_buff *skb, struct igbk_ring *tx_ring)
{
	struct igbk_tx_buffer *first;
	int tso;
	u32 tx_flags = 0;
	unsigned short f;
	u16 count = TXD_USE_COUNT(skb_headlen(skb));
	__be16 protocol = vlan_get_protocol(skb);
	u8 hdr_len = 0;

	/* need: 1 descriptor per page * PAGE_SIZE/IGB_MAX_DATA_PER_TXD,
	 *       + 1 desc for skb_headlen/IGB_MAX_DATA_PER_TXD,
	 *       + 2 desc gap to keep tail from touching head,
	 *       + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++)
		count += TXD_USE_COUNT(skb_frag_size(
						&skb_shinfo(skb)->frags[f]));

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;

	/* record initial flags and protocol */
	first->tx_flags = tx_flags;
	first->protocol = protocol;

	/* TODO: add tso later */
	/*
	tso = igbk_tso(tx_ring, first, &hdr_len);
	if (tso < 0)
		goto out_drop;
	else if (!tso)
		igbk_tx_csum(tx_ring, first);

	*/
	if (igbk_tx_map(tx_ring, first, hdr_len))
		goto cleanup_tx_tstamp;

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(first->skb);
	first->skb = NULL;
cleanup_tx_tstamp:
	if (unlikely(tx_flags & IGBK_TX_FLAGS_TSTAMP)) {
		struct igbk_adapter *adapter = netdev_priv(tx_ring->netdev);

		dev_kfree_skb_any(adapter->ptp_tx_skb);
		adapter->ptp_tx_skb = NULL;
		cancel_work_sync(&adapter->ptp_tx_work);
		clear_bit_unlock(__IGBK_PTP_TX_IN_PROGRESS, &adapter->state);
	}

	return NETDEV_TX_OK;
}

static netdev_tx_t igbk_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct igbk_adapter *adapter = netdev_priv(netdev);
	unsigned int r_idx = skb->queue_mapping;

	if (r_idx >= adapter->num_tx_queues)
		r_idx = r_idx % adapter->num_tx_queues;
	return igbk_xmit_frame_ring(skb, adapter->tx_ring[r_idx]);
}

static const struct pci_device_id igbk_pci_tbl[] = {
	{PCI_DEVICE(IGB_VENDOR_ID, IGB_DEVICE_ID)},
	{0,},
};
MODULE_DEVICE_TABLE(pci, igbk_pci_tbl);

struct igbk_priv {
	uint32_t unVersion;
	void *buffer;
	uint32_t buf_len;
};

struct pcpu_dstats {
	u64 tx_packets;
	u64 tx_bytes;
	struct u64_stats_sync syncp;
};

int32_t igbk_eth_rx(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct icmphdr *icmph = NULL;
	int32_t addr = 0;
	char eth_addr[ETH_ALEN];

	if (skb == NULL) {
		printk(KERN_ERR "DETH: skb is null\n");
		return -EINVAL;
	}

	/* Mangle the packet to send ICMP/ping reply */
	iph = ip_hdr(skb);
	if (iph && iph->protocol == IPPROTO_ICMP) {
		__wsum csum = 0;

		icmph = icmp_hdr(skb);
		if (icmph == NULL) {
			printk(KERN_ERR "DETH: no such ICMP header\n");
			goto free;
		}
		print_hex_dump(KERN_ERR, "DETH B: ", 0, 16, 1, skb->data, skb->len, 0);
		/* Alter MAC addresses */
		memcpy(eth_addr, skb->data, ETH_ALEN);
		memmove(skb->data, skb->data + ETH_ALEN, ETH_ALEN);
		memcpy(skb->data + ETH_ALEN, eth_addr, ETH_ALEN);
		/* Alter IP addresses */
		addr = iph->daddr;
		iph->daddr = iph->saddr;
		iph->saddr = addr;
		/* ICMP echo reply */
		icmph->type = ICMP_ECHOREPLY;
		/* FIXME: Recalculate ICMP header checksum */
		icmph->checksum = 0;
		csum = csum_partial((u8 *)icmph, ntohs(iph->tot_len) - (iph->ihl * 4), csum);
		icmph->checksum = csum_fold(csum);

		print_hex_dump(KERN_ERR, "DETH A: ", 0, 16, 1, skb->data, skb->len, 0);
		/* Pass frame up. XXX: need to enable hairpin, as same netdev? */
		skb->protocol = eth_type_trans(skb, skb->dev);
		netif_rx(skb);
	} else {
		printk(KERN_ERR "DETH: not a ping packet\n");
		goto free;
	}

	return 0;
free:
	dev_kfree_skb(skb);

	return 0;
}

static void igbk_tx(struct sk_buff *skb){}
static int igbk_init_interrupt_scheme(struct igbk_adapter *adapter, bool msix){return 0;}
static void igbk_irq_disable(struct igbk_adapter *adapter){}

static netdev_tx_t igbk_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);

	skb_tx_timestamp(skb);

	/* TODO: implement igbk_tx function */
	//if (igbk_tx(skb))
	//	dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}

static int igbk_dev_init(struct net_device *dev)
{
	struct igbk_priv *priv = netdev_priv(dev);

	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	dev->dstats = netdev_alloc_pcpu_stats(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;

	priv->buffer = kcalloc(1, PRIV_BUF_LEN, GFP_KERNEL);
	if (!priv->buffer)
		free_percpu(dev->dstats);

	return 0;
}

static void igbk_dev_uninit(struct net_device *dev)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	free_percpu(dev->dstats);
}

static int igbk_change_carrier(struct net_device *dev, bool new_carrier)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

static int igbk_open(struct net_device *dev)
{
	printk(KERN_ERR "KETH: %s() - called\n", __func__);
	netif_start_queue(dev);

	return 0;
}

static int igbk_close(struct net_device *dev)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	netif_stop_queue(dev);

	return 0;
}

static const struct net_device_ops igbk_netdev_ops = {
		.ndo_init				= igbk_dev_init,
		.ndo_uninit				= igbk_dev_uninit,
		.ndo_start_xmit			= igbk_xmit_frame,
		.ndo_validate_addr		= eth_validate_addr,
		.ndo_set_mac_address	= eth_mac_addr,
		.ndo_change_carrier		= igbk_change_carrier,
		.ndo_open				= igbk_open,
		.ndo_stop				= igbk_close,
};

static void igbk_get_drvinfo(struct net_device *dev,
							  struct ethtool_drvinfo *info)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static int igbk_get_ts_info(struct net_device *dev,
							 struct ethtool_ts_info *ts_info)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	ts_info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
							   SOF_TIMESTAMPING_RX_SOFTWARE |
							   SOF_TIMESTAMPING_SOFTWARE;
	ts_info->phc_index = -1;

	return 0;
}

static const struct ethtool_ops igbk_ethtool_ops = {
		.get_drvinfo = igbk_get_drvinfo,
		.get_ts_info = igbk_get_ts_info,
};

static void igbk_setup(struct net_device *dev)
{
	ether_setup(dev);

	/* Initialize the device structure */
	dev->netdev_ops = &igbk_netdev_ops;
	dev->ethtool_ops = &igbk_ethtool_ops;

	/* TODO: do we still need a netif here?
	/* Fill in device structure with ehternet-generic values */
	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	dev-> features |= NETIF_F_SG | NETIF_F_FRAGLIST; 
	dev-> features |= NETIF_F_ALL_TSO;
	dev-> features |= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
	dev-> features |= NETIF_F_GSO_ENCAP_ALL;
	dev->hw_features |= dev->features;
	dev->hw_enc_features |= dev->features;
	eth_hw_addr_random(dev);

	dev->min_mtu = ETH_MIN_MTU;;
	dev->max_mtu = MAX_STD_JUMBO_FRAME_SIZE;
}

static int igbk_sw_init(struct igbk_adapter *adapter) {
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_hw *hw = &adapter->hw;

	pci_read_config_word(pdev, PCI_COMMAND, &hw->bus.pci_cmd_word);

	/* set default ring sizes */
	adapter->tx_ring_count = IGBK_DEFAULT_TXD;
	adapter->rx_ring_count = IGBK_DEFAULT_RXD;

	/* set default ITR values */
	adapter->rx_itr_setting = IGBK_DEFAULT_ITR;
	adapter->tx_itr_setting = IGBK_DEFAULT_ITR;

	/* set default work limits */
	adapter->tx_work_limit = IGBK_DEFAULT_TX_WORK;

	adapter->max_frame_size = netdev->mtu + IGBK_ETH_PKT_HDR_PAD;
	adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

	adapter->flags |= IGBK_FLAG_HAS_MSIX;

	//TODO: do we need to populate mac_table here?
	//TODO: rx implement
	if (igbk_init_interrupt_scheme(adapter, true)) {
		dev_err(&pdev->dev, "Unable to allocate memory for queues\n");
		return -ENOMEM;
	}
	igbk_irq_disable(adapter);

	return 0;
}

static int igbk_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct igbk_adapter *adapter;
	struct e1000_hw *hw;
	int err;

	netdev = alloc_etherdev(sizeof(struct igbk_adapter));
	if (!netdev)
		return -ENOMEM;
	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(&pdev->dev, "No usable DMA configuration, aborting\n");
		goto err_dma;
	}

	err = pci_request_mem_regions(pdev, "igbk");
	if (err)
		goto err_pci_reg;

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);
	pci_save_state(pdev);
	pci_set_drvdata(pdev, netdev);

	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	hw = &adapter->hw;
	hw->back = adapter;
	adapter->ioaddr = pci_iomap(pdev, 0, 0);
	if (!adapter->ioaddr) {
		err = -ENOMEM;
		goto err_iomap;
	}

	err = igbk_sw_init(adapter);
	/* Set up the device and register it with the network layer */
	strncpy(netdev->name, "eth%d", IFNAMSIZ);
	netdev->irq = pdev->irq;
	netdev->netdev_ops = &igbk_netdev_ops;
	netdev->ethtool_ops = &igbk_ethtool_ops;

	igbk_setup(netdev);
	err = register_netdev(netdev);
	if (err)
		goto err_register_netdev;

	return 0;

err_register_netdev:
		iounmap(adapter->ioaddr);
err_iomap:
		free_netdev(netdev);
err_pci_reg:
err_dma:
		pci_disable_device(pdev);
		return err;
}

static void igbk_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);

	unregister_netdev(netdev);
	iounmap((void __iomem *)netdev->base_addr);
	free_netdev(netdev);
}

static struct pci_driver igbk_driver = {
	.name = "igbk",
	.id_table = igbk_pci_tbl,
	.probe = igbk_probe,
	.remove = igbk_remove,
};

static int __init igbk_init_module(void)
{
	int err = 0;

	printk("igbk eth module init\n");
	err = pci_register_driver(&igbk_driver);

	return err;
}

static void __exit igbk_cleanup_module(void)
{
	printk("igbk eth module exit\n");
	pci_unregister_driver(&igbk_driver);
}

module_init(igbk_init_module);
module_exit(igbk_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
MODULE_VERSION(DRV_VERSION);
