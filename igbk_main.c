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

static void igbk_tx(struct sk_buff *skb);
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
		.ndo_start_xmit			= igbk_xmit,
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

	dev->min_mtu = 0;
	dev->max_mtu = 0;
}

static struct rtnl_link_ops igbk_link_ops __read_mostly = {
        .kind           = DRV_NAME,
        .priv_size      = sizeof(struct igbk_priv),
        .setup          = igbk_setup,
};

static void igbk_sw_init(struct igbk_adapter *adapter) {}
static int igbk_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    struct net_device *dev;
    struct igbk_adapter *adapter;
    void __iomem *ioaddr;
    int err;

    dev = alloc_etherdev(sizeof(struct igbk_adapter));
    if (!dev)
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
    pci_set_drvdata(pdev, dev);

    adapter = netdev_priv(dev);
    adapter->netdev = dev;
    adapter->pdev = pdev;
    adapter->ioaddr = pci_iomap(pdev, 0, 0);
    if (!adapter->ioaddr) {
        err = -ENOMEM;
        goto err_iomap;
    }

    igbk_sw_init(adapter);
    /* Set up the device and register it with the network layer */
    strncpy(dev->name, "eth%d", IFNAMSIZ);
    dev->irq = pdev->irq;
    dev->base_addr = (unsigned long)ioaddr;
    dev->netdev_ops = &igbk_netdev_ops;

    err = register_netdev(dev);
    if (err)
        goto err_register_netdev;

    return 0;

err_register_netdev:
    iounmap(ioaddr);
err_iomap:
    free_netdev(dev);
err_pci_reg:
err_dma:
    pci_disable_device(pdev);
    return err;
}

static void igbk_remove(struct pci_dev *pdev)
{
    struct net_device *dev = pci_get_drvdata(pdev);

    unregister_netdev(dev);
    iounmap((void __iomem *)dev->base_addr);
    free_netdev(dev);
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

	// TODO: check if we need to move this into probe function
	rtnl_lock();
	err = __rtnl_link_register(&igbk_link_ops);
	if (err < 0)
		goto out;
	err = pci_register_driver(&igbk_driver);
	if (err < 0)
		__rtnl_link_unregister(&igbk_link_ops);
out:
	rtnl_unlock();

	return err;
}

static void __exit igbk_cleanup_module(void)
{
	printk("igbk eth module exit\n");
	 __rtnl_link_unregister(&igbk_link_ops);
}

module_init(igbk_init_module);
module_exit(igbk_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
MODULE_VERSION(DRV_VERSION);
