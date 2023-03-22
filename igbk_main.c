/* dummy.c: a dummy net-driver */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>
#include <linux/net_tstamp.h>
#include <net/rtnetlink.h>
#include <linux/u64_stats_sync.h>

/* Protocol specific headers */
#include <linux/ip.h>
#include <linux/icmp.h>

#define DRV_NAME		"dummy-eth"
#define DRV_VERSION		"1.0"
#define DRV_AUTHOR		"Kyung Min Park"

#undef pr_fmt
#define pr_fmt(fmt)	DRV_NAME ": " fmt

#define PRIV_BUF_LEN	128

/* Exported APIs from dummy HW module */
extern int lt_hw_tx(struct sk_buff *skb);
extern int32_t lt_request_irq(bool mode, int32_t (*dummy_rx)(struct sk_buff *));

struct dummy_priv {
	uint32_t unVersion;
	void *buffer;
	uint32_t buf_len;
};

struct pcpu_dstats {
	u64 tx_packets;
	u64 tx_bytes;
	struct u64_stats_sync syncp;
};

int32_t dummy_eth_rx(struct sk_buff *skb)
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

static netdev_tx_t dummy_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);

	skb_tx_timestamp(skb);

	/* Call HW xmit function */
	if (lt_hw_tx(skb))
		dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}

static int dummy_dev_init(struct net_device *dev)
{
	struct dummy_priv *priv = netdev_priv(dev);

	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	dev->dstats = netdev_alloc_pcpu_stats(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;

	priv->buffer = kcalloc(1, PRIV_BUF_LEN, GFP_KERNEL);
	if (!priv->buffer)
		free_percpu(dev->dstats);

	return 0;
}

static void dummy_dev_uninit(struct net_device *dev)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	free_percpu(dev->dstats);
}

static int dummy_change_carrier(struct net_device *dev, bool new_carrier)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

static int dummy_open(struct net_device *dev)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	netif_start_queue(dev);

	return 0;
}

static int dummy_close(struct net_device *dev)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	netif_stop_queue(dev);

	return 0;
}

static const struct net_device_ops dummy_netdev_ops = {
		.ndo_init				= dummy_dev_init,
		.ndo_uninit				= dummy_dev_uninit,
		.ndo_start_xmit			= dummy_xmit,
		.ndo_validate_addr		= eth_validate_addr,
		.ndo_set_mac_address	= eth_mac_addr,
		.ndo_change_carrier		= dummy_change_carrier,
		.ndo_open				= dummy_open,
		.ndo_stop				= dummy_close,
};

static void dummy_get_drvinfo(struct net_device *dev,
							  struct ethtool_drvinfo *info)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static int dummy_get_ts_info(struct net_device *dev,
							 struct ethtool_ts_info *ts_info)
{
	printk(KERN_ERR "DETH: %s() - called\n", __func__);
	ts_info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
							   SOF_TIMESTAMPING_RX_SOFTWARE |
							   SOF_TIMESTAMPING_SOFTWARE;
	ts_info->phc_index = -1;

	return 0;
}

static const struct ethtool_ops dummy_ethtool_ops = {
		.get_drvinfo = dummy_get_drvinfo,
		.get_ts_info = dummy_get_ts_info,
};

static void dummy_setup(struct net_device *dev)
{
	ether_setup(dev);

	/* Initialize the device structure */
	dev->netdev_ops = &dummy_netdev_ops;
	dev->ethtool_ops = &dummy_ethtool_ops;

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

static struct rtnl_link_ops dummy_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct dummy_priv),
	.setup		= dummy_setup,
};

static int __init dummy_init_one(void)
{
	int err;
	struct net_device *dev_dummy;

	dev_dummy = alloc_netdev(sizeof(struct dummy_priv),
							 "deth%d", NET_NAME_ENUM, dummy_setup);
	if (!dev_dummy)
		return -ENOMEM;

	dev_dummy->rtnl_link_ops = &dummy_link_ops;
	err = register_netdevice(dev_dummy);
	if (err < 0)
		goto err;

	/* True : Register, False : Deregister */
	if ((err = lt_request_irq(true, &dummy_eth_rx)))
		return err;

	return 0;
err:
	free_netdev(dev_dummy);

	return err;
}

static int __init dummy_init_module(void)
{
	int err = 0;

	printk("Dummy eth module init\n");

	rtnl_lock();
	err = __rtnl_link_register(&dummy_link_ops);
	if (err < 0)
		goto out;
	err = dummy_init_one();
	if (err < 0)
		__rtnl_link_unregister(&dummy_link_ops);
out:
	rtnl_unlock();

	return err;
}

static void __exit dummy_cleanup_module(void)
{
	printk("Dummy eth module exit\n");
	 __rtnl_link_unregister(&dummy_link_ops);
}

module_init(dummy_init_module);
module_exit(dummy_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
MODULE_VERSION(DRV_VERSION);
MODULE_AUTHOR(DRV_AUTHOR);
