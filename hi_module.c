#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>


struct nf_hook_ops bundle;
static char module_header[] = "hi_module: ";
static long trg_ip[] = {92, 53, 114, 76};


unsigned int hook_func(const struct nf_hook_ops *ops,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    printk("%sPacket to receive, src ip addr: %pI4\n", module_header, &iph->saddr);

    if (ntohl(ip->saddr) >> 24 == trg_ip[0] &&
        (ntohl(ip->saddr) >> 16) & 0x00FF == trg_ip[1] &&
        (ntohl(ip->saddr) >> 8) & 0x0000FF == trg_ip[2] &&
        (ntohl(ip->saddr)) & 0x000000FF == trg_ip[3])
    {
        printk("From target ip!\n");
    }

    if (iph->protocol == IPPROTO_TCP) {
        // struct tcphdr *tcph = tcp_hdr(skb);
        // char *payload = (char *)(
        //         skb->data + sizeof() + sizeof(struct tcphdr)
        //     );
    }

    return NF_ACCEPT;
}


int init_func(void) {
    printk("%sStart initializing new hook\n", module_header);

    bundle.hook = hook_func;
    bundle.owner = THIS_MODULE;
    bundle.pf = PF_INET;
    bundle.hooknum = NF_INET_PRE_ROUTING;
    bundle.priority = NF_IP_PRI_LAST;

    nf_register_hook(&bundle);

    return 0;
}


void exit_func(void) {
    nf_unregister_hook(&bundle);
    printk("%sEnd of working wuth hook_func\n", module_header);
}


module_init(init_func);
module_exit(exit_func);