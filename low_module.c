#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>


struct nf_hook_ops bundle;
static char module_header[] = "low_module: ";

unsigned int hook_func(const struct nf_hook_ops *ops,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    printk("%sPacket to send, dst ip addr: %pI4\n", module_header, &iph->daddr);

    

    return NF_ACCEPT;
}


int init_func(void) {
    printk("%sStart initializing new hook\n", module_header);

    bundle.hook = hook_func;
    bundle.owner = THIS_MODULE;
    bundle.pf = PF_INET;
    bundle.hooknum = NF_INET_POST_ROUTING;
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