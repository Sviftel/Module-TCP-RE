#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/ip.h>

#include "cache_structure.h"
#include "tcp_processing.h"

MODULE_LICENSE("GPL");

struct nf_hook_ops bundle;
char module_header[] = "low_module: ";
// long trg_ip[] = {192, 168, 56, 1};
// long trg_port = 13334;


struct cache *c;


// void print_pkt(const struct sk_buff *skb) {
//     int i;

//     printk("TCP segment: ");
//     unsigned char *tcp_d = (unsigned char *)(
//             skb->data + ip_hdrlen(skb)
//         );
//     for (i = 0 ; i < tcp_hdrlen(skb); ++i) {
//         printk("%x", *(tcp_d + i));
//     }

//     printk(" Payload: ");
//     unsigned char *pl = (unsigned char *)(
//             skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
//         );

//     for (i = 0 ; i < skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb); ++i) {
//         printk("%x", *(pl + i));
//     }
// }


void restore_pl(unsigned char *pl,
                const unsigned char *cached_pl,
                int cached_pl_len)
{
    memcpy(pl, cached_pl, cached_pl_len);
}



unsigned int hook_func(const struct nf_hook_ops *ops,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{
    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *iph = ip_hdr(skb);

        // if (ntohl(iph->saddr) >> 24 == trg_ip[0] &&
        //     ((ntohl(iph->saddr) >> 16) & 0x00FF) == trg_ip[1] &&
        //     ((ntohl(iph->saddr) >> 8) & 0x0000FF) == trg_ip[2] &&
        //     ((ntohl(iph->saddr)) & 0x000000FF) == trg_ip[3])
        // {
            // if (iph->protocol == IPPROTO_TCP &&
            //     ntohs(tcp_hdr(skb)->dest) == trg_port)
            if (iph->protocol == IPPROTO_TCP) {
                unsigned int pl_len = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
                unsigned char *pl = (unsigned char *)(
                        skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
                    );

                // printk("%sBefore. ", module_header);
                // print_pkt(skb);
                // printk("\n");

                if (pl_len > TOTAL_HASH_INFO_LEN) {
                    unsigned char *hash_val, id;
                    add_to_cache(c, pl, pl_len, &hash_val, &id);
                } else
                if (pl_len == TOTAL_HASH_INFO_LEN) {
                    if (tcp_is_hashed(tcp_hdr(skb))) {
                        unsigned char *cached_pl;
                        int cached_pl_len;
                        unsigned char id = pl[HASH_LEN];
                        get_pl_info(c, pl, id, &cached_pl, &cached_pl_len);

                        if (cached_pl != NULL) {
                            unsigned int d = cached_pl_len - pl_len;

                            if (!pskb_expand_head(skb, 0, d, GFP_KERNEL)) {
                                skb_put(skb, d);
                                struct tcphdr *tcph = tcp_hdr(skb);
                                iph = ip_hdr(skb);

                                iph->tot_len = htons((unsigned short)skb->len);

                                pl = (unsigned char *)(
                                        skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
                                    );
                                restore_pl(pl, cached_pl, cached_pl_len);

                                tcph->check = htons(0);
                                int len = skb->len - ip_hdrlen(skb);
                                tcph->check = tcp_v4_check(len, iph->saddr, iph->daddr,
                                                           csum_partial((char*)tcph,
                                                           len, 0));

                                iph->check = htons(0);
                                iph->check = ip_fast_csum((unsigned char *)iph,
                                                          iph->ihl);

                                // printk("%sAfter restoring. ", module_header);
                                // print_pkt(skb);
                                // printk("\n");
                            }
                        }
                    }
                }
            }
        // }
    }

    return NF_ACCEPT;
}


int init_func(void) {
    printk("%sStart initializing new hook\n", module_header);

    alloc_hash_structs();
    c = kmalloc(sizeof(struct cache), GFP_KERNEL);
    init_cache(c, 256);

    bundle.hook = hook_func;
    bundle.owner = THIS_MODULE;
    bundle.pf = PF_INET;
    bundle.hooknum = NF_INET_PRE_ROUTING;
    bundle.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&bundle);

    return 0;
}


void exit_func(void) {
    printk("%sTotal hitrate: %d\n", module_header, get_hitrate(c));
    printk("%sSaved traffic part: %d\n", module_header,
           get_saved_traffic_part(c));

    clean_cache(c);
    kfree(c);
    free_hash_structs();

    nf_unregister_hook(&bundle);
    printk("%sEnd of working wuth hook_func\n", module_header);
}


module_init(init_func);
module_exit(exit_func);
