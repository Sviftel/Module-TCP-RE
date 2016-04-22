#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/tcp.h>


struct nf_hook_ops bundle;
char module_header[] = "low_module: ";
long trg_ip[] = {192, 168, 56, 101};
long trg_port = 13334;

unsigned char new_char = 'F';
unsigned char trg_msg[] = {'d', 'd', 'd', 'd', '\n'};
unsigned int trg_msg_len = 5;


bool check_pl(unsigned char *pl, unsigned int pl_len) {
    if (pl_len != trg_msg_len)
        return false;

    unsigned int i;
    for (i = 0; i < pl_len; ++i)
        if (pl[i] != trg_msg[i])
            return false;

    return true;
}


void fill_pl(unsigned char *pl, unsigned int pl_len) {
    int i;

    for (i = 0; i < pl_len; ++i) {
        pl[i] = new_char;
    }
}


void print_chars(unsigned char *buf, int buf_len) {
    int i;
    unsigned char curr_char;

    for (i = 0; i < buf_len; i++) {
        curr_char = buf[i];
        if (curr_char >= 'A' && curr_char <= 'Z' ||
            curr_char >= 'a' && curr_char <= 'z')
            printk("%c", curr_char);
        else 
            printk("!");
    }
}


void print_pkt(struct sk_buff *skb) {
    int i;

    printk("Packet: ");
    for (i = 0 ; i < skb->len; ++i) {
        printk("%x", *(skb->data + i));
    }

    printk(" Payload: ");
    unsigned char *pl = (unsigned char *)(
            skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
        );

    for (i = 0 ; i < skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb); ++i) {
        printk("%x", *(pl + i));
    }
}


unsigned int hook_func(const struct nf_hook_ops *ops,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);

    if (ntohl(iph->daddr) >> 24 == trg_ip[0] &&
        ((ntohl(iph->daddr) >> 16) & 0x00FF) == trg_ip[1] &&
        ((ntohl(iph->daddr) >> 8) & 0x0000FF) == trg_ip[2] &&
        ((ntohl(iph->daddr)) & 0x000000FF) == trg_ip[3])
    {
        if (iph->protocol == IPPROTO_TCP &&
            ntohs(tcp_hdr(skb)->dest) == trg_port)
        {
            unsigned int pl_len = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
            unsigned char *pl = (unsigned char *)(
                        skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
                    );
            if (check_pl(pl, pl_len)) {
                printk("%sBefore. ", module_header);
                print_pkt(skb);
                printk("\n");


                unsigned int d = pl_len / 2;


                skb_trim(skb, ip_hdrlen(skb) + tcp_hdrlen(skb) + d);
                struct tcphdr *tcph = tcp_hdr(skb);
                iph = ip_hdr(skb);
                pl = (unsigned char *)(
                        skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
                    );

                iph->tot_len = htons((unsigned short)skb->len);
                pl_len = d;
                fill_pl(pl, pl_len);


                tcph->check = htons(0);
                int len = skb->len - ip_hdrlen(skb);
                tcph->check = tcp_v4_check(len, iph->saddr, iph->daddr,
                                           csum_partial((char*)tcph, len, 0));

                iph->check = htons(0);
                iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);


                printk("%sAfter trim. ", module_header);
                print_pkt(skb);
                printk("\n");
            }
        }
    }

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
    printk("%sEnd of working with hook_func\n", module_header);
}


module_init(init_func);
module_exit(exit_func);