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

char new_char = 'F';
char trg_msg[] = {'d', 'd', 'd', 'd', 'd', '\n'};
unsigned int trg_msg_len = 6;


bool check_pl(char *pl, unsigned int pl_len) {
    if (pl_len != trg_msg_len)
        return false;

    unsigned int i;
    for (i = 0; i < pl_len; ++i)
        if (pl[i] != trg_msg[i])
            return false;

    return true;
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
        printk("%02x", *(pl + i));
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
            if (pl_len >= 2) {
            // if (check_pl(pl, pl_len)) {
                printk("%sBefore. ", module_header);

                struct tcphdr *tcph = tcp_hdr(skb);
                // printk("IP csum: 0x%x. ", (unsigned int)ntohs(iph->check));
                // printk("TCP csum: 0x%x. ", (unsigned int)ntohs(tcph->check));

                // print_chars(pl, pl_len);

                print_pkt(skb);

                // printk(" Skb->len: %d, IP tot len: %d; ", skb->len, ntohs(iph->tot_len));

                printk("\n");

                // unsigned int d = pl_len / 2;
                // int i;
                // for (i = 0; i < d; ++i) {
                //     pl[i] = new_char;
                // }
                unsigned int d = 2;
                unsigned short *tmp = pl;
                *tmp = tcph->check;


                // skb_trim(skb, skb->len - (pl_len - d));
                // iph->tot_len = htons(ntohs(iph->tot_len) - (pl_len - d));
                // pl_len = d;
                skb_trim(skb, ip_hdrlen(skb) + tcp_hdrlen(skb) + d);
                tcph = tcp_hdr(skb);
                iph = ip_hdr(skb);
                iph->tot_len = htons((unsigned short)skb->len);
                pl_len = d;


                printk("%sAfter trim. ", module_header);
                // print_chars(pl. pl_len);
                // printk(" ");


                tcph->check = htons(0);
                // int len = skb->len - skb_transport_offset(skb);
                // tcph->check = tcp_v4_check(len, iph->saddr, iph->daddr,
                //                            csum_partial((char*)tcph, len, 0));
                tcph->check = tcp_v4_check(skb->len - 4 * iph->ihl, iph->saddr,
                                           iph->daddr,
                                           csum_partial((char*)tcph,
                                                        skb->len - 4 * iph->ihl,
                                                        0));
                // uint32_t csum = skb_checksum(skb, skb_transport_offset(skb), len, 0);
                // tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len,
                //                              iph->protocol, csum);

                iph->check = htons(0);
                iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

                // printk("IP csum: 0x%x. ", (unsigned int)ntohs(iph->check));
                // printk("TCP csum: 0x%x. ", (unsigned int)ntohs(tcph->check));


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