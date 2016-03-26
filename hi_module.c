#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/tcp.h>


struct nf_hook_ops bundle;
char module_header[] = "hi_module: ";
long trg_ip[] = {192, 168, 56, 1};
long trg_port = 13334;


unsigned char true_msg[] = {'d', 'd', 'd', 'd', 'd', '\n'};
unsigned int true_msg_len = 6;

char trg_char = 'F';
// unsigned int trg_msg_len = true_msg_len / 2;
// char trg_msg[] = {'F', 'F', 'F'};


bool check_pl(char *pl, unsigned int pl_len) {
    if (pl_len != true_msg_len / 2)
        return false;
    
    unsigned int i;
    for (i = 0; i < pl_len; ++i)
        if (pl[i] != trg_char)
            return false;

    return true;
}


int restore_pl(unsigned char *pl) {
    memcpy(pl, true_msg, true_msg_len);
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

    if (ntohl(iph->saddr) >> 24 == trg_ip[0] &&
        ((ntohl(iph->saddr) >> 16) & 0x00FF) == trg_ip[1] &&
        ((ntohl(iph->saddr) >> 8) & 0x0000FF) == trg_ip[2] &&
        ((ntohl(iph->saddr)) & 0x000000FF) == trg_ip[3])
    {
        if (iph->protocol == IPPROTO_TCP &&
            ntohs(tcp_hdr(skb)->dest) == trg_port)
        {
            unsigned int pl_len = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
            unsigned char *pl = (unsigned char *)(
                    skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
                );
            if (pl_len > 0) {
            // if (check_pl(pl, pl_len)) {
                struct tcphdr *tcph = tcp_hdr(skb);
                printk("%sBefore. ", module_header);
                // printk("%sold skb. Pl len: 0x%x, ", module_header, pl_len);
                // printk("skb->len: 0x%x, iph->tot_len: 0x%x, ", skb->len, ntohs(iph->tot_len));
                // printk("Headr: 0x%x, ", skb_headroom(skb));
                // printk("Tailr: 0x%x, ", skb_tailroom(skb));
                // printk("IP csum: 0x%x. ", (unsigned int)ntohs(iph->check));
                // printk("TCP csum: 0x%x. ", (unsigned int)ntohs(tcph->check));


                // print_chars(pl, pl_len);

                print_pkt(skb);

                printk("\n");
                unsigned short *tmp = pl;
                unsigned short true_tcp_csum = *tmp;
// /*
                // int d = 3;
                // unsigned int trg_msg_len = true_msg_len / 2;
                // int d = true_msg_len - trg_msg_len;
                int d = true_msg_len - 2;
                if (!pskb_expand_head(skb, 0, d, GFP_KERNEL)) {
                    printk("%sAfter expand. ", module_header);
                    print_pkt(skb);
                    printk("\n");

                    skb_put(skb, d);
                    tcph = tcp_hdr(skb);
                    iph = ip_hdr(skb);

                    iph->tot_len = htons((unsigned short)skb->len);

                    // unsigned int new_pl_len = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
                    // if (new_pl_len != pl_len + d)
                    //     printk(" AAAAAAAA! FAULT!");

                    printk("%sAfter ", module_header);
                    // printk("%saft exp. Pl len: 0x%x + 0x%x, ", module_header, pl_len, d);
                    // printk("skb->len: 0x%x, iph->tot_len: 0x%x, ", skb->len, ntohs(iph->tot_len));

                    pl = (unsigned char *)(
                            skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb)
                        );
                    // pl[true_msg_len] = 0;
                    restore_pl(pl);

                    // tcph->check = true_tcp_csum;
                    tcph->check = htons(0);
                    int len = skb->len - skb_transport_offset(skb);
                    tcph->check = tcp_v4_check(len, iph->saddr, iph->daddr,
                                               csum_partial((char*)tcph, len, 0));

                    iph->check = htons(0);
                    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);


                    // printk("IP csum: 0x%x. ", (unsigned int)ntohs(iph->check));
                    // printk("TCP csum: 0x%x. ", (unsigned int)ntohs(tcph->check));


                    // print_chars(pl, new_pl_len);

                    printk("%sAfter put and correction. ", module_header);
                    print_pkt(skb);
                    printk("\n");

                    printk("\n");
                }
// */

/* ************************* */

/*
                // int d = 3;
                int d = true_msg_len - trg_msg_len;
                struct sk_buff *new_skb = skb_copy_expand(skb, skb_headroom(skb),
                                                          skb_tailroom(skb) + d,
                                                          GFP_KERNEL);
                if (new_skb != NULL) {
                    pl_len = new_skb->len - ip_hdrlen(new_skb) - tcp_hdrlen(new_skb);
                    pl = (char *)(
                        new_skb->data + ip_hdrlen(new_skb) + tcp_hdrlen(new_skb)
                    );

                    tcph = tcp_hdr(new_skb);
                    iph = ip_hdr(new_skb);

                    skb_put(new_skb, d);
                    iph->tot_len = htons((unsigned short)new_skb->len);

                    unsigned int new_pl_len; 
                    new_pl_len = new_skb->len - ip_hdrlen(new_skb) - tcp_hdrlen(new_skb);
                    if (pl_len + d != new_pl_len)
                        printk(" AAAAAAAA! FAULT!");

                    printk("%snew skb. Pl len: 0x%x + 0x%x, ", module_header, pl_len, d);
                    printk("Headr: 0x%x, ", skb_headroom(new_skb));
                    printk("Tailr: 0x%x, ", skb_tailroom(new_skb));


                    restore_pl(pl);


                    tcph->check = htons(0);
                    int len = new_skb->len - skb_transport_offset(new_skb);
                    tcph->check = tcp_v4_check(len, iph->saddr, iph->daddr,
                                               csum_partial((char*)tcph, len, 0));
                    iph->check = htons(0);
                    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);


                    printk("IP csum: 0x%x. ", (unsigned int)ntohs(iph->check));
                    printk("TCP csum: 0x%x. ", (unsigned int)ntohs(tcph->check));

                    for (i = 0; i < new_pl_len; ++i) {
                        n_sym = pl[i];
                        if (n_sym >= 97 && n_sym <= 122 ||
                            n_sym >= 65 && n_sym <= 90)
                            printk("%c", n_sym);
                        else                        
                            printk("!");
                    }
                    printk("\n");


                    // kfree_skb(skb);
                    skb = new_skb;
                }
// */
            }
        }
    }

    // printk("\n");

    return NF_ACCEPT;
}


int init_func(void) {
    printk("%sStart initializing new hook\n", module_header);

    bundle.hook = hook_func;
    bundle.owner = THIS_MODULE;
    bundle.pf = PF_INET;
    bundle.hooknum = NF_INET_PRE_ROUTING;
    bundle.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&bundle);

    return 0;
}


void exit_func(void) {
    nf_unregister_hook(&bundle);
    printk("%sEnd of working wuth hook_func\n", module_header);
}


module_init(init_func);
module_exit(exit_func);