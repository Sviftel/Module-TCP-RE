#include <uapi/linux/tcp.h>
#include "tcp_processing.h"


// from 1 to 2, number of bit in tcphdr.res1
#define HFLAG_BITNUM 1


void adjust_tcp_res_bits(struct tcphdr *tcph, int is_hashed) {
    // res &= 1001b
    tcph->res1 &= 1 + (1 << 3);
    // setting the flag
    tcph->res1 |= (is_hashed == IS_HASHED ? 1 : 0) << HFLAG_BITNUM;
}


unsigned char tcp_is_hashed(const struct tcphdr *tcph) {
    unsigned char result;
    result = tcph->res1 & (1 << HFLAG_BITNUM);
    return result;
}
