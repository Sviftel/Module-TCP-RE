#ifndef SKB_PROCESSING_H
#define SKB_PROCESSING_H


#define IS_HASHED 1
#define NOT_HASHED 0


void adjust_tcp_res_bits(struct tcphdr *tcph, int is_hashed);
unsigned char tcp_is_hashed(const struct tcphdr *tcph);

#endif
