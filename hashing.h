#ifndef HASHING_H
#define HASHING_H

#define MD5_LENGTH 16


void alloc_hash_structs(void);

void calc_hash(const unsigned char *buf,
               unsigned int buf_len,
               unsigned char *output);

void free_hash_structs(void);


#endif