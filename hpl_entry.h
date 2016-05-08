#ifndef HPL_ENTRY_H
#define HPL_ENTRY_H


#include "hashing.h"


#define HASH_LEN MD5_LENGTH


struct hpl_entry {
    int size;
    unsigned char *pl;
    unsigned char hash[HASH_LEN];
};


int copy_hpl_entry(struct hpl_entry* dst, const struct hpl_entry* src);

int eq_hpl_entries(const struct hpl_entry* e1, const struct hpl_entry* e2);

int eq_hash_vals(const unsigned char* h1, const unsigned char* h2);

void free_hpl_entry(struct hpl_entry *entry);


#endif
