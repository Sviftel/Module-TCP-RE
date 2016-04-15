#ifndef HPL_ENTRY_H
#define HPL_ENTRY_H


#include "hashing.h"


#define HASH_LEN MD5_LENGTH


struct hpl_entry {
    int size;
    unsigned char *pl;
    unsigned char hash[HASH_LEN];
};


struct hpl_entry* create_hpl_entry(const unsigned char *pl, int s);

void fill_hpl_entry(struct hpl_entry *entry,
                    const unsigned char *pl,
                    int s);

int eq_hpl_entries(const struct hpl_entry* e1, const struct hpl_entry* e2);

int eq_hash_vals(const unsigned char* h1, const unsigned char* h2);

void free_hpl_entry(struct hpl_entry *entry);


#endif
