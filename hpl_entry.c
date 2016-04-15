#include "hpl_entry.h"
#include <linux/slab.h>


struct hpl_entry* create_hpl_entry(const unsigned char *pl, int s)
{
    int i;
    struct hpl_entry *new_entry = kmalloc(sizeof(struct hpl_entry), GFP_KERNEL);

    new_entry->size = s;
    new_entry->pl = kmalloc(s, GFP_KERNEL);
    for (i = 0; i < s; ++i) {
        new_entry->pl[i] = pl[i];
    }

    calc_hash(new_entry->pl, s, new_entry->hash);

    return new_entry;
}


void fill_hpl_entry(struct hpl_entry *entry,
                    const unsigned char *pl, int s)
{
    int i;
    entry->size = s;
    entry->pl = kmalloc(s, GFP_KERNEL);
    for (i = 0; i < s; ++i) {
        entry->pl[i] = pl[i];
    }

    calc_hash(entry->pl, s, entry->hash);
}


int eq_hpl_entries(const struct hpl_entry* e1, const struct hpl_entry* e2) {
    if (e1->size != e2->size)
        return 0;

    int i;
    for (i = 0; i < HASH_LEN; ++i) {
        if (e1->hash[i] != e2->hash[i])
            return 0;
    }

    for (i = 0; i < e1->size; ++i) {
        if (e1->pl[i] != e2->pl[i])
            return 0;
    }

    return 1;
}

int eq_hash_vals(const unsigned char* h1, const unsigned char* h2) {
    int i;
    for (i = 0; i < HASH_LEN; ++i) {
        if (h1[i] != h2[i])
            return 0;
    }

    return 1;
}


void free_hpl_entry(struct hpl_entry *entry) {
    kfree(entry->pl);
}
