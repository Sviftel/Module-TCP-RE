#include "hpl_entry.h"
#include <linux/slab.h>


int copy_hpl_entry(struct hpl_entry* dst, const struct hpl_entry* src) {
    dst->size = src->size;
    dst->pl = kmalloc(dst->size, GFP_KERNEL);
    memcpy(dst->pl, src->pl, dst->size);
    memcpy(dst->hash, src->hash, HASH_LEN);
}


int eq_hpl_entries(const struct hpl_entry* e1, const struct hpl_entry* e2) {
    if (e1->size != e2->size) {
        printk("HERE0, sizes: %x != %x\n", e1->size, e2->size);
        return 0;
    }

    int i;
    for (i = 0; i < HASH_LEN; ++i) {
        if (e1->hash[i] != e2->hash[i]) {
            printk("HERE, %d! %x != %x\n", i, e1->hash[i], e2->hash[i]);
            return 0;
        }
    }

    for (i = 0; i < e1->size; ++i) {
        if (e1->pl[i] != e2->pl[i]) {
            printk("HERE2, %d! %x != %x\n", i, e1->pl[i], e2->pl[i]);
            return 0;
        }
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
