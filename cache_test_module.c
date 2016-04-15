#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "cache_structure.h"
#include "hashing.h"

#include "hpl_entry.h"

MODULE_LICENSE("GPL");


char module_header[] = "cache_test_module: ";
struct cache *c;


/************/

struct rbtree_entry {
    int cnt;
    struct hpl_entry data;
    struct rb_node node;
};


void tree_print(struct rb_root *root) {
    struct rb_node *node;
    for (node = rb_first(root); node; node = rb_next(node)) {
        int i;
        struct rbtree_entry *entry;
        entry = container_of(node, struct rbtree_entry, node);

        printk("%sPayload: ", module_header);
        for (i = 0; i < entry->data.size; ++i) {
            printk("%c", entry->data.pl[i]);
        }

        printk(" Freq: %d ", entry->cnt);

        printk(" Hash: ");
        for (i = 0; i < 16; ++i) {
            printk("\\x%x", entry->data.hash[i]);
        }
        printk("\n");
    }
}


struct ht_entry {
    struct rbtree_entry *rb_entry;
    struct hlist_node node;
};

void cache_ht_print(struct cache *c) {
    struct ht_entry *curr_ht_entry;
    struct rbtree_entry *curr_rb_entry;
    int i, k;

    for (k = 0; k < 1 << CACHE_BITS_NUM; ++k) {
        hash_for_each_possible(c->ht, curr_ht_entry, node, k) {
            curr_rb_entry = curr_ht_entry->rb_entry;

            printk("%sPayload: ", module_header);
            for (i = 0; i < curr_rb_entry->data.size; ++i) {
                printk("%c", curr_rb_entry->data.pl[i]);
            }

            printk(" Freq: %d ", curr_rb_entry->cnt);

            printk(" Hash: ");
            for (i = 0; i < 16; ++i) {
                printk("\\x%x", curr_rb_entry->data.hash[i]);
            }
            printk("\n");
        }
    }
}


/************/


int init_func(void) {
    printk("%sStart working with cache\n", module_header);

    c = kmalloc(sizeof(struct cache), GFP_KERNEL);
    init_cache(c, 256);
    int i, j, entries_num = 3, msg_len = 1;

    alloc_hash_structs();

    unsigned char words[entries_num][msg_len];
    unsigned char ch = 'a';
    for (i = 0; i < entries_num; ++i) {
        for (j = 0; j < msg_len; ++j) {
            words[i][j] = ch + i;
        }

        for (j = 0; j < entries_num - i; ++j) {
            add_to_cache(c, words[i], msg_len);
        }
    }

    // printk("%sTest getting payload from cache:\n", module_header);
    // unsigned char *h[entries_num];
    // h[0] = "\x4a\x8a\x8\xf0\x9d\x37\xb7\x37\x95\x64\x90\x38\x40\x8b\x5f\x33";
    // h[1] = "\x92\xeb\x5f\xfe\xe6\xae\x2f\xec\x3a\xd7\x1c\x77\x75\x31\x57\x8f";
    // h[2] = "\xc\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61";
    // for (i = 0; i < entries_num; ++i) {
    //     printk("%sNext payload:", module_header);
    //     unsigned char *pl;
    //     int s, _k;
    //     // calc_hash(words[i], msg_len, h);
    //     // __get_hash_key_to_buff(words[i], msg_len, h, &_k);

    //     // get_pl_info(c, h[i], pl, &s);
    //     // for (j = 0; j < s; ++j) {
    //     //     printk("%c", pl[j]);
    //     // }
    // }


    printk("%sPrint from tree:\n", module_header);
    tree_print(&(c->tree));

    // printk("%sPrint from hash table:\n", module_header);
    // cache_ht_print(c);

    printk("%sSize, in bytes: %ld, Hitrate: %d\n",
           module_header, c->curr_size, get_hitrate(c));

    return 0;
}


void exit_func(void) {
    clean_cache(c);

    printk("%sAfter clean:\n", module_header);
    printk("%sPrint from tree:\n", module_header);
    tree_print(&(c->tree));
    printk("%sPrint from hash table:\n", module_header);
    cache_ht_print(c);

    kfree(c);
    free_hash_structs();
    printk("%sStop working with cache\n", module_header);
}


module_init(init_func);
module_exit(exit_func);