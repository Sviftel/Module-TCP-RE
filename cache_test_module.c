#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "cache_structure.h"
#include "hashing.h"

#include "hpl_entry.h"
#include "test_consts.h"

MODULE_LICENSE("GPL");


char module_header[] = "cache_test_module: ";
struct cache *c;


/************/

struct ht_entry {
    unsigned char hash[HASH_LEN];
    unsigned char packets_num;
    // HLIST_HEAD(packets_list);
    struct hlist_head packets_list;
    struct hlist_node ht_node;
};


struct data_entry {
    int cnt;
    struct hpl_entry data;
    struct rb_node tree_node;

    struct hlist_node list_node;
    struct ht_entry *same_hash_packets;
    unsigned char id;
};


void tree_print(struct rb_root *root) {
    struct rb_node *node;
    for (node = rb_first(root); node; node = rb_next(node)) {
        int i;
        struct data_entry *entry;
        entry = container_of(node, struct data_entry, tree_node);

        printk("%sPayload: ", module_header);
        for (i = 0; i < entry->data.size; ++i) {
            printk("%x", entry->data.pl[i]);
        }

        printk(" Freq: %d ", entry->cnt);

        printk(" Hash: ");
        for (i = 0; i < 16; ++i) {
            printk("\\x%x", entry->data.hash[i]);
        }
        printk(" ID: %d", entry->id);
        printk("\n");
    }
}


void cache_ht_print(struct cache *c) {
    struct ht_entry *same_hash_set;
    int i, k;

    for (k = 0; k < 1 << CACHE_BITS_NUM; ++k) {
        hash_for_each_possible(c->ht, same_hash_set, ht_node, k) {
            struct data_entry *same_hash_packet;

            printk("%sNext same_hash_set, hash : ", module_header);
            for (i = 0; i < 16; ++i) {
                printk("\\x%x", same_hash_set->hash[i]);
            }
            printk(" # packets: %d\n", same_hash_set->packets_num);


            hlist_for_each_entry(same_hash_packet,
                                 &(same_hash_set->packets_list),
                                 list_node)
            {
                printk("%sPayload: ", module_header);
                for (i = 0; i < same_hash_packet->data.size; ++i) {
                    printk("%x", same_hash_packet->data.pl[i]);
                }

                printk(" Freq: %d ", same_hash_packet->cnt);

                printk(" ID: %d", same_hash_packet->id);
                printk("\n");
            }
        }
    }
}


/************/


int bytes_check(const unsigned char *msg, int msg_len,
                const unsigned char *pl, int pl_len, int step_num)
{
    int i;
    if (pl_len != msg_len) {
        printk("%sStep %d, Wrong lengths\n", module_header, step_num);
        return 0;
    }
    for (i = 0; i < pl_len; ++i) {
        if (pl[i] != msg[i]) {
            printk("%sStep %d, Wrong symbol %d: %x != %x \n",
                   module_header, step_num, i, pl[i], msg[i]);
            return 0;
        }
    }
    return 1;
}


void test_collisions(void) {
    init_cache(c, 256);
    int i, pl_len;
    unsigned char *_hval, _id, *pl, h1[HASH_LEN], h2[HASH_LEN];
    printk("%sTest collisions\n", module_header);

    add_to_cache(c, m1, M1_LEN, &_hval, &_id);
    add_to_cache(c, m2, M2_LEN, &_hval, &_id);

    calc_hash(m1, M1_LEN, h1);
    calc_hash(m2, M2_LEN, h2);

    for (i = 0; i < HASH_LEN; ++i) {
        if (h1[i] != h2[i]) {
            printk("%sHashes are different at %d: %x != %x\n",
                   module_header, i, h1[i], h2[i]);
            return;
        }
    }

    get_pl_info(c, h1, 0, &pl, &pl_len);
    if (bytes_check(m1, M1_LEN, pl, pl_len, 0)) {
        printk("%sStep %d - ok\n", module_header, 0);
    }
    get_pl_info(c, h2, 1, &pl, &pl_len);
    if (bytes_check(m2, M2_LEN, pl, pl_len, 1)) {
        printk("%sStep %d - ok\n", module_header, 1);
    }

    add_to_cache(c, m2, M2_LEN, &_hval, &_id);
    add_to_cache(c, m2, M2_LEN, &_hval, &_id);
    __cache_del_entry(c);

    struct rb_node *node = rb_first(&(c->tree));
    struct data_entry *entry;
    entry = container_of(node, struct data_entry, tree_node);
    if (entry->id != 0) {
        printk("%sID haven't been changed!\n", module_header);
    } else {
        printk("%sStep %d - ok\n", module_header, 2);
    }

    if (entry->cnt != 4) {
        printk("%sPacket freq is wrong!\n", module_header);
    } else {
        printk("%sStep %d - ok\n", module_header, 3);
    }

    clean_cache(c);
}


void test_basic_functionality(void) {
    init_cache(c, 256);

    int i, j, entries_num = 3, msg_len = 5;
    unsigned char words[entries_num][msg_len];
    unsigned char ch = 'a';
    for (i = 0; i < entries_num; ++i) {
        for (j = 0; j < msg_len; ++j) {
            words[i][j] = ch + i;
        }

        for (j = 0; j < entries_num - i; ++j) {
            unsigned char *_hval, _id;
            add_to_cache(c, words[i], msg_len, &_hval, &_id);
        }
    }

    printk("%sTest getting payload from cache:\n", module_header);
    for (i = 0; i < entries_num; ++i) {
        // printk("%sNext payload: ", module_header);
        unsigned char *pl, h[HASH_LEN];
        int s;

        calc_hash(words[i], msg_len, h);
        get_pl_info(c, h, 0, &pl, &s);

        if (s != msg_len) {
            printk("%sWrong message len at %d word!",
                   module_header, i);
            return;
        }

        for (j = 0; j < s; ++j) {
            if (pl[j] != words[i][j]) {
                printk("%sWrong symbol at pos %d, word %d: %x != %x!",
                    module_header, j, i, pl[j], words[i][j]);
                return;
            }
        }
        printk("%sWord %d - ok\n", module_header, i);
    }

    // printk("%sSize, in bytes: %ld, Hitrate: %d\n",
    //        module_header, c->curr_size, get_hitrate(c));

    if (get_hitrate(c) != 66) {
        printk("%sWrong hitrate!", module_header);
    } else {
        printk("%sStep %d - ok\n", module_header, 0);
    }

    clean_cache(c);
}


int init_func(void) {
    printk("%sStart working with cache\n", module_header);

    c = kmalloc(sizeof(struct cache), GFP_KERNEL);
    alloc_hash_structs();

    test_basic_functionality();

    test_collisions();

    return 0;
}


void exit_func(void) {
    kfree(c);

    free_hash_structs();
    printk("%sStop working with cache\n", module_header);
}


module_init(init_func);
module_exit(exit_func);