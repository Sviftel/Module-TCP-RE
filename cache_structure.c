#include "cache_structure.h"
#include <linux/slab.h>

// 251 = 2^8 - 5
#define MULTIPL 251
// 65521 = 2^16 - 2^8 + 7
#define MOD 65287


struct ht_entry {
    unsigned char hash[HASH_LEN];
    unsigned char packets_num;
    // HLIST_HEAD(packets_list);
    struct hlist_head packets_list;
    struct hlist_node ht_node;
};


// TODO: add timestamp fields
struct data_entry {
    int cnt;
    struct hpl_entry data;
    struct rb_node tree_node;

    struct hlist_node list_node;
    struct ht_entry *same_hash_packets;
    unsigned char id;
};


unsigned int __get_key_from_hash(const unsigned char *hash) {
    unsigned int i, key;
    key = 0;
    for (i = 0; i < HASH_LEN; i += 2) {
        unsigned int addit = hash[i];

        // key = (O(2**16) + O(2**8) * O(2**8)) % O(2**16)
        key = (key + addit * MULTIPL) % MOD;
    }

    return key;
}


void __get_hash_key_to_buff(const unsigned char *pl, int s,
                            unsigned char *hash, unsigned int *key)
{
    calc_hash(pl, s, hash);
    *key = __get_key_from_hash(hash);
}


int __tree_insert(struct rb_root *root, struct data_entry *entry) {
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        struct data_entry *curr_entry;
        curr_entry = container_of(*new, struct data_entry, tree_node);

        parent = *new;
        if (entry->cnt <= curr_entry->cnt)
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    rb_link_node(&(entry->tree_node), parent, new);
    rb_insert_color(&(entry->tree_node), root);

    return 1;
}


void __tree_remove(struct rb_root *tree, struct data_entry *entry) {
    rb_erase(&(entry->tree_node), tree);
}


// function also frees entry, should be
// called after __ht_clean()
void __tree_rec_clean(struct rb_node *node) {
    if (node == NULL)
        return;

    __tree_rec_clean(node->rb_left);
    __tree_rec_clean(node->rb_right);
    node->rb_left = NULL;
    node->rb_right = NULL;

    struct data_entry *entry;
    entry = container_of(node, struct data_entry, tree_node);
    free_hpl_entry(&(entry->data));
    kfree(entry);
    node = NULL;
}


void __ht_clean(struct cache *c) {
    int k;

    for (k = 0; k < 1 << CACHE_BITS_NUM; ++k) {
        while (c->ht[k].first != NULL) {
            struct ht_entry *same_hash_set;
            same_hash_set = container_of(c->ht[k].first,
                                         struct ht_entry,
                                         ht_node);
            hlist_del(&(same_hash_set->ht_node));
            kfree(same_hash_set);
        }
    }
}


void __cache_del_entry(struct cache *c) {
    struct rb_node *node_to_rm;
    struct data_entry *entry_to_rm;
    struct ht_entry *same_hash_set;

    node_to_rm = rb_first(&(c->tree));
    entry_to_rm = container_of(node_to_rm, struct data_entry, tree_node);

    __tree_remove(&(c->tree), entry_to_rm);
    hlist_del(&(entry_to_rm->list_node));

    same_hash_set = entry_to_rm->same_hash_packets;
    if (!--(same_hash_set->packets_num)) {
        hlist_del(&(same_hash_set->ht_node));
        kfree(same_hash_set);
    } else {
        struct data_entry *same_hash_packet;

        hlist_for_each_entry(same_hash_packet,
                             &(same_hash_set->packets_list),
                             list_node)
        {
            if (same_hash_packet->id > entry_to_rm->id) {
                --(same_hash_packet->id);
            }
        }
    }

    c->curr_size -= entry_to_rm->data.size;

    free_hpl_entry(&(entry_to_rm->data));
    kfree(entry_to_rm);
}


void add_to_cache(struct cache *c,
                  const unsigned char *pl,
                  int s,
                  unsigned char **hash_val,
                  unsigned char *id)
{
    struct hpl_entry new_hpl_entry;
    unsigned int k;
    struct ht_entry *same_hash_set;

    new_hpl_entry.size = s;
    new_hpl_entry.pl = pl;
    __get_hash_key_to_buff(pl, s, new_hpl_entry.hash, &k);

    same_hash_set = NULL;
    hash_for_each_possible(c->ht, same_hash_set, ht_node, k) {
        if (eq_hash_vals(new_hpl_entry.hash, same_hash_set->hash)) {
            struct data_entry *same_hash_packet;

            hlist_for_each_entry(same_hash_packet,
                                 &(same_hash_set->packets_list),
                                 list_node)
            {
                if (eq_hpl_entries(&(same_hash_packet->data), &new_hpl_entry)) {
                    same_hash_packet->cnt += 1;
                    __tree_remove(&(c->tree), same_hash_packet);
                    __tree_insert(&(c->tree), same_hash_packet);
                    c->hits++;
                    c->saved_traffic_size += s;
                    c->total_traffic_size += s;
                    
                    *hash_val = same_hash_packet->data.hash;
                    *id = same_hash_packet->id;
                    return;
                }
            }

            break;
        }
    }

    while (c->curr_size + s > c->max_size) {
        __cache_del_entry(c);
    }

    if (same_hash_set == NULL) {
        int i;

        same_hash_set = kmalloc(sizeof(struct ht_entry), GFP_KERNEL);
        same_hash_set->packets_num = 0;
        same_hash_set->packets_list.first = NULL;
        for (i = 0; i < HASH_LEN; ++i) {
            same_hash_set->hash[i] = new_hpl_entry.hash[i];
        }
        INIT_HLIST_NODE(&(same_hash_set->ht_node));
        hash_add(c->ht, &(same_hash_set->ht_node), k);
    }

    struct data_entry *new_entry;
    new_entry = kmalloc(sizeof(struct data_entry), GFP_KERNEL);

    new_entry->cnt = 1;
    copy_hpl_entry(&(new_entry->data), &new_hpl_entry);

    __tree_insert(&(c->tree), new_entry);
    INIT_HLIST_NODE(&(new_entry->list_node));
    hlist_add_head(&(new_entry->list_node), &(same_hash_set->packets_list));
    new_entry->same_hash_packets = same_hash_set;
    new_entry->id = (same_hash_set->packets_num)++;

    c->curr_size += s;
    c->misses++;
    c->total_traffic_size += s;

    *hash_val = NULL;
    *id = 0;
    return;
}


void init_cache(struct cache *c, int cache_size) {
    c->max_size = cache_size * 1024 * 1024;
    c->curr_size = 0;
    c->hits = 0;
    c->misses = 0;
    c->saved_traffic_size = 0;
    c->total_traffic_size = 0;

    c->tree = RB_ROOT;
    hash_init(c->ht);
}


void clean_cache(struct cache *c) {
    __ht_clean(c);
    __tree_rec_clean(c->tree.rb_node);

    c->tree = RB_ROOT;
    hash_init(c->ht);
    c->curr_size = 0;
    c->hits = 0;
    c->misses = 0;
    c->saved_traffic_size = 0;
    c->total_traffic_size = 0;
}


void get_pl_info(struct cache *c,
                 const unsigned char *hash_val,
                 unsigned char id,
                 unsigned char **pl,
                 int *pl_s)
{
    struct ht_entry *same_hash_set;
    int k;

    k = __get_key_from_hash(hash_val);

    hash_for_each_possible(c->ht, same_hash_set, ht_node, k) {
        if (eq_hash_vals(hash_val, same_hash_set->hash)) {
            struct data_entry *same_hash_packet;

            hlist_for_each_entry(same_hash_packet,
                                 &(same_hash_set->packets_list),
                                 list_node)
            {
                if (same_hash_packet->id == id) {
                    same_hash_packet->cnt += 1;
                    __tree_remove(&(c->tree), same_hash_packet);
                    __tree_insert(&(c->tree), same_hash_packet);
                    c->hits++;
                    c->saved_traffic_size += same_hash_packet->data.size;
                    c->total_traffic_size += same_hash_packet->data.size;

                    *pl = same_hash_packet->data.pl;
                    *pl_s = same_hash_packet->data.size;
                    return;
                }
            }
        }
    }
    pl = NULL;
    *pl_s = 0;
}



int get_hitrate(struct cache *c) {
    if (c->misses == 0)
        return 0;

    return 100 * c->hits / (c->hits + c->misses);
}

int get_saved_traffic_part(struct cache *c) {
    if (c->total_traffic_size == 0)
        return 0;

    return 100 * c->saved_traffic_size / c->total_traffic_size;
}
