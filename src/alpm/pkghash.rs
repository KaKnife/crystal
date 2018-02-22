use super::*;
/*
 *  pkghash.h
 *
 *  Copyright (c) 2011-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// #ifndef ALPM_PKGHASH_H
// #define ALPM_PKGHASH_H
//
// #include <stdlib.h>
//
// #include "alpm.h"
// #include "alpm_list.h"

/**
 * @brief A hash table for holding Package objects.
 *
 * A combination of a hash table and a list, allowing for fast look-up
 * by package name but also iteration over the packages.
 */
#[derive(Debug, Default, Clone)]
pub struct alpm_pkghash_t {
    /// data held by the hash table
    pub hash_table: Vec<Package>,
    /// head node of the hash table data in normal list format
    pub list: alpm_list_t<Package>,
    ///number of buckets in hash table
    pub buckets: usize,
    /// number of entries in hash table
    pub entries: usize,
    /// max number of entries before a resize is needed
    pub limit: usize,
}

// typedef struct __alpm_pkghash_t alpm_pkghash_t;
//
// alpm_pkghash_t *_alpm_pkghash_create(unsigned int size);
//
// alpm_pkghash_t *_alpm_pkghash_add(alpm_pkghash_t *hash, Package *pkg);
// alpm_pkghash_t *_alpm_pkghash_add_sorted(alpm_pkghash_t *hash, Package *pkg);
// alpm_pkghash_t *_alpm_pkghash_remove(alpm_pkghash_t *hash, Package *pkg, Package **data);
//
// void _alpm_pkghash_free(alpm_pkghash_t *hash);
//
// Package *_alpm_pkghash_find(alpm_pkghash_t *hash, const char *name);
//
// /*
//  *  pkghash.c
//  *
//  *  Copyright (c) 2011-2017 Pacman Development Team <pacman-dev@archlinux.org>
//  *
//  *  This program is free software; you can redistribute it and/or modify
//  *  it under the terms of the GNU General Public License as published by
//  *  the Free Software Foundation; either version 2 of the License, or
//  *  (at your option) any later version.
//  *
//  *  This program is distributed in the hope that it will be useful,
//  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  *  GNU General Public License for more details.
//  *
//  *  You should have received a copy of the GNU General Public License
//  *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//  */
//
// #include <errno.h>
//
// #include "pkghash.h"
// #include "util.h"
//
// /* List of primes for possible sizes of hash tables.
//  *
//  * The maximum table size is the last prime under 1,000,000.  That is
//  * more than an order of magnitude greater than the number of packages
//  * in any Linux distribution, and well under UINT_MAX.
//  */
const prime_list: [usize; 145] = [
    11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 103, 109,
    113, 127, 137, 139, 149, 157, 167, 179, 193, 199, 211, 227, 241, 257, 277, 293, 313, 337, 359,
    383, 409, 439, 467, 503, 541, 577, 619, 661, 709, 761, 823, 887, 953, 1031, 1109, 1193, 1289,
    1381, 1493, 1613, 1741, 1879, 2029, 2179, 2357, 2549, 2753, 2971, 3209, 3469, 3739, 4027, 4349,
    4703, 5087, 5503, 5953, 6427, 6949, 7517, 8123, 8783, 9497, 10273, 11113, 12011, 12983, 14033,
    15173, 16411, 17749, 19183, 20753, 22447, 24281, 26267, 28411, 30727, 33223, 35933, 38873,
    42043, 45481, 49201, 53201, 57557, 62233, 67307, 72817, 78779, 85229, 92203, 99733, 107897,
    116731, 126271, 136607, 147793, 159871, 172933, 187091, 202409, 218971, 236897, 256279, 277261,
    299951, 324503, 351061, 379787, 410857, 444487, 480881, 520241, 562841, 608903, 658753, 712697,
    771049, 834181, 902483, 976369,
];
//
// /* How far forward do we look when linear probing for a spot? */
// static const unsigned int stride = 1;
// /* What is the maximum load percentage of our hash table? */
const max_hash_load: f32 = 0.68;
// /* Initial load percentage given a certain size */
// static const double initial_hash_load = 0.58;
//
/* Allocate a hash table with space for at least "size" elements */
pub fn _alpm_pkghash_create() -> alpm_pkghash_t {
    // unimplemented!();
    // 	alpm_pkghash_t *hash = NULL;
    let hash = alpm_pkghash_t::default();
    // 	unsigned int i, loopsize;
    //
    // 	CALLOC(hash, 1, sizeof(alpm_pkghash_t), return NULL);
    // 	size = size / initial_hash_load + 1;
    //
    // let loopsize = prime_list.len();
    // 	for i in 0 .. loopsize {
    // 		if prime_list[i] > size {
    // 			hash.buckets = prime_list[i];
    // 			hash.limit = (hash.buckets as f32 * max_hash_load) as i32;
    // 			break;
    // 		}
    // 	}
    //
    // 	if(hash->buckets < size) {
    // 		errno = ERANGE;
    // 		free(hash);
    // 		return NULL;
    // 	}
    //
    // 	CALLOC(hash->hash_table, hash->buckets, sizeof(alpm_list_t *), \
    // 				free(hash); return NULL);
    //
    return hash;
}

// static unsigned int get_hash_position(unsigned long name_hash,
// 		alpm_pkghash_t *hash)
// {
// 	unsigned int position;
//
// 	position = name_hash % hash->buckets;
//
// 	/* collision resolution using open addressing with linear probing */
// 	while(hash->hash_table[position] != NULL) {
// 		position += stride;
// 		while(position >= hash->buckets) {
// 			position -= hash->buckets;
// 		}
// 	}
//
// 	return position;
// }
//

// alpm_pkghash_t *_alpm_pkghash_add_sorted(alpm_pkghash_t *hash, Package *pkg)
// {
// 	return pkghash_add_pkg(hash, pkg, 1);
// }
//
// static unsigned int move_one_entry(alpm_pkghash_t *hash,
// 		unsigned int start, unsigned int end)
// {
// 	/* Iterate backwards from 'end' to 'start', seeing if any of the items
// 	 * would hash to 'start'. If we find one, we move it there and break.  If
// 	 * we get all the way back to position and find none that hash to it, we
// 	 * also end iteration. Iterating backwards helps prevent needless shuffles;
// 	 * we will never need to move more than one item per function call.  The
// 	 * return value is our current iteration location; if this is equal to
// 	 * 'start' we can stop this madness. */
// 	while(end != start) {
// 		alpm_list_t *i = hash->hash_table[end];
// 		Package *info = i->data;
// 		unsigned int new_position = get_hash_position(info->name_hash, hash);
//
// 		if(new_position == start) {
// 			hash->hash_table[start] = i;
// 			hash->hash_table[end] = NULL;
// 			break;
// 		}
//
// 		/* the odd math ensures we are always positive, e.g.
// 		 * e.g. (0 - 1) % 47      == -1
// 		 * e.g. (47 + 0 - 1) % 47 == 46 */
// 		end = (hash->buckets + end - stride) % hash->buckets;
// 	}
// 	return end;
// }
//
// /**
//  * @brief Remove a package from a pkghash.
//  *
//  * @param hash     the hash to remove the package from
//  * @param pkg      the package we are removing
//  * @param data     output parameter containing the removed item
//  *
//  * @return the resultant hash
//  */
// alpm_pkghash_t *_alpm_pkghash_remove(alpm_pkghash_t *hash, Package *pkg,
// 		Package **data)
// {
// 	alpm_list_t *i;
// 	unsigned int position;
//
// 	if(data) {
// 		*data = NULL;
// 	}
//
// 	if(pkg == NULL || hash == NULL) {
// 		return hash;
// 	}
//
// 	position = pkg->name_hash % hash->buckets;
// 	while((i = hash->hash_table[position]) != NULL) {
// 		Package *info = i->data;
//
// 		if(info->name_hash == pkg->name_hash &&
// 					strcmp(info->name, pkg->name) == 0) {
// 			unsigned int stop, prev;
//
// 			/* remove from list and hash */
// 			hash->list = alpm_list_remove_item(hash->list, i);
// 			if(data) {
// 				*data = info;
// 			}
// 			hash->hash_table[position] = NULL;
// 			free(i);
// 			hash->entries -= 1;
//
// 			/* Potentially move entries following removed entry to keep open
// 			 * addressing collision resolution working. We start by finding the
// 			 * next null bucket to know how far we have to look. */
// 			stop = position + stride;
// 			while(stop >= hash->buckets) {
// 				stop -= hash->buckets;
// 			}
// 			while(hash->hash_table[stop] != NULL && stop != position) {
// 				stop += stride;
// 				while(stop >= hash->buckets) {
// 					stop -= hash->buckets;
// 				}
// 			}
// 			stop = (hash->buckets + stop - stride) % hash->buckets;
//
// 			/* We now search backwards from stop to position. If we find an
// 			 * item that now hashes to position, we will move it, and then try
// 			 * to plug the new hole we just opened up, until we finally don't
// 			 * move anything. */
// 			while((prev = move_one_entry(hash, position, stop)) != position) {
// 				position = prev;
// 			}
//
// 			return hash;
// 		}
//
// 		position += stride;
// 		while(position >= hash->buckets) {
// 			position -= hash->buckets;
// 		}
// 	}
//
// 	return hash;
// }
//
// void _alpm_pkghash_free(alpm_pkghash_t *hash)
// {
// 	if(hash != NULL) {
// 		unsigned int i;
// 		for(i = 0; i < hash->buckets; i++) {
// 			free(hash->hash_table[i]);
// 		}
// 		free(hash->hash_table);
// 	}
// 	free(hash);
// }
//
impl alpm_pkghash_t {
    /* Expand the hash table size to the next increment and rebin the entries */
    fn rehash(&mut self) {
        unimplemented!();
        // 	alpm_pkghash_t *newhash;
        // 	unsigned int newsize, i;
        //
        // 	/* Hash tables will need resized in two cases:
        // 	 *  - adding packages to the local database
        // 	 *  - poor estimation of the number of packages in sync database
        // 	 *
        // 	 * For small hash tables sizes (<500) the increase in size is by a
        // 	 * minimum of a factor of 2 for optimal rehash efficiency.  For
        // 	 * larger database sizes, this increase is reduced to avoid excess
        // 	 * memory allocation as both scenarios requiring a rehash should not
        // 	 * require a table size increase that large. */
        // 	if(oldhash->buckets < 500) {
        // 		newsize = oldhash->buckets * 2;
        // 	} else if(oldhash->buckets < 2000) {
        // 		newsize = oldhash->buckets * 3 / 2;
        // 	} else if(oldhash->buckets < 5000) {
        // 		newsize = oldhash->buckets * 4 / 3;
        // 	} else {
        // 		newsize = oldhash->buckets + 1;
        // 	}
        //
        // 	newhash = _alpm_pkghash_create(newsize);
        // 	if(newhash == NULL) {
        // 		/* creation of newhash failed, stick with old one... */
        // 		return oldhash;
        // 	}
        //
        // 	newhash->list = oldhash->list;
        // 	oldhash->list = NULL;
        //
        // 	for(i = 0; i < oldhash->buckets; i++) {
        // 		if(oldhash->hash_table[i] != NULL) {
        // 			Package *package = oldhash->hash_table[i]->data;
        // 			unsigned int position = get_hash_position(package->name_hash, newhash);
        //
        // 			newhash->hash_table[position] = oldhash->hash_table[i];
        // 			oldhash->hash_table[i] = NULL;
        // 		}
        // 	}
        //
        // 	newhash->entries = oldhash->entries;
        //
        // 	_alpm_pkghash_free(oldhash);
        //
        // 	return newhash;
    }

    pub fn _alpm_pkghash_add(&mut self, pkg: Package) {
        self.pkghash_add_pkg(pkg, 0);
    }

    pub fn _alpm_pkghash_find(&self, name: &String) -> Package {
        unimplemented!();
        // 	alpm_list_t *lp;
        // 	unsigned long name_hash;
        // 	unsigned int position;
        //
        // 	if(name == NULL || hash == NULL) {
        // 		return NULL;
        // 	}
        //
        // 	name_hash = _alpm_hash_sdbm(name);
        //
        // 	position = name_hash % hash->buckets;
        //
        // 	while((lp = hash->hash_table[position]) != NULL) {
        // 		Package *info = lp->data;
        //
        // 		if(info->name_hash == name_hash && strcmp(info->name, name) == 0) {
        // 			return info;
        // 		}
        //
        // 		position += stride;
        // 		while(position >= hash->buckets) {
        // 			position -= hash->buckets;
        // 		}
        // 	}
        //
        // 	return NULL;
    }

    fn pkghash_add_pkg(&mut self, pkg: Package, sorted: i32) {
        // let position;
        // 	alpm_list_t *ptr;
        // 	unsigned int position;
        //
        // 	if(pkg == NULL || hash == NULL) {
        // 		return hash;
        // 	}
        //
        // if self.entries >= self.limit {
        //     self.rehash();
        // }

        // position = get_hash_position(pkg.name_hash, hash);

        // 	MALLOC(ptr, sizeof(alpm_list_t), return hash);

        // 	ptr->data = pkg;
        // 	ptr->prev = ptr;
        // 	ptr->next = NULL;

        self.list.push(pkg);
        // 	if(!sorted) {
        // 		hash->list = alpm_list_join(hash->list, ptr);
        // 	} else {
        // 		hash->list = alpm_list_mmerge(hash->list, ptr, _alpm_pkg_cmp);
        // 	}

        self.entries += 1;
        // return hash;
    }
}
