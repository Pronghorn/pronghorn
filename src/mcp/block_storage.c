/* Pronghorn Block Storage
 * Copyright (C) 2012 Department of Defence Australia
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <glib.h>

#include <prong_assert.h>

#include "block_storage.h"

static const unsigned int BLOCK_MAGIC = 0xFBC28BE4;

/** The block storage structure */
struct block_store
{
  unsigned int magic;
  GSequence *block_list;
  unsigned long long current_pos;
};

/** This is the structure stored in block_list */
struct block_range
{
  /** The starting offset */
  unsigned long long block;
  /** The length of this range */
  unsigned int length;
};

block_store_t block_store_init()
{
  struct block_store *blocks = (struct block_store *) g_malloc(sizeof(struct block_store));

  blocks->magic = BLOCK_MAGIC;
  blocks->block_list = g_sequence_new(g_free);
  blocks->current_pos = 0;

  return (block_store_t) blocks;
}


/**
 * Compares block ranges.
 *
 * If the block ranges overlap then they're considered equal.
 *
 * Otherwise it compares the starting addresses.
 *
 * \param a The first block range
 * \param b The second block range
 * \param data Not used
 * \returns 1 if a<b, 0 if a==b, -1 if a>b
 */
static gint block_range_compare(const struct block_range *a, const struct block_range *b, gpointer data)
{
  // If there is any overlap, then these are equal
  if (a->block > b->block)
  {
    // b is before a
    if ((b->block + b->length) > a->block)
    {
      // b overlaps with a
      return 0;
    }
    return 1;
  }
  // a is before b
  if ((a->block + a->length) > b->block)
  {
    // a overlaps with b
    return 0;
  }
  return -1;
}

/**
 * Merges block ranges into one block range.
 *
 * This function looks at the block_list for any overlapping or adjacent
 * block ranges. If found it removes them from the list and adds them
 * to this block range.
 *
 * \param block_list the block list to glob against
 * \param br The block range
 */
static void glob_blocks(GSequence * block_list, struct block_range *br)
{
  GSequenceIter *iter = NULL;

  do
  {
    iter = g_sequence_lookup(block_list, br, (GCompareDataFunc) block_range_compare, NULL);

    if (iter != NULL)
    {
      struct block_range *br_iter = (struct block_range *) g_sequence_get(iter);

      unsigned long long iter_start = br_iter->block;
      unsigned long long iter_stop = br_iter->block + br_iter->length;

      g_sequence_remove(iter);

      if (iter_start > br->block)
      {
        iter_start = br->block;
      }

      if (iter_stop < br->block + br->length)
      {
        iter_stop = br->block + br->length;
      }

      br->block = iter_start;
      br->length = iter_stop - iter_start;
    }
  }
  while (iter != NULL);

  // Need to check whether we are adjacent to an existing block
  // Checking the block prior
  if (br->block != 0)
  {
    br->block--;
    br->length++;
    if (g_sequence_lookup(block_list, br, (GCompareDataFunc) block_range_compare, NULL) != NULL)
    {
      glob_blocks(block_list, br);
    } else
    {
      // Nope, not adjacent
      br->block++;
      br->length--;
    }
  }
  // Checking the block after
  br->block++;
  br->length--;
  if (g_sequence_lookup(block_list, br, (GCompareDataFunc) block_range_compare, NULL) != NULL)
  {
    glob_blocks(block_list, br);
  } else
  {
    // Nope, not adjacent
    br->block--;
    br->length++;
  }
}

static int store_range(block_store_t store, unsigned long long start_offset, unsigned long long range)
{
  prong_assert(store != NULL);
  struct block_store *blocks = (struct block_store *) store;

  prong_assert(blocks->magic == BLOCK_MAGIC);

  if (blocks->current_pos >= (start_offset + range))
  {
    // No point doing pointless work.
    return 0;
  }

  if (blocks->current_pos >= start_offset)
  {
    blocks->current_pos = start_offset + range;
    // No point recording this as we're already beyond its range
    return 0;
  }

  struct block_range *br = (struct block_range *) g_malloc(sizeof(struct block_range));

  br->block = start_offset;
  br->length = range;

  glob_blocks(blocks->block_list, br);

  g_sequence_insert_sorted(blocks->block_list, br, (GCompareDataFunc) block_range_compare, NULL);

  return 0;
}

int store_blocks(block_store_t store, block_range_t * ranges, unsigned int num_ranges)
{
  int err = 0;

  for (int i = 0; i < num_ranges; i++)
  {
    unsigned long long pos;
    unsigned long long len;
    int ret = block_range_get_range(ranges[i], &pos, &len);

    prong_assert(ret == 0);
    err += store_range(store, pos, len);
  }
  return err;
}

// Also marks off the returned value in the store
unsigned long long int next_missing_block(block_store_t store)
{
  prong_assert(store != NULL);
  struct block_store *blocks = (struct block_store *) store;

  prong_assert(blocks->magic == BLOCK_MAGIC);

  GSequenceIter *iter = g_sequence_get_begin_iter(blocks->block_list);

  while (iter != g_sequence_get_end_iter(blocks->block_list))
  {
    struct block_range *br = (struct block_range *) g_sequence_get(iter);

    if (blocks->current_pos < br->block)
    {
      break;
    }

    if (blocks->current_pos < br->block + br->length)
    {
      blocks->current_pos = br->block + br->length;
    }
    g_sequence_remove(iter);
    iter = g_sequence_get_begin_iter(blocks->block_list);
  }

  return blocks->current_pos++;
}

int block_store_close(block_store_t to_close)
{
  prong_assert(to_close != NULL);
  struct block_store *blocks = (struct block_store *) to_close;

  prong_assert(blocks->magic == BLOCK_MAGIC);

  g_sequence_free(blocks->block_list);
  g_free(blocks);

  return 0;
}
