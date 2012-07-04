/* Pronghorn Block Manager Library
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

#include <stdio.h>

#include <blocks.h>
#include <config.h>
#include <defaults.h>
#include <logger.h>
#include <prong_assert.h>

/** The block size (read from the config service) */
int block_size = 0;

/** The absolute offset start point */
long long int absolute_offset = -1;

/** The list of block ranges */
GTree *block_range_tree = NULL;

unsigned int array_pos = 0;

/**
 * Inserts a block into the block_list
 *
 * \param block The block to insert
 */
static void insert_block(unsigned long long block)
{
  block_range_t b = block_range_init(NULL, 0);

  int ret = block_range_set_range(b, block, 1);
  prong_assert(ret == 0);

  block_range_t old_b;
  char *DO_NOT_USE;

  if (g_tree_lookup_extended(block_range_tree, b, (gpointer *) & old_b, (gpointer *) & DO_NOT_USE) == FALSE)
  {
    g_tree_insert(block_range_tree, b, NULL);
    return;
  }
  // One was found! Making sure it encompases our needs
  unsigned long long old_pos = 0;
  unsigned long long old_len = 0;

  block_range_get_range(old_b, &old_pos, &old_len);

  int changed = 0;

  if (old_pos > block)
  {
    // This block now starts the block range
    old_pos = block;
    old_len++;
    changed = 1;
  }
  if ((old_pos + old_len) == block)
  {
    // This block now ends the block range
    old_len++;
    changed = 1;
  }

  if (changed == 1)
  {
    // We need to remove it to see if we would also match in the other
    // direction (and join two block ranges together)
    // Note that we need to specify the same criteria to find it to ensure we remove the correct one
    gboolean ret = g_tree_remove(block_range_tree, b);

    prong_assert(ret == TRUE);
    block_range_close(old_b);

    block_range_t other_b;

    if (g_tree_lookup_extended(block_range_tree, b, (gpointer *) & other_b, (gpointer *) & DO_NOT_USE) == FALSE)
    {
      // Only joining one side
      ret = block_range_set_range(b, old_pos, old_len);
      prong_assert(ret == 0);
      g_tree_insert(block_range_tree, b, NULL);
      return;
    }
    // We need to join two sides together!
    unsigned long long other_pos = 0;
    unsigned long long other_len = 0;

    block_range_get_range(other_b, &other_pos, &other_len);

    if (old_pos < other_pos)
    {
      old_len += (other_pos + other_len) - (old_pos + old_len);
    } else
    {
      old_len += old_pos - other_pos;
      old_pos = other_pos;
    }
    ret = g_tree_remove(block_range_tree, b);
    prong_assert(ret == TRUE);
    block_range_close(other_b);

    ret = block_range_set_range(b, old_pos, old_len);
    prong_assert(ret == 0);
    g_tree_insert(block_range_tree, b, NULL);
  }
}

/**
 * Convert the given bytes into blocks and insert them into the block list
 *
 * \param offset The offset of the first byte
 * \param length The length of the data block
 */
static void insert_bytes(unsigned long long offset, unsigned long long length)
{
  if (absolute_offset < 0)
  {
    // Nothing to do! It's invalid
    return;
  }

  offset += absolute_offset;

  // We only claim a block if we 'own' the first byte in that block
  unsigned long long start_block = 0;

  if (offset != 0)
  {
    start_block = ((offset - 1) / block_size) + 1;
  }

  unsigned long long end_block = (offset + length) / block_size;

  // End block is incremented as we want to claim it
  end_block++;

  for (unsigned long long block = start_block; block < end_block; block++)
  {
    insert_block(block);
  }
}

/**
 * Compares two block ranges
 *
 * If the block ranges overlap then they are considered equal.
 *
 * IMPORTANT: If the block ranges are adjacent, they are also considered equal!
 *
 * Otherwise one is before the other.
 *
 * \param a The first pointer
 * \param b The second pointer
 * \param user_data Not used
 * \returns -1 if a < b, 0 if a==b, 1 if a > b
 */
static gint block_range_compare(block_range_t a, block_range_t b, gpointer user_data)
{
  prong_assert(a != NULL);
  prong_assert(b != NULL);

  unsigned long long pos_a = 0;
  unsigned long long len_a = 0;
  unsigned long long pos_b = 0;
  unsigned long long len_b = 0;

  block_range_get_range(a, &pos_a, &len_a);
  block_range_get_range(b, &pos_b, &len_b);

  if (pos_a > (pos_b + len_b))
  {
    return 1;
  }

  if (pos_b > (pos_a + len_a))
  {
    return -1;
  }

  return 0;
}

static gboolean destroy_block_ranges(block_range_t range, gpointer value, gpointer user)
{
  block_range_close(range);

  return FALSE;
}

void block_start(long long int _absolute_offset)
{
  absolute_offset = _absolute_offset;

  if (config_get_int_with_default_macro(NULL, CONFIG_BLOCK_SIZE, &block_size) != 0)
  {
    error_log("Unable to get block size! This indicates a problem with the config service.");
    block_size = 512;
  } else
  {
    //debug_log("Using block size of %i", block_size);
  }

  if (block_range_tree != NULL)
  {
    g_tree_foreach(block_range_tree, (GTraverseFunc) destroy_block_ranges, NULL);
    g_tree_destroy(block_range_tree);
    block_range_tree = NULL;
  }

  block_range_tree = g_tree_new_full((GCompareDataFunc) block_range_compare, NULL, NULL, NULL);
}

int block_add_byte(unsigned long long byte)
{
  if (block_range_tree == NULL)
  {
    return -1;
  }

  insert_bytes(byte, 1);

  return 0;
}

int block_add_byte_range(unsigned long long start_byte, unsigned long long end_byte)
{
  if (block_range_tree == NULL)
  {
    return -1;
  }

  if (start_byte > end_byte)
  {
    return -1;
  }

  insert_bytes(start_byte, end_byte - start_byte + 1);

  return 0;
}

int block_add_block(unsigned long long block, unsigned int size)
{
  if (block_range_tree == NULL)
  {
    return -1;
  }

  insert_bytes(block * size, size);

  return 0;
}

int block_add_block_range(unsigned long long start_block, unsigned long long end_block, unsigned int bsize)
{
  if (block_range_tree == NULL)
  {
    return -1;
  }

  if (start_block > end_block)
  {
    return -1;
  }

  insert_bytes(start_block * bsize, (end_block - start_block + 1) * bsize);

  return 0;
}

static gboolean grab_block_ranges(block_range_t range, gpointer value, block_range_t * array)
{
  array[array_pos++] = range;

  return FALSE;
}

block_range_t *block_end(unsigned int *size)
{
  *size = 0;
  if (block_range_tree == NULL)
  {
    return NULL;
  }

  *size = g_tree_nnodes(block_range_tree);

  block_range_t *array = (block_range_t *) g_malloc(sizeof(block_range_t) * *size);

  array_pos = 0;
  g_tree_foreach(block_range_tree, (GTraverseFunc) grab_block_ranges, array);
  g_tree_destroy(block_range_tree);
  block_range_tree = NULL;

  return array;
}
