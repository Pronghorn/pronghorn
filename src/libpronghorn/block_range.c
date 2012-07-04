/* libpronghorn Block Range Library
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

/**
 * \file block_range.c
 * \brief Library functions for block ranges
 */

#include <string.h>
#include <errno.h>

#include <prong_assert.h>

#include "structures.pb-c.h"
#include "block_range.h"

/**
 * A unique ID to identify a block_range reference.
 * 
 * It's just four bytes taken from /dev/urandom
 */
static const unsigned int BLOCK_RANGE_MAGIC = 0xFA044ABE;

block_range_t block_range_init(const char *initial_values, unsigned int initial_values_size)
{
  BlockRange temp = BLOCK_RANGE__INIT;
  BlockRange *b = (BlockRange *) g_malloc(sizeof(BlockRange));

  memcpy(b, &temp, sizeof(BlockRange));
  b->has_magic = 1;
  b->magic = BLOCK_RANGE_MAGIC;

  if (initial_values != NULL)
  {
    // We need to free unpacked_block_range using block_range__free_unpacked
    // Unfortunately this means we need to copy all the internal variables to our own structure
    BlockRange *unpacked_block_range = block_range__unpack(NULL, initial_values_size, (const unsigned char *) initial_values);

    if ((unpacked_block_range == NULL) || (unpacked_block_range->has_magic != 1) || (unpacked_block_range->magic != BLOCK_RANGE_MAGIC))
    {
      block_range_close((block_range_t) b);
      errno = EINVAL;
      return NULL;
    }

    b->has_offset = unpacked_block_range->has_offset;
    b->offset = unpacked_block_range->offset;
    b->has_length = unpacked_block_range->has_length;
    b->length = unpacked_block_range->length;

    block_range__free_unpacked(unpacked_block_range, NULL);
  }

  return (block_range_t) b;
}

char *block_range_serialise(block_range_t _b, unsigned int *output_data_size)
{
  prong_assert(_b != NULL);
  BlockRange *b = (BlockRange *) _b;

  prong_assert(b->magic == BLOCK_RANGE_MAGIC);

  *output_data_size = block_range__get_packed_size(b);
  char *buf = (char *) g_malloc(*output_data_size);

  block_range__pack(b, (unsigned char *) buf);

  return buf;
}

block_range_t block_range_clone(block_range_t _b)
{
  unsigned int size;
  char *b_serialised = block_range_serialise(_b, &size);

  if (b_serialised == NULL)
  {
    return NULL;
  }

  block_range_t new_block_range = block_range_init(b_serialised, size);

  g_free(b_serialised);

  return new_block_range;
}

int block_range_set_range(block_range_t _b, unsigned long long position, unsigned long long length)
{
  prong_assert(_b != NULL);
  prong_assert(length > 0);
  BlockRange *b = (BlockRange *) _b;

  prong_assert(b->magic == BLOCK_RANGE_MAGIC);
  b->has_offset = 1;
  b->offset = position;
  b->has_length = 1;
  b->length = length;

  return 0;
}

int block_range_get_range(block_range_t _b, unsigned long long *position, unsigned long long *length)
{
  prong_assert(_b != NULL);
  BlockRange *b = (BlockRange *) _b;

  prong_assert(b->magic == BLOCK_RANGE_MAGIC);

  if (b->has_offset == 0)
  {
    // The values aren't populated
    return -1;
  }

  *position = b->offset;
  *length = b->length;
  return 0;
}

int block_range_close(block_range_t _b)
{
  if (_b == NULL)
  {
    return -1;
  }

  BlockRange *b = (BlockRange *) _b;

  prong_assert(b->magic == BLOCK_RANGE_MAGIC);
  g_free(b);

  return 0;
}
