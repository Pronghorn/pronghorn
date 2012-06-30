/* Pronghorn File Manager
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
#include <string.h>
#include <errno.h>

#include <logger.h>
#include <prong_assert.h>

#include "file_manager.h"

#define MIN_WINDOW_SIZE 2048
#define MIN_BUFFER_SIZE (8*1024)
#define MIN_BUFFER_SIZE_MULTIPLE (8*1024)

const unsigned int FILE_MANAGER_MAGIC = 0x9F8081BE;

struct file_manager
{
  unsigned int magic;
  FILE *file_handle;
  unsigned int block_size;
  off_t current_offset;
  unsigned char *buffer;
  unsigned int buffer_size;
  unsigned int buffer_offset_pointer;
  unsigned int buffer_fill_size;
  unsigned int window_size;
};


// Documented in header
pronghorn_file_t prong_file_init(const char *path, unsigned int block_size, unsigned int window_size)
{
  struct file_manager *fm = (struct file_manager *) g_malloc(sizeof(struct file_manager));

  fm->magic = FILE_MANAGER_MAGIC;

  fm->file_handle = fopen(path, "rb");
  if (fm->file_handle == NULL)
  {
    g_free(fm);
    severe_log("Could not open file! File=%s. Error=%s", path, strerror(errno));
    return NULL;
  }

  fm->block_size = block_size;
  fm->current_offset = 0;

  if (window_size < block_size)
  {
    window_size = block_size;
  }

  if (window_size < MIN_WINDOW_SIZE)
  {
    // This is the minimum we support
    window_size = MIN_WINDOW_SIZE;
  }

  fm->window_size = window_size;
  fm->buffer_size = window_size;
  if (fm->buffer_size < MIN_BUFFER_SIZE)
  {
    fm->buffer_size = MIN_BUFFER_SIZE;
  }

  if ((fm->buffer_size % MIN_BUFFER_SIZE_MULTIPLE) != 0)
  {
    fm->buffer_size = ((fm->buffer_size / MIN_BUFFER_SIZE_MULTIPLE) + 1) * MIN_BUFFER_SIZE_MULTIPLE;
  }

  fm->buffer = (unsigned char *) g_malloc(fm->buffer_size);
  fm->buffer_offset_pointer = 0;

  fm->buffer_fill_size = fread(fm->buffer, 1, fm->buffer_size, fm->file_handle);

  return (pronghorn_file_t) fm;
}

static const unsigned char *roll_buffer(struct file_manager *fm, unsigned int *buff_size)
{
  if ((fm->buffer_size - fm->buffer_offset_pointer) >= fm->window_size)
  {
    // We have enough data in out buffer to service this request immediately
    unsigned char *ptr = fm->buffer + fm->buffer_offset_pointer;

    if (fm->buffer_fill_size <= fm->buffer_offset_pointer)
    {
      *buff_size = 0;
      return NULL;
    } else if ((fm->buffer_fill_size - fm->buffer_offset_pointer) < fm->window_size)
    {
      *buff_size = fm->buffer_fill_size - fm->buffer_offset_pointer;
    } else
    {
      *buff_size = fm->window_size;
    }

    fm->buffer_offset_pointer += fm->block_size;
    fm->current_offset += fm->block_size;

    return ptr;
  }
  // Rotate the buffer and read more data
  fm->buffer_fill_size -= fm->buffer_offset_pointer;
  if (fm->buffer_offset_pointer > fm->buffer_fill_size)
  {
    memcpy(fm->buffer, fm->buffer + fm->buffer_offset_pointer, fm->buffer_fill_size);
  } else
  {
    char *b = (char *) g_malloc(fm->buffer_fill_size);

    memcpy(b, fm->buffer + fm->buffer_offset_pointer, fm->buffer_fill_size);
    memcpy(fm->buffer, b, fm->buffer_fill_size);
    g_free(b);
  }
  fm->buffer_offset_pointer = 0;
  int size = fread(fm->buffer + fm->buffer_fill_size, 1, fm->buffer_size - fm->buffer_fill_size, fm->file_handle);

  if (size < 0)
  {
    severe_log("Unable to read file? Err=%s", strerror(errno));
    *buff_size = 0;
    return NULL;
  }
  fm->buffer_fill_size += size;

  if (fm->buffer_fill_size < fm->window_size)
  {
    *buff_size = fm->buffer_fill_size;
    if (fm->buffer_fill_size >= fm->block_size)
    {
      fm->buffer_offset_pointer += fm->block_size;
      fm->current_offset += fm->block_size;
    } else
    {
      fm->buffer_offset_pointer += fm->buffer_fill_size;
      fm->current_offset += fm->buffer_fill_size;
    }
    return fm->buffer;
  }

  fm->buffer_offset_pointer = fm->block_size;
  fm->current_offset += fm->block_size;
  *buff_size = fm->window_size;
  return fm->buffer;
}

const unsigned char *prong_file_read_offset(pronghorn_file_t pf, unsigned long long offset, unsigned int *buff_size)
{
  prong_assert(pf != NULL);
  struct file_manager *fm = (struct file_manager *) pf;

  prong_assert(fm->magic == FILE_MANAGER_MAGIC);

  if (offset != fm->current_offset)
  {
    fm->current_offset = offset;
    fseeko(fm->file_handle, offset, SEEK_SET);
    int size = fread(fm->buffer, 1, fm->buffer_size, fm->file_handle);

    if (size < 0)
    {
      severe_log("Unable to read file? Err=%s", strerror(errno));
      *buff_size = 0;
      return NULL;
    }
    fm->buffer_fill_size = size;
    fm->buffer_offset_pointer = 0;
  }

  return roll_buffer(fm, buff_size);
}

unsigned long long prong_file_discover_num_constant_blocks(pronghorn_file_t pf, unsigned long long file_pointer_offset)
{
  prong_assert(pf != NULL);
  struct file_manager *fm = (struct file_manager *) pf;

  prong_assert(fm->magic == FILE_MANAGER_MAGIC);

  unsigned long long num_blocks = 1;

  // Save the offset so we can restore it
  off_t offset = ftello(fm->file_handle);

  fseeko(fm->file_handle, file_pointer_offset, SEEK_SET);

  unsigned char *source_buf = (unsigned char *) g_malloc(fm->block_size);

  if (fread(source_buf, 1, fm->block_size, fm->file_handle) == fm->block_size)
  {
    unsigned char *check_buf = (unsigned char *) g_malloc(fm->block_size);
    int amount_read = fread(check_buf, 1, fm->block_size, fm->file_handle);

    while ((amount_read > 0) && (memcmp(source_buf, check_buf, amount_read) == 0))
    {
      num_blocks++;
      amount_read = fread(check_buf, 1, fm->block_size, fm->file_handle);
      if ((num_blocks & 0xFFFF) == 0)
      {
        info_log("Processed another run of %u constant blocks", 0x10000);
      }
    }

    g_free(check_buf);
  }

  g_free(source_buf);
  // Restore the offset
  fseeko(fm->file_handle, offset, SEEK_SET);

  if (num_blocks > 2)
  {
    return num_blocks - 2;
  }
  return 1;
}

int prong_file_close(pronghorn_file_t pf)
{
  prong_assert(pf != NULL);
  struct file_manager *fm = (struct file_manager *) pf;

  prong_assert(fm->magic == FILE_MANAGER_MAGIC);

  fclose(fm->file_handle);
  g_free(fm->buffer);
  g_free(fm);

  return 0;
}
