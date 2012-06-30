/* libpronghorn Subcontractor zlib
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
 */

/**  
  * \file subcontractor_zilb.c
  * \brief This is the ZLIB compression subcontractor for pronghorn
  *
  * It will attempt to parse the supplied ZLIB encoded file and fuse
  * mount the decompressed result.
  *
  * Confidence values:
  * 75: It processed the file, but encountered errors.
  * 100: It processed the whole file successfully.
  * 
  */
#include <stdio.h>
#include <string.h>
#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <base_fuse.h>

#include "subcontractor_helper.h"

// Include required for zlib
#include <zlib.h>

/**
 * An array of supported MAGIC_TYPE* entries. Must be 0 terminated.
 */
unsigned int supported_file_types[] = { MAGIC_TYPE_ZLIB, 0 };

/**
  * Pointers to the compressed and decompressed data.
  */
guchar *compressed_data = NULL;
guchar *decompressed_data = NULL;
unsigned long decompressed_data_length = 0;

/**
  * Creates new contracts for the decompressed data
  *
  * \param mnt_path The path of the file
  * \param result The result to attach the contract to.
  * \returns 0 on success.
  */
int zlib_create_new_contracts(gchar * mnt_path, result_t result)
{
  gchar *sub_path;

  sub_path = g_strdup_printf("%s/%d", mnt_path, 0);
  contract_t new_contract = contract_init(NULL, 0);

  contract_set_path(new_contract, sub_path);
  contract_set_absolute_offset(new_contract, -1);
  contract_set_contiguous(new_contract, 0);
  result_add_new_contract(result, new_contract);
  contract_close(new_contract);

  g_free(sub_path);
  return 0;
}

/**
  * Inits global stuctures
  *
  * returns 0 for success
  */
int subcontractor_init(void)
{
  // Initialise any structures here

  debug_log("The ZLIB Subcontractor is Active");

  return 0;
}

/**
  * Analyse whatever contract is provided and respond
  *
  * Attemps to parse the supplied file as an archive.
  * See top level comment for more details.
  *
  * \param to_analyse The contract to analyse.
  * \param ccr The contract completion report to populate
  * \returns 0 on success, -1 on failure
  */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  // File pointer
  FILE *fp;

  // Variables associated with the result we'll send back.
  guint confidence = 0;

  // Grab the path of the file from the contract we've been given. Also grab the offset and contiguous value.
  const gchar *path = contract_get_path(to_analyse);
  gulong absolute_offset = contract_get_absolute_offset(to_analyse);
  gint is_contiguous = contract_is_contiguous(to_analyse);

  // Try to open the file.
  if ((fp = fopen(path, "rb")) == NULL)
  {
    error_log("Was not able to open file for scanning");
    return -1;
  }
  // Get the size of file, we'll set a limit for the max
  // amount of data to be read if the file is massive.
  fseeko(fp, 0, SEEK_END);
  off_t file_length = ftello(fp);

  fseeko(fp, 0, SEEK_SET);

  if (file_length > 10000000)
  {
    file_length = 10000000;
  }
  // Allocate enough memory to read in the data, then read it in
  compressed_data = (guchar *) g_malloc(file_length);
  guint bytes_read;

  bytes_read = fread(compressed_data, 1, file_length, fp);
  debug_log("Successfull read in %d bytes", bytes_read);
  fclose(fp);

  // Because we don't know how much space we'll need to hold the
  // decompressed data, we'll be very conservative and assume a 
  // 10 to 1 compression ration... in reality, it should never
  // be this much.
  decompressed_data_length = file_length * 10;
  decompressed_data = (guchar *) g_malloc(decompressed_data_length);

  // Try to decompress the data
  debug_log("Attempting to decompress data");
  int z_result = 0;

  z_result = uncompress(decompressed_data, &decompressed_data_length, compressed_data, bytes_read);
  gchar *mnt_path = NULL;
  result_t result = result_init(NULL, 0);
  unsigned long long length_of_data = 0;

  switch (z_result)
  {
  case Z_OK:
    debug_log("Successfully decompressed data. Decompressed size is %lu", decompressed_data_length);

    // Since it successfully decoded the data, we want to claim
    // the associated blocks and fuse mount the decompressed data.
    add_file(0, "decompressed_zlib", (size_t) decompressed_data_length);

    mnt_path = g_strdup_printf("%s:mnt-zlib", path);
    zlib_create_new_contracts(mnt_path, result);
    do_mount(mnt_path);
    g_free(mnt_path);

    confidence = 100;

    // We don't currently know how much of the input was decompressed.
    // As a quick safe guard, we'll only claim blocks if the decompressed
    // data is bigger than the original data
    if (decompressed_data_length > bytes_read)
    {
      length_of_data = bytes_read;
    } else
    {
      debug_log("Size of decompressed data is smaller than original file. Not claiming blocks");
    }
    break;
  case Z_DATA_ERROR:
    error_log("Was unable to decompress data");
    confidence = 0;
    break;
  case Z_MEM_ERROR:
    error_log("MEMORY ERROR WHILST DECOMPRESSING");
    confidence = 75;
    break;
  case Z_BUF_ERROR:
    error_log("BUFFER ERROR WHILST DECOMPRESSING");
    confidence = 75;
    break;
  }

  // If the confidence value is greater than zero, finish up by sending the results back to the ccr... and we're done!
  if (confidence)
  {
    populate_result_with_length(result, "ZLib", "ZLib Data", confidence, absolute_offset, length_of_data, is_contiguous);
    contract_completion_report_add_result(ccr, result);
  }
  // Free the data streams & path pointer and close the result.
  result_close(result);
  g_free(compressed_data);
  g_free(decompressed_data);

  return 0;
}

int subcontractor_close(void)
{
  // Destroy structures initialised in subcontractor_init

  debug_log("Shutting Down ZLIB");

  return 0;
}

/**
  * Populates the buffer with the contents of the specified filename.
  *
  * \param id_number The id number of the file (in our case the inode)
  * \param filename The real filename for this file.
  * \param buf The buffer to write data into
  * \param size The size of the buffer
  * \param offset The offset into the file the data should be taken from.
  * \returns The amount of bytes read.
  */
int do_read(unsigned int id_number, const char *filename, char *buf, size_t size, off_t offset)
{
  // Open a file to record when reading occurs 
  FILE *log;

  log = fopen("/tmp/zlib.log", "a");
  fprintf(log, "Reading file id: %d, name: %s, size: %zd, offset: %zd\n", id_number, filename, size, (size_t) offset);

  // Set out original readable length to the size of the decompressed data
  guint readable_data_size = decompressed_data_length - offset;

  // Make sure the offset is within the data stream. ie the readable data size is a positive number
  if (readable_data_size <= 0)
  {
    return 0;
  }
  // The size asked for shouldn't exceed the buffer size.
  if (readable_data_size > size)
  {
    readable_data_size = size;
  }
  // Copy the data from the stream onto the buffer.
  memcpy(buf, decompressed_data + offset, readable_data_size);
  fprintf(log, "Returning data from %zd to %zd. Read total of %zd\n", (size_t) offset, (size_t) offset + size, size);
  fclose(log);
  return size;
}

/**
  * Called when the filesystem is unmounted, and allows the destruction
  * of structures and freeing allocated memory.
  */
void cleanup(void)
{
  // The filesystem is unmounted
  // Destroy any filesystem related structures
}
