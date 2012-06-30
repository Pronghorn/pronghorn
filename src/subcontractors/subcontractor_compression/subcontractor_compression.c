/* libpronghorn Subcontractor Compression
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
 * \file subcontractor_compression.c
 * \brief This is the archive and compression parser and FUSE mount
 * for Pronghorn.
 *
 * It will attempt to parse the supplied archive and provde a FUSE
 * mount into the archive. If it encounters an error reading the archive
 * it will abort processing and only present the arhive entries that were
 * previously parsed.
 *
 * Confidence values:
 * 60: It was able to determine the underlying compression format
 * 70: It was able to determine the archive format and encountered
 * errors reading from the archive.
 * 90: It was able to pull out at least 2 files from the archive but
 * not able to process the whole archive.
 * 100: It processed the whole archive successfully.
 * 
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <prong_assert.h>

#include <archive.h>
#include <archive_entry.h>
//#include <archive_private.h>
//#include <archive_read_private.h>

#include <base_fuse.h>

#include "subcontractor_helper.h"

unsigned int supported_file_types[] = { MAGIC_TYPE_ZIP, MAGIC_TYPE_BZIP2, MAGIC_TYPE_GZIP, MAGIC_TYPE_COMPRESS, 0 };

#define TEMP_BUFFER_SIZE 10240
#define BLOCK_SIZE 10240

/** A global variable referencing the archive which
 * is used to provide access to the files inside the archive
 * for the fuse do_read method. We can do this because we call
 * the base_fuse do_mount method which forks this process freezing
 * its state.
 */
static char *global_path = NULL;
static struct archive *global_archive = NULL;

// The rest aren't used in analyse_contract
static char *global_data = NULL;
static size_t global_data_size = 0;
static int global_entry_index = -1;

const static int NOT_OFFICE_DOC = 0x00;
const static int OFFICE_DOCX_TYPE = 0x01;
const static int OFFICE_XLSX_TYPE = 0x02;
const static int OFFICE_PPTX_TYPE = 0x04;
const static int OFFICE_INDICATOR_1 = 0x08;
const static int OFFICE_INDICATOR_2 = 0x10;

/**
 * Looks within an archive for files which indicate the archive is
 * actually an office document container
 *
 * \param entry_path the name of the file being examined within the archive
 * \returns A code flag which identifies whether the file belongs to an office type
 */
static int compression_identify_office_container(const char *entry_path)
{
  //const char *mimetype_file = "mimetype";
  //const char *open_types[3] = {"ODT","ODS","OPD"};
  //const char *open_words[3] = {"text","spreadsheet","presentation"};

#define NUM_FIELDS 5
  int flags[NUM_FIELDS] = { OFFICE_INDICATOR_1, OFFICE_INDICATOR_2, OFFICE_DOCX_TYPE, OFFICE_XLSX_TYPE, OFFICE_PPTX_TYPE };
  const char *office_words[NUM_FIELDS] = { "[Content_Types].xml", "_rels/.rels", "word/document.xml", "xl/workbook.xml", "ppt/presentation.xml" };

  // Go though our list of office related filenames
  for (int i = 0; i < NUM_FIELDS; i++)
  {
    // If the file being examined in this list is one of the words, return the flag
    if (strstr(entry_path, office_words[i]))
    {
      return flags[i];
    }
  }
  // If we reach this point, we didn't find a match. In this case return NOT_OFFICE_DOC.
  return NOT_OFFICE_DOC;
}

/**
 * Inits global stuctures
 *
 * returns 0 for success
 */
int subcontractor_init(void)
{
  // Initialise any structures here

  debug_log("compression - init");

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
 * \returns 0 on success, -1 on error
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  // These should have been free'd properly on the last execution
  prong_assert(global_path == NULL);
  prong_assert(global_archive == NULL);

  global_path = g_strdup(contract_get_path(to_analyse));

  GString *file_type = g_string_new(NULL);
  int confidence = 0;

  global_archive = archive_read_new();
  archive_read_support_filter_all(global_archive);
  archive_read_support_format_all(global_archive);
  int ret = archive_read_open_filename(global_archive, global_path, BLOCK_SIZE);

  gboolean try_and_continue = TRUE;

  switch (ret)
  {
  case ARCHIVE_OK:
    debug_log("Archive opened OK");
    break;
  case ARCHIVE_WARN:
    debug_log("Archive opened with warning (%s) ... will try and continue", archive_error_string(global_archive));
    break;
  case ARCHIVE_FATAL:
    debug_log("Archive had a fatal error (%s) ... giving up.", archive_error_string(global_archive));
    try_and_continue = FALSE;
    break;
  case ARCHIVE_RETRY:
    debug_log("Archive should be retried (%s). Retry is not currently supported (NYI). Will not retry.", archive_error_string(global_archive));
    try_and_continue = FALSE;
    break;
  case ARCHIVE_EOF:
    debug_log("Archive EOF encountered ... will try and continue");
    break;
  default:
    debug_log("Unknown response code. Will not continue");
    try_and_continue = FALSE;
  }

  // Don't even try and continue
  if (try_and_continue == FALSE)
  {
    g_string_free(file_type, TRUE);
    g_free(global_path);
    global_path = NULL;
    ret = archive_read_free(global_archive);
    if (ret != ARCHIVE_OK)
    {
      debug_log("Error freeing archive");
    }
    global_archive = NULL;
    return 0;
  }
  // Ignore the last or only filter since it doesn't contain useful information.
  for (int i = (archive_filter_count(global_archive) - 2); i >= 0; i--)
  {
    // We will drop the first space later
    g_string_append_printf(file_type, " %s", archive_filter_name(global_archive, i));
    debug_log("Filter %d %s", i, archive_filter_name(global_archive, i));
    confidence = 60;
  }

  char *mountpoint = g_strdup_printf("%s:mnt-compressed", global_path);

  // Process archive entries
  int archive_entry_index = 0;
  int added_files = 0;
  int read_error = 0;
  struct archive_entry *entry;
  int office_flags = 0;
  result_t result = result_init(NULL, 0);
  gboolean encrypted = FALSE;
  char buf[TEMP_BUFFER_SIZE];

  while ((ret = archive_read_next_header(global_archive, &entry)) == ARCHIVE_OK)
  {
    const char *entry_path = archive_entry_pathname(entry);

    debug_log("Processing entry %s", entry_path);
    confidence = 90;

    if (archive_entry_index == 0)
    {
      g_string_append_printf(file_type, " %s", archive_format_name(global_archive));
      confidence = 70;
    }
    // Determine file size
    size_t size = 0;
    if (!archive_entry_size_is_set(entry))
    {
      debug_log("Size has not been set");

      while ((ret = archive_read_data(global_archive, &buf, TEMP_BUFFER_SIZE)) > 0)
      {
        size += ret;
      }

      if (ret != 0)
      {
        debug_log("Error reading data from archive %s/%s %s %d", global_path, entry_path, archive_error_string(global_archive), ret);
        read_error++;
      }
    } else
    {

      debug_log("Entry had size set, it was %lu", (unsigned long) size);

      size = archive_entry_size(entry);

      if (archive_entry_index == 0)
      {
        ret = archive_read_data(global_archive, &buf, TEMP_BUFFER_SIZE);
        if (ret < 0)
        {
          if(strcmp("Encrypted file is unsupported", archive_error_string(global_archive)) == 0)
          {
            encrypted = TRUE;
            g_string_append(file_type, " PASSWORD PROTECTED");
          }
          else
          {
            debug_log("Error reading data from archive %s/%s %s %d", global_path, entry_path, archive_error_string(global_archive), ret);
            read_error++;          
          }
        }
      }

      ret = archive_read_data_skip(global_archive);
      if (ret != ARCHIVE_OK)
      {
        debug_log("Error skipping data from archive %s/%s %s %d", global_path, entry_path, archive_error_string(global_archive), ret);
        read_error++;
      }
    }

    //Determine if the file is a key file for an office container
    office_flags |= compression_identify_office_container(entry_path);

    // If reading archive was successful 
    if (size > 0  && ret >= 0 && read_error == 0 && !encrypted)
    {
      // Create subcontract
      char *sub_path = g_strdup_printf("%s/%d", mountpoint, added_files);
      contract_t sub_contract = contract_init(NULL, 0);

      contract_set_path(sub_contract, sub_path);
      contract_set_absolute_offset(sub_contract, -1);
      contract_set_contiguous(sub_contract, 0);
      result_add_new_contract(result, sub_contract);
      contract_close(sub_contract);

      //Add file to fuse mount
      debug_log("Adding file %s with size %zd", sub_path, size);
      add_file(added_files, archive_entry_pathname(entry), size);
      added_files++;

      g_free(sub_path);
    } else
    {
      if (!encrypted)
      {
        debug_log("Had a read error");
        break;
      }
    }

    archive_entry_index++;
  }

  // Parsed the whole archive successfully 
  if (ret == ARCHIVE_EOF && read_error == 0 && confidence >= 70)
  {
    debug_log("Successfully parsed archive %s", global_path);
    confidence = 100;
  } else
  {
    debug_log("Had errors parsing archive %s", global_path);
    g_string_append_printf(file_type, " %s", "CORRUPTED");
    confidence = confidence > 70 ? 70 : confidence;
  }

  if (added_files > 0)
  {
    debug_log("Called do_mount on %s", mountpoint);
    do_mount(mountpoint);
  }
  // Got some information about the archive
  if (confidence > 0)
  {
    char *brief_description = NULL;
    char *description = NULL;

    // office_flags needs both OFFICE_INDICATOR_1 and 2, and one of DOCX, PPTX, XLSX
    if (((office_flags & (OFFICE_INDICATOR_1 | OFFICE_INDICATOR_2)) == (OFFICE_INDICATOR_1 | OFFICE_INDICATOR_2)) && (office_flags & (OFFICE_DOCX_TYPE | OFFICE_PPTX_TYPE | OFFICE_XLSX_TYPE)))
    {

      if (office_flags & OFFICE_DOCX_TYPE)
      {
        brief_description = g_strdup_printf("DOCX");
      }
      if (office_flags & OFFICE_XLSX_TYPE)
      {
        if (brief_description == NULL)
        {
          brief_description = g_strdup_printf("XLSX");
        } else
        {
          char *temp = g_strdup_printf("%s,XLSX", brief_description);

          brief_description = temp;
          g_free(temp);
        }
      }
      if (office_flags & OFFICE_PPTX_TYPE)
      {
        if (brief_description == NULL)
        {
          brief_description = g_strdup_printf("PPTX");
        } else
        {
          char *temp = g_strdup_printf("%s,PPTX", brief_description);

          brief_description = temp;
          g_free(temp);
        }
      }
      description = g_strdup("OfficeX Document");
    } else
    {
      // Because of how we appended
      // drop the first space from the file_type string.
      // Create a short description from the first 4 characters.
      brief_description = (char *) g_malloc(5);

      memcpy(brief_description, file_type->str + 1, 4);
      brief_description[4] = '\0';
      g_strchomp(brief_description);

      char *temp = g_ascii_strup(brief_description, -1);

      g_free(brief_description);
      brief_description = temp;
      description = g_strdup(file_type->str + 1);
    }

    populate_result_with_length(result, brief_description, description, confidence, contract_get_absolute_offset(to_analyse), archive_filter_bytes(global_archive, -1),
                                contract_is_contiguous(to_analyse));
    contract_completion_report_add_result(ccr, result);

    g_free(brief_description);
    g_free(description);
  }
  // Cleanup
  result_close(result);
  g_string_free(file_type, TRUE);
  g_free(mountpoint);

  ret = archive_read_free(global_archive);
  if (ret != ARCHIVE_OK)
  {
    debug_log("Error freeing archive");
  }
  global_archive = NULL;

  g_free(global_path);
  global_path = NULL;

  return 0;
}

int subcontractor_close(void)
{
  // Destroy structures initialised in subcontractor_init

  debug_log("Bye");

  return 0;
}

/**
 * Populates the buffer with the contents of the specified filename.
 * The archive is read sequentially and it keeps track of its position
 * in the archive and if it already parsed the file it will reprocess
 * the archive from the beginning. Otherwise it will keep processing
 * from the current position.
 * It stores the content of the last file in memory to save
 * reprocessing when multiple do_read calls are received.
 *
 * \param id_number The id number of the file (in our case the inode)
 * \param filename The real filename for this file.
 * \param buf The buffer to write data into
 * \param size The size of the buffer
 * \param offset The offset into the file the data should be taken from.
 * \returns The amount of bytes read, or -1 on error.
 */
int do_read(unsigned int id_number, const char *filename, char *buf, size_t size, off_t offset)
{
  //FILE *log = fopen("/tmp/compression.log", "a");

  //fprintf(log, "Reading file id:%d name:%s size:%zd offset:%lld\n", id_number, filename, size, (long long) offset);
  // Read data from id_number (or optionally 'filename')
  // Populate buf with 'size' bytes at offset 'offset' into the file

  // If the id_number is greater than our current position keep
  // travering the archive. Otherwise start again.

  if (global_entry_index == id_number)
  {
    // We are reading a file we have already read.
    // Just return the previous result.
    size_t read_size = (size < global_data_size - offset) ? size : global_data_size - offset;

    memcpy(buf, global_data + offset, read_size);
    //fprintf(log, "Returning cached data from %lld to %lld. Read %zd\n", (long long) offset, (long long) offset + size, read_size);
    //fclose(log);
    return read_size;
  }

  if (global_entry_index == -1 || global_entry_index > id_number)
  {
    // We have already read past this point or never started so we need to go back
    // to the beginning.

    if (global_archive != NULL)
    {
      if (archive_read_free(global_archive) != ARCHIVE_OK)
      {
        //fprintf(log, "Error freeing archive %s %s", archive_error_string(global_archive), global_path);
        //fclose(log);
        return -1;
      }
    }
    // Open archive from the beginning
    global_archive = archive_read_new();
    archive_read_support_filter_all(global_archive);
    archive_read_support_format_all(global_archive);
    int r = archive_read_open_filename(global_archive, global_path, BLOCK_SIZE);

    if (r != ARCHIVE_OK)
    {
      //fprintf(log, "Error reading archive for file %s %s\n", filename, archive_error_string(global_archive));
      //fclose(log);
      return -1;
    }
    global_entry_index = 0;
    //fprintf(log, "Opened archive %s\n", global_path);
  } else
  {
    // We already read the previous entry so we don't have so skip it.
    // Therefore increase global_entry_index by one before starting
    global_entry_index++;
  }

  if (global_data != NULL)
  {
    g_free(global_data);
    global_data_size = 0;
  }

  struct archive_entry *entry;

  for (; global_entry_index < id_number; global_entry_index++)
  {
    if (archive_read_next_header(global_archive, &entry) != ARCHIVE_OK)
    {
      //fprintf(log, "Error reading file: %s %s\n", filename, archive_error_string(global_archive));
      //fclose(log);
      return -1;
    }
    //fprintf(log, "Skipping header %d\n", global_entry_index);

    archive_read_data_skip(global_archive);
  }

  if (archive_read_next_header(global_archive, &entry) != ARCHIVE_OK)
  {
    //fprintf(log, "Error reading file: %s %s\n", filename, archive_error_string(global_archive));
    //fclose(log);
    return -1;
  }
  //fprintf(log, "Read header for %d %s\n", global_entry_index, archive_entry_pathname(entry));

  int buf_size = 0;

  if (!archive_entry_size_is_set(entry))
  {
    //fprintf(log, "Size has not been set");
    buf_size = BLOCK_SIZE;
  } else
  {
    buf_size = archive_entry_size(entry) + 1;
  }
  global_data = (char *) g_malloc(buf_size);

  int bytes_read = 0;

  while ((bytes_read = archive_read_data(global_archive, global_data + global_data_size, buf_size - global_data_size)) > 0)
  {
    global_data_size += bytes_read;
    prong_assert(global_data_size <= buf_size);
    if (global_data_size == buf_size)
    {
      global_data = (char *) g_realloc(global_data, global_data_size * 2 + 1);
      buf_size = global_data_size * 2 + 1;
      if (global_data == NULL)
      {
        //fprintf(log, "Error reallocting memory %s\n", strerror(errno));
        //fclose(log);
        return -1;
      }
    }
  }

  if (bytes_read < 0)
  {
    //fprintf(log, "Error reading %s %s\n", strerror(archive_errno(global_archive)), archive_error_string(global_archive));
    //fclose(log);
    return -1;
  }

  //fprintf(log, "Read %zd bytes\n", global_data_size);
  //fclose(log);

  // Return the request chunk of data
  size_t read_size = (size < global_data_size - offset) ? size : global_data_size - offset;

  memcpy(buf, global_data + offset, read_size);
  return read_size;
}

/**
 * Called when the filesystem is unmounted, and allows the destruction
 * of structures and freeing allocated memory.
 */
void cleanup(void)
{
  // The filesystem is unmounted
  // Destroy any filesystem related structures
  g_free(global_path);
  g_free(global_data);

  if (global_archive != NULL)
  {
    if (archive_read_free(global_archive) != ARCHIVE_OK)
    {
      return;
    }
  }
}
