/* libpronghorn Subcontractor pdf
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
 * \file subcontractor_pdf.c
 *
 * \brief Subcontractor for procesing PDF files using Pronghorn
 *
 *
 * Confidence Levels:
 * 100 - Poppler lib can open the file and process the pdf
 * 75 - Valid PDF EOF reference found, but poppler returns IS_ENCRYPTED error
 * 50 - Valid PDF EOF reference found, but poppler is unable to open the file
 * 0 - Was unable to find a valid EOF reference and poppler did not open.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib/gstdio.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <base_fuse.h>
#include "subcontractor_helper.h"


// Import poppler-glib and cairo libraries required by this plugin
#include <poppler/glib/poppler.h>
#include <cairo/cairo.h>

// Subcontractor specific variables
const char *SUBCONTRACTOR_NAME = "pdf";

unsigned int supported_file_types[] = { MAGIC_TYPE_PDF, 0 };

// Declare functions for determining if the block is a valid pdf
gulong pdf_find_EOF(FILE * fp);
gchar *pdf_import_binary_data(FILE * fp, gulong approx_length, gulong * actual_length);
gulong pdf_find_pattern(gchar * stream, gulong actual_length, gchar pattern[], gulong pattern_size);

// Declare functions for scanning text tags within a file (case where we're not using the poppler lib)
int pdf_extract_encoded_streams(gchar * stream, gulong actual_length);

// Declare functions to run against pdf successfully opened by poppler.
guint pdf_scan_pages(PopplerDocument * pdf, gint num_of_pages);
guint pdf_get_image_info(PopplerPage * page);

// Declare functions for adding all the extracted streams to the fuse mount
gulong pdf_add_files_for_mounting(void);
int pdf_create_new_contracts(gchar * mnt_path, result_t result);

// Global variable for holding the loaded file data
gchar *file_stream = NULL;

// We'll also have a global for our data description.
gchar *description = NULL;

// Global variable for holding the information about it's embedded streams.
GList *embedded_stream_offset = NULL;
GList *embedded_stream_size = NULL;

/**
 * Inits global structures
 *
 * \returns 0 on success
 */
int subcontractor_init(void)
{
  // Initialise any structures here

  g_type_init();
  description = g_strdup("NOT YET PROVIDED");

  debug_log("The PDF sub-contractor is active!");

  return 0;
}

/**
 * Analyse whatever contract sent to it and respond
 *
 * Attempts to parse the supplied file as a PDF 
 *
 * \param to_analyse The contract to analyse
 * \param ccr The contract completion report to populate
 * \return 0 on success, -1 on error
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  // Variables associates with poppler
  PopplerDocument *pdf = NULL;
  GError *poppler_error = NULL;
  gint num_of_pages;

  // File pointer
  FILE *fp;

  // The variable into which we load the file, its size etc.
  gulong approx_length;
  gulong actual_length;

  // Our confidence value
  guint confidence = 0;

  // Flag for whether or not we think the file is encrypted
  guint is_encrypted = 0;

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
  // Try and find valid start and end of file tags for PDFs. If it can, increase the confidence.
  if ((approx_length = pdf_find_EOF(fp)) == 0)
  {
    debug_log("Unable to determine file length, probably not a valid PDF!");
    g_free(description);
    description = g_strdup("Probably not a valid PDF");
  } else
  {
    // since we could find a valid EOF, we have some confidence that it is a pdf.
    confidence = 50;
    debug_log("Approx File Size: %lu", approx_length);
  }

  // Load the file into memory (from the start until the file length we derived previously.
  file_stream = pdf_import_binary_data(fp, approx_length, &actual_length);


  debug_log("Actual File Length: %lu", actual_length);

  // close the file reference when we're done with it.
  fclose(fp);

  // get poppler to try to open the file, but only if the actual length is reasonable.
  if (actual_length > 1)
  {
    pdf = poppler_document_new_from_data(file_stream, actual_length, NULL, &poppler_error);

    // If poppler returns null, leave a low confidence
    if (pdf == NULL)
    {
      // first check to see if poppler couldn't open it due to encryption.
      if (poppler_error->code == POPPLER_ERROR_ENCRYPTED)
      {
        debug_log("This is possibly an encrypted pdf");
        g_free(description);
        description = g_strdup("Possibly encrypted pdf");
        confidence += 25;
        is_encrypted = 1;
      } else
      {
        debug_log("Poppler was unable to open the file. Possibly not a real PDF");
        g_free(description);
        description = g_strdup("Possibly a PDF, but library was unable to open.");
      }
    }

    else
    {
      //If poppler was able to open the file. Enumerate the number of pages. 
      // If it has pages, then it is definitely a pdf. Give a high confidence value.
      num_of_pages = poppler_document_get_n_pages(pdf);
      if (num_of_pages)
      {
        debug_log("Number of pages found: %d", num_of_pages);

        confidence = 100;
        g_free(description);
        description = g_strdup_printf("Valid PDF document. %d pages", num_of_pages);

        // Scan through all the pages in the document using poppler. This will give us more info to report back.
        pdf_scan_pages(pdf, num_of_pages);
      }
    }
  }

  result_t result = result_init(NULL, 0);

  // Let's extract all the embedded streams and add them to the filesystem. Don't bother if the file is encrypted.
  if ((!is_encrypted) && (actual_length > 1))
  {
    pdf_extract_encoded_streams(file_stream, actual_length);
  }
  // Add all the extracted streams to the mount and send back new contracts for processing.
  if (g_list_length(embedded_stream_size) > 0)
  {
    pdf_add_files_for_mounting();
    gchar *mnt_path = g_strdup_printf("%s:mnt-pdf", path);

    pdf_create_new_contracts(mnt_path, result);
    do_mount(mnt_path);
    g_free(mnt_path);
  }
  // If the confidence value is greater than zero, finish up by sending the results back to the ccr... and we're done!
  if (confidence)
  {
    populate_result_with_length(result, "PDF", description, confidence, absolute_offset, actual_length, is_contiguous);
    contract_completion_report_add_result(ccr, result);
  }

  // Clean Up

  result_close(result);

  if (embedded_stream_offset != NULL)
  {
    g_list_free(embedded_stream_offset);
    embedded_stream_offset = NULL;
  }

  if (embedded_stream_size != NULL)
  {
    g_list_free(embedded_stream_size);
    embedded_stream_size = NULL;
  }

  // free the popplerdocument created
  if (pdf != NULL)
  {
    g_object_unref(pdf);
  }
  // free the file stream once we are done with it.
  if (file_stream != NULL)
  {
    g_free(file_stream);
    file_stream = NULL;
  }

  return 0;
}

/**
 * Invoked when subcontractor is closing
 * Frees up any lingerging structs
 */
int subcontractor_close(void)
{

  g_list_free(embedded_stream_size);
  g_list_free(embedded_stream_offset);
  g_free(description);

  debug_log("PDF Subcontractor Closing");

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

  log = fopen("/tmp/pdf.log", "a");
  fprintf(log, "Reading file id: %d, name: %s, size: %zd, offset: %zd\n", id_number, filename, size, (size_t) offset);

  // Match the supplied id_number to it's offset and size in the data stream
  guint current_stream_offset = GPOINTER_TO_UINT(g_list_nth_data(embedded_stream_offset, id_number));
  guint current_stream_size = GPOINTER_TO_UINT(g_list_nth_data(embedded_stream_size, id_number));

  if (current_stream_size <= offset)
  {
    // The offset is too far into the stream. Nothing to read
    return 0;
  }

  current_stream_offset += offset;
  current_stream_size -= offset;

  if (current_stream_size > size)
  {
    // Truncating read as the output buffer isn't large enough to handle all of the data
    current_stream_size = size;
  }
  // Copy the data from the stream onto the buffer.
  memcpy(buf, file_stream + current_stream_offset, current_stream_size);
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

  g_free(file_stream);
  g_list_free(embedded_stream_offset);
  g_list_free(embedded_stream_size);
}

/**
 * Looks for the PDF EOF reference in a supplied file
 *
 * \param fp pointer to file that will be read.
 * \returns filesize of the of the pdf should a valid end be found.
 */
gulong pdf_find_EOF(FILE * fp)
{
  gchar *stream;
  gulong buf_size = 4096;
  gchar end_of_file[5];

  // EOF bytes for a pdf file: %%EOF
  end_of_file[0] = 0x25;
  end_of_file[1] = 0x25;
  end_of_file[2] = 0x45;
  end_of_file[3] = 0x4f;
  end_of_file[4] = 0x46;

  gulong approx_length = 0;
  guint end_found = 0;
  guint counter = 0;
  guint num_of_finds = 0;
  gulong current_end = 0;
  gulong last_find_count = 0;

  stream = (gchar *) g_malloc(buf_size);

  // PDF's are stupid and can have multiple EOF flags, so I look for at most two. This can be made greater if need be.
  while (num_of_finds < 2)
  {
    fseek(fp, counter * buf_size, SEEK_SET);

    // Possibly change this to use fgets... reading it line by line as text.
    if (fread(stream, 1, buf_size, fp) < 1)
    {
      debug_log("Unable to read buf_size bytes. Probably reached end of file.");
      break;
    }

    if ((end_found = pdf_find_pattern(stream, buf_size, end_of_file, 4)) != 0)
    {
      current_end = end_found;
      debug_log("EOF reference found!");
      num_of_finds++;
      last_find_count = counter;
    }
    // set a maximum amount of grabs before we give up.
    if ((counter++) > 100000)
    {
      break;
    }
  }

  // Calculate the file length from the number of times we grabbed data and the offset of the EOF tag.
  if (num_of_finds)
  {
    approx_length = (last_find_count) * buf_size + current_end + 6;
  }
  // Free the stream before we leave.
  g_free(stream);
  return approx_length;
}

/**
 * Opens up the supplied file and reads bytes into an array
 *
 * \param[in] fp pointer to file to be read
 * \param[in] approx_length number of bytes to try to read
 * \param[out] actual_length number of bytes actually read
 * \returns the array of bytes read
 */
gchar *pdf_import_binary_data(FILE * fp, gulong approx_length, gulong * actual_length)
{
  gchar *imported_data;

  // Make sure we are at the start of the file.
  fseeko(fp, 0, SEEK_SET);

  // Allocate enough memory to store the data.
  imported_data = (gchar *) g_malloc(approx_length + 1);

  *actual_length = fread(imported_data, 1, approx_length + 1, fp);

  return imported_data;
}

/**
 * Parses PDF data for embedded encoded streams. Attempts to fuse mount and create
 * new contracts for the streams found
 *
 * \param[in] stream the main data stream to be searched
 * \param[in] actual_length the length of the main stream
 */
int pdf_extract_encoded_streams(gchar * stream, gulong actual_length)
{
  gchar *start_ptr = stream;
  gchar *end_ptr = stream;
  guint stream_start_offset = 0;
  guint stream_end_offset = 0;
  guint current_offset = 0;
  guint num_of_streams = 0;
  guint max_num_of_streams = 4096;

  guint found_offset = 0;

  // define the string of bytes that represent the start of binary streams: "stream"
  gchar start_string[6];

  start_string[0] = 0x73;
  start_string[1] = 0x74;
  start_string[2] = 0x72;
  start_string[3] = 0x65;
  start_string[4] = 0x61;
  start_string[5] = 0x6d;

  // define the string of bytes that represent the end of binary streams: "endstream"
  gchar end_string[9];

  end_string[0] = 0x65;
  end_string[1] = 0x6e;
  end_string[2] = 0x64;
  end_string[3] = 0x73;
  end_string[4] = 0x74;
  end_string[5] = 0x72;
  end_string[6] = 0x65;
  end_string[7] = 0x61;
  end_string[8] = 0x6d;

  while (current_offset <= actual_length - 10)
  {
    if ((stream_start_offset = pdf_find_pattern(stream + current_offset, actual_length - current_offset, start_string, 6)) != 0)
    {
      start_ptr += stream_start_offset;

      // we add 1 to the offset to accout for a new line character after the stream keyword.
      current_offset += stream_start_offset + 7;
      found_offset = current_offset;

      // PDF can be formatted in odd ways, so there may be an extra "\n" that we have to consider.
      // If the byte at the found offset is \n, increment it one byte further.
      if (*(stream + found_offset) == '\n')
      {
        found_offset++;
      }

    } else
    {
      // didn't find a start tag, so we might as well break out of the loop.
      break;
    }

    if ((stream_end_offset = pdf_find_pattern(stream + current_offset, actual_length, end_string, 9)) != 0)
    {
      end_ptr += stream_end_offset;
      current_offset += stream_end_offset + 10;

      embedded_stream_offset = g_list_append(embedded_stream_offset, GUINT_TO_POINTER(found_offset));
      embedded_stream_size = g_list_append(embedded_stream_size, GUINT_TO_POINTER(stream_end_offset));

      // Break if we reach our max amount.
      if ((num_of_streams++) == max_num_of_streams)
      {
        break;
      }
    } else
    {
      debug_log("Unable to find end of stream. Something went wrong.");
      break;
    }
  }

  debug_log("Number of embedded streams found: %u", num_of_streams);

  return 0;
}

/**
 * Searches a given stream of bytes for a pattern of characters
 *
 * \param stream the data stream to be searched
 * \param actual_length the length of the data stream being searched
 * \param pattern the pattern being searched for in the stream
 * \param pattern_size the length of the pattern being searched
 * \returns the offset in the stream where the pattern was found
 */
gulong pdf_find_pattern(gchar * stream, gulong actual_length, gchar pattern[], gulong pattern_size)
{
  gulong i = 0;
  gulong j = 0;
  gulong offset_flag = 0;
  gulong matches = 0;

  for (i = 0; i < actual_length - pattern_size; i++)
  {
    matches = 0;
    for (j = 0; j <= (pattern_size - 1); j++)
    {
      if (i + j >= actual_length)
      {
        return offset_flag;
      }

      if (*(stream + i + j) != pattern[j])
      {
        break;
      }
      matches++;

    }

    if (matches >= pattern_size - 1)
    {
      offset_flag = i;
      break;
    }
  }

  // Return the offset into the stream where we found the pattern.
  return offset_flag;
}

/**
 * Parses each page of a pdf document, determining if the page contains images
 * This function can be expanded in the future to look for other pdf related info
 *
 * \param pdf the pdf file to scan
 * \param num_of_pages the number of pages the document contains
 * \returns the total number of images found in the document (this should be altered later)
 */
guint pdf_scan_pages(PopplerDocument * pdf, gint num_of_pages)
{

  gint i = 0;
  PopplerPage *page = NULL;
  gint total_images = 0;

  for (i = 0; i < num_of_pages; i++)
  {
    // Grab a page
    page = poppler_document_get_page(pdf, i);

    //Let's find any embedded images.
    total_images += pdf_get_image_info(page);

    if (page != NULL)
    {
      g_object_unref(page);
      page = NULL;
    }
  }

  // if we think there are some embedded images in there, append this to the description.
  if (total_images)
  {
    gchar* new_description = g_strdup_printf("%s, possibly %d image(s)", description, total_images);
    g_free(description);

    description = new_description;
  }

  return 0;
}

/**
 * Obtains the number of images on a page within a pdf
 * This may be expanded later to actually extract the images
 *
 * \param page the page to search for images
 * \returns the number of images found
 */
guint pdf_get_image_info(PopplerPage * page)
{
  GList *image_mapping;
  guint num_of_images;

  image_mapping = poppler_page_get_image_mapping(page);
  num_of_images = g_list_length(image_mapping);

  // Free the mapping when we're done.            
  poppler_page_free_image_mapping(image_mapping);
  return num_of_images;
}

/**
 * Invokes add_file on all the embedded data streams found in a pdf
 * so that they can be fuse mounted
 *
 * \returns the number of streams added for mounting
 */
gulong pdf_add_files_for_mounting(void)
{
  gchar *stream_name = NULL;
  gulong num_streams_added = 0;
  guint i = 0;
  gulong *current_size;

  for (i = 0; i < g_list_length(embedded_stream_size); i++)
  {

    stream_name = g_strdup_printf("stream_%d", i);
    current_size = (gulong *) g_list_nth_data(embedded_stream_size, i);
    add_file(i, stream_name, (size_t) current_size);
    g_free(stream_name);

  }

  return num_streams_added;
}

/**
 * Creates new contracts for each of the embedded data streams previously identified
 *
 * \param mnt_path the path where the streams are to be mounted
 * \param result the result item to which we will add the contracts
 * \returns the number of new contracts created
 */
int pdf_create_new_contracts(gchar * mnt_path, result_t result)
{
  guint i = 0;
  gchar *sub_path = NULL;
  int num_of_new_contracts = 0;

  for (i = 0; i < g_list_length(embedded_stream_size); i++)
  {
    sub_path = g_strdup_printf("%s/%d", mnt_path, i);

    contract_t new_contract = contract_init(NULL, 0);

    contract_set_path(new_contract, sub_path);
    
    g_free(sub_path);

    contract_set_absolute_offset(new_contract, -1);
    contract_set_contiguous(new_contract, 0);
    result_add_new_contract(result, new_contract);
    contract_close(new_contract);
    num_of_new_contracts++;
  }


  return num_of_new_contracts;
}
