/* libpronghorn JBig Subcontractor
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
 * \file subcontractor_jbig.c
 *
 * \brief Subcontractor for processing JBIG image files using Pronghorn
 *
 * Confidence Levels:
 * 100 - libjbig can open the file and process the image
 * 0 - libjbig was unable to detect an EOF or header
 */
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <lightmagic.h>
//#include <base_fuse.h>

#include "subcontractor_helper.h"

#ifdef __cplusplus
extern "C"
{
#endif

#include <jbig.h>

#ifdef __cplusplus
}
#endif

/* Define constants */
#define BYTE 1
#define JHEAD_SIZE 20

unsigned int supported_file_types[] = { MAGIC_TYPE_JBIG, 0 };

/**
 * Initialises environment
 *
 * \returns 0 on success
 */
int subcontractor_init(void)
{
  debug_log("Hello world!");

  return 0;
}

/**
 * Analyse contract and respond
 *
 * Attempts to parse the supplied file as JBIG
 *
 * \param to_analyse The contract to analyse
 * \param ccr The contract completion report to populate
 * \returns 0 on sucess, -1 on error
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  struct jbg_dec_state sd;
  unsigned char data[JHEAD_SIZE];
  int status;
  size_t cnt;

  const char *path = contract_get_path(to_analyse);

  jbg_dec_init(&sd);
  FILE *file = fopen(path, "r");

  if (file == NULL)
  {
    warning_log("analyse_contract: Could not open file");
    return 0;
  }

  /* Read header and check for valid JBIG */
  int size = 0;

  size = fread(&data, BYTE, JHEAD_SIZE, file);
  status = jbg_dec_in(&sd, data, JHEAD_SIZE, &cnt);

  if (status >= JBG_EINVAL && status <= (JBG_EINVAL | 14))
  {
    debug_log("Not a valid JBIG file");
    jbg_dec_free(&sd);
    return 0;
  }

  /* Read in the whole JBIG */
  int bytes_read;

  while ((bytes_read = fread(&data, BYTE, BYTE, file)))
  {
    size += bytes_read;
    status = jbg_dec_in(&sd, data, BYTE, &cnt);

    if (status == JBG_EOK)
    {                           /* Found end of file */
      break;
    } else if (status != JBG_EAGAIN)
    {                           /* Error value returned */
      debug_log("Error reading JBIG: %s", jbg_strerror(status));
      jbg_dec_free(&sd);
      return 0;
    } else if (size == 104857600)
    {                           /* Only read upto 100MB */
      debug_log("Read 100MB, couldnt find end of JBIG");
      jbg_dec_free(&sd);
      return 0;
    }
  }
  fclose(file);

  /* Process loaded JBIG */
  gchar *hxw = g_strdup_printf("%ldx%ld", jbg_dec_getwidth(&sd), jbg_dec_getheight(&sd));
  gchar *planes = g_strdup_printf("%d plane(s)", jbg_dec_getplanes(&sd));
  gchar *bytes = g_strdup_printf("%dB", size);

  gchar *data_str = g_strdup_printf("%s, %s, %s", bytes, hxw, planes);

  g_free(hxw);
  g_free(planes);
  g_free(bytes);

  /* Fill in report and result data, identifying blocks if possible */
  long long int offset = contract_get_absolute_offset(to_analyse);
  int contig = contract_is_contiguous(to_analyse);

  result_t result = result_init(NULL, 0);

  populate_result_with_length(result, "JBIG", data_str, 100, offset, size, contig);
  contract_completion_report_add_result(ccr, result);
  result_close(result);

  g_free(data_str);

  return 0;
}

/**
 * Invoked when the subcontractor is closing
 */
int subcontractor_close(void)
{
  debug_log("Bye");
  return 0;
}
