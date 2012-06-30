/* Pronghorn texthelper header
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

#include "text_helper.h"

int length_of_text(char *buff, int buff_len)
{
  int i;

  for (i = 0; i < buff_len; i++)
  {
    if (!(g_ascii_isprint(buff[i]) || g_ascii_ispunct(buff[i]) || g_ascii_isspace(buff[i])))
    {
      break;
    }
  }
  return i;
}

//smart read will load an ascii text file that of a unknown length up the max_size
//smart read will only ever read the bits from disk once but may copy them around in memory
//this is a tradeoff to try and keep the memory allocation close to the (unkown) file size
//returns the number of bytes loaded into memory
//modifies pointer dst to point at those bytes
int smart_read_text(char **dst, FILE * file, int block_size, int max_size)
{
  //start by allocating the smallest ammount of memory that could store the file
  char *buff = (char *) g_malloc(block_size + 1);
  int bytes_read = 0;
  int total_ascii_bytes = 0;
  int bytes_to_read = block_size;

  while ((bytes_read = fread(buff + total_ascii_bytes, 1, bytes_to_read, file)) > 0)
  {
    int ascii_bytes = length_of_text(buff + total_ascii_bytes, bytes_read);

    total_ascii_bytes += ascii_bytes;

    //if reached end of ascii or hit max size
    if (bytes_read > ascii_bytes)
    {
      break;
    }

    if (total_ascii_bytes >= max_size)
    {
      total_ascii_bytes = max_size;
      break;
    }
    //allocate a new buffer twice the size of the current data
    //copy the data into the new buffer and free the old one
    buff = (char *) g_realloc(buff, (total_ascii_bytes * 2) + 1);
    bytes_to_read = total_ascii_bytes;
  }

  //null terminate string
  buff[total_ascii_bytes] = '\0';
  *dst = buff;

  return total_ascii_bytes;
}

int regex_match_count(char *buff, int buff_size, const gchar * regex_string, GRegexCompileFlags compile_flags)
{
  int matches = 0;

  //create regex
  GError *regex_error = NULL;
  GMatchInfo *match_info = NULL;
  GRegex *regex = g_regex_new(regex_string, compile_flags, (GRegexMatchFlags) 0, &regex_error);

  if (regex_error != NULL)
  {
    debug_log("regex error code was: %s", regex_error->message);
    g_error_free(regex_error);
  } else
  {
    g_regex_match_full(regex, buff, buff_size, 0, (GRegexMatchFlags) 0, &match_info, &regex_error);
    if (regex_error != NULL)
    {
      debug_log("regex error code was: %s", regex_error->message);
      g_error_free(regex_error);
    }
    while (g_match_info_matches(match_info))
    {
      gchar *word = g_match_info_fetch(match_info, 0);

      //debug_log("Regex matched: : %s", word);
      g_free(word);
      g_match_info_next(match_info, NULL);
      matches++;
    }
    //free match info
    g_match_info_free(match_info);
  }

  //free regex
  g_regex_unref(regex);

  return matches;
}

int *regexen_match_counts(char *buff, int buff_size, const gchar ** regex_strings, int regex_count, GRegexCompileFlags compile_flags)
{
  int *match_counts = (int *) g_malloc(regex_count * sizeof(int));

  memset(match_counts, 0, regex_count * sizeof(int));

  for (int i = 0; i < regex_count; i++)
  {
    match_counts[i] = regex_match_count(buff, buff_size, regex_strings[i], compile_flags);
  }

  return match_counts;
}

int regexen_matched_count(char *buff, int buff_size, const gchar ** regex_strings, int regex_count, GRegexCompileFlags compile_flags)
{
  int *match_counts = regexen_match_counts(buff, buff_size, regex_strings, regex_count, compile_flags);
  int regexen_matched = 0;

  for (int i = 0; i < regex_count; i++)
  {
    if (match_counts[i] > 0)
    {
      regexen_matched++;
    }
  }
  g_free(match_counts);

  return regexen_matched;
}
