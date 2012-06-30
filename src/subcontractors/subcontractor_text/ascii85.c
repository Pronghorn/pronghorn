/*
 * ascii85 - Ascii85 encode/decode data and print to standard output
 *
 * Copyright (C) 2012 Remy Oukaour
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <glib.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

guint getc_nospace(const char *buff)
{
  guint pos = 0;

  while (isspace(buff[pos]) && buff[pos] != '\0')
  {
    pos++;
  }
  return pos;
}

void decode_tuple(uint32_t tuple, int count, GString * result)
{
  int i;

  for (i = 1; i < count; i++)
  {
    g_string_append_c(result, tuple >> ((4 - i) * 8));
  }
}

gchar *ascii85_decode(const char *buff, gsize * out_length)
{
  GString *result = g_string_new(NULL);

  int count = 0;
  guint cur_pos = 0;
  uint32_t tuple = 0, pows[] = { 85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1 };

  if (buff[cur_pos] == '<' && buff[cur_pos + 1] == '~')
  {
    cur_pos += 2;
  }

  for (;;)
  {
    cur_pos += getc_nospace(&buff[cur_pos]);
    if (buff[cur_pos] == 'z' && count == 0)
    {
      decode_tuple(0, 5, result);
      cur_pos++;
      continue;
    }
    if (buff[cur_pos] == 'y' && count == 0)
    {
      decode_tuple(0x20202020, 5, result);
      cur_pos++;
      continue;
    }
    if (buff[cur_pos] == '\0' || (buff[cur_pos] == '~' && buff[cur_pos + 1] == '>'))
    {
      if (count > 0)
      {
        tuple += pows[count - 1];
        decode_tuple(tuple, count, result);
      }
      break;
    }
    if (buff[cur_pos] < '!' || buff[cur_pos] > 'u')
    {
      cur_pos++;
      continue;
    }
    tuple += (buff[cur_pos] - '!') * pows[count++];
    if (count == 5)
    {
      decode_tuple(tuple, count, result);
      tuple = 0;
      count = 0;
    }
    cur_pos++;

  }

  *out_length = result->len;
  return g_string_free(result, FALSE);
}
