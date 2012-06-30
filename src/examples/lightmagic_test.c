/* Pronghorn Lightmagic Test 
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

#include <lightmagic.h>

#define BLOCK_SIZE 512
#define BUFFER_SIZE_IN_BLOCKS 100
#define MAGIC_BLOCK_SIZE 2048

void process(unsigned char *buf, unsigned int size)
{
  GArray *array = lightmagic_detect(buf, size, size);

  int i;

  for (i = 0; i < array->len; i++)
  {
    printf("%s ", lightmagic_human_friendly_descriptive_name(g_array_index(array, int, i)));
  }
  printf("\n");

  g_array_free(array, TRUE);
}

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    printf("Usage: %s <file>\n", argv[0]);
    printf("Light magic over blocks\n");
    return -1;
  }

  unsigned char buf[BUFFER_SIZE_IN_BLOCKS * BLOCK_SIZE];

  FILE *infile = fopen(argv[1], "rb");

  if (infile == NULL)
  {
    perror(argv[1]);
    return -1;
  }

  int size = 0;
  int offset = 0;

  while ((size = fread(buf + offset, BLOCK_SIZE, BUFFER_SIZE_IN_BLOCKS - (offset / BLOCK_SIZE), infile)) > 0)
  {
    unsigned int i;

    size = (size * BLOCK_SIZE) + offset;
    if (size < MAGIC_BLOCK_SIZE)
    {
      offset = size;
      break;
    }

    for (i = 0; i < (size + 1) - MAGIC_BLOCK_SIZE; i += BLOCK_SIZE)
    {
      process(buf + i, MAGIC_BLOCK_SIZE);
    }

    offset = size - i;
    memcpy(buf, buf + i, offset);
  }

  unsigned int i;

  for (i = 0; i < offset; i += BLOCK_SIZE)
  {
    process(buf + i, offset - i);
  }

  fclose(infile);

  return 0;
}
