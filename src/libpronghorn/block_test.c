/* Pronghorn Block Tester
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
#include <stdlib.h>
#include <string.h>

#include <blocks.h>

#define BLOCK_SIZE 512

static char *split(char *string, char c)
{
  char *ptr = strchr(string, c);

  if (ptr == NULL)
  {
    return NULL;
  }

  *ptr = '\0';

  ptr++;
  return ptr;
}

int main(int argc, char *argv[])
{
  printf("Block size = %d\n", BLOCK_SIZE);
  printf("Specify bytes/blocks to add. Syntax is\n");
  printf("<byte>\n");
  printf("<start byte>-<stop byte>\n");
  printf("<block>*<block_size>\n");
  printf("<start block>-<end block>*<block_size>\n\n");
  printf("CTRL-D to finish\n");

  block_start(BLOCK_SIZE);

  char input_string[80];

  while (fgets(input_string, 79, stdin) != NULL)
  {
    split(input_string, '\n');

    char *ptr = split(input_string, '*');

    if (ptr != NULL)
    {
      // Block input
      int block = atoi(ptr);

      if (block <= 0)
      {
        printf("Invalid input. Block is <= 0\n");
        continue;
      }

      ptr = split(input_string, '-');
      if (ptr != NULL)
      {
        // It's a range
        int a = atoi(input_string);
        int b = atoi(ptr);

        if (b <= a)
        {
          printf("Invalid input. b <= a\n");
        }

        if (a < 0)
        {
          printf("Invalid input. a < 0\n");
        }

        printf("Adding block range %d - %d (block size = %d)\n", a, b, block);
        block_add_block_range(a, b, block);
      } else
      {
        // It's one block
        int a = atoi(input_string);

        if (a < 0)
        {
          printf("Invalid input. a < 0\n");
        }

        printf("Adding block %d (block size = %d)\n", a, block);
        block_add_block(a, block);
      }
    } else
    {
      // Byte input
      ptr = split(input_string, '-');
      if (ptr != NULL)
      {
        // It's a range
        int a = atoi(input_string);
        int b = atoi(ptr);

        if (b <= a)
        {
          printf("Invalid input. b <= a\n");
        }

        if (a < 0)
        {
          printf("Invalid input. a < 0\n");
        }

        printf("Adding byte range %d - %d\n", a, b);
        block_add_byte_range(a, b);
      } else
      {
        // It's one byte
        int a = atoi(input_string);

        if (a < 0)
        {
          printf("Invalid input. a < 0\n");
        }

        printf("Adding byte %d\n", a);
        block_add_byte(a);
      }
    }
  }

  int size;
  unsigned long long *data = block_end(&size);

  printf("Size is %d, data is %p\n", size, data);

  int i;

  for (i = 0; i < size; i++)
  {
    printf("%d: %llu\n", i, data[i]);
  }

  g_free(data);

  printf("Done\n");
  return 0;
}
