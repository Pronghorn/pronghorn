/* libpronghorn Example loopback mount
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
 * \file example_fuse.c
 * \brief This is an example implementation of a fuse filesystem using the Pronghorn design
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/time.h>
#include <sys/types.h>
#include <glib.h>

#include <basename_safe.h>

#include <base_fuse.h>

/** This is the argc array passed to fuse_main */
static int fuse_argc = 0;

/** This is the argv array passed to fuse_main */
static char **fuse_argv = NULL;

/** This is the name of the current process */
const char *SHORT_PROCESS_NAME = NULL;

/** This is the name of the current process */
const char *PROCESS_NAME = NULL;

/**
 * Populates the buffer with the contents of the specified filename.
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
  int pos = 0;

  while (size >= strlen(filename))
  {
    memcpy(buf + pos, filename, strlen(filename));
    pos += strlen(filename);
    size -= strlen(filename);
  }
  memcpy(buf + pos, filename, size);
  pos += size;
  return pos;
}

/**
 * Called when the filesystem is unmounted, and allows the destruction
 * of structures and freeing allocated memory.
 */
void cleanup(void)
{
  int i;

  for (i = 0; i < fuse_argc; i++)
  {
    g_free(fuse_argv[i]);
    fuse_argv[i] = NULL;
  }
  fuse_argc = 0;

  if (fuse_argv != NULL)
  {
    g_free(fuse_argv);
    fuse_argv = NULL;
  }
}

/**
 * Prints the usage statement to screen.
 *
 * \param prog This programs name.
 */
static void print_usage(const char *prog)
{
  printf("\nUsage: %s <mount point>\n", prog);
  printf("\nAn example filesystem\n");
}

/**
 * Starts sleuthmount.
 *
 * \param argc The number of arguments
 * \param argv The argument array
 * \returns 0 on success, -1 on error
 */
int main(int argc, char *argv[])
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];

  if (argc != 2)
  {
    print_usage(argv[0]);
    return -1;
  }
  // Adding some sample files into our filesystem
  add_file(10, "ten", 10);
  add_file(100, "hundred", 100);
  add_file(1000, "something_else", 60);

  int ret = do_mount(argv[argc - 1]);

  // There may not be a purpose to doing this
  cleanup();

  return ret;
}
