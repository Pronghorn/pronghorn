/* Libpronghorn Config Server Test
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
#include <libgen.h>

#include <glib.h>

#include <basename_safe.h>
#include <config.h>

/** This is the name of the current process */
const char *SHORT_PROCESS_NAME = NULL;

/** This is the name of the current process */
const char *PROCESS_NAME = NULL;

int main(int argc, char *argv[])
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];

  if (argc != 2)
  {
    printf("Usage: %s <endpoint>\n", argv[0]);
    return -1;
  }

  if (config_init(argv[1]) != 0)
  {
    perror("Creating config");
    return -1;
  }

  unsigned int size;
  const char *everything = config_get_all_values(&size);

  printf("%s\n", everything);

  int ret = config_set("Foo", "Bar", "Win");

  printf("Set = %d\n", ret);

  char *val;

  if (config_get("foo", "bar", &val) != 0)
  {
    printf("Failed to get value\n");
  } else
  {
    printf("Val = %s\n", val);
    g_free(val);
  }

  if (config_get("Somethings", "Missing", &val) != 0)
  {
    printf("Failed to get value\n");
  } else
  {
    if (val == NULL)
    {
      printf("It's not set\n");
    } else
    {
      printf("Value is %s\n", val);
    }
  }

  config_close();

  return 0;
}
