/* Libpronghorn Config Example
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

// An example (and test) of how to use the glib GKeyFile stuff
//
// Note that no matter what I do, valgrind has issues
// Using G_SLICE=always-malloc and G_DEBUG=gc-friendly
// makes things better, but doesn't eliminate things.
//
// However putting the 'leaky' code into a massive loop
// does not make things more 'leaky', hence I blame the
// glib memory pool rather than any true leaks.
//

#include <stdio.h>
#include <glib.h>

void dump_config(GKeyFile * config)
{
  GError *error = NULL;
  gsize groups_count = 0;
  gchar **groups = g_key_file_get_groups(config, &groups_count);
  int i;

  for (i = 0; i < groups_count; i++)
  {
    printf("[%s]\n", groups[i]);

    gsize keys_count = 0;
    gchar **keys = g_key_file_get_keys(config, groups[i], &keys_count, &error);

    if (error != NULL)
    {
      printf("Listing keys for group '%s' failed: %s\n", groups[i], error->message);
      g_error_free(error);
      error = NULL;
      continue;
    }

    int j;

    for (j = 0; j < keys_count; j++)
    {
      gchar *value = g_key_file_get_value(config, groups[i], keys[j], &error);

      if (error != NULL)
      {
        printf("Getting value for key '%s' in group '%s' failed: %s\n", keys[j], groups[i], error->message);
        g_error_free(error);
        error = NULL;
        continue;
      }

      printf("%s = %s\n", keys[j], value);
      g_free(value);
    }

    g_strfreev(keys);
  }

  g_strfreev(groups);
}

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    printf("Usage: %s <ini file>\n", argv[0]);
    return -1;
  }

  GKeyFile *config = g_key_file_new();
  GError *error = NULL;

  g_key_file_load_from_file(config, argv[1], G_KEY_FILE_NONE, &error);
  if (error != NULL)
  {
    printf("Parsing config file '%s' failed: %s\n", argv[1], error->message);
    g_error_free(error);
    error = NULL;
    g_key_file_free(config);
    return -1;
  }

  dump_config(config);

  g_key_file_free(config);

  return 0;
}
