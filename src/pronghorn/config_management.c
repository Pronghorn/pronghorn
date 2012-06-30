/* libpronghorn configuration server
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

/**
 * \file config_management.c
 * \brief This server provides a centralised configuration storage and
 * retrieval mechanism for every Pronghorn process
 *
 * It also launches the logger and the MCP. This is the program that starts Pronghorn
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>

#include <config.h>
#include <logger.h>

#include "config_management.h"

/**
 * Merges two key files into one key file
 *
 * \param dest_config The config file to store the merged values
 * \param src_config The config file to merge into dest_config
 * \returns A GError object, or NULL if the merge succeeded
 */
static GError *merge_config(GKeyFile * dest_config, GKeyFile * src_config)
{
  GError *error = NULL;

  gsize groups_count = 0;
  gchar **groups = g_key_file_get_groups(src_config, &groups_count);
  int i;

  for (i = 0; i < groups_count; i++)
  {
    gsize keys_count = 0;
    gchar **keys = g_key_file_get_keys(src_config, groups[i], &keys_count, &error);

    if (error != NULL)
    {
      g_strfreev(groups);
      return error;
    }

    int j;

    for (j = 0; j < keys_count; j++)
    {
      gchar *value = g_key_file_get_value(src_config, groups[i], keys[j], &error);

      if (error != NULL)
      {
        g_strfreev(keys);
        g_strfreev(groups);
        return error;
      }

      char *old_param = g_key_file_get_param(dest_config, groups[i], keys[j]);

      if (old_param != NULL)
      {
        warning_log("Replacing value in %s.%s. Old value=%s, New value=%s", groups[i], keys[j], old_param, value);
        g_free(old_param);
      }

      g_key_file_set_param(dest_config, groups[i], keys[j], value);

      g_free(value);
    }

    g_strfreev(keys);
  }

  g_strfreev(groups);

  return error;
}

/**
 * Merges a key file and a serialised key files into one key file
 *
 * \param config The config file to store the merged values
 * \param config_file The serialised config file on the file system to merge into config.
 * \returns A GError object, or NULL if the merge succeeded
 */
static GError *merge_config_file(GKeyFile * config, char *config_file)
{
  GKeyFile *temp_config = g_key_file_new();
  GError *error = NULL;

  g_key_file_load_from_file(temp_config, config_file, G_KEY_FILE_NONE, &error);
  if (error != NULL)
  {
    g_key_file_free(temp_config);
    return error;
  }

  error = merge_config(config, temp_config);
  g_key_file_free(temp_config);

  return error;
}

/**
 * Reads the config file from the command line and merges it into the config key file.
 *
 * In the event of an error the error value is printed to screen.
 *
 * \param config The key file to merge into
 * \param file The file to read and merge into the config.
 * \returns 0 on success, -1 on error
 */
static int process_file(GKeyFile * config, char *file)
{
  debug_log("Pronghorn now processing file: %s", file);

  GError *error = merge_config_file(config, file);

  if (error != NULL)
  {
    error_log("Pronghorn has an error parsing config: %s", error->message);
    g_error_free(error);
    return -1;
  }

  return 0;
}

/**
 * Opens the directory and processes any config files held in it.
 *
 * Config files are any files ending in .conf
 *
 * \param config The GKeyFile to populate
 * \param directory The directory to examine
 * \return 0 on success, -1 on error
 */
static int process_dir(GKeyFile * config, char *directory)
{
  DIR *dir = opendir(directory);

  if (dir == NULL)
  {
    return -1;
  }
  // Errno is unchanged on successful end, see the manpage
  errno = 0;
  struct dirent *entry = NULL;
  GSList *entries = NULL;

  while ((entry = readdir(dir)) != NULL)
  {
    if (g_str_has_suffix(entry->d_name, ".conf") == TRUE)
    {
      char *path = g_strdup_printf("%s/%s", directory, entry->d_name);

      entries = g_slist_insert_sorted(entries, path, (GCompareFunc) strcasecmp);
    }
  }

  int ret = (errno == 0) ? 0 : -1;

  GSList *iter = entries;

  while (iter != NULL)
  {
    process_file(config, (char *) iter->data);
    iter = iter->next;
  }

  g_slist_free_full(entries, g_free);

  closedir(dir);

  return ret;
}

/**
 * Prints the usage to screen.
 *
 * \param prog The name of the current process
 */
static void print_usage(char *prog)
{
  printf("Usage: %s <opts>\n", prog);
  printf("All opts are optional\n\n");
  printf("Options are:\n");
  printf("-o <group.key=value>\n");
}

int parse_group_key(const char *string, char **group, char **key)
{
  *group = NULL;
  *key = NULL;

  const char *key_ptr = strchr(string, '.');

  if ((key_ptr == NULL) || (string == key_ptr))
  {
    // The period must exist, and must not be the first character
    return -1;
  }

  key_ptr++;

  if (strchr(key_ptr, '.') != NULL)
  {
    // There can only be one period
    return -1;
  }

  *group = g_strstrip(g_strndup(string, (key_ptr - string) - 1));
  *key = g_strstrip(g_strdup(key_ptr));

  return 0;
}

int parse_group_key_value(const char *string, char **group, char **key, char **value)
{
  *group = NULL;
  *key = NULL;
  *value = NULL;

  const char *key_ptr = strchr(string, '.');

  if ((key_ptr == NULL) || (string == key_ptr))
  {
    // The period must exist, and must not be the first character
    return -1;
  }

  key_ptr++;

  const char *value_ptr = strchr(string, '=');

  if ((value_ptr == NULL) || (value_ptr <= key_ptr))
  {
    // The equals must exist, and not occur before the period.
    return -1;
  }

  value_ptr++;
  // Disabled. We are now allowing equals in arg
//      if (strchr(value_ptr, '=') != NULL)
//      {
//              // There can only be one equals
//              return -1;
//      }

  if (*value_ptr == '\0')
  {
    // There must be a value
    return -1;
  }

  *group = g_strstrip(g_strndup(string, (key_ptr - string) - 1));
  *key = g_strstrip(g_strndup(key_ptr, (value_ptr - key_ptr) - 1));
  *value = g_strstrip(g_strdup(value_ptr));

  // Final test. There cannot be a period in the key name
  if (strchr(*key, '.') != NULL)
  {
    // Doh
    g_free(*group);
    g_free(*key);
    g_free(*value);
    *group = NULL;
    *key = NULL;
    *value = NULL;
    return -1;
  }
  return 0;
}

/**
 * Parses all command line arguments.
 *
 * \param argc The number of args
 * \param argv The arg array
 * \returns A populated key file or NULL on error
 */
static GKeyFile *parse_args(int argc, char *argv[])
{
  GKeyFile *config = g_key_file_new();
  int opt;
  char *group;
  char *key;
  char *value;

  while ((opt = getopt(argc, argv, "o:")) != -1)
  {
    switch (opt)
    {
    case 'o':
      if (parse_group_key_value(optarg, &group, &key, &value) != 0)
      {
        error_log("Pronghorn - Invalid -o option: %s\n", optarg);
        print_usage(argv[0]);
        g_key_file_free(config);
        return NULL;
      }

      g_key_file_set_param(config, group, key, value);

      g_free(group);
      g_free(key);
      g_free(value);

      break;
    default:
      print_usage(argv[0]);
      g_key_file_free(config);
      return NULL;
    }
  }

  if (optind != argc)
  {
    error_log("Pronghorn - Unknown arguments on command line: %s\n", argv[optind]);
    print_usage(argv[0]);
    g_key_file_free(config);
    return NULL;
  }

  return config;
}

GKeyFile *generate_config(int argc, char *argv[])
{
  GKeyFile *config_override = parse_args(argc, argv);

  if (config_override == NULL)
  {
    return NULL;
  }

  gchar *config_path = g_key_file_get_param(config_override, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_CONFIG_DIRECTORY_OPTION_NAME);

  if (config_path == NULL)
  {
    config_path = g_strdup(CONFIG_CONFIG_DIRECTORY_DEFAULT);
  }

  GKeyFile *config = g_key_file_new();

  if (process_dir(config, config_path) == -1)
  {
    warning_log("Pronghorn - Unable to parse config dir (%s)", strerror(errno));
  }
  g_free(config_path);

  debug_log("Pronghorn now processing command line options");
  // Merging the override
  merge_config(config, config_override);
  g_key_file_free(config_override);

  return config;
}
