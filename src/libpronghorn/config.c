/* Libpronghorn config structure
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
 * \file config.c
 * \brief Libpronghorn config structure
 *
 * This defines the config structure.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include <glib.h>

#include <transport.h>
#include <config.h>
#include <logger.h>
#include <prong_assert.h>

/** This is the endpoint for the config server */
static transport_t configserver_endpoint = NULL;

/** This is the current process's pid */
static char *process_pid = NULL;

/** The timeout value */
static int timeout = 0;
static GKeyFile *cache = NULL;

int config_init(const char *endpoint)
{
  prong_assert(SHORT_PROCESS_NAME != NULL);

  if (endpoint == NULL)
  {
    error_log("Can't init config with a NULL endpoint");
    return -1;
  }

  if (configserver_endpoint != NULL)
  {
    error_log("Trying to init the config object twice!");
    return -1;
  }

  configserver_endpoint = transport_init(TRANSPORT_TYPE_PUSHPULL, endpoint);

  if (configserver_endpoint == NULL)
  {
    return -1;
  }

  process_pid = g_strdup_printf("%d", getpid());

  if (config_get_int_with_default_macro(NULL, CONFIG_CONFIG_TIMEOUT, &timeout) != 0)
  {
    // Comms error
    error_log("Could not get config timeout value. Is the config server not working?");
    config_close();
    return -1;
  }

  return 0;
}

int config_set(const char *group, const char *key, const char *value)
{
  if (configserver_endpoint == NULL)
  {
    return -1;
  }

  prong_assert(group != NULL);
  prong_assert(key != NULL);
  prong_assert(value != NULL);

  char *send_string = g_strdup_printf("%s.%s=%s", group, key, value);

  int recvsize;

  const char *recv = transport_sendrecv(configserver_endpoint, send_string, strlen(send_string) + 1, NULL, &recvsize);

  g_free(send_string);

  if (recv == NULL)
  {
    return -1;  
  }

  if (strcmp(recv, SUCCESS_RESPONSE) != 0)
  {
    return -1;
  }

  return 0;
}

gchar *g_key_file_get_param(GKeyFile * key_file, const gchar * group_name, const gchar * key_name)
{
  char *group = g_ascii_strdown(group_name, -1);
  char *key = g_ascii_strdown(key_name, -1);

  gchar *string = g_key_file_get_string(key_file, group, key, NULL);

  g_free(key);
  g_free(group);

  if (string == NULL)
  {
    return NULL;
  }

  return string;
}

void g_key_file_set_param(GKeyFile * key_file, const gchar * group_name, const gchar * key_name, const char *string)
{
  char *group = g_ascii_strdown(group_name, -1);
  char *key = g_ascii_strdown(key_name, -1);

  if (config_is_null_response(string))
  {
    GError *error = NULL;

    g_key_file_remove_key(key_file, group, key, &error);
    if (error != NULL)
    {
      error_log("An error happened in pronghorn:g_key_file_set_param: %s", error->message);
      g_error_free(error);
      prong_assert(0);
    }
  } else
  {
    g_key_file_set_string(key_file, group, key, string);
  }

  g_free(key);
  g_free(group);
}

static char *expand_variables_depth(GKeyFile * config, char *string, int depth)
{
  if (string == NULL)
  {
    return NULL;
  }

  if (depth >= 10)
  {
    // We're 10 levels deep! Something must be wrong. Bailing
    error_log("expand_variables indicates a depth of %d. Something is wrong or someone is trying to break us", depth);
    return string;
  }

  char *start_ptr = strstr(string, "${");

  if (start_ptr == NULL)
  {
    return string;
  }

  char *output_string = g_strndup(string, start_ptr - string);

  while (start_ptr != NULL)
  {
    char *end_ptr = strchr(start_ptr, '}');

    if (end_ptr == NULL)
    {
      char *temp = g_strdup_printf("%s%s", output_string, start_ptr);

      g_free(output_string);
      output_string = temp;

      start_ptr = NULL;
      continue;
    }

    start_ptr += 2;
    char *variable = g_strndup(start_ptr, (end_ptr - start_ptr));
    char *expanded_variable = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, variable);

    g_free(variable);
    if (expanded_variable != NULL)
    {
      char *temp = g_strdup_printf("%s%s", output_string, expanded_variable);

      g_free(expanded_variable);
      g_free(output_string);
      output_string = temp;
    }

    end_ptr++;
    start_ptr = strstr(end_ptr, "${");
    if (start_ptr != NULL)
    {
      char *temp = g_strndup(end_ptr, start_ptr - end_ptr);
      char *temp2 = g_strdup_printf("%s%s", output_string, temp);

      g_free(output_string);
      g_free(temp);
      output_string = temp2;
    } else
    {
      char *temp = g_strdup_printf("%s%s", output_string, end_ptr);

      g_free(output_string);
      output_string = temp;
    }
  }

  g_free(string);
  return expand_variables_depth(config, output_string, depth + 1);
}

char *expand_variables(GKeyFile * config, char *string)
{
  return expand_variables_depth(config, string, 0);
}

static int config_get_direct(const char *group, const char *key, char **value)
{
  char *send_string = g_strdup_printf("%s.%s", group, key);
  int recvsize;
  const char *recv = transport_sendrecv(configserver_endpoint, send_string, strlen(send_string) + 1, NULL, &recvsize);

  g_free(send_string);

  if (recv == NULL)
  {
    // Timeout? Interrupt?
    debug_log("recv was NULL in config_get");
    return -1;
  }

  if (config_is_err_response(recv) != 0)
  {
    warning_log("Config received an errored response from the config server");
    return -1;
  }

  if (config_is_null_response(recv) == 0)
  {
    *value = g_strdup(recv);
  }

  return 0;
}

int config_get(const char *group, const char *key, char **value)
{
  *value = NULL;

  if (configserver_endpoint == NULL)
  {
    return -1;
  }

  prong_assert(key != NULL);

  if (group == NULL)
  {
    if ((config_get(SHORT_PROCESS_NAME, key, value) == 0) && (*value != NULL))
    {
      return 0;
    }
    if ((config_get(process_pid, key, value) == 0) && (*value != NULL))
    {
      return 0;
    }

    return config_get("general", key, value);
  }

  if (strchr(group, '.') != NULL)
  {
    error_log("Group cannot have a period in it. Group=%s", group);
    prong_assert(strchr(group, '.') == NULL);
    return -1;
  }

  if (cache == NULL)
  {
    cache = g_key_file_new();
    int size;
    const char *vals = config_get_all_values(&size);

    if (vals == NULL)
    {
      return config_get_direct(group, key, value);
    }
    if (g_key_file_load_from_data(cache, vals, size, G_KEY_FILE_NONE, NULL) != TRUE)
    {
      return config_get_direct(group, key, value);
    }
  }

  *value = expand_variables(cache, g_key_file_get_param(cache, group, key));

  return 0;
}

int config_get_with_default(const char *group, const char *key, const char *default_value, char **value)
{
  if (config_get(group, key, value) != 0)
  {
    // Indicates an error retreiving value!
    return -1;
  }

  if (*value == NULL)
  {
    *value = g_strdup(default_value);
  }

  return 0;
}

int config_get_group_or_general_with_default(const char *group, const char *key, const char *default_value, char **value)
{

  if (config_get(group, key, value) != 0)
  {
    // Indicates an error retreiving value!
    return -1;
  }

  if (*value == NULL)
  {
    if (config_get(CONFIG_GENERAL_GROUP_OPTION_NAME, key, value) != 0)
    {
      return -1;
    }

    if (*value == NULL)
    {
      *value = g_strdup(default_value);
    }
  }

  return 0;
}

int config_get_int(const char *group, const char *key, int *value)
{
  char *v;

  if ((config_get(group, key, &v) != 0) || (v == NULL))
  {
    return -1;
  }

  *value = atoi(v);
  g_free(v);

  return 0;
}

int config_get_int_with_default(const char *group, const char *key, int default_value, int *value)
{
  char *v;

  if (config_get(group, key, &v) != 0)
  {
    return -1;
  }

  if (v == NULL)
  {
    *value = default_value;
  } else
  {
    *value = atoi(v);
    g_free(v);
  }

  return 0;
}

int config_get_longlong(const char *group, const char *key, long long *value)
{
  char *v;

  if ((config_get(group, key, &v) != 0) || (v == NULL))
  {
    return -1;
  }

  *value = atoll(v);
  g_free(v);

  return 0;
}

int config_get_long(const char *group, const char *key, long *value)
{
  char *v;

  if ((config_get(group, key, &v) != 0) || (v == NULL))
  {
    return -1;
  }

  *value = atol(v);
  g_free(v);

  return 0;
}

int config_get_long_with_default(const char *group, const char *key, long default_value, long *value)
{
  char *v;

  if (config_get(group, key, &v) != 0)
  {
    return -1;
  }

  if (v == NULL)
  {
    *value = default_value;
  } else
  {
    *value = atol(v);
    g_free(v);
  }

  return 0;
}

int config_get_long_group_or_general_with_default(const char *group, const char *key, long default_value, long *value)
{
  char *v;

  if (config_get(group, key, &v) != 0)
  {
    return -1;
  }

  if (v != NULL)
  {
    // Group.key
    *value = atol(v);
    g_free(v);
  } else
  {
    if (config_get(CONFIG_GENERAL_GROUP_OPTION_NAME, key, &v) != 0)
    {
      return -1;
    }

    if (v != NULL)
    {
      // general.key
      *value = atol(v);
      g_free(v);
    } else
    {
      // default
      *value = default_value;
    }

  }

  return 0;

}

int config_get_long_long_with_default(const char *group, const char *key, long long default_value, long long *value)
{
  char *v;

  if (config_get(group, key, &v) != 0)
  {
    return -1;
  }

  if (v == NULL)
  {
    *value = default_value;
  } else
  {
    *value = atoll(v);
    g_free(v);
  }

  return 0;
}

const char *config_get_all_values(int *size)
{
  if (configserver_endpoint == NULL)
  {
    return NULL;
  }

  const char *recv = transport_sendrecv(configserver_endpoint, "", 1, NULL, size);

  if (config_is_err_response(recv) != 0)
  {
    return NULL;
  }
  return recv;
}

int config_is_null_response(const char *string)
{
  if (string == NULL)
  {
    return 0;
  }

  if (strcmp(string, NULL_RESPONSE) != 0)
  {
    return 0;
  }
  return 1;
}

int config_is_err_response(const char *string)
{
  if (string == NULL)
  {
    return 0;
  }

  if (strcmp(string, ERROR_RESPONSE) != 0)
  {
    return 0;
  }
  return 1;
}

void config_clear_cache()
{
  if (cache != NULL)
  {
    g_key_file_free(cache);
    cache = NULL;
  }
}

int config_close()
{
  config_clear_cache();

  if (configserver_endpoint != NULL)
  {
    transport_close(configserver_endpoint);
    configserver_endpoint = NULL;
  }

  if (process_pid != NULL)
  {
    g_free(process_pid);
    process_pid = NULL;
  }

  return 0;
}
