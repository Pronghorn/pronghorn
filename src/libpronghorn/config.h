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
 * \file config.h
 * \brief Libpronghorn config structure
 *
 * This defines the config structure.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <defaults.h>
#include <glib.h>

/** This is the response the server will give when asked to quit */
#define QUIT_RESPONSE "Bye!"

/** This is the response when the server is successfully asked to set a value */
#define SUCCESS_RESPONSE "OK"

/** This is the response when the server does not understand the request */
#define ERROR_RESPONSE "ERR"

/** This is the response when the configuration item requested does not exist */
#define NULL_RESPONSE "<NULL>"

/** Macro to make it easier and neater to get a string with a default value */
#define config_get_with_default_macro(g, k, v) config_get_with_default(g, k ## _OPTION_NAME, k ## _DEFAULT, v)
/** Macro to make it easier and neater to get an int with a default value */
#define config_get_int_with_default_macro(g, k, v) config_get_int_with_default(g, k ## _OPTION_NAME, k ## _DEFAULT, v)
/** Macro to make it easier and neater to get a long with a default value */
#define config_get_long_with_default_macro(g, k, v) config_get_long_with_default(g, k ## _OPTION_NAME, k ## _DEFAULT, v)
/** Macro to make it easier and neater to get a long with the general or a default value */
#define config_get_long_group_or_general_with_default_macro(g, k, v) config_get_long_group_or_general_with_default(g, k ## _OPTION_NAME, k ## _DEFAULT, v)
/** Macro to make it easier and neater to get a long long with a default value */
#define config_get_long_long_with_default_macro(g, k, v) config_get_long_long_with_default(g, k ## _OPTION_NAME, k ## _DEFAULT, v)
/**
 * Initialises the config object.
 *
 * The config endpoint must point to a configserver.
 *
 * \warning You must call config_close when the program exits.
 *
 * \param endpoint The configserver endpoint
 * \returns 0 on success, -1 on error
 */
int config_init(const char *endpoint);

/**
 * Sets the configuration value for group.key=value.
 *
 * \warning group may not be NULL
 *
 * \param group The group to set
 * \param key The key to set
 * \param value The value to set
 * \returns 0 on success, -1 on error
 */
int config_set(const char *group, const char *key, const char *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Gets a parameter from the specified key file
 *
 * \warning The caller must free the returned value using g_free
 *
 * \param key_file The key file to query
 * \param group_name The group name
 * \param key_name The key to query
 * \returns A string, or NULL on error
 */
gchar *g_key_file_get_param(GKeyFile * key_file, const gchar * group_name, const gchar * key_name);

/**
 * Sets a parameter in the key file.
 *
 * \param key_file The key file to set
 * \param group_name The group
 * \param key_name The key name
 * \param string The value to set it to
 */
void g_key_file_set_param(GKeyFile * key_file, const gchar * group_name, const gchar * key_name, const char *string);

/**
 * Expands the variables located in a string using values obtained from the config file.
 *
 * Variables are identified by ${var}
 *
 * The parameter 'string' will be freed internally.
 *
 * \warning The caller must free the returned string
 *
 * \param config The gkeyfile config file
 * \param string The string to expand
 * \returns the expanded string
 */
char *expand_variables(GKeyFile * config, char *string);

/**
 * Gets the configuration value for group.key.
 *
 * If group is set to NULL it will search for
 *
 * - [process name].key, then
 * - [pid].key, then
 * - general.key
 *
 * and return the first matching value.
 *
 * If the value does not currently exist it will set *value to NULL and return 0
 *
 * \warning The caller must free value using g_free
 *
 * \param group The group to get
 * \param key The key to get
 * \param value The address to store the value string
 * \returns 0 on success, -1 on error
 */
int config_get(const char *group, const char *key, char **value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Identical to config_get except it returns the default value if the key wasn't found.
 *
 * \warning The caller must free value using g_free
 *
 * \param group The group to get
 * \param key The key to get
 * \param default_value The default value to use
 * \param value The address to store the value string
 * \returns 0 on success, -1 on error
 */
int config_get_with_default(const char *group, const char *key, const char *default_value, char **value) G_GNUC_WARN_UNUSED_RESULT;


/**
 * Identical to config_get except it returns the "general" value if the group wasn't found, and the default value if "general" wasn't found.
 *
 * \warning The caller must free value using g_free
 *
 * \param group The group to get
 * \param key The key to get
 * \param default_value The default value to use
 * \param value The address to store the value string
 * \returns 0 on success, -1 on error
 */
int config_get_group_or_general_with_default(const char *group, const char *key, const char *default_value, char **value) G_GNUC_WARN_UNUSED_RESULT;


/**
 * Identical to config_get except it retreives an int.
 *
 * If group is set to NULL it will search for
 *
 * - [process name].key, then
 * - [pid].key, then
 * - general.key
 *
 * and return the first matching value.
 *
 * \param group The group to get
 * \param key The key to get
 * \param value The value of the key
 * \return 0 on success, -1 on error
 */
int config_get_int(const char *group, const char *key, int *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Identical to config_get except it returns the default value if the key wasn't found.
 *
 * \param group The group to get
 * \param key The key to get
 * \param default_value The default value to use
 * \param value The address to store the int value
 * \returns 0 on success, -1 on error
 */
int config_get_int_with_default(const char *group, const char *key, int default_value, int *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Identical to config_get except it retreives a long long.
 *
 * If group is set to NULL it will search for
 *
 * - [process name].key, then
 * - [pid].key, then
 * - general.key
 *
 * and return the first matching value.
 *
 * \param group The group to get
 * \param key The key to get
 * \param value The value of the key
 * \return 0 on success, -1 on error
 */
int config_get_longlong(const char *group, const char *key, long long *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Identical to config_get except it retreives a long.
 *
 * If group is set to NULL it will search for
 *
 * - [process name].key, then
 * - [pid].key, then
 * - general.key
 *
 * and return the first matching value.
 *
 * \param group The group to get
 * \param key The key to get
 * \param value The value of the key
 * \return 0 on success, -1 on error
 */
int config_get_long(const char *group, const char *key, long *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Identical to config_get except it returns the default value if the key wasn't found.
 *
 * \param group The group to get
 * \param key The key to get
 * \param default_value The default value to use
 * \param value The address to store the long value
 * \returns 0 on success, -1 on error
 */
int config_get_long_with_default(const char *group, const char *key, long default_value, long *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Identical to config_get_long except it returns the "general" value if the group wasn't found, and the default value if "general" wasn't found.
 *
 * \param group The group to get
 * \param key The key to get
 * \param default_value The default value to use
 * \param value The address to store the long value
 * \returns 0 on success, -1 on error
 */
int config_get_long_group_or_general_with_default(const char *group, const char *key, long default_value, long *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Identical to config_get except it returns the default value if the key wasn't found.
 *
 * \param group The group to get
 * \param key The key to get
 * \param default_value The default value to use
 * \param value The address to store the long long value
 * \returns 0 on success, -1 on error
 */
int config_get_long_long_with_default(const char *group, const char *key, long long default_value, long long *value) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Retreives the entire configuration value list.
 *
 * The list is suitable for parsing by g_key_file_load_from_data
 *
 * http://developer.gnome.org/glib/2.32/glib-Key-value-file-parser.html#g-key-file-load-from-data
 *
 * \returns The entire configuration value list.
 */
const char *config_get_all_values(unsigned int *size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Checks whether the response indicates the request was not understood.
 *
 * \param string The response to check
 * \returns 1 if the response indicates an error has occurred
 */
int config_is_err_response(const char *string) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Checks whether the response indicates a value is not set.
 *
 * \param string The response to check.
 * \returns 1 if it's a NULL response, 0 if it's something else.
 */
int config_is_null_response(const char *string) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Clears the internal config cache. On the next request it will re-acquire a fresh set of
 * results from the config server.
 */
void config_clear_cache();

/**
 * Destroys the config object.
 *
 * \returns 0 on success, -1 on error
 */
int config_close(void);

#endif
