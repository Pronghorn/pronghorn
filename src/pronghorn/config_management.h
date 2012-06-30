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
 * \file config_management.h
 * \brief This server provides a centralised configuration storage and
 * retrieval mechanism for every Pronghorn process
 *
 * It also launches the logger and the MCP. This is the program that starts Pronghorn
 */

#ifndef CONFIG_MANAGEMENT_H
#define CONFIG_MANAGEMENT_H

#include <glib.h>

/**
 * Parses a group and key from an input string.
 * 
 * The string is assumed to be formated as [group].[key]
 *
 * \warning The caller must free group and key using g_free
 *
 * \param string The string to parse
 * \param group The address to store the group name
 * \param key The address to store the key name
 * \returns 0 on success, -1 on error
 */
int parse_group_key(const char *string, char **group, char **key);

/**
 * Parses a group, key and value from an input string
 *
 * The string is assumed to be formatted as [group].[key]=[value]
 *
 * \warning The caller must free group, key and string using g_free
 *
 * \param string The string to parse
 * \param group The address to store the group name
 * \param key The address to store the key name
 * \param value The address to store the value
 * \returns 0 on success, -1 on error
 */
int parse_group_key_value(const char *string, char **group, char **key, char **value);

/**
 * Generates a config key file with regards to the command line arguments
 *
 * \param argc The number of args
 * \param argv The arg array
 * \returns A key file, or NULL on error
 */
GKeyFile *generate_config(int argc, char *argv[]);

#endif
