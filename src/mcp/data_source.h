/* Data Source Helper
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
 * \file data_source.h
 * \brief This file helps managing a data source, e.g. marking blocks
 * complete, requesting the next block to process, etc.
 */

#ifndef DATA_SOURCE_H
#define DATA_SOURCE_H

#include <stdio.h>
#include <glib.h>

#include <contract.h>
#include <result.h>
#include <report.h>
#include <logger.h>

/**
 * Type definition for convenience
 */
typedef struct data_source* data_source_t;


/**
 * \brief Setup a data source
 *
 * \param file_name File name to open. Must exist and be readable.
 * \param block_size What block size to use when chunking up the data source
 * \return Returns a data_source_t object that corresponds to the file_name
 *
 * To use a data source, provide a file name, and a block size and this will
 * return a data_source "object".
 *
 * \warning You must:\n
 * - use data_source_close to enusre the data_source_t
 *   is freed and the file is closed.\n
 * - Ensure logger is setup and ready to use, and closed seperately after
 *   data_source_close
 *
 */
data_source_t data_source_init(const char* file_name, unsigned long long block_size) G_GNUC_WARN_UNUSED_RESULT;


/** 
 * \brief Print out the status of the job tree in "dot" format
 *
 * \param source The data source whose tree we wish to print
 *
 * Useful for testing, this prints out the state of the job tree to stdout
 *
 */
void data_source_print_tree_status(data_source_t source);


/**
 * \brief Unmounts everything below the specified path
 * \param path The path below which everything should be unmounted
 * \param lazy If true this will not wait for the command to complete.
 * \return 0 on success, -1 on error. -1 May indicate mounts will still exist
 *
 */
int unmount_everything_below_path(const gchar* path, const gboolean lazy) G_GNUC_WARN_UNUSED_RESULT;


/**
 * \brief Close the data source
 *
 * \param source Data source to close
 * \return 0 on success, -1 on failure
 *
 * Closes the data source, and frees up the resources associated with it
 * as best it can.
 */
int data_source_close(data_source_t source) G_GNUC_WARN_UNUSED_RESULT;


/**
 * \brief Unmounts a loop back raw mount of a data source
 *
 * \param source The data_source_t object which you want to unmount
 * \return -1 on error, 0 on success
 *
 */
int data_source_unmount(data_source_t source) G_GNUC_WARN_UNUSED_RESULT;


/**
 * \brief Mounts a loop back raw mount of a data source in the mount_directory
 *
 * \param source The data_source_t object which you want to mount
 * \param mount_directory The directory that the data source should be mounted in
 *
 * \return -1 on error, 0 on success
 *
 */
int data_source_mount(data_source_t source, const char* mount_directory) G_GNUC_WARN_UNUSED_RESULT;


/**
 * Takes in a CCR and provides the next contract to be processed
 *
 * \param cr The CCR to accept (special case for first CCR's)
 * \param source The data source reference
 * \returns A new contract
 */
contract_t data_source_get_next_contract(data_source_t source, contract_completion_report_t cr);

#endif // DATA_SOURCE_H
