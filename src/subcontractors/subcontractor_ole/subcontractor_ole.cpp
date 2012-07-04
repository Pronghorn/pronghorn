/* libpronghorn Subcontractor template
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
 * \file subcontractor_ole.cpp
 */
using namespace std;

#ifndef FORCED_CXX_COMPILE
extern "C" {
#endif

#include <stdio.h>
#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <base_fuse.h>
#include <lightmagic.h>
#include "subcontractor_helper.h"

#ifndef FORCED_CXX_COMPILE
}
#endif

#include "pole.h"

unsigned int supported_file_types[] = {MAGIC_TYPE_OLE, 0};

/** The global storage object, used by do_read */
POLE::Storage *g_storage;

/** The base mountpoint */
std::string g_mountpoint;

/**
 * Inits global stuctures
 *
 * \return 0 for success
 */
int subcontractor_init(void)
{
	return 0;
}

/**
 * Creates a contract with the specified values
 *
 * \param offset The offset value for the contract
 * \param contiguous Whether the data for the contract is contiguous
 * \param path The path for the contract
 * \return A newly created contract, or NULL on error
 * \warning The caller is responsible for contract_close-ing the returned contract
 *
 */
static contract_t init_contract_with_values(int offset, int contiguous, char *path)
{
	contract_t contract = NULL;
	gboolean error = TRUE;
	
	/* Create the contract, add the relevant fields and return it if all goes well */
	if ((contract = contract_init(NULL, 0)))
		if (contract_set_absolute_offset(contract, offset) == 0)
			if (contract_set_contiguous(contract, contiguous) == 0) 
				if (contract_set_path(contract, path) == 0)
					error = FALSE;

	if (error == TRUE)
	{
		if (contract != NULL)
		{
			contract_close(contract);
		}
		return NULL;
	}

	return contract;
}

/**
 * Creates a result with the specified values, automatically
 * inserting "PROCESS_NAME" as the subcontractor name
 *
 * \param type The type to specify in the result
 * \param data_type The data type string to set in the result
 * \return A newly created result 
 * \warning The called is responsible for result_close-ing the returned result
 */
static result_t init_result_with_values(int type, char *data_type)
{
	result_t result;
	gboolean error = TRUE;

	/* Create the result, add the relevant fields and return it if all goes well */
	if ((result = result_init(NULL, 0)))
		if ((result_set_brief_data_description(result, "OLE") == 0))
			if ((result_set_data_description(result, "OLE Document") == 0))
					error = FALSE;
	
	if (error == TRUE)
	{
		if (result != NULL)
		{
			result_close(result);
		}
		return NULL;
	}

	return result;
}

/**
 * Recursive function to walk an OLE path, add all files therein to the 
 * FUSE filesystem, create contracts for said files and add them to the 
 * result object.
 *
 * \param path The path to walk
 * \param result The pronghorn result object
 * \param count Returns the number of files added to the result object
 */
static void walk_directory(std::string path, result_t result, unsigned int *count)
{
	std::list<std::string> entries = g_storage->entries(path);

	std::list<std::string>::iterator it;

	for(it = entries.begin(); it != entries.end(); ++it) 
	{
		std::string name = *it;
		std::string fullname = path + name;

		/* If the current 'file' is a directory, recurse over it */
		if (g_storage->isDirectory(fullname)) 
		{
			walk_directory(fullname + "/", result, count);
		}
		else 
		{
			POLE::Stream *ss = new POLE::Stream(g_storage, fullname);

			if ((ss) && (!ss->fail())) {

				/* Add the file to the FUSE filesystem, create a contract for it and add 
				 * the contract to the result */

				contract_t contract;
				char* contract_path = g_strdup_printf("%s/%u", g_mountpoint.c_str(), *count);

				debug_log("%s: %lu, %i", fullname.c_str(), ss->size(), *count);

				add_file(*count, fullname.c_str(), ss->size());

				if ((contract = init_contract_with_values(-1, 0, contract_path))) {
					result_add_new_contract(result, contract);
				}

				g_free(contract_path);
				contract_close(contract);
				delete ss;
				*count = *count + 1;

			} else
			{
				delete ss;
			}
		}
	}
}

/**
 * Analyse whatever contract is provided and respond
 *
 * Do not free to_analyse
 * The return value is also freed elsewhere.
 *
 * \param to_analyse The contract to analyse.
 * \param ccr The contract completion report to populate
 * \returns 0 on success, -1 on error
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
	const char *path = contract_get_path(to_analyse);
	
	g_storage = new POLE::Storage(path);

	result_t result;
	int ret = 0;
	unsigned int file_count = 0;
	int contiguous = 0;
	int offset = 0;
	block_range_t *ranges;
	unsigned int num_ranges = 0;

	/* Create our mountpoint name */
	g_mountpoint = path;
	g_mountpoint = g_mountpoint + ":mnt-ole";

	/* Get the required information from the contract */
	contiguous = contract_is_contiguous(to_analyse);
	offset = contract_get_absolute_offset(to_analyse);

  /* Set up the required information in the result object */
	if ((result = init_result_with_values(MAGIC_TYPE_OLE, (char*) "OLE Document")) == NULL) {
		delete g_storage;
    warning_log("Failed to create result.");
		return -1;
	}

	debug_log("Filesize: %i", g_storage->filesize());

	/* Attempt to open the file */
	g_storage->open();

	debug_log("storage->open()");

	switch (g_storage->result()) {

		case POLE::Storage::Ok:
			debug_log("Storage::Ok");

			/* Ok - 100 confidence */
			result_set_confidence(result, 100);
			walk_directory("/", result, &file_count);
			do_mount((char*)g_mountpoint.c_str());

			/* If it makes sense to, add the block list to the result */
			if ((offset >= 0) && (contiguous == 1)) {
				block_start(offset);
				block_add_byte_range(0, g_storage->filesize());
				ranges = block_end(&num_ranges);

				if (result_set_block_ranges(result, ranges, num_ranges)) 
				{
					cleanup();
					return -1;
				}

        for (unsigned int i = 0; i < num_ranges; i++)
        {
          block_range_close(ranges[i]);
        }
        g_free(ranges);
			}
			break;

		case POLE::Storage::BadOLE:
			/* BadOLE - 50 confidence */
			debug_log("Storage::BadOLE");
			result_set_confidence(result, 50);
			break;

		case POLE::Storage::NotOLE:
			debug_log("Storage::NotOLE");
			/* NotOLE - 0 confidence */
			result_set_confidence(result, 0);
			break;

		default:
			debug_log("Opening OLE document failed");
			result_close(result);
			return -1; // If we couldnt open the file, something went badly wrong.
	}

	ret = contract_completion_report_add_result(ccr, result);

	result_close(result);
	cleanup();

	if (ret != 0) {
		return -1;
	}

	return 0;
}

/**
 * Destroys global stuctures
 *
 * returns 0 for success
 */
int subcontractor_close(void)
{
	return 0;
}

/**
 * Finds the requested file in the OLE structure and returns a POLE::Stream object
 * which can be used to access the contents - works recursively.
 *
 * \param id_number The requested file id
 * \param count An integer required to be passed in
 * \paqam path The current path to search
 */
static POLE::Stream *get_file(unsigned int id_number, unsigned int *count, std::string path)
{
	std::list<std::string> entries = g_storage->entries(path);

	/* Walk the list of files in the current directory */
	std::list<std::string>::iterator it;

	for(it = entries.begin(); it != entries.end(); ++it) 
	{
		std::string name = *it;
		std::string fullname = path + name;
		if (g_storage->isDirectory(fullname)) 
		{
			POLE::Stream *result = get_file(id_number, count, fullname + "/");
			if (result != NULL) 
			{
				return result;
			}
		}
		else 
		{
			POLE::Stream *ss = new POLE::Stream(g_storage, fullname);

			/* If we've found the file who's id matches the one we want, return it */
			if ((ss) && (!ss->fail()) && (*count == id_number)) 
			{
				return ss;
			}
			delete ss;
			*count = *count + 1;
		}
	}
	return NULL;
}

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
int do_read(unsigned int id_number, const char* filename, char* buf, size_t size, off_t offset)
{

	unsigned int count = 0;
	int ret = 0;
	int stream_size = 0;

	POLE::Stream *stream = get_file(id_number, &count, "/");

	if (stream == NULL)
	{
		return 0;
	}

	stream_size = stream->size();

	if (offset) {
		stream->seek(offset);
	}

	if (!stream->fail()) {
		ret = stream->read((unsigned char*) buf, size);

		if (offset + ret > stream_size) {
			ret = stream_size - offset;
		}
	}
	else
	{
		ret = 0;
	}

	delete stream;
	return ret;
}

/**
 * Called when the filesystem is unmounted, and allows the destruction
 * of structures and freeing allocated memory.
 */
void cleanup(void)
{
	g_storage->close();
	delete g_storage;
}

