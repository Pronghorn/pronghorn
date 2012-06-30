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
 * \file subcontractor_template.c
 */
#include <stdio.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <lightmagic.h>
//#include <base_fuse.h>

#include "subcontractor_helper.h"

/**
 * An array of supported MAGIC_TYPE* entries. Must be 0 terminated.
 */
unsigned int supported_file_types[] = { MAGIC_TYPE_TEXT, 0 };

int subcontractor_init(void)
{
  // Initialise any structures here

  debug_log("Hello world!");

  return 0;
}

int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  // This is where all the magic happens

  /*
   * The contract will indicate
   * - The file (path) to process (see contract_get_path in the doco) 
   * - The absolute offset this file exists on the real input file (if known) 
   *      (see contract_get_absolute_offset noting this will return -1 if the 
   *      absolute offset isn't known)
   * - Whether the data exists in a contiguous space (see contract_is_contiguous in the doco)
   *
   * The documentation for this can be found in the source documentation 
   * ("make doc", then look in doc/source_doc/html/). In particular, 
   * the contract_* range of functions will allow you to operate on a 
   * contract structs. Some useful functions at time of writing (check 
   * the doco for the latest) include contract_get_path. For example, 
   * to obtain the path you are meant to process, you can simply call 
   * contract_get_path(to_analyse), which will return the path you are 
   * expected to open and analyse. Then it's just a matter of actually 
   * analysing it....
   *
   * Your objective, should you choose to accept, is to do the following.
   * Analyse the contract and create a result, and add it to the CCR.
   * You will probably find the functions in subcontractor_helper handy for
   * this. You should really only add one result (at this stage). Into the
   * result, you need to set:
   * - A brief description
   * - An extended description
   * - Your confidence (0-100). 
   *
   * IF the contract has an absolute offset AND it has been marked as 
   * contiguous AND you can figure out the real size of the data you
   * are processing, you can also set the range the data you are 
   * claiming occupies. Again, have a look at subcontractor_help to 
   * make your life easier.
   *
   * If your file can contain subfiles (ie, it's a container, or can be 
   * used as a container) then you have some more work to do!
   *
   * You need to: 
   * - Report these subfiles as new contracts inside the result object 
   *   (create a new contract using contract_init, contract_set_path, 
   *   contract_set_contiguous (assume it's not contiguous if you don't know), 
   *   contract_set_absolute_offset (if you know it) and then add it to the result 
   *   structure using 
   * - Add references to these files into the FUSE filesystem by calling add_file()
   *   for each subfile, then call do mount once all the files have been added
   * - Implement do_read() and cleanup()
   * - NOTE: Contracts should contain FULL PATHS, add_file should contain 
   *   RELATIVE PATHS (relative to your FUSE mount point)
   *
   *   Once you've done all that, add the result reference(s) to the 
   *   contract_completion_report (see contract_completion_report_add_result). 
   *   Return 0 for success. In the event you encounter a serious error, 
   *   return -1... but be aware, you may be killed
   *
   * Also, for your convenience the following are available to you
   *
   * - Config - For configuration options you can look at config_get* to get 
   * options you might want/need from the user
   * - Logging - A logger is already initialised for you. Just call debug_log, 
   * info_log, warning_log, error_log or severe_log just as you would use printf.
   *
   * Warnings
   *
   * Try not to fork(). If you do need to fork, make sure you don't call any 
   * logging or config functions in the child, or you will be destroyed.
   *
   * POPULATING BLOCKS
   *
   * This can be tricky, since the user might have specified a different block 
   * size to the one you need to work with. To make things simple, and awesome, 
   * there is a "blocks" object you can use Simply call block_start(), then 
   * add bytes, byte ranges, blocks and/or block ranges in whatever block size 
   * you desire/ Then call block_end() and pass the array into the result structure as a block list.
   */

  return 0;
}

int subcontractor_close(void)
{
  // Destroy structures initialised in subcontractor_init

  debug_log("Bye");

  return 0;
}

/*
int do_read(unsigned int id_number, const char* filename, char* buf, size_t size, off_t offset)
{
  // Read data from id_number (or optionally 'filename')
  // Populate buf with 'size' bytes at offset 'offset' into the file
}

void cleanup(void)
{
  // The filesystem is unmounted
  // Destroy any filesystem related structures
}
*/
