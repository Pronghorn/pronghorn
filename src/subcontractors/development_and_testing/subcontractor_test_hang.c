/* Pronghorn Subcontractor Test - Hang
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

/** \file subcontractor_test_hang.c
 *
 * DO NOT USE THIS FILE. TESTING ONLY.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <logger.h>
#include "subcontractor_helper.h"

//#include <base_fuse.h>

const char *SUBCONTRACTOR_NAME = "subcontractor_test_hang";

unsigned int supported_file_types[] = { 0 };
//unsigned int supported_file_types[] = {MAGIC_TYPE_TEXT, 0};

int subcontractor_init()
{
  // Initialise any structures here
  debug_log("Starting up.");
  return 0;
}

int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  // This is where all the magic happens

  debug_log("About to hang.");

  while (1)
  {
    sleep(200);
  }

  return 0;
}

int subcontractor_close()
{
  // Destroy structures initialised in subcontractor_init
  debug_log("Your lucky day!");
  return 0;
}

/*
int do_read(unsigned int id_number, const char* filename, char* buf, size_t size, off_t offset)
{
  // Read data from id_number (or optionally 'filename')
  // Populate buf with 'size' bytes at offset 'offset' into the file
}

void cleanup()
{
  // The filesystem is unmounted
  // Destroy any filesystem related structures
}
*/
