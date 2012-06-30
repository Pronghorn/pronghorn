/* Pronghorn File Manager
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

#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <stdio.h>

/** A typdef for a file manager struct */
typedef struct pronghorn_file* pronghorn_file_t;

/**
 * \brief Setup a pronghorn file manager
 *
 * \param path The path to the file to be opened
 * \param block_size The block size we intend to process this file with
 * \param window_size For efficieny, read parts of the file in large blocks
 * \return The newly created file_manager, or NULL on error
 */
pronghorn_file_t prong_file_init(const char* path, unsigned int block_size, unsigned int window_size);


const unsigned char* prong_file_read_offset(pronghorn_file_t pf, unsigned long long offset, unsigned int* buff_size);

/**
 * Calculates the number of blocks that are constant.
 *
 * This function expects the first block to already be constant!
 *
 * \param file_pointer The file pointer to search
 * \param file_pointer_offset The offset for the START of the first constant block
 * \param block_size The block size to process
 * \returns The total number of consecutive constant blocks
 */
unsigned long long prong_file_discover_num_constant_blocks(pronghorn_file_t pf, unsigned long long file_pointer_offset);

int prong_file_close(pronghorn_file_t pf);

#endif 
