/* libpronghorn Block Manager Library
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
 * \file blocks.h
 * \brief This block manager allows a process to record byte and blocks in arbitrary
 * sizes and lengths, and convert them into a different block range.
 *
 * For example, a process needs to convert a bitmap of 512 byte blocks into
 * a bitmap of full 2048 byte blocks, without losing adjoining block information.
 *
 * Input: (512byte blocks)
 *  Block array 1: 0-2
 *  Block array 2: 3-9
 *
 * If each block array was converted independently then the first block array would
 * be entirely lost as it does not span a complete and aligned 2048 byte block. The
 * only complete block would be block 1 (ie, byte offset 2048-4096)
 *
 * With this library the fact that block array 1 and 2 are adjoining is maintained
 * so that when the output is generated it returns 0-1 as expected.
 */
#ifndef BLOCKS_H
#define BLOCKS_H

#include <glib.h>

#include <block_range.h>

/**
 * Initialises the block manager for this process.
 *
 * Can be called multiple times per process but will reset the block 
 * manager each time
 *
 * \param absolute_offset The absolute offset the file is located in
 */
void block_start(long long int absolute_offset);

/**
 * Adds a byte offset to the block manager.
 *
 * \param byte The byte position to add
 * \returns 0 on success, -1 on error
 */
int block_add_byte(unsigned long long byte);

/**
 * Adds a byte range to the block manager.
 *
 * Note the byte range is inclusive of both the start byte and end byte.
 *
 * \param start_byte The starting byte
 * \param end_byte The ending byte (inclusive)
 * \returns 0 on success, -1 on error
 */
int block_add_byte_range(unsigned long long start_byte, unsigned long long end_byte);

/**
 * Adds a block to the block manager.
 *
 * A block is defined as a zero based offset of block_size bytes.
 *
 * So block 0 is at byte address 0.
 * Block 10 of 512 byte sized blocks is at byte address 5120
 *
 * \param block The block address 
 * \param block_size The block size
 * \returns 0 on success, -1 on error
 */
int block_add_block(unsigned long long block, int block_size);

/**
 * Adds a block range to the block manager.
 *
 * A block is defined as a zero based offset of block_size bytes.
 *
 * So block 0 is at byte address 0.
 * Block 10 of 512 byte sized blocks is at byte address 5120
 *
 * The block range is inclusive of both the start block and end block.
 *
 * \param start_block The starting block
 * \param end_block The ending block
 * \param block_size The size of the blocks
 * \returns 0 on success, -1 on error
 */
int block_add_block_range(unsigned long long start_block, unsigned long long end_block, int block_size);

/**
 * Finishes the block transformation.
 *
 * \warning The caller must free the array returned using g_free!
 *
 * This function returns the block array represented in the new block_size.
 *
 * \param size The size of the array
 * \returns The converted block array, or NULL if empty
 */
block_range_t* block_end(unsigned int *size) G_GNUC_WARN_UNUSED_RESULT;

#endif
