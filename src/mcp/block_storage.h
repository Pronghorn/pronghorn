/* Pronghorn Block Storage
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
 * \file block_storage.h
 * \brief A helper to efficiently manage tracking a collection of blocks.
 *
 */

#ifndef BLOCK_STORAGE_H
#define BLOCK_STORAGE_H

#include <stdio.h>
#include <block_range.h>

#include <block_range.h>

/** This represents a single block store instance */
typedef struct block_store* block_store_t;

/**
 * \brief Initialise a block store object
 *
 * \warning The user is responsible for calling block_store_close on the returned reference
 * \returns A newly created block store reference
 */
block_store_t block_store_init() G_GNUC_WARN_UNUSED_RESULT;

/** 
 * \brief Store blocks 
 *
 * \param store The block store reference in which to store the blocks
 * \param blocks The collection of blocks to add the block store
 * \block_count The number of blocks in the collection to be added
 * \return 0 on success, -1 on error
 *
 */
int store_blocks(block_store_t store, block_range_t* ranges, unsigned int num_ranges) G_GNUC_WARN_UNUSED_RESULT;

/**
 * \brief Get the next missing block (in increasing numerical order)
 *
 * \note This also stores the returned blcok in the block store
 * \param store The block store reference from which to retrieve the next missing block
 * \return The next missing block
 */
unsigned long long int next_missing_block(block_store_t store) G_GNUC_WARN_UNUSED_RESULT;

/**
 * \brief Closes the block store, frees resources
 * \param store The block store reference we wish to close
 * \return 0 on success, -1 on failure
 */
int block_store_close(block_store_t to_close) G_GNUC_WARN_UNUSED_RESULT;

#endif


