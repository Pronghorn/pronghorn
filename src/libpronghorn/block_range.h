/* libpronghorn Block Range Library
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
 * \file block_range.h
 * \brief Library functions for block ranges
 */
#ifndef BLOCK_RANGE_H
#define BLOCK_RANGE_H

#include <glib.h>

/**
 * The block range reference.
 */
typedef struct block_range* block_range_t;

/**
 * Initialises the block_range reference.
 *
 * \warning The returned reference must be freed by the caller using block_range_close.
 *
 * \param initial_values holds the serialised data from another block_range reference
 * \param initial_values_size the size of the initial_values_buffer
 * \returns an initialised block_range_t reference or NULL on error
 */
block_range_t block_range_init(const char *initial_values, const int initial_values_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the block_range reference as a serialised buffer.
 *
 * \warning The caller must free the returned buffer using g_free
 *
 * \param b the block_range reference to serialise
 * \param output_data_size the size of the output buffer
 * \returns the output buffer, or NULL on error.
 */
char *block_range_serialise(block_range_t b, int *output_data_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Clones a block_range reference.
 *
 * \warning The returned reference must be freed by the caller using block_range_close.
 *
 * \param b the block_range reference to clone
 * \returns an identical block_range reference or NULL on error
 */
block_range_t block_range_clone(block_range_t b) G_GNUC_WARN_UNUSED_RESULT;

/**
 * \brief Sets the range of the block range
 * 
 * \param b The block range we are setting
 * \param position The start position of this block range (in blocks)
 * \param length The length of the block range in blocks
 * \return 0 on success, -1 on failure
 */
int block_range_set_range(block_range_t b, unsigned long long position, unsigned long long length) G_GNUC_WARN_UNUSED_RESULT;

/**
 * \brief Gets the range of the block range
 * 
 * \param b The block range we are requesting the range of
 * \param position The variable which will be populated with the position of this range
 * \param length The variable which will be populated with the length of this range
 * \return 0 on success, -1 on failure
 */
int block_range_get_range(block_range_t b, unsigned long long* position, unsigned long long* length);

/**
 * Destroys the block_range reference.
 *
 * \param r the block_range reference to close
 * \returns 0 on success, -1 on error
 */
int block_range_close(block_range_t b);

#endif

