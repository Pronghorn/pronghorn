/* libpronghorn Result Library
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
 * \file result.h
 * \brief Library functions for contract completion reports
 *
 * In pronghorn, jobs tend to be passed around as "contracts". A contract
 * is normally along the lines of "please classify this block". When the 
 * classification is done, a "contract completion report" is generated 
 * containing the results (and potentially new contracts we've found).
 * This file contains functions to work with these contract completion
 * reports.
 */
#ifndef RESULT_H
#define RESULT_H

#include <glib.h>

#include "block_range.h"
#include "contract.h"

/**
 * The result reference.
 */
typedef struct result* result_t;

/**
 * Initialises the result reference.
 *
 * The initial_values must be a buffer created from having a result
 * reference converted to a buffer with result_serialise or result_serialise_raw.
 *
 * If you set initial_values to NULL an empty result reference is created.
 *
 * \warning The returned reference must be freed by the caller using result_close.
 *
 * \param initial_values holds the serialised data from another result reference
 * \param initial_values_size the size of the initial_values_buffer
 * \returns an initialised result_t reference or NULL on error
 */
result_t result_init(const char *initial_values, unsigned int initial_values_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the result reference as a serialised buffer.
 *
 * \warning The caller must free the returned buffer using g_free
 *
 * \param r the result reference to serialise
 * \param output_data_size the size of the output buffer
 * \returns the output buffer, or NULL on error.
 */
char *result_serialise(result_t r, unsigned int *output_data_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Clones a result reference.
 *
 * \warning The returned reference must be freed by the caller using result_close.
 *
 * \param r the result reference to clone
 * \returns an identical result reference or NULL on error
 */
result_t result_clone(result_t r) G_GNUC_WARN_UNUSED_RESULT;

block_range_t* result_get_block_ranges(result_t r, unsigned int* num_ranges);

int result_set_block_ranges(result_t r, block_range_t* ranges, unsigned int num_ranges);

/**
 * Gets the extended data description.
 *
 * The data description is a string representation of the data located on 
 * this/these blocks.
 *
 * The subcontractor is free to populate this with any descriptive string to 
 * describe the data found. It should be relatively short (ideally less than 
 * a line or so) and provide information on the data.
 *
 * The caller must NOT free the string.
 *
 * \param r The result reference.
 * \returns The data description string, or NULL on error.
 */
const char *result_get_data_description(result_t r) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Gets the brief data description.
 *
 * The brief data description is a very short string representation of the 
 * data located on this/these blocks. It should only a word or so, e.g. 
 * TEXT, PDF, etc.
 *
 * The caller must NOT free the string.
 *
 * \param r The result reference.
 * \returns The data type string, or NULL on error.
 */
const char *result_get_brief_data_description(result_t r) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the data description.
 *
 * The data description is a string representation of the data located on this 
 * block. The subcontractor is free to populate this with any descriptive 
 * string to describe the data found. It should be fairly short, say a line 
 * or so.
 *
 * \param r The result reference.
 * \param data_description A null terminated string representing the data type 
 * (must not be NULL)
 * \returns 0 on success, -1 on error
 */
int result_set_data_description(result_t r, const char *data_description);

/**
 * Sets the brief data description.
 *
 * The brief data description is a very short string representation of the 
 * data located on this block. The subcontractor is free to populate this 
 * with any descriptive string to describe the data found. It should be 
 * a single word or so, e.g. TEXT, JPEG, etc.
 *
 * \param r The result reference.
 * \param brief_data_description A null terminated string representing the data 
 * type (must not be NULL)
 * \returns 0 on success, -1 on error
 */
int result_set_brief_data_description(result_t r, const char *brief_data_description);

/**
 * Gets the confidence value.
 *
 * The confidence value indicates the level of confidence that the subcontractor has in specifying the type is correct.
 *
 * The range is between -2 and 100.
 *
 * A value of -1 indicates there is no subcontractor available to process the data - or the subcontractor failed.
 * A value of -2 is observed when no confidence has been set on an uninitialised result reference.
 *
 * \param r The result reference.
 * \returns The confidence value.
 */
int result_get_confidence(result_t r) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the confidence value.
 *
 * The confidence value indicates the level of confidence that the subcontractor has in specifying the type is correct.
 *
 * The range is between -2 and 100.
 *
 * A value of -1 indicates there is no subcontractor available to process the data - or the subcontractor failed.
 * A value of -2 is observed when no confidence has been set on an uninitialised result reference.
 *
 * \param r The results reference.
 * \param confidence Must be between -1 and 100 inclusive.
 * \returns 0 on success, -1 on error
 */
int result_set_confidence(result_t r, int confidence);

/**
 * Gets the subcontractor name.
 *
 * The caller should NOT free the returned string.
 *
 * \param r The result reference.
 * \returns The subcontractor name.
 */
const char *result_get_subcontractor_name(result_t r) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the subcontractor name that produced this result.
 *
 * \param r The result reference.
 * \param subcontractor_name The subcontractor's name to set.
 * \returns 0 on success, -1 on error.
 */
int result_set_subcontractor_name(result_t r, const char *subcontractor_name);

/**
 * Returns the array of new contracts attached to the results reference.
 *
 * \param r The result reference.
 * \param new_contracts_count The number of elements in the returned array.
 * \returns The array of new contracts
 */
const contract_t *result_get_new_contracts(result_t r, unsigned int *new_contracts_count);

/**
 * Adds a contract to the result reference.
 *
 * \param r The result reference.
 * \param new_contract The contract to add to the result
 * \returns 0 on success, -1 on error.
 */
int result_add_new_contract(result_t r, contract_t new_contract);

/**
 * Destroys the result reference.
 *
 * \param r the result reference to close
 * \returns 0 on success, -1 on error
 */
int result_close(result_t r);

#endif
