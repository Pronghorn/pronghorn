/* libpronghorn Report Library
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
 * \file report.h
 * \brief Library functions for contract completion reports
 *
 * In pronghorn, jobs tend to be passed around as "contracts". A contract
 * is normally along the lines of "please classify this block". When the 
 * classification is done, a "contract completion report" is generated 
 * containing the results (and potentially new contracts we've found).
 * This file contains functions to work with these contract completion
 * reports.
 */
#ifndef REPORT_H
#define REPORT_H

#include <glib.h>

#include "result.h"

/** The typedef for the contract completion report reference */
typedef struct contract_completion_report* contract_completion_report_t;

/**
 * Initialises the contract_completion_report reference.
 *
 * The initial_values must be a buffer created from having a contract_completion_report
 * reference converted to a buffer with contract_completion_report_serialise or contract_completion_report_serialise_raw.
 *
 * If you set initial_values to NULL an empty contract_completion_report reference is created.
 *
 * \warning The returned reference must be freed by the caller using contract_completion_report_close.
 *
 * \param initial_values holds the serialised data from another contract_completion_report reference
 * \param initial_values_size the size of the initial_values_buffer
 * \returns an initialised contract_completion_report_t reference or NULL on error
 */
contract_completion_report_t contract_completion_report_init(const char *initial_values, const int initial_values_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the contract_completion_report reference as a serialised buffer.
 *
 * \warning The caller must free the returned buffer using g_free
 *
 * \param r the contract_completion_report reference to serialise
 * \param output_data_size the size of the output buffer
 * \returns the output buffer, or NULL on error.
 */
char *contract_completion_report_serialise(contract_completion_report_t r, int *output_data_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Clones a contract_completion_report reference.
 *
 * \warning The returned reference must be freed by the caller using contract_completion_report_close.
 *
 * \param r the contract_completion_report reference to clone
 * \returns an identical contract_completion_report reference or NULL on error
 */
contract_completion_report_t contract_completion_report_clone(contract_completion_report_t r) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Gets the results array from the contract_completion_report.
 *
 * The caller should NOT free the returned array.
 *
 * \param r The contract_completion_report reference
 * \param num_results The number of elements in the returned array
 * \returns The array of results references.
 */
const result_t *contract_completion_report_get_results(contract_completion_report_t r, int *num_results);

/**
 * Adds a result to the contract_completion_report reference.
 *
 * \warning This will clone the new_result paramter, so the caller is still
 * responsible for closing the new_result reference.
 *
 * \param r The contract_completion_report reference
 * \param new_result The result reference to add (may not be NULL)
 * \returns 0 on success, -1 on error.
 */
int contract_completion_report_add_result(contract_completion_report_t r, result_t new_result);

/**
 * Retreives the original contract request from the contract completion report reference.
 *
 * This is so the MCP is aware of the contract request that created this
 * report.
 *
 * The caller should NOT free the returned contract_t reference.
 *
 * \param r The contract_completion_report reference
 * \returns The original contract reference, or NULL on error
 */
const contract_t contract_completion_report_get_original_contract(contract_completion_report_t r) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Inserts the original contract request into the contract completion report reference.
 *
 * This is so the MCP is aware of the contract request that created this
 * report.
 *
 * \param r The contract_completion_report reference
 * \param c The contract reference to insert
 * \returns 0 on success, -1 on error
 */
int contract_completion_report_set_original_contract(contract_completion_report_t r, contract_t c);

/**
 * Destroys the contract_completion_report reference.
 *
 * \param r the contract_completion_report reference to close
 * \returns 0 on success, -1 on error
 */
int contract_completion_report_close(contract_completion_report_t r);

#endif
