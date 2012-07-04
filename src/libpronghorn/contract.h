/* Libpronghorn Contract Structure
 * Copyright (C) 2012 AUTHOR
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
 * \file contract.h
 * \brief Libpronghorn contract structure
 *
 * This defines the contract structure.
 */

#ifndef CONTRACT_H
#define CONTRACT_H

#include <glib.h>

/**
 * The contract reference.
 */
typedef struct contract* contract_t;

/**
 * Initialises the contract reference.
 *
 * The initial_values must be a buffer created from having a contract
 * reference converted to a buffer with contract_serialise or contract_serialise_raw.
 *
 * If you set initial_values to NULL an empty contract reference is created.
 *
 * \warning The returned reference must be freed by the caller using contract_close.
 *
 * \param initial_values holds the serialised data from another contract reference
 * \param initial_values_size the size of the initial_values_buffer
 * \returns an initialised contract_t reference or NULL on error
 */
contract_t contract_init(const char *initial_values, unsigned int initial_values_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the contract reference as a serialised buffer.
 *
 * \warning The caller must free the returned buffer using g_free
 *
 * \param c the contract reference to serialise
 * \param output_data_size the size of the output buffer
 * \returns the output buffer, or NULL on error.
 */
char *contract_serialise(contract_t c, unsigned int *output_data_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Clones a contract reference.
 *
 * \warning The returned reference must be freed by the caller using contract_close.
 *
 * \param c the contract reference to clone
 * \returns an identical contract reference or NULL on error
 */
contract_t contract_clone(contract_t c) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the path.
 *
 * \param c The contract reference.
 * \returns The path for this contract, or NULL.
 */
const char *contract_get_path(contract_t c) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the path.
 *
 * \param c The contract reference.
 * \param path The path to set.
 * \returns 0 on success, -1 on failure.
 */
int contract_set_path(contract_t c, const char *path);

/**
 * Returns an array of types this contract reference should be processed as.
 *
 * \param c The contract reference
 * \param num_types The number of types in the returned array (may not be NULL)
 * \returns An array of type codes.
 */
const unsigned int *contract_get_types(contract_t c, unsigned int *num_types) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Deletes the array of types.
 *
 * \param c The contract reference
 * \returns 0 on success, -1 on failure.
 */
int contract_delete_types(contract_t c);

/**
 * Adds a type to the contract.
 *
 * \param c The contract reference.
 * \param type The type of data this contract should be processes as.
 * \returns 0 on success, -1 on error
 */
int contract_add_type(contract_t c, unsigned int type);

/**
 * Returns whether the contract is over a contiguous allocated area.
 *
 * \param c The contract
 * \returns 1 if contiguous, 0 if not contiguous
 */
int contract_is_contiguous(contract_t c) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets whether this contract works over a contiguous allocated area.
 *
 * \param c The contract
 * \param is_contiguous 1 if contiguous, 0 if not.
 * \returns 0 is success, -1 on error
 */
int contract_set_contiguous(contract_t c, unsigned int is_contiguous);

/**
 * Returns the absolute offset this contract exists relative to the 
 * original input file.
 *
 * It will be -1 if this is not known.
 *
 * \param c The contract
 * \returns The absolute offset in bytes, or -1 if not known.
 */
long long int contract_get_absolute_offset(contract_t c) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the absolute offset for this contract (relative to the original
 * input file)
 *
 * Set this to -1 if not known.
 *
 * \param c The contract
 * \param offset The absolute offset in bytes.
 * \returns 0 if success, -1 on error
 */
int contract_set_absolute_offset(contract_t c, long long int offset);

/** 
 * Sets the time to sleep before attempting to process another contract. Negative 
 * values imply shutdown and stop processing
 *
 * \param c The contract
 * \param sleep The time in ms to sleep for before requesting a new contract.
 * \return 0 on success, -1 on error
 *
 * Set this to 0 in normal cases
 */
int contract_set_sleep_time(contract_t c, int sleep);

/** 
 * Get the time to sleep before attempting to process another contract. Negative 
 * values imply shutdown and stop processing
 *
 * \param c The contract
 * \return The time to sleep for before trying to process a contract, negative
 * values imply stop and shutdown
 *
 */
int contract_get_sleep_time(contract_t c);

/**
 * Destroys the contract reference.
 *
 * \param c the contract reference to close
 * \returns 0 on success, -1 on error
 */
int contract_close(contract_t c);

#endif
