/* Libpronghorn log structure
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
 * \file log.h
 * \brief Libpronghorn log structure
 *
 * This defines the log structure used when passing logging messages.
 */

#ifndef LOG_H
#define LOG_H

#include <glib.h>

/**
 * The log reference.
 */
typedef struct log* log_t;

/**
 * Initialises the log reference.
 *
 * The initial_values must be a buffer created from having a log
 * reference converted to a buffer with log_serialise or log_serialise_raw.
 *
 * If you set initial_values to NULL an empty log reference is created.
 *
 * \warning The returned reference must be freed by the caller using log_close.
 *
 * \param initial_values holds the serialised data from another log reference
 * \param initial_values_size the size of the initial_values_buffer
 * \returns an initialised log_t reference or NULL on error
 */
log_t log_init(const char *initial_values, const unsigned int initial_values_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the log reference as a serialised buffer.
 *
 * \warning The caller must free the returned buffer using g_free
 *
 * \param l the log reference to serialise
 * \param output_data_size the size of the output buffer
 * \returns the output buffer, or NULL on error.
 */
char *log_serialise(log_t l, unsigned int *output_data_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Clones a log reference.
 *
 * \warning The returned reference must be freed by the caller using log_close.
 *
 * \param l the log reference to clone
 * \returns an identical log reference or NULL on error
 */
log_t log_clone(log_t l) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Gets the sender ID for this log message.
 *
 * Do not free the returned string.
 *
 * \param l the log reference
 * \returns the sender ID or NULL on error
 */
const char *log_get_sender_id(log_t l) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the sender ID.
 *
 * \param l the log reference
 * \param sender_id the ID string of the sender (may not be NULL)
 * \returns 0 on success, -1 on error
 */
int log_set_sender_id(log_t l, const char *sender_id);

/**
 * Gets the severity of this log message.
 *
 * \param l the log reference
 * \returns the severity, or -1.
 */
int log_get_severity(log_t l) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the severity.
 *
 * \param l the log reference.
 * \param severity The severity of the message. One of LOG_SEVERITY_{DEBUG,INFO,WARNING,ERROR,SEVERE}
 * \returns 0 on success, -1 on error.
 */
int log_set_severity(log_t l, const unsigned int severity);

/**
 * Gets the message attached to this log message.
 *
 * \param l the log reference
 * \returns the message, or NULL.
 */
const char *log_get_message(log_t l) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the message.
 *
 * \param l the log reference
 * \param message The message to set (may not be NULL)
 * \returns 0 on success, -1 on error
 */
int log_set_message(log_t l, const char *message);

/**
 * Gets the timestamp for this log message in seconds.
 *
 * \param l the log reference
 * \returns the number of seconds since epoch or -1.
 */
long log_get_timestamp_sec(log_t l) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Gets the timestamp for this log message in microseconds.
 *
 * \param l the log reference
 * \returns the number of microseconds since the last full second or -1.
 */
long log_get_timestamp_usec(log_t l) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the timestamp for the log message.
 *
 * \param l The log reference
 * \param sec The number of seconds since epoch (must be greater than zero)
 * \param usec The number of microseconds since the last full second (must be greater than zero)
 * \returns 0 on success, -1 on error
 */
int log_set_timestamp(log_t l, long sec, long usec);

/**
 * Destroys the log reference.
 *
 * \param l the log reference to close
 * \returns 0 on success, -1 on error
 */
int log_close(log_t l);

#endif
