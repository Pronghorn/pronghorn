/* libpronghorn logger library
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
 * \file logger.h
 * \brief Library functions for the remote logging facility
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <glib.h>

/** Indicates the message is only used for debugging purposes. */
#define LOG_SEVERITY_DEBUG 1
/** Indicates the message is only for info */
#define LOG_SEVERITY_INFO 2
/** Indicates the message indicated a non-critical warning */
#define LOG_SEVERITY_WARNING 3
/** Indicates an error has occurred but may be handled internally */
#define LOG_SEVERITY_ERROR 4
/** Indicates a severe error has occured causing the application to stop. */
#define LOG_SEVERITY_SEVERE 5

/** The ID name of the owner of this logger reference. Everyone MUST populate this in main() */
extern const char *SHORT_PROCESS_NAME;

/** The ID name of the owner of this logger reference. Everyone MUST populate this in main() */
extern const char *PROCESS_NAME;

/** This is the global logger reference */
//extern struct logger* global_logger;
/** This is the global log level filter */
//extern int global_log_level;

/**
 * Initializing the logger object. 
 *
 * Consider using logger_config_init instead as it reads the global configuration values for you
 *
 * \warning Not thread safe!
 *
 * If this is not called before attempting to send messages it will
 * send the message to stderr instead.
 *
 * \param logLevel The log level for filtering. All levels lower than this will be filtered. Must be one of LOG_SEVERITY_{DEBUG,INFO,WARNING,ERROR,SEVERE}
 * \param endpoint The remote logserver endpoint.
 * \param timeout_milliseconds The send timeout in milliseconds
 * \returns 0 on success, -1 on error.
 */
int logger_init(unsigned int logLevel, const char *endpoint, int timeout_milliseconds);

/**
 * Call this function instead of calling logger_init if you have already initialised your config object.
 * 
 * This will automatically load your logger configuration from the config server.
 *
 * \warning It is an error to call this function without first initialising your config object
 *
 * \returns 0 on success, -1 on error
 */
int logger_config_init(void);

/**
 * Sets the log level for the logger reference.
 *
 * The log level is a filter, and any messages lower in severity than this log level will be silently dropped.
 *
 * The log severity levels, in descending order, are
 *
 * LOG_SEVERITY_SEVERE
 * LOG_SEVERITY_ERROR
 * LOG_SEVERITY_WARNING
 * LOG_SEVERITY_INFO
 * LOG_SEVERITY_DEBUG
 *
 * It's safe to call this without calling logger_init first. In this case
 * it will simply filter messages before sending the messages to stderr.
 *
 * \param new_severity The severity to filter on.
 * \returns 0 on success, -1 on error.
 */
int set_log_level(unsigned int new_severity);

/**
 * Returns the severity value as a string.
 *
 * \param severity The severity value
 * \returns A string (do not free)
 */
const char *log_get_severity_string(unsigned int severity) G_GNUC_WARN_UNUSED_RESULT;

#define debug_log(...) debug_log_real("[" G_STRLOC "] " __VA_ARGS__)

/**
 * Used to write a debug event to the logger.
 *
 * \param format The message to send. Identical to the format for printf.
 * \returns 0 on success, -1 on error. errno is set
 */
int debug_log_real(const char *format, ...) G_GNUC_PRINTF(1, 2);

/**
 * Used to write a info event to the logger.
 *
 * \param format The message to send. Identical to the format for printf.
 * \returns 0 on success, -1 on error. errno is set
 */
int info_log(const char *format, ...) G_GNUC_PRINTF(1, 2);

/**
 * Used to write a warning event to the logger.
 *
 * \param format The message to send. Identical to the format for printf.
 * \returns 0 on success, -1 on error. errno is set
 */
int warning_log(const char *format, ...) G_GNUC_PRINTF(1, 2);

/**
 * Used to write a error event to the logger.
 *
 * \param format The message to send. Identical to the format for printf.
 * \returns 0 on success, -1 on error. errno is set
 */
int error_log(const char *format, ...) G_GNUC_PRINTF(1, 2);

/**
 * Used to write a severe event to the logger.
 *
 * \param format The message to send. Identical to the format for printf.
 * \returns 0 on success, -1 on error. errno is set
 */
int severe_log(const char *format, ...) G_GNUC_PRINTF(1, 2);

/**
 * Return the int representation of a vebosity string
 *
 * \param text_verbosity A textual representation of verbosity (e.g. WARN)
 * \return The verbosity value as an int, -1 if it wasn't valid
 */
int lookup_verbosity(const char *text_verbosity) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Closes the logger object.
 *
 * Must be called to free internal structures if logger_init is called.
 *
 * It's safe to call this as many times as you want.
 *
 */
void logger_close(void);

#endif
