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
 * \file logger.c
 * \brief Library functions for the remote logging facility
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <glib.h>

#include <basename_safe.h>
#include <transport.h>
#include <log.h>
#include <config.h>
#include <prong_assert.h>

#include "logger.h"

/** This defines the initial size of the logger's internal buffer */
#define INITIAL_BUFFER_SIZE 128

/** This is the PID and process name */
static char *id = NULL;

/** The desired log level filter */
static int logLevel = LOG_SEVERITY_DEBUG;

/** The transport object */
static transport_t transport = NULL;

/** The internal buffer */
static char *buffer = NULL;

/** The size of the internal buffer */
static int buffer_size = 0;

int logger_init(int _logLevel, const char *endpoint, int timeout_milliseconds)
{
  prong_assert(logLevel >= LOG_SEVERITY_DEBUG);
  prong_assert(logLevel <= LOG_SEVERITY_SEVERE);
  prong_assert(endpoint != NULL);

  if (id != NULL)
  {
    g_free(id);
  }
  id = g_strdup_printf("PID(%d) %s", getpid(), basename_safe(PROCESS_NAME));

  logLevel = _logLevel;

  if (transport == NULL)
  {
    transport_close(transport);
  }
  transport = transport_init(TRANSPORT_TYPE_PUSH, endpoint);
  if (transport == NULL)
  {
    g_free(id);
    return -1;
  }

  transport_set_send_timeout(transport, timeout_milliseconds);

  return 0;
}

int logger_config_init(void)
{
  char *verbosity_string;

  if (config_get_with_default_macro(NULL, CONFIG_LOG_VERBOSITY, &verbosity_string) != 0)
  {
    error_log("Unable to get log verbosity! This indicates a problem with the config service.");
    return -1;
  }
  int verbosity = lookup_verbosity(verbosity_string);

  logLevel = verbosity;
  g_free(verbosity_string);
  if (verbosity == -1)
  {
    error_log("Verbosity value is invalid!");
    return -1;
  }

  int log_to_stderr_only;

  if ((config_get_int(NULL, CONFIG_FORCE_STDERR_LOGGING, &log_to_stderr_only) == 0) && (log_to_stderr_only != 0))
  {
    // Report success, even though we haven't done anything
    return 0;
  }

  int timeout;

  if (config_get_int_with_default_macro(NULL, CONFIG_LOG_TIMEOUT, &timeout) != 0)
  {
    error_log("Unable to get log timeout! This indicates a problem with the config service.");
    return -1;
  }

  char *endpoint;

  if (config_get_with_default_macro(NULL, CONFIG_LOG_CONNECT_ENDPOINT, &endpoint) != 0)
  {
    error_log("Could not determine logger endpoint!");
    return -1;
  }

  int ret = logger_init(verbosity, endpoint, timeout);

  g_free(endpoint);

  if (ret != 0)
  {
    fprintf(stderr, "Failed to create log transport\n");
    return -1;
  }

  return 0;
}

int set_log_level(const int new_level)
{
  if ((new_level < LOG_SEVERITY_DEBUG) || (new_level > LOG_SEVERITY_SEVERE))
  {
    errno = EINVAL;
    return -1;
  }

  logLevel = new_level;

  return 0;
}

const char *log_get_severity_string(int severity)
{
  switch (severity)
  {
  case LOG_SEVERITY_DEBUG:
    return "DEBUG";
  case LOG_SEVERITY_INFO:
    return "INFO";
  case LOG_SEVERITY_WARNING:
    return "WARNING";
  case LOG_SEVERITY_ERROR:
    return "ERROR";
  case LOG_SEVERITY_SEVERE:
    return "SEVERE";
  }

  return "***INVALID***";
}

/**
 * An internal worker function to perform the logging.
 *
 * Takes VA_ARGS similar to vprintf.
 *
 * \param _l The logger reference.
 * \param severity The severity of the message
 * \param format The message to send
 * \param ap The va_list for the format paramater
 * \returns 0 on success, -1 on error.
 */
static int vlog(int severity, const char *format, va_list ap)
{
  if (logLevel > severity)
  {
    return 0;
  }

  if (buffer == NULL)
  {
    buffer = (char *) g_malloc(INITIAL_BUFFER_SIZE);
    buffer_size = INITIAL_BUFFER_SIZE;
  }

  struct timeval timestamp;

  // Populate buffer with time stamp
  if (gettimeofday(&timestamp, NULL) != 0)
  {
    // Print the message to stderr before erroring out
    fprintf(stderr, "??.?? PID(%d) %s: [%s] ", getpid(), basename_safe(PROCESS_NAME), log_get_severity_string(severity));
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");

    fflush(stderr);

    return -1;
  }

  int ret = g_vsnprintf(buffer, buffer_size, format, ap);

  if (ret < 0)
  {
    // Broken implementation of vsnprintf?
    // Print the message to stderr before erroring out
    fprintf(stderr, "%ld.%06ld PID(%d) %s: [%s] ", timestamp.tv_sec, timestamp.tv_usec, getpid(), basename_safe(PROCESS_NAME), log_get_severity_string(severity));
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");

    fflush(stderr);
    return -1;
  }

  if (ret >= buffer_size)
  {
    g_free(buffer);

    buffer = (char *) g_malloc(ret * 2);
    buffer_size = ret * 2;

    errno = EAGAIN;
    return -1;
  }

  if (id == NULL)
  {
    fprintf(stderr, "%ld.%06ld PID(%d) %s: [%s] %s\n", timestamp.tv_sec, timestamp.tv_usec, getpid(), basename_safe(PROCESS_NAME), log_get_severity_string(severity), buffer);
    return 0;
  }

  log_t log = log_init(NULL, 0);

  log_set_sender_id(log, id);
  log_set_severity(log, severity);
  log_set_timestamp(log, timestamp.tv_sec, timestamp.tv_usec);
  log_set_message(log, buffer);

  int size;
  char *s = log_serialise(log, &size);

  log_close(log);

  ret = transport_send(transport, s, NULL, size);
  g_free(s);

  return ret;
}

int debug_log_real(const char *format, ...)
{
  va_list args;

  va_start(args, format);

  int ret = vlog(LOG_SEVERITY_DEBUG, format, args);

  if ((ret == -1) && (errno == EAGAIN))
  {
    va_start(args, format);
    ret = vlog(LOG_SEVERITY_DEBUG, format, args);
  }

  va_end(args);

  return ret;
}

int info_log(const char *format, ...)
{
  va_list args;

  va_start(args, format);

  int ret = vlog(LOG_SEVERITY_INFO, format, args);

  if ((ret == -1) && (errno == EAGAIN))
  {
    va_start(args, format);
    ret = vlog(LOG_SEVERITY_INFO, format, args);
  }

  va_end(args);

  return ret;
}

int warning_log(const char *format, ...)
{
  va_list args;

  va_start(args, format);

  int ret = vlog(LOG_SEVERITY_WARNING, format, args);

  if ((ret == -1) && (errno == EAGAIN))
  {
    va_start(args, format);
    ret = vlog(LOG_SEVERITY_WARNING, format, args);
  }

  va_end(args);

  return ret;
}

int error_log(const char *format, ...)
{
  va_list args;

  va_start(args, format);

  int ret = vlog(LOG_SEVERITY_ERROR, format, args);

  if ((ret == -1) && (errno == EAGAIN))
  {
    va_start(args, format);
    ret = vlog(LOG_SEVERITY_ERROR, format, args);
  }

  va_end(args);

  return ret;
}

int severe_log(const char *format, ...)
{
  va_list args;

  va_start(args, format);

  int ret = vlog(LOG_SEVERITY_SEVERE, format, args);

  if ((ret == -1) && (errno == EAGAIN))
  {
    va_start(args, format);
    ret = vlog(LOG_SEVERITY_SEVERE, format, args);
  }

  va_end(args);

  return ret;
}

int lookup_verbosity(const char *text_verbosity)
{
  if (g_ascii_strcasecmp(text_verbosity, "DEBUG") == 0)
  {
    return LOG_SEVERITY_DEBUG;
  }

  if (g_ascii_strcasecmp(text_verbosity, "INFO") == 0)
  {
    return LOG_SEVERITY_INFO;
  }

  if (g_ascii_strcasecmp(text_verbosity, "WARN") == 0)
  {
    return LOG_SEVERITY_WARNING;
  }

  if (g_ascii_strcasecmp(text_verbosity, "ERROR") == 0)
  {
    return LOG_SEVERITY_ERROR;
  }

  if (g_ascii_strcasecmp(text_verbosity, "SEVERE") == 0)
  {
    return LOG_SEVERITY_SEVERE;
  }

  return -1;
}

void logger_close(void)
{
  if (buffer != NULL)
  {
    g_free(buffer);
    buffer = NULL;
  }
  // We need to make sure all users of transport* close() properly... otherwise
  // our messages aren't guaranteed to arrive!

  if (transport != NULL)
  {
    transport_close(transport);
    transport = NULL;
  }

  if (id != NULL)
  {
    g_free(id);
    id = NULL;
  }
}
