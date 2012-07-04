/* Pronghorn Log Server
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

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>

#include <glib.h>

#include <transport.h>
#include <log.h>
#include <logger.h>
#include <basename_safe.h>

#include <config.h>

/** This is the name of the process */
const char *SHORT_PROCESS_NAME = NULL;

/** This is the name of the process */
const char *PROCESS_NAME = NULL;

static FILE *general_output_file = NULL;
static FILE *debug_output_file = NULL;
static FILE *info_output_file = NULL;
static FILE *warning_output_file = NULL;
static FILE *error_output_file = NULL;
static FILE *severe_output_file = NULL;

static FILE *open_output_file(int append, const char *option_name)
{
  char *filename = NULL;

  if ((config_get(NULL, option_name, &filename) == 0) && (filename != NULL))
  {
    // Success
    if (strlen(filename) > 0)
    {
      if (append == 0)
      {
        FILE *file = fopen(filename, "w");

        g_free(filename);
        return file;
      } else
      {
        FILE *file = fopen(filename, "a");

        g_free(filename);
        return file;
      }
    }
  }

  return NULL;
}

static void open_output_files(void)
{
  int append;

  if (config_get_int_with_default_macro(NULL, CONFIG_LOG_SERVER_OUTPUT_FILE_APPEND, &append) != 0)
  {
    // Bad things?
    warning_log("Could not contact the log server?");
    return;
  }

  general_output_file = open_output_file(append, CONFIG_LOG_SERVER_GENERAL_OUTPUT_FILE_OPTION_NAME);
  debug_output_file = open_output_file(append, CONFIG_LOG_SERVER_DEBUG_OUTPUT_FILE_OPTION_NAME);
  info_output_file = open_output_file(append, CONFIG_LOG_SERVER_INFO_OUTPUT_FILE_OPTION_NAME);
  warning_output_file = open_output_file(append, CONFIG_LOG_SERVER_WARNING_OUTPUT_FILE_OPTION_NAME);
  error_output_file = open_output_file(append, CONFIG_LOG_SERVER_ERROR_OUTPUT_FILE_OPTION_NAME);
  severe_output_file = open_output_file(append, CONFIG_LOG_SERVER_SEVERE_OUTPUT_FILE_OPTION_NAME);
}

static void log_output(FILE * output_file, log_t l)
{
  fprintf(output_file, "%ld.%06ld %s: [%s] %s\n", log_get_timestamp_sec(l), log_get_timestamp_usec(l), log_get_sender_id(l), log_get_severity_string(log_get_severity(l)), log_get_message(l));

  fflush(output_file);          // Will slow things down, but worth it (I think)
}

/**
 * The main log server routine
 *
 * \return 0 on clean exit, -1 on failed exit
 *
 * Simply listens on the address provided on zeroMQ for log messages
 * and prints them out.
 */
int main(int argc, char **argv)
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];
  // Stop buffering on stdout and stderr
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (argc != 2)
  {
    severe_log("Usage: %s <config endpoint>", argv[0]);
    return -1;
  }

  if (config_init(argv[1]) != 0)
  {
    severe_log("Logserver unable to connect to the config server: %s", strerror(errno));
    return -1;
  }

  logger_config_init();

  open_output_files();

  char *endpoint;

  if (config_get_with_default_macro(NULL, CONFIG_LOG_LISTEN_ENDPOINT, &endpoint) != 0)
  {
    severe_log("Logserver unable to get logger endpoint!");
    return -1;
  }

  transport_t listen_transport = transport_init(TRANSPORT_TYPE_PULL, endpoint);

  if (listen_transport == NULL)
  {
    error_log("Error starting up the log server: %s", strerror(errno));
    return -1;
  }

  debug_log("Logserver is now listening on %s", endpoint);

  int quit = 0;

  while (quit == 0)
  {
    unsigned int logmsg_size;

    const char *logmsg = transport_recv(listen_transport, NULL, &logmsg_size);

    if (logmsg == NULL)
    {
      debug_log("Logserver had issue with transport_recv: %s", strerror(errno));
      continue;
    }

    log_t l = log_init(logmsg, logmsg_size);

    if (l == NULL)
    {
      error_log("Logserver couldn't reconstruct log message: %s", strerror(errno));
      continue;
    }

    int output = 0;

    if (general_output_file != NULL)
    {
      log_output(general_output_file, l);
      output = 1;
    }

    switch (log_get_severity(l))
    {
    case LOG_SEVERITY_DEBUG:
      if (debug_output_file != NULL)
      {
        log_output(debug_output_file, l);
        output = 1;
      }
      break;
    case LOG_SEVERITY_INFO:
      if (info_output_file != NULL)
      {
        log_output(info_output_file, l);
        output = 1;
      }
      break;
    case LOG_SEVERITY_WARNING:
      if (warning_output_file != NULL)
      {
        log_output(warning_output_file, l);
        output = 1;
      }
      break;
    case LOG_SEVERITY_ERROR:
      if (error_output_file != NULL)
      {
        log_output(error_output_file, l);
        output = 1;
      }
      break;
    case LOG_SEVERITY_SEVERE:
      if (severe_output_file != NULL)
      {
        log_output(severe_output_file, l);
        output = 1;
      }
      break;
    }

    if (output != 1)
    {
      // This message wasn't output
      // Let's output it now
      log_output(stderr, l);
    }

    if (strcmp(log_get_message(l), "quit") == 0)
    {
      quit = 1;
    }

    log_close(l);
  }

  transport_close(listen_transport);

  return 0;
}
