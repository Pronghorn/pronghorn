/* libpronghorn configuration server
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
 * \file pronghorn.c
 * \brief This server provides a centralised configuration storage and
 * retrieval mechanism for every Pronghorn process
 *
 * It also launches the logserver and the MCP. This is the program that starts Pronghorn
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libgen.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <glib.h>

#include <basename_safe.h>
#include <logger.h>
#include <transport.h>
#include <config.h>
#include <defaults.h>
#include <lprocess.h>

#include "config_management.h"

/** This is the pid of the logserver (or 0 if it's not running) */
static volatile sig_atomic_t logserver_pid = 0;

/** This is the exit status of the logserver  */
static volatile sig_atomic_t logserver_status = 0;

/** This is the pid of the MCP (or 0 if it's not running) */
static volatile sig_atomic_t mcp_pid = 0;

/** This is the exit status of the mcp */
static volatile sig_atomic_t mcp_status = 0;

/** This is indicates Pronghorn wants to quit (When -1) */
static volatile sig_atomic_t quitting_time = 0;

/** This is the name of the current process */
const char *SHORT_PROCESS_NAME = NULL;

/** This is the name of the current process */
const char *PROCESS_NAME = NULL;

/** The process group of pronghorn */
//static pid_t process_group = -1;

/**
 * This is the sigchld handler for this process.
 *
 * It is responsible for reaping children.
 *
 * Unless the program is terminating, any children that die cause
 * the entire process to exit.
 *
 * \warning We can't use any printfs/transport/logger functions in here!
 *
 * \param sig The signal (should be SIGCHLD)
 * \param sig_info Information about the signal
 *
 * \param ucontext Nothing we care about
 */
static void sigchld_handler(int sig, siginfo_t * sig_info, void *ucontext)
{
  // Reaping the child
  int status;
  int pid;

  // Two signals that happen at the same time may be merged into one
  // http://www.cs.utah.edu/dept/old/texinfo/glibc-manual-0.02/library_toc.html#SEC356
  while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
  {
    if ((WIFEXITED(status) == TRUE) || WIFSIGNALED(status) == TRUE)
    {
      quitting_time = -1;
      if (pid == logserver_pid)
      {
        logserver_pid = 0;
        logserver_status = status;
      }

      if (pid == mcp_pid)
      {
        mcp_pid = 0;
        mcp_status = status;
      }
    }
  }
}

/**
 * Sets up the SIGCHLD handler
 *
 * \returns 0 on success, -1 on error
 */
static int setup_sigchld_handler(void)
{
  struct sigaction action;

  memset(&action, 0, sizeof(action));
  action.sa_sigaction = sigchld_handler;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGCHLD, &action, NULL))
  {
    warning_log("problem setting sigaction for SIGCHLD (%s)", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * Starts the config server listening on the required endpoint
 *
 * \warning The caller must close the transport using transport_close
 *
 * \param endpoint The endpoint to listen on
 * \returns The transport reference, or NULL on error
 */
static transport_t start_listening(const char *endpoint)
{
  transport_t transport = transport_init(TRANSPORT_TYPE_PULLPUSH, endpoint);

  if (transport == NULL)
  {
    error_log("Pronghorn failed to create transport! (%s)", strerror(errno));
    return NULL;
  }

  info_log("Pronghorn listening on %s", endpoint);
  return transport;
}

/**
 * Starts the log server
 * 
 * It requires the config file so the function can determine how to spawn the log server
 *
 * \param config The config file
 * \param endpoint The endpoint for this process
 * \returns 0 on success, -1 on error
 */
static int spawn_log_server(GKeyFile * config, const char *endpoint)
{
  char *args[3];

  args[0] = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_LOGSERVER_EXECUTABLE_NAME_OPTION_NAME);
  if (args[0] == NULL)
  {
    args[0] = g_strdup(CONFIG_LOGSERVER_EXECUTABLE_NAME_DEFAULT);
  }

  args[0] = expand_variables(config, args[0]);
  args[1] = g_strdup(endpoint);
  args[2] = NULL;

  char *valgrind_options = g_key_file_get_param(config, basename_safe(args[0]), CONFIG_VALGRIND_OPTION_NAME);

  debug_log("Spawning logserver: %s", args[0]);

  int ret = spawn_limited_process_with_valgrind(args, (sig_atomic_t *) & logserver_pid, -1, -1, -1, valgrind_options);

  g_free(args[0]);
  g_free(args[1]);

  if (ret != 0)
  {
    return -1;
  }

  return 0;
}

/**
 * Changes the logger reference to use the newly spawned logserver
 *
 * \param config The config reference
 * \returns 0 on success, -1 on error
 */
static int use_logserver(GKeyFile * config)
{
  char *log_level_string = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_LOG_VERBOSITY_OPTION_NAME);

  if (log_level_string == NULL)
  {
    log_level_string = g_strdup(CONFIG_LOG_VERBOSITY_DEFAULT);
  }

  int log_level = lookup_verbosity(log_level_string);

  if (log_level == -1)
  {
    error_log("The log level was invalid! Log level = %s", log_level_string);
    g_free(log_level_string);
    return -1;
  }
  debug_log("Log level=%s which resolved to %i", log_level_string, log_level);
  g_free(log_level_string);
  set_log_level(log_level);

  char *log_to_stderr_only = g_key_file_get_param(config, SHORT_PROCESS_NAME, CONFIG_FORCE_STDERR_LOGGING);

  if (log_to_stderr_only == NULL)
  {
    log_to_stderr_only = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_FORCE_STDERR_LOGGING);
  }

  if ((log_to_stderr_only != NULL) && (atoi(log_to_stderr_only) != 0))
  {
    // Report success, even though we haven't done anything
    return 0;
  }

  char *logserver_endpoint = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_LOG_CONNECT_ENDPOINT_OPTION_NAME);

  if (logserver_endpoint == NULL)
  {
    logserver_endpoint = g_strdup(CONFIG_LOG_CONNECT_ENDPOINT_DEFAULT);
  }

  int timeout = CONFIG_LOG_TIMEOUT_DEFAULT;
  char *timeout_string = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_LOG_TIMEOUT_OPTION_NAME);

  if (timeout_string != NULL)
  {
    timeout = atoi(timeout_string);
    g_free(timeout_string);
  }

  debug_log("Now switching to using the logserver at %s (timeout=%d, verbosity=%i)", logserver_endpoint, timeout, log_level);

  int ret = 0;

  ret = logger_init(log_level, logserver_endpoint, timeout);
  g_free(logserver_endpoint);

  if (ret != 0)
  {
    warning_log("Unable to init logger");
    return -1;
  }

  debug_log("I am now talking to you from the logserver");

  return 0;
}

/**
 * Starts the MCP
 *
 * It requires the config file so the function can determine how to spawn the log server
 *
 * \param config The config file
 * \param endpoint The endpoint for the configuration sever
 * returns 0 on success, -1 on error
 */
static int spawn_mcp(GKeyFile * config, const char *endpoint)
{
  char *args[3];

  args[0] = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_MCP_EXECUTABLE_NAME_OPTION_NAME);

  if (args[0] == NULL)
  {
    args[0] = g_strdup(CONFIG_MCP_EXECUTABLE_NAME_DEFAULT);
  }
  args[0] = expand_variables(config, args[0]);
  args[1] = g_strdup(endpoint); 
  args[2] = NULL;

  char *valgrind_options = g_key_file_get_param(config, basename_safe(args[0]), CONFIG_VALGRIND_OPTION_NAME);

  debug_log("Spawning mcp: %s", args[0]);

  int ret = spawn_limited_process_with_valgrind(args, (sig_atomic_t *) & mcp_pid, -1, -1, -1, valgrind_options);

  g_free(args[0]);
  g_free(args[1]);

  if (ret != 0)
  {
    ret = 0;
    return -1;
  }
  return 0;
}

/**
 * Starts the server and serves all incoming requests.
 *
 * \param config The key file to serve out
 * \param transport The transport reference to communicate
 */
static void serve_config(GKeyFile * config, transport_t transport)
{
  long timeout = CONFIG_CONFIG_TIMEOUT_DEFAULT;

  char *timeout_string = g_key_file_get_param(config,
                                              CONFIG_GENERAL_GROUP_OPTION_NAME,
                                              CONFIG_CONFIG_TIMEOUT_OPTION_NAME);

  if (timeout_string != NULL)
  {
    timeout = atol(timeout_string);
  }

  transport_set_recv_timeout(transport, timeout);

  // Time to switch to using the logserver
  if (use_logserver(config) != 0)
  {
    return;
  }

  debug_log("Serving config");

  int quit = 0;

  while ((quit == 0) && (mcp_pid > 0) && (logserver_pid > 0))
  {
    int size;
    const char *request = transport_recv(transport, &quitting_time, &size);

    if (request == NULL)
    {
      // Must have been interrupted or timed out
      continue;
    }
    // Are we being asked to quit?
    if ((strcasecmp(request, "exit") == 0) || (strcasecmp(request, "quit") == 0))
    {
      debug_log("Exit received");
      quit = 1;
      transport_send(transport, QUIT_RESPONSE, &quitting_time, strlen(QUIT_RESPONSE) + 1);
      continue;
    }
    // If the request is empty, return all data
    if (size <= 1)
    {
      debug_log("All config data requested");
      gsize data_size;
      char *response = g_key_file_to_data(config, &data_size, NULL);

      transport_send(transport, response, &quitting_time, data_size);
      g_free(response);
      continue;
    }

    char *group;
    char *key;
    char *value;

    // See if the request is to set a value
    if (parse_group_key_value(request, &group, &key, &value) == 0)
    {
      debug_log("Set %s.%s=%s", group, key, value);
      g_key_file_set_param(config, group, key, value);
      g_free(group);
      g_free(key);
      g_free(value);
      transport_send(transport, SUCCESS_RESPONSE, &quitting_time, strlen(SUCCESS_RESPONSE) + 1);
      continue;
    }
    // See if the request is to get a value
    if (parse_group_key(request, &group, &key) == 0)
    {
      value = g_key_file_get_param(config, group, key);

      if (value != NULL)
      {
        value = expand_variables(config, value);
        debug_log("Get %s.%s=%s", group, key, value);
        transport_send(transport, value, &quitting_time, strlen(value) + 1);
        g_free(value);
      } else
      {
        debug_log("Get %s.%s does not exist", group, key);
        transport_send(transport, NULL_RESPONSE, &quitting_time, strlen(NULL_RESPONSE) + 1);
      }
      g_free(group);
      g_free(key);
      continue;
    }
    // Unknown request
    transport_send(transport, ERROR_RESPONSE, &quitting_time, strlen(ERROR_RESPONSE) + 1);
  }
  // We destroy the logserver now as we can't be guaranteed that it is up and running
  logger_close();

  quit = 1;
  if (logserver_pid == 0)
  {
    if (WIFEXITED(logserver_status))
    {
      int code = WEXITSTATUS(logserver_status);

      if (code == 0)
      {
        info_log("The logserver died with return value %d", code);
      } else
      {
        error_log("The logserver died with return value %d", code);
      }
    } else
    {
      error_log("The logserver was killed with signal %d", WTERMSIG(logserver_status));
    }
  }
  if (mcp_pid == 0)
  {
    if (WIFEXITED(mcp_status))
    {
      int code = WEXITSTATUS(mcp_status);

      if (code == 0)
      {
        info_log("The MCP died with return value %d", code);
      } else
      {
        error_log("The MCP died with return value %d", code);
      }
    } else
    {
      error_log("The MCP was killed with signal %d", WTERMSIG(mcp_status));
    }
  }
}

/**
 * Kills the logserver and mcp.
 */
void kill_children(void)
{
  // Killing off our children
  volatile int local_mcp_pid = mcp_pid;

  if (local_mcp_pid > 0)
  {
    debug_log("Sending SIGINT to MCP");
    kill(local_mcp_pid, SIGINT);
    sleep(10);
    local_mcp_pid = mcp_pid;
    if (local_mcp_pid != 0)
    {
      debug_log("Sending SIGKILL to MCP");
      kill(local_mcp_pid, SIGKILL);
    } else
    {
      debug_log("MCP died");
    }
  }

  volatile int local_logserver_pid = logserver_pid;

  if (local_logserver_pid > 0)
  {
    logger_close();
    // We need to wait for the logserver to receive and process all messages - otherwise they get lost!
    sleep(1);
    debug_log("Sending SIGINT to logserver");
    kill(local_logserver_pid, SIGINT);
    sleep(10);
    local_logserver_pid = logserver_pid;
    if (local_logserver_pid != 0)
    {
      debug_log("Sending SIGKILL to logserver");
      kill(local_logserver_pid, SIGKILL);
    } else
    {
      debug_log("Logserver died");
    }
  }
  // And then try and kill everything
  //killpg(process_group, SIGKILL);

}


/**
 * \brief If the security warning is enabled, print it to stdout
 * \config The current config options
 *
 */
void check_security_warning(GKeyFile * config)
{

  const char *ok = "OK";
  const char *ok_l = "ok";
	const char *ok_m = "Ok";

  char *security = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_WARN_ABOUT_SECURITY_OPTION_NAME);

  if (security == NULL || (g_strcmp0(security, ok) != 0 && g_strcmp0(security, ok_l) != 0 && g_strcmp0(security, ok_m)))
  {

    printf("\n"
    "#######################\n"
    "WARNING - DO NOT USE THIS CODE ON PRODUCTION SYSTEMS.\n"
    "#######################\n\n"
    "The supplied code is a prototype solution that is not guaranteed to be error free.\n\n"
    "Pronghorn makes extensive use of untrusted third party libraries. The efficacy of the code cannot be assured. The consequences of failure of the software include (but are not limited to)\n\n"
    "- Exploitation of the system (via a suitably crafted disk image being analysed)\n"
    "- Loss of files on the system the code is run on.\n\n"
    "DSD strongly encourages the use of safe computing practices, such as running code using accounts with limited privileges. For more examples please refer to DSD's list of Top 35 mitigation strategies http://dsd.gov.au/infosec/top35mitigationstrategies.htm\n\n"
    "######################\n\n"
    "To disable this warning add \"-o general.security_warning=OK\" to the end of the command line.\n\n");
  }
}


/**
 * Starts the process.
 *
 * \param argc The number of args
 * \param argv The arg array
 * \returns 0 on success, -1 on error
 */
int main(int argc, char *argv[])
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];

  // Stop buffering on stdout and stderr
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // Set ourselves to be the process leader
  //process_group = setpgrp();

  GKeyFile *config = generate_config(argc, argv);

  if (config == NULL)
  {
    return -1;
  }

#ifdef DEBUG
  fprintf(stderr, "==========\n");
  fprintf(stderr, "Runtime config settings\n");
  gsize data_size;
  char *response = g_key_file_to_data(config, &data_size, NULL);

  fprintf(stderr, "%s", response);
  fprintf(stderr, "==========\n\n");
  g_free(response);
#endif

  check_security_warning(config);

  char *endpoint = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_CONFIG_LISTEN_ENDPOINT_OPTION_NAME);

  if (endpoint == NULL)
  {
    endpoint = g_strdup(CONFIG_CONFIG_LISTEN_ENDPOINT_DEFAULT);
  }

  if (setup_sigchld_handler() != 0)
  {
    severe_log("Unable to setup signal handler for sigchld");
    g_free(endpoint);
    g_key_file_free(config);
    return -1;
  }

  transport_t transport = start_listening(endpoint);

  if (transport == NULL)
  {
    severe_log("Error starting the config server listening endpoint");
    g_free(endpoint);
    g_key_file_free(config);
    return -1;
  }

  g_free(endpoint);
  endpoint = g_key_file_get_param(config, CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_CONFIG_CONNECT_ENDPOINT_OPTION_NAME);

  if (endpoint == NULL)
  {
    endpoint = g_strdup(CONFIG_CONFIG_CONNECT_ENDPOINT_DEFAULT);
  }

  if (spawn_log_server(config, endpoint) != 0)
  {
    severe_log("Error spawning the logserver. Error=%s", strerror(errno));
    transport_close(transport);
    g_free(endpoint);
    g_key_file_free(config);
    return -1;
  }

  if (spawn_mcp(config, endpoint) != 0)
  {
    severe_log("Error spawning the MCP");
    transport_close(transport);
    g_free(endpoint);
    g_key_file_free(config);
    kill_children();
    return -1;
  }
  // After this the log server is up and running and we have switched to using it
  serve_config(config, transport);

  debug_log("Pronghorn has left the building");

  transport_close(transport);
  g_free(endpoint);

  g_key_file_free(config);
  config = NULL;

  kill_children();

  return 0;
}
