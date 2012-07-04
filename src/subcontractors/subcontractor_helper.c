/* Pronghorn Subcontractor Helper
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <glib.h>

#include <transport.h>
#include <log.h>
#include <contract.h>
#include <result.h>
#include <report.h>
#include <config.h>
#include <defaults.h>
#include <blocks.h>
#include <basename_safe.h>
#include <prong_assert.h>

#include "subcontractor_helper.h"

/** This is the name of the current process */
const char *SHORT_PROCESS_NAME = NULL;

/** This is the name of the current process */
const char *PROCESS_NAME = NULL;

/** This is our end of the comms channel with the upstream contractor */
static transport_t contractor_upstream_transport = NULL;
static int block_size = 0;

static int setup_logging(void)
{
  int ret = logger_config_init();

  if (ret != 0)
  {
    severe_log("Failed to create log transport: %s", strerror(errno));
    return -1;
  }

  return 0;
}

int setup_upstream_transport(char *endpoint)
{
  contractor_upstream_transport = transport_init(TRANSPORT_TYPE_PULLPUSH, endpoint);

  if (contractor_upstream_transport == NULL)
  {
    severe_log("Failed to create upstream transport on address %s. Errno = %d", endpoint, errno);
    return -1;
  }
  // Set the timeout to -1. A key assumption is that contractors don't die. If we end up
  // in some hung state, it's the contractor's job to kill us anyway. 
  transport_set_recv_timeout(contractor_upstream_transport, -1);

  return 0;
}

int run_main_subcontactor_loop(void)
{
  debug_log("Sub contractor is starting its main loop");

  contract_t new_contract = NULL;
  unsigned int msg_size;
  const char *msg = transport_recv(contractor_upstream_transport, NULL, &msg_size);

  debug_log("Sub got its first message!");

  int finished = 0;

  while (finished == 0)
  {
    if (msg == NULL)
    {
      severe_log("Received a null message. Something went wrong. Exiting");
      break;
    }

    new_contract = contract_init(msg, msg_size);

    if (new_contract == NULL)
    {
      severe_log("Couldn't parse a message from the contractor.");
      // Need to send back some junk otherwise the contractor will hang
      transport_send(contractor_upstream_transport, "Bad read", NULL, 9);
      continue;
    }

    if (strcmp(contract_get_path(new_contract), "") == 0)
    {
      info_log("Received an empty contract from the contractor. Assuming my work here is done!");
      finished = 1;
      contract_close(new_contract);

      // Send back some junk to show we've closed down OK
      transport_send(contractor_upstream_transport, "Bye", NULL, 4);
      break;
    }
    // Else, yay, a valid contract! Process it!
    contract_completion_report_t ccr = contract_completion_report_init(NULL, 0);

    contract_completion_report_set_original_contract(ccr, new_contract);

    int ret = analyse_contract(new_contract, ccr);

    if (ret != 0)
    {
      warning_log("Analysis function produced an error!");
    } else
    {
      debug_log("Analysis function produced output!");
    }

    // We need to pass this back to the upstream transport!
    unsigned int to_send_size;
    char *to_send = contract_completion_report_serialise(ccr, &to_send_size);

    debug_log("Sending result back to contractor!");

    transport_send(contractor_upstream_transport, to_send, NULL, to_send_size); 
    g_free(to_send);

    contract_completion_report_close(ccr);
    contract_close(new_contract);

    debug_log("Now receving next job");

    msg = transport_recv(contractor_upstream_transport, NULL, &msg_size);
  }

  return 0;
}

static void register_data_types(const char *mypath)
{
  //debug_log("Registering supported data types");

  for (unsigned int *type = supported_file_types; *type != 0; type++)
  {
    debug_log("Registering interest for data type: %s(%u)", lightmagic_text_representation(*type), *type);

    char *registered_subcontractors = NULL;
    const char *type_string = lightmagic_text_representation(*type);

    if ((config_get(CONFIG_GENERAL_GROUP_OPTION_NAME, type_string, &registered_subcontractors) != 0) || (registered_subcontractors == NULL))
    {
      // No currently registered subcontractors for this data type! Time to add ourselves
      if (config_set(CONFIG_GENERAL_GROUP_OPTION_NAME, type_string, mypath) != 0)
      {
        error_log("Error registering our interest for a data type! errno = %d", errno);
      }
    } else
    {
      // Check to make sure we're not duplicating an entry
      if (strstr(registered_subcontractors, mypath) != NULL)
      {
        g_free(registered_subcontractors);
        continue;
      }
      // We need to append to this string
      char *new_list_of_subcontractors = g_strdup_printf("%s,%s", registered_subcontractors, mypath);

      g_free(registered_subcontractors);
      if (config_set(CONFIG_GENERAL_GROUP_OPTION_NAME, type_string, new_list_of_subcontractors) != 0)
      {
        error_log("Error registering our interest for a data type! errno = %d", errno);
      }
      g_free(new_list_of_subcontractors);
    }
  }
}

/**
 * Prints the usage statement to screen.
 */
static void print_usage(void)
{
  error_log("Usage: %s <configserver endpoint> <contractor endpoint>", PROCESS_NAME);
  error_log("This is a Pronghorn subcontractor");
  error_log("(alternate usage: %s <configserver endpoint> - though you probably don't want this as it ONLY populates the config object)", PROCESS_NAME);
}

/**
 * Starts the process.
 *
 * \param argc Num of args
 * \param argv Args
 * \returns 0 on success, -1 on error
 */
int main(int argc, char *argv[])
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];
  // Stop buffering on stdout and stderr
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // We need at least one argument
  if (argc < 2)
  {
    print_usage();
    return -1;
  }
  // Starting the config manager and the logger
  if (config_init(argv[1]) != 0)
  {
    error_log("Unable to setup config object. Is there a problem with the endpoint syntax? %s", argv[1]);
    return -1;
  }

  if (setup_logging() != 0)
  {
    warning_log("Could not setup logging!");
  }
  // We accept either one or two arguments.
  // If we receive one argument then the MCP is asking us to register our interest for
  // data types - then exit
  if (argc == 2)
  {
    if (subcontractor_init() != 0)
    {
      error_log("Failed to init subcontractor! Electing not to register it");
//                      return -1;
    }
    // Register supported data types
    register_data_types(argv[0]);

    logger_close();
    config_close();
    return 0;
  }
  // If we receive two arguments then we're doing some work.
  // The two arguments are the transport address of the
  // global configuration server and the endpoint to talk to the contractor
  if (argc != 3)
  {
    print_usage();
    logger_close();
    config_close();
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_BLOCK_SIZE, &block_size) != 0)
  {
    error_log("Unable to get block size! This indicates a problem with the config service.");
    block_size = 512;
  } else
  {
    //debug_log("Using block size of %i", block_size);
  }

  debug_log("Sub contractor starting up");

  if (setup_upstream_transport(argv[2]) != 0)
  {
    error_log("Unable to setup upstream transport");
    logger_close();
    config_close();
    return -1;
  }

  if (subcontractor_init() != 0)
  {
    error_log("Subcontractor reported an error during init!");
    transport_close(contractor_upstream_transport);
    logger_close();
    config_close();
    return -1;
  }

  debug_log("Sub contractor setup completed OK.");

  debug_log("About to commence main sub contractor loop for %s", SHORT_PROCESS_NAME);

  int ret = run_main_subcontactor_loop();

  debug_log("Subcontractor exited with return code %d", ret);

  if (subcontractor_close() != 0)
  {
    warning_log("Subcontractor reported an error during close()");
  }

  transport_close(contractor_upstream_transport);
  logger_close();
  config_close();

  return ret;
}

/*
 * Populates a result for you to add it to the contract completion report
 * Calls add_result_blocks with Blocks = NULL and b_size = 0 indicate blocks not found.
 */
int populate_result(result_t result, const gchar * brief_description, const gchar * description, int conf)
{
  return populate_result_blocks(result, brief_description, description, conf, NULL, 0);
}

/*
 * Populates a result for you to add it to the contract completion report
 */
int populate_result_blocks(result_t result, const gchar * brief_description, const gchar * description, int confidence, block_range_t * ranges, int num_ranges)
{
  int error = 0;

  if (result_set_data_description(result, description) != 0)
  {
    error_log("Couldn't set data description in result");
    error = 1;
  }

  if (result_set_brief_data_description(result, brief_description) != 0)
  {
    error_log("Couldn't set brief data descirption in result");
    error = 1;
  }

  if (result_set_confidence(result, confidence) != 0)
  {
    error_log("Couldn't set confidence in result");
    error = 1;
  }

  if ((ranges != NULL) && (num_ranges != 0))
  {
    if (result_set_block_ranges(result, ranges, num_ranges) != 0)
    {
      error_log("Couldn't set blocks in result");
      error = 1;
    }
  }

  if (error == 1)
  {
    return -1;
  }

  return 0;
}

/*
 * Populates a result for you to add it to the contract completion report
 */
int populate_result_with_length(result_t result, const gchar * brief_description, const gchar * description, int confidence, long long int abs_off, unsigned long long length, int is_contiguous)
{
  if ((is_contiguous == 0) || (abs_off == -1) || (length == 0))
  {
    return populate_result(result, brief_description, description, confidence);
  }

  block_range_t range = block_range_init(NULL, 0);

  int ret = block_range_set_range(range, abs_off / block_size, ((length - 1) / block_size) + 1);
  prong_assert(ret == 0);

  ret = populate_result_blocks(result, brief_description, description, confidence, &range, 1);

  block_range_close(range);

  return ret;
}
