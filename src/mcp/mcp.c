/* Pronghorn Master Controller Program
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
 * \file mcp.c
 * \brief The mcp provides the origin of new contracts based on an input
 * source, and is responsible for co-ordinating contractors.
 *
 * This includes where actual information is provided to the user etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <glib.h>

#include <transport.h>
#include <contract.h>
#include <result.h>
#include <report.h>
#include <log.h>
#include <lprocess.h>
#include <sanity.h>
#include <basename_safe.h>

#include <config.h>
#include <lightmagic.h>
#include <prong_assert.h>

#include "defaults.h"
#include "data_source.h"
#include "contractor_controller.h"

/* Globals */

/** This is the name of the current process */
const char *SHORT_PROCESS_NAME = NULL;

/** This is the name of the current process */
const char *PROCESS_NAME = NULL;

extern volatile sig_atomic_t contractor_exited;

/** Flag to determine if the MCP is shutting down. Useful so we don't
 * abort suddenly when our log server gracefully shuts down as part
 * of the normal shutdown, for example.
 *
 * \brief Is the MCP undergoing shutdown
 */
volatile sig_atomic_t mcp_state = RUNNING;


/* Functions */

/**
 * \brief Cleans up the MCP.
 *
 * Checks to see what needs to be cleans up, and does so.
 *
 * \return The return value is simply whatever you pass to it. 
 * This allows you to call clean_up(-1) if you cleaning up due to 
 * an error, or simply clean_up(0) if you are exiting normally.
 * \param Specify 0 if exiting normally, -1 if error. This function 
 * will then return whatever you pass it
 * \param transport The transport currently in use that may or may not 
 * need cleaning up
 * \param source The data source in use that may or may not need cleaning 
 * up
 * 
 */
gint clean_up(int return_value, transport_t transport, data_source_t source)
{

  debug_log("Entering clean_up");

  if (mcp_state == RUNNING)
  {
    mcp_state = SHUTTING_DOWN_ERROR;
  }

  debug_log("Closing transport");

  if (transport != NULL)
  {
    transport_close(transport);
    transport = NULL;
  }

  debug_log("Closing data_source");

  if (source != NULL)
  {
    if (data_source_close(source) != 0)
    {
      warning_log("Couldn't close the data source.");
    }
    source = NULL;
  }

  debug_log("Closing contractor controller");

  if (contractor_controller_close() != 0)
  {
    warning_log("Couldn't close the contractor controller. Contractors may still exist?");
  }

  debug_log("Closing logger");

  logger_close();

  debug_log("Closing config");

  config_close();

  return return_value;
}


/*
 * \brief Respond to transport specified with a NULL contract
 *
 * \param transport the transport to use
 * \return 0 on success, -1 on failure
 *
 */
int respond_with_null_contract(transport_t transport)
{
  prong_assert(transport != NULL);

  contract_t a_contract = contract_init(NULL, 0);

  contract_set_path(a_contract, "");
  contract_set_sleep_time(a_contract, -1);

  unsigned int contract_string_size;
  char *contract_string = contract_serialise(a_contract, &contract_string_size);

  if (transport_send(transport, contract_string, &contractor_exited, contract_string_size) < 0)
  {
    severe_log("Transport send error in responding with null contract (%s)", strerror(errno));
    g_free(contract_string);
    contract_close(a_contract);
    return -1;
  }
  g_free(contract_string);
  contract_close(a_contract);

  return 0;
}


/**
 * \brief Print out program usage to stderr
 *
 */
void usage()
{

  fprintf(stderr,
          "\nPronghorn Master Controller Program\n\n"
          "Usage: mcp <configuration server endpoint>\n\n"
          "The MCP requires a number of configuration options in order to run. "
          "The way this is handled in pronghorn is that the mcp is passed a "
          "configuration server endpoint which it will query on startup. "
          "This obviously implies a configuration server must be listening "
          "at the specified endpoint.\n"
          "In summary, if you are trying to run pronghorn, you will not "
          "normally spawn the MCP yourself. Instead, you will spawn a " "configuration server which will then in turn spawn the MCP. " "The supplied scripts do this.");

}


/**
 * \brief Mount the fuse file system
 *
 * \param source The data source we want to mount
 * \return 0 on success, -1 on error
 *
 * The data_source is actually responsible for mounting the FUSE FS, 
 * however this helper function just picks the right mount point etc
 * based on configuration etc.
 *
 */
int mount_fuse(data_source_t source)
{
  prong_assert(source != NULL);

  gchar *fuse_subdir = NULL;
  gchar *working_dir = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_FUSE_SUB_DIR, &fuse_subdir) != 0) || (fuse_subdir == NULL))
  {
    severe_log("Couldn't get the fuse_sub_dir from the configuration!");
    if (fuse_subdir != NULL)
    {
      g_free(fuse_subdir);
      return -1;
    }
  }

  if ((config_get_with_default_macro(NULL, CONFIG_WORKING_DIRECTORY, &working_dir) != 0) || (working_dir == NULL))
  {
    severe_log("Couldn't get the working_dir from the configuration!");
    if (working_dir != NULL)
    {
      g_free(working_dir);
    }
    return -1;
  }

  struct stat info;

  if (stat(working_dir, &info) != 0)
  {
    severe_log("The working directory (%s) doesn't appear to exist!", working_dir);
    g_free(working_dir);
    return -1;
  }

  if (!S_ISDIR(info.st_mode))
  {
    severe_log("The working directory (%s) doesn't appear to be a " "directory!", working_dir);
    g_free(working_dir);
    return -1;
  }

  gchar *mount_point = g_strdup_printf("%s/%s", working_dir,
                                       fuse_subdir);

  g_free(working_dir);
  g_free(fuse_subdir);

  debug_log("Requested fuse mount directory has been calculated as %s", mount_point);

  if (stat(mount_point, &info) != 0)
  {

    debug_log("Creating mount point directory %s", mount_point);

    // Need to create it.
    int create_dir = mkdir(mount_point, S_IRWXU);

    if (create_dir != 0)
    {
      severe_log("Failed to create the mount point (it " "didn't exist, tried to create it, failed).");
      g_free(mount_point);
      return -1;
    }
  }

  debug_log("Asking data source to mount...");

  int return_val = data_source_mount(source, mount_point);

  g_free(mount_point);

  return return_val;
}


/**
 * Respond to transport with next contract from source
 *
 * \param transport The transport to respond on 
 * \param source The data source to get the next contract from
 * \return Returns 0 on success, -1 on error
 * \warning Assumes "source", "transport" and "logger" are all setup and 
 * not in an error state
 *
 * This function responds to transport with the next contract available from
 * source.
 *
 */
int respond_with_contract(transport_t transport, const contract_t contract)
{

  prong_assert(transport != NULL);
  prong_assert(contract != NULL);

  unsigned int contract_string_size;
  char *contract_string = contract_serialise(contract, &contract_string_size);

  if (transport_send(transport, contract_string, NULL, contract_string_size) < 0)
  {
    severe_log("Problem responding with contract (Error: %s)", strerror(errno));
    g_free(contract_string);
    return -1;
  }

  debug_log("Responded to contractor with contract %s.", contract_get_path(contract));
  g_free(contract_string);

  return 0;
}


#include <sys/time.h>
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec)
  {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;

    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000)
  {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;

    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}


/**
 * \brief This is the main contract processing loop of the MCP. This is 
 * where the MCP should spend most of its time.
 *
 * \param transport The transport we are using to communicate with our 
 * our contractors
 * \param source The data source we are currently processing
 * \return 0 on success / clean exit, -1 on failure / non clean exit
 */
int contract_processing_loop(transport_t transport, data_source_t source)
{

  debug_log("Commencing main MCP loop");

  contract_completion_report_t current_contract_completion_report = NULL;

  unsigned int from_contractor_size = 0;
  const char *from_contractor = NULL;
  contract_t next_contract = NULL;

  while ((mcp_state != SHUTTING_DOWN_ERROR) && (mcp_state != SHUTTING_DOWN_CONTRACTORS_NOTIFIED))
  {
    /* Check if we are in a valid state */

    if ((contractor_exited == -1) && (mcp_state == RUNNING))
    {
      severe_log("Something happened to our contractor controller. It is reporting it's no longer valid. A contractor died when we weren't expecting it.");
      mcp_state = SHUTTING_DOWN_ERROR;
      continue;
    }

    from_contractor_size = 0;
    from_contractor = NULL;

    /* Receive CCRs */

    debug_log("MCP about to wait to receive incoming contract completion report.");

    from_contractor = transport_recv(transport, &contractor_exited, &from_contractor_size);

    if (from_contractor == NULL)
    {

      if (contractor_controller_number_contractors() == 0)
      {
        info_log("All contractors reported as dead. MCP Is about to exit.");
        if (mcp_state == RUNNING)
          mcp_state = SHUTTING_DOWN_ERROR;
        else if (mcp_state == SHUTTING_DOWN_NO_MORE_BLOCKS)
          mcp_state = SHUTTING_DOWN_CONTRACTORS_NOTIFIED;
        continue;
      }

      if (errno == EAGAIN)
      {
        debug_log("Transport receive time out in processing mcp loop (%s). MCP state is %i and there are %i alive contractors.", strerror(errno), mcp_state,contractor_controller_number_contractors());
        continue;
      }

      warning_log("Transport receive error (NOT a time out) in processing mcp loop (%s)", strerror(errno));
      mcp_state = SHUTTING_DOWN_ERROR;
      continue;
    }

    /* Handle the CCR we just got */

    current_contract_completion_report = contract_completion_report_init(from_contractor, from_contractor_size);

    if (next_contract != NULL)
    {
      contract_close(next_contract);
      next_contract = NULL;
    }

    /* Decide what to provide back to the contractor */
    next_contract = data_source_get_next_contract(source, current_contract_completion_report);

    contract_completion_report_close(current_contract_completion_report);

    if ((next_contract != NULL) && (mcp_state == RUNNING) && (contractor_exited != -1))
    {
      // We have a valid contract and we're not shutting down, and nothing has died 
      // Just pass out the next contract
      if (respond_with_contract(transport, next_contract) != 0)
      {
        warning_log("Error responding with next contract!");
      }

    } else if ((next_contract != NULL) && (mcp_state == SHUTTING_DOWN_NO_MORE_BLOCKS) && (contractor_exited != -1))
    {
      // We have a valid contract and we are shutting down, and nothing has died
      // We need to pass out the contract and stop the shut down
      if (respond_with_contract(transport, next_contract) != 0)
      {
        warning_log("Error responding with next contract!");
      }

      // We could probably respawn more contractors here. 
      info_log("NYI - Might need to respawn more contractors here!");
      mcp_state = RUNNING;

    } else if ((next_contract == NULL) && ((mcp_state == RUNNING) || (mcp_state == SHUTTING_DOWN_NO_MORE_BLOCKS)) && (contractor_exited != -1))
    {
      // We don't have a valid contract and we aren't shutting down, and nothing has died
      // OR
      // We don't have a valid contract and we are shutting down, and nothing has died

      // We need to shutdown (or continue it), we'll check up above if we have no more contractors
      mcp_state = SHUTTING_DOWN_NO_MORE_BLOCKS;

      if (respond_with_null_contract(transport) != 0)
      {
        warning_log("Error responding with null contract!");
      } else
      {
        debug_log("Responded with NULL contract, sleeping...");
      }

    } else if ((contractor_exited == -1) || (mcp_state == SHUTTING_DOWN_ERROR))
    {
      // Something has died
      // Let things continue and we'll bail out.
      mcp_state = SHUTTING_DOWN_ERROR;
      continue;
    } else
    {
      // Should not happen.
      prong_assert(0);
    }

  }                             // end while loop

  if (next_contract != NULL)
  {
    contract_close(next_contract);
    next_contract = NULL;
  }

  if (mcp_state == SHUTTING_DOWN_ERROR)
  {
    severe_log("Shut down due to an error state. Either a contractor unexpectedly exited, or we had a transport error when communicating with a contractor (not including a time out)");
    if (kill_all_contractors_using_signal(SIGTERM) != 0)
    {
      severe_log("Failed to send all contractors a signal! They may still exist...");
    }
    return -1;
  }

  if (contractor_controller_number_contractors() != 0)
  {
    warning_log("Not all contractors dead on clean exit");
    if (kill_all_contractors_using_signal(SIGTERM) != 0)
    {
      warning_log("Not all contractors dead on clean exit and sending SIGTERM also failed");
    }
  } else
  {
    debug_log("All contractors reported dead on exit");
  }

  // Shut down due to no more blocks.

  return 0;
}

/** 
 * \brief Sets up the contractor to MCP transport
 *
 * \param transport The transport to setup (*transport should be NULL)
 * \return 0 on success, -1 on failure
 *
 */
int setup_transport(transport_t * transport)
{
  prong_assert(*transport == NULL);

  gchar *transport_connect = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_MCP_CONNECT_ENDPOINT, &transport_connect) != 0) || (transport_connect == NULL))
  {
    severe_log("Couldn't determine the endpoint I'm meant to connect to!");
    if (transport_connect != NULL)
    {
      g_free(transport_connect);
    }
    return -1;

  }

  *transport = transport_init(TRANSPORT_TYPE_PULLPUSH, transport_connect);

  g_free(transport_connect);

  if (*transport == NULL)
  {
    severe_log("Couldn't init transport (%s) in mcp:setup_transport()", strerror(errno));

    return -1;
  }

  long timeout = CONFIG_MCP_RECV_FROM_CONTRACTOR_TIMEOUT_DEFAULT;

  if (config_get_long_with_default_macro(NULL, CONFIG_MCP_RECV_FROM_CONTRACTOR_TIMEOUT, &timeout) != 0)
  {
    warning_log("Couldn't find out what timeout option to use for MCP <-> Contractor!");
  }

  /* We don't do this anymore, we want a short timeout but we never give up.
     gint num_contractors = 1;

     if (config_get_int_with_default_macro(NULL, CONFIG_CONCURRENCY, &num_contractors) != 0)
     {
     warning_log("Couldn't get the number of contractors to calculate a better timeout. Assuming 1.");
     }
     transport_set_recv_timeout(*transport, timeout * ((long) num_contractors)));
   */

  transport_set_recv_timeout(*transport, timeout);

  debug_log("Using %lims for MCP <-> Contractor timeout", timeout);

  return 0;

}

/**
 * \brief Sets up the contractor controller
 *
 * \return 0 on success, -1 on failure
 * 
 * Queries the configuration server to determine how many contractors
 * we should spawn, and initialises the contractor_controller 
 * accordingly
 *
 */
int setup_contractor_controller()
{
  gint num_contractors;

  if (config_get_int_with_default_macro(NULL, CONFIG_CONCURRENCY, &num_contractors) != 0)
  {
    severe_log("Couldn't get the number of contractors to spawn!");
    return -1;
  }

  debug_log("Will try and spawn %i contractors", num_contractors);

  if (contractor_controller_init(num_contractors) != 0)
  {
    severe_log("There was a problem spawning the contractors!");
    return -1;
  }

  debug_log("Successfully spawned contractors");

  return 0;
}

/**
 * \brief Sets up the data source
 *
 * \param source The data source we are setting up (*source should == NULL)
 * \return 0 on success, -1 on failure
 *
 */
int setup_data_source(data_source_t * source)
{
  prong_assert(*source == NULL);

  /* Sanity check we can open the file and setup the data source */

  gchar *file_to_open = NULL;

  if ((config_get(NULL, CONFIG_INPUT_FILE_OPTION_NAME, &file_to_open) != 0) || (file_to_open == NULL))
  {
    severe_log("Couldn't get input file!");
    return -1;
  }

  gint bs;

  if (config_get_int(NULL, CONFIG_BLOCK_SIZE_OPTION_NAME, &bs) != 0)
  {

    warning_log("No block size set! Will try and get the default but you should probably set it. Subcontractors *should* use the default but they may not.");

    if (config_get_int_with_default_macro(NULL, CONFIG_BLOCK_SIZE, &bs) != 0)
    {
      severe_log("Tried to fall back to the default block size, but errored out on that too. Can't continue.");
      return -1;
    }

    info_log("Obtained default block size of %i, will set this in the config server.", bs);

    gchar* block_size_str = g_strdup_printf("%i", CONFIG_BLOCK_SIZE_DEFAULT) ;

    if (config_set(CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_BLOCK_SIZE_OPTION_NAME, block_size_str) != 0)
    {
      warning_log("Couldn't update the block size in the config server. Will continue.");
    } else
    {
      debug_log("Set the block size in the config server to value of %s", block_size_str);
    }
    g_free(block_size_str);

  }

  *source = data_source_init(file_to_open, bs);
  g_free(file_to_open);

  if (*source == NULL)
  {
    error_log("There was a problem opening the data source!");
    return -1;
  }

  debug_log("File appears to be valid");

  /* Mount the file into the working directory */

  debug_log("Mounting FUSE fs for basic carver");

  if (mount_fuse(*source) != 0)
  {
    severe_log("There was an error mounting the FUSE FS!");
    severe_log("  Was 'user_allow_other' set in /etc/fuse.conf ?");
    severe_log("  Is the current user in the 'fuse' group ?");

    return -1;
  }

  return 0;
}

/** 
 * \brief Sets up logging based on the configuration provided
 *
 * \return 0 on success, -1 on failure
 *
 */
int setup_logging()
{
  int ret = logger_config_init();

  if (ret != 0)
  {
    severe_log("Failed to create log transport! Aborting.");
    return -1;
  }

  return 0;
}


/**
 * \brief Parse the command line arguments to the MCP
 *
 * \param argc The number of args passed on the command line
 * \param argv The args passed on the command line
 * \param config_end_point The variable into which the config end point
 * will be populated
 * \warning Caller is responsible for free-ing the config_end_point
 *
 * \return 0 on success, -1 on failure
 *
 */
int parse_command_args(int argc, char **argv, gchar ** config_end_point)
{

  int error = 0;

  if (argc != 2)
  {
    severe_log("Wrong number of args passed. You only need to pass the " "config end point to the MCP.");
    usage();
    return -1;
  }
  // The last argument is the config end point
  *config_end_point = g_strdup(argv[1]);

  if (*config_end_point == NULL)
  {
    error = 1;
  }

  return error;
}

/**
 * \brief Validate whether the MCP has enough options required to process
 * a file
 *
 * \return 0 if the minimum required arguments have been validated, -1
 * if there are insufficient minimum arguments supplied
 */
int validate_minimum_config_supplied()
{

  // Everything else should be OK with or without,
  // since they have sane defaults
  const char *required_options[] = { CONFIG_INPUT_FILE_OPTION_NAME,
    NULL,
  };

  int i = 0;

  while (required_options[i] != NULL)
  {
    const gchar *item = required_options[i];
    gchar *opt = NULL;

    if ((config_get(NULL, item, &opt) != 0) || (opt == NULL))
    {
      severe_log("Couldn't find %s which is mandatory!", item);
      severe_log("Either specify %s with -o on the command line, (e.g. -o general.%s = <value> or -o mcp.%s = <value> , or put in the configuration file!", item, item, item);

      if (opt != NULL)
      {
        g_free(opt);
      }

      return -1;
    } else
    {
      debug_log("Option %s is %s", item, opt);
    }

    g_free(opt);
    i++;
  }

/* DEPRECATED - No longer required
  long mcp_timeout = CONFIG_MCP_CONTRACTOR_TIMEOUT_DEFAULT;
  if (config_get_long_with_default_macro(NULL, CONFIG_MCP_CONTRACTOR_TIMEOUT, &mcp_timeout) != 0)
  {
    warning_log("Couldn't get the timeout for the MCP");
  }

  if (mcp_timeout != -1)
  {
    warning_log("The MCP to contractor timeout has been set to something other than the default (no timeout). This could have serious consequences if you aren't careful setting it. For example, if the sum of subcontractor time outs is less than this value, you may get unexpected behaviour as the MCP will timeout a contractor without just cause.");

  }
  */

  return 0;
}

/** 
 * \brief Setup the config client
 *
 * \param config_end_point The end point to connect to
 * \return 0 on success, -1 on failure
 */
int setup_config(gchar * config_end_point)
{

  if (config_end_point == NULL)
  {
    return -1;
  }

  /* Config Setup */

  if (config_init(config_end_point) != 0)
  {
    severe_log("Problem setting up the configuration engine (endpoint: %s, " "error: %s). Aborting.", config_end_point, strerror(errno));

    return -1;
  }

  if (validate_minimum_config_supplied() != 0)
  {
    severe_log("Insufficient minimum (or invalid) information available to " "start the program!");

    return -1;
  }

  return 0;
}

/**
 * Autoconfigures all subcontractors in a specified directory.
 *
 * It will also recurse into any subdirectories
 *
 * \param directory The directory to examine
 */
static void autoconfigure_subcontractor_directory(char *directory)
{

//debug_log("Autoprocessing subcontractor directory \"%s\"", directory);

  DIR *dir = opendir(directory);

  if (dir == NULL)
  {
    error_log("Examining directories for subcontractors - \"%s\" is not a directory.", directory);
    return;
  }

  char *config_endpoint = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_CONFIG_CONNECT_ENDPOINT, &config_endpoint) != 0) || (config_endpoint == NULL))
  {
    severe_log("autoconfig subcontractor: Unable to get config endpoint!");
    closedir(dir);
    return;
  }

  struct dirent *entry = NULL;

  while ((entry = readdir(dir)) != NULL)
  {
    char *path = g_strdup_printf("%s/%s", directory, entry->d_name);

    struct stat s;

    if (stat(path, &s) == 0)
    {
      if (S_ISDIR(s.st_mode))
      {
        if ((strcmp(entry->d_name, ".") != 0) && (strcmp(entry->d_name, "..") != 0))
        {
          autoconfigure_subcontractor_directory(path);
        }
      } else if (s.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
      {
        if (g_str_has_prefix(entry->d_name, "subcontractor_") == FALSE)
        {
          debug_log("\"%s\" does not have the prefix of \"subcontractor\", not executing.", entry->d_name);
          g_free(path);
          continue;
        }
        // The execute bit is set. Try to execute.
        char *argv[] = { NULL, config_endpoint, NULL };
        argv[0] = g_strdup_printf("%s/%s", directory, entry->d_name);
        int status = spawn_limited_process_and_wait(argv, -1, -1, 2);

        g_free(argv[0]);

        if (WIFEXITED(status))
        {
          int ret = WEXITSTATUS(status);

          if (ret != 0)
          {
            warning_log("Autoconfig subcontractor: \"%s\" exited with return code %d.", entry->d_name, ret);
          }
        } else if (WIFSIGNALED(status))
        {
          int sig = WTERMSIG(status);

          error_log("Autoconfig subcontractor: \"%s\" was killed buy signal %d.", entry->d_name, sig);
        } else
        {
          error_log("Autoconfig subcontractor: \"%s\" died due to strange causes? status=%d.", entry->d_name, status);
        }
      }
    } else
    {
      error_log("Autoconfigure subcontractor: Stat() failed on \"%s\". Errno = %d", path, errno);
    }
    g_free(path);
  }

  g_free(config_endpoint);
  closedir(dir);
}


/**
 * Allows the subcontractors to autoconfigure and register their interest in specific filetypes.
 */
static void autoconfigure_subcontractors(void)
{
  // Spawn every executable in subcontractor directory array with one arg.

  // Get list of subcontractor directories
  char *directories_string = NULL;

  if ((config_get(NULL, CONFIG_SUBCONTRACTOR_DIRECTORIES, &directories_string) != 0) || (directories_string == NULL))
  {
    debug_log("No subcontractor directories available?");
    return;
  }

  char **directories_array = g_strsplit(directories_string, ",", -1);

  g_free(directories_string);

  // Taking a copy of this point so we can free it later
  char **directories_array_to_free = directories_array;

  while (directories_array[0] != NULL)
  {
    g_strstrip(directories_array[0]);

    autoconfigure_subcontractor_directory(directories_array[0]);

    directories_array++;
  }

  g_strfreev(directories_array_to_free);
}

/**
 * \brief Main of MCP
 *
 * \return 0 on clean exit, -1 on error
 * \param argc Arg count
 * \param argv Args
 *
 * The main of MCP. Mostly setup, the actual work is does in the
 * contract processing loop
 */
int main(int argc, char **argv)
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];
  // Stop buffering on stdout and stderr
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  /**
   * The transport we'll use to talk to the contractors (which
   * we will spawn). 
   * \brief Transport used to talk to the contractors
   */
  transport_t transport = NULL;

  /** Our data source. This is the thing we are trying to classify
   * \brief Data source to classify
   */
  data_source_t source = NULL;

  /* Check dependencies */

  // NB - Until the config is setup (config_init),
  // there is no way to determine what the logging
  // level is, so as such we need to be wary of spitting
  // out any non critical 

#ifdef DEBUG
  set_log_level(LOG_SEVERITY_DEBUG);
#else
  set_log_level(LOG_SEVERITY_WARNING);
#endif

  if (are_all_dependencies_met() != 1)
  {
    severe_log("Dependencies not met!");
    return -1;
  }

  debug_log("MCP Started. Dependencies met. About to parse command line args then startup config connection");

  /* Command Line Arguments */

  // MCP relies heavily on a configuration server. All we (should) get passed 
  // is the configuration end point.

  gchar *config_end_point = NULL;

  if (parse_command_args(argc, argv, &config_end_point) != 0)
  {
    severe_log("Invalid command line options found!");
    if (config_end_point != NULL)
      g_free(config_end_point);
    return -1;
  }

  /* Config Setup */

  if (setup_config(config_end_point) != 0)
  {
    severe_log("Couldn't setup the config client, or bad values set");
    g_free(config_end_point);
    return clean_up(-1, transport, source);
  }

  g_free(config_end_point);

  debug_log("Baseline config options validated." " We should have all the info we need to start now");

  /* END command line arguments and config setup */

  /* 0MQ Setup */

  if (setup_logging() != 0)
  {
    severe_log("Failed to setup the log transport! Aborting.");
    return clean_up(-1, transport, source);
  }

  if (setup_transport(&transport) != 0)
  {
    severe_log("Failed to setup the MCP transport. Aborting.");
    return clean_up(-1, transport, source);
  }

  debug_log("Transports initialised OK.");

  if (setup_data_source(&source) != 0)
  {
    severe_log("Failed to setup the data source. Aborting.");
    return clean_up(-1, transport, source);
  }
  // Giving the subcontractors the ability to autoconfigure
  autoconfigure_subcontractors();

  /* Setup the contractors */

  debug_log("Spawning Contractors.");

  if (setup_contractor_controller() != 0)
  {
    severe_log("Failed to setup the contractor controller. Aborting.");
    return -1;
  }

  /* GO! */

  int ret_val = contract_processing_loop(transport, source);

  return clean_up(ret_val, transport, source);
}
