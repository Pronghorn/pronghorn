/* Pronghorn Contractor
 * Copyright (C) 2012 Department of Defence Australia
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * \file contractor.c
 * \brief Main contractor program
 *
 * A contractor doesn't actually do block classification - for this it
 * relies on subcontractors. However, it is reponsible for receving jobs
 * from the MCP and handing them off to subcontractors, who do actually
 * do the classification. It is therefore responsible for spawning 
 * subcontractors when required, and collecting all the results to send
 * back to the MCP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <glib.h>
#include <errno.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <logger.h>
#include <contract.h>
#include <result.h>
#include <report.h>
#include <lightmagic.h>
#include <lprocess.h>
#include <basename_safe.h>
#include <defaults.h>
#include <config.h>
#include <transport.h>
#include <prong_assert.h>

/** The prefix we use when trying to clean up old IPC end points */
#define IPC_PREFIX "ipc://"

/** This is the name of the current process */
const char *SHORT_PROCESS_NAME = NULL;

/** This is the name of the current process */
const char *PROCESS_NAME = NULL;

/** A struct representing one of our subcontractors */
struct subcontractor
{
  /**
   * The path that points to the subcontractor executable
   * that will be spawned when this subcontractor is required
   *
   * \brief Path to subcontractor executable
   * \warning Stored backwards for efficiency when searching / sorting!
   */
  char *execution_path;

  /**
   * The name of the subcontractor, stored for convenience. 
   * \warning Stored backwards for efficiency when searching / sorting!
   */
  char *subcontractor_name;

  /**
   * The process id of the sub contractor, or negative one if
   * the sub contractor is not alive (died or hasn't been spawned 
   * yet)
   * \brief PID of subcontractor, -1 implies dead
   */
  volatile sig_atomic_t pid;    // -1 implies it's dead

  /** 
   * The transport used to communicate with this particular 
   * subcontractor. It is setup when the sub contractor is spawned. 
   * \brief Transport used to talk to this subcontractor
   */
  transport_t subcontractor_transport;

  /** 
   * The name of the transport IPC we use to communicate 
   * with this subscontractor. This is for convenience when 
   * cleaning up
   */
  char *subcontractor_transport_name;

  /**
   * The minimum score threshold for this subcontractor. This is
   * loaded when the sub contractor is loaded, so if the configuration
   * is changed after loading, it will not be reflected in this 
   * variable. This is for performance reasons.
   */
  int subcontractor_confidence_threshold;

  /**
   * An array containing all the contract type ids that this
   * subcontractor supports.
   */
  GArray *supported_types;

};


/* Global Variables */

/** 
 * This is our team of subcontractors we'll use to process contracts. 
 * Initialised in setup_subcontractors. It is sorted by precedence, i.e.
 * subcontractors at the START of the list are those with a higher
 * precedence.
 *
 * \brief Subcontractor team that does the actual work. A list of all our
 * subcontractors in order of precedence (highest precedence at the start)
 */
static GSList *subcontractor_list = NULL;

/**
 * Just a number we increment for use with setting up transports to 
 * our subcontractors. We incrememt it everytime we spawn a subcontractor.
 * \brief Unique incremented number for sub contractor transports
 */
static unsigned int transport_id = 0;

/**
 * Has there been a child death that we should be aware of? At the moment
 * we don't actually act on this, as it's not technically required.
 */
static volatile sig_atomic_t unhandled_subcontractor_exit_signal = 0;

/**
 * Has there been a child death that we should be aware of? At the moment
 * we don't actually act on this, as it's not technically required.
 */
static volatile sig_atomic_t unhandled_subcontractor_exit_normal = 0;

/**
 * Have we been sent a SIGTERM?
 */
static volatile sig_atomic_t sigterm_received = 0;

/** 
 * Are we running in brute force mode? We look this up once then store
 * it as a global so we don't need to perform a config look up everytime
 * we process a contract. Note that this means you can't change this 
 * option in the middle of a pronghorn run at present.
 * \brief Are we running in brute force mode
 */
static int brute_force_mode = 0;

/**
 * If the contractor can't talk to the MCP, how many times should it retry
 * before giving up and exiting?
 */
static int contractor_to_mcp_retries = CONFIG_CONTRACTOR_RECV_FROM_MCP_RETRIES_DEFAULT;

/**
 * For efficiency store a bitmap of filetypes we don't have a subcontractor for
 */
static unsigned char unsupported_filetype_bitmap[32] = { 0 };


/* Definitions */

/**
 * \brief Returns the subcontractor process with a given pid
 *
 * \param pid The pid of the subcontractor process we want
 * \return If a subcontractor is found with given pid, returns it. If a 
 * subcontractor process is not found with the given pid, returns NULL.
 */
struct subcontractor *get_subcontractor_by_pid(pid_t pid)
{

  GSList *curr = subcontractor_list;

  while (curr != NULL)
  {
    struct subcontractor *current = (struct subcontractor *) curr->data;

    prong_assert(current != NULL);

    if (current->pid == pid)
    {
      return current;
    }

    curr = g_slist_next(curr);
  }

  return NULL;
}


/**
 * \brief Determines if the passed pid is a subcontractor process
 *
 * \param pid The pid to determine whether or not is a subcontractor
 * \return 1 if the pid is a subcontractor, 0 if it's not
 */
gint pid_is_subcontractor(pid_t pid)
{
  if (get_subcontractor_by_pid(pid) == NULL)
  {
    return 0;
  }

  return 1;
}


/**
 * \brief SIGCHLD handler for contractor (i.e. handles sub contractors dying)
 *
 * \param sig Signal to handle
 * \param sig_info Signal info
 * \param ucontext Not used
 * \warning This doesn't restart sub contractors, that happens when we next want to use them
 *
 * Called when a sub contractor dies. All it does is mark the
 * sub contractor as dead, and the assumption is something will restart
 * it later if and when required.
 *
 */
void subcontractor_sigchld_handler(int sig, siginfo_t * sig_info, void *ucontext)
{

  // Should never happen
  if (sig != SIGCHLD)
  {
    return;
  }
  // If it's not a subcontractor, ignore it. Also just double check it's not -1, as that is our way of marking sub contractors as being dead.
  int status = 0;
  pid_t pid;

  while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
  {

    if (pid_is_subcontractor(pid) != 1)
    {
      return;
    }
    // Have reaped the child, now need to handle it from a contractor point
    // of view!
    if (WIFEXITED(status) == TRUE)
    {
      unhandled_subcontractor_exit_normal = 1;
    }

    if (WIFSIGNALED(status) == TRUE)
    {
      unhandled_subcontractor_exit_signal = 1;
    }

    struct subcontractor *remove_me = NULL;

    remove_me = get_subcontractor_by_pid(pid);

    if (remove_me == NULL)
    {
      return;
    }

    remove_me->pid = -1;
  }

}


/**
 * \brief Handle a SIGTERM sent to the contractor
 *
 * \param sig The signal
 * \param sig_info The signal info
 * \param ucontext Context
 *
 */
void contractor_sigterm_handler(int sig, siginfo_t * sig_info, void *ucontext)
{

  // Should never happen
  if (sig != SIGTERM)
    return;

  // All we do is set our flag.
  sigterm_received = 1;
}


/**
 * \brief Returns the subcontractor process with a given reversed name
 *
 * \param rev_name The reversed name of the subcontractor process we want
 * \return If a subcontractor is found with given reversed name, returns 
 * it. If a subcontractor process is not found with the given reversed 
 * name, returns NULL.
 */
struct subcontractor *get_subcontractor_by_rev_name(const gchar * rev_name)
{

  GSList *curr = subcontractor_list;

  while (curr != NULL)
  {
    struct subcontractor *current = (struct subcontractor *) curr->data;

    prong_assert(current != NULL);

    if (g_strcmp0(current->subcontractor_name, rev_name) == 0)
    {
      return current;
    }

    curr = g_slist_next(curr);
  }

  return NULL;

}


/**
 * \brief Returns the subcontractor process with a given path (reversed)
 *
 * \param rev_path The reversed path of the subcontractor process we want
 * \return If a subcontractor is found with given reversed path, returns 
 * it. If a subcontractor process is not found with the given reversed
 * path, returns NULL.
 */
struct subcontractor *get_subcontractor_by_rev_path(const gchar * rev_path)
{

  GSList *curr = subcontractor_list;

  while (curr != NULL)
  {
    struct subcontractor *current = (struct subcontractor *) curr->data;

    prong_assert(current != NULL);

    if (g_strcmp0(current->execution_path, rev_path) == 0)
    {
      return current;
    }

    curr = g_slist_next(curr);
  }

  return NULL;

}



/**
 * \brief Returns (as a number) the position of the given subcontractor in 
 * terms of its precedence
 *
 * \param precedence_data A null terminated string array containing 
 * subcontractornames ordered by precedence
 * \param subcon_name The subcontractor for which the precedence is to be 
 * determined
 * \return The precedence position of the given subcontractor. If there is no 
 * information (it's not found), then it just returns GMAXINT-1
 */
gint get_precedence_position(gchar ** precedence_data, const gchar * subcon_name)
{

  gint pos = 0;

  for (pos = 0; pos < g_strv_length(precedence_data); pos++)
  {
    if (g_strcmp0(subcon_name, precedence_data[pos]) == 0)
    {
      return pos;
    }

  }

  return G_MAXINT - 1;
}


/**
 * \brief Sort function for two subcontractors based on precedence
 *
 * \param subcon_a The first subcontractor to be compared
 * \param subcon_b The second subcontractor to be compared
 * \param precedence_data An array of strings given the names of subcontractors in 
 * order of precedence
 * \return -1, 0, 1 if a is less than, equal to or greater than b in 
 * precedence order
 */
gint g_slist_compare_precedence(gconstpointer subcon_a, gconstpointer subcon_b, gpointer precedence_data)
{

  if (subcon_a == NULL && subcon_b == NULL)
  {
    return 0;
  } else if (subcon_a == NULL && subcon_b != NULL)
  {
    return 1;
  } else if (subcon_b == NULL && subcon_a != NULL)
  {
    return -1;
  }
  // Setup data
  struct subcontractor *subcontractor_a = (struct subcontractor *) subcon_a;
  struct subcontractor *subcontractor_b = (struct subcontractor *) subcon_b;

  gchar **precedence_array = (gchar **) precedence_data;

  gchar *normal_name_subcon_a = g_strreverse(g_strdup(subcontractor_a->subcontractor_name));
  gchar *normal_name_subcon_b = g_strreverse(g_strdup(subcontractor_b->subcontractor_name));

  gint position_in_precedence_of_a = get_precedence_position(precedence_array, normal_name_subcon_a);
  gint position_in_precedence_of_b = get_precedence_position(precedence_array, normal_name_subcon_b);

  g_free(normal_name_subcon_a);
  g_free(normal_name_subcon_b);

  if (position_in_precedence_of_a < position_in_precedence_of_b)
    return -1;
  if (position_in_precedence_of_a > position_in_precedence_of_b)
    return 1;

  return 0;

}


/**
 * \brief Adds subcontractors to our collection for the specified type
 *
 * \param contract_type Which type of contract should this subcontractor 
 * process
 * \param subcontractors_to_add The sub contractors to add (NULL terminated)
 * \param precedence_array A array (NULL terminated) of subcontractors names in precedence order
 * \return 0 on success, -1 on error
 *
 * Adds sub contractors to the collection based on a contract type. For a single
 * subcontractor that supports multiple contract types, it is safe to call this multiple
 * times for the same subcontractor with different contract types.
 *
 */
gint add_subcontractors(int contract_type, gchar ** subcontractors_to_add, gchar ** precedence_array)
{

  //debug_log("Adding %i subcontractors...", g_strv_length(subcontractors_to_add));

  guint num_subcontractors_to_add = g_strv_length(subcontractors_to_add);

  if (num_subcontractors_to_add == 0)
  {
    return 0;
  }

  guint i = 0;
  gchar *current_sub = NULL;

  for (i = 0; i < num_subcontractors_to_add; i++)
  {
    // Sanity check each one. Lots. //

    //debug_log("Adding %s to sub store against type %i", subcontractors_to_add[i], contract_type);

    if (subcontractors_to_add[i] == NULL)
    {
      warning_log("Can't add a NULL subcontractor!");
      continue;
    }

    current_sub = g_strdup(subcontractors_to_add[i]);
    g_strstrip(current_sub);

    if (access(subcontractors_to_add[i], R_OK | X_OK) != 0)
    {

      warning_log("Don't have access to read or execute %s, so I can't add it as a sub contractor!", current_sub);

      g_free(current_sub);
      current_sub = NULL;
      continue;
    }
    // One last check, check it's a regular file... 
    struct stat info;

    if (stat(current_sub, &info) != 0)
    {
      warning_log("Don't have access to %s, so I can't add it as a sub contractor!", current_sub);

      g_free(current_sub);
      current_sub = NULL;
      continue;
    }

    if (!S_ISREG(info.st_mode))
    {
      warning_log("%s is not a regular file... so I can't add it as a sub contractor!", current_sub);

      if (current_sub != NULL)
      {
        g_free(current_sub);
        current_sub = NULL;
      }
      continue;

    }
    // Store them 

    // Do we already have this sub contractor in our GSList? 

    gchar *reversed_string = g_strreverse(g_strdup(current_sub));

    struct subcontractor *existing = get_subcontractor_by_rev_path(reversed_string);

    g_free(reversed_string);

    if (existing != NULL)
    {
      //debug_log("Existing entry, just adding type %i to it", contract_type);

      // Yes - Just add the new type to the existing entry. 
      g_array_append(existing->supported_types, contract_type);

    } else
    {
      // No - Create it.

      gchar *exec_path = g_strdup(current_sub);
      const char *base_name = basename_safe(exec_path);

      // free'd in clean_up()
      struct subcontractor *to_add = (struct subcontractor *) g_malloc(sizeof(struct subcontractor));

      to_add->pid = -1;
      to_add->subcontractor_transport = NULL;
      to_add->subcontractor_transport_name = NULL;
      to_add->execution_path = NULL;
      to_add->supported_types = g_array_new(TRUE, TRUE, sizeof(gint));

      g_array_append_val(to_add->supported_types, contract_type);

      // Stored backwards for efficiency, free'd in clean_up()
      to_add->execution_path = g_strreverse(g_strdup(current_sub));

      // Stored backwards for efficiency, free'd in clean_up()
      to_add->subcontractor_name = g_strreverse(g_strdup(base_name));

      //debug_log("Set name as \"%s\" and path as %s", to_add->subcontractor_name , to_add->execution_path);

      // Calculate its confidence threshold
      int sub_conf_thresh = -1;

      if ((config_get_int(base_name, CONFIG_SCON_MIN_CONF_THRESHOLD_OPTION_NAME, &sub_conf_thresh) != 0) || sub_conf_thresh == -1)
      {
        //debug_log("No specific threshold set for %s, will obtain default if possible", base_name);

        if ((config_get_int_with_default_macro("general", CONFIG_SCON_MIN_CONF_THRESHOLD, &sub_conf_thresh) != 0) || sub_conf_thresh == -1)

        {
          warning_log("Failed to get even the the default value for %s, using the global default of %i", base_name, CONFIG_SCON_MIN_CONF_THRESHOLD_DEFAULT);
          sub_conf_thresh = CONFIG_SCON_MIN_CONF_THRESHOLD_DEFAULT;
        }

      }

      to_add->subcontractor_confidence_threshold = sub_conf_thresh;
      g_free(exec_path);

      //debug_log("Adding new scon to subcontractor_list");

      // Add it to the GSList in order of precedence
      subcontractor_list = g_slist_insert_sorted_with_data(subcontractor_list, to_add, g_slist_compare_precedence, precedence_array);

    }

    g_free(current_sub);
    current_sub = NULL;

  }

  return 0;

}


/** 
 * \brief If it exists, try and clean up the provided endpoint
 *
 * \param endpoint The end point to clean up
 * \return 0 on success, -1 on failure
 *
 */
int clean_up_end_point_file_if_exists(const char *endpoint)
{

  if (endpoint == NULL)
  {
    return 0;
  }

  if (g_str_has_prefix(endpoint, IPC_PREFIX) == FALSE)
  {
    return 0;
  }

  const char *file = strstr(endpoint, IPC_PREFIX);
  int error = 0;

  if (file != NULL && (strlen(endpoint) > (strlen(IPC_PREFIX) + 1)))
  {
    file = endpoint + strlen(IPC_PREFIX);

    struct stat info;

    if (stat(file, &info) != 0)
    {
      debug_log("Couldn't stat %s, not cleaning up.", file);
    } else
    {
      if (unlink(file) != 0)
      {
        warning_log("Couldn't delete endpoint %s, may still exist. Error was %i (%s)", file, errno, strerror(errno));
        error = 1;
      } else
      {
        debug_log("Deleted left over IPC end point %s", file);
      }
    }
  } else
  {
    debug_log("End point doesn't appear to be ipc. Not removing file: %s ", endpoint);
  }

  return error;
}


/**
 * \brief Free a sub contractor struct, including the memory alloc-ed 
 * within
 *
 * \param to_free The pointer to the struct to free
 *
 * Frees a subcontractor struct properly.
 */
void subcontractor_gslist_free(gpointer to_free)
{
  struct subcontractor *data = (struct subcontractor *) to_free;

  if (data->execution_path != NULL)
  {
    g_free(data->execution_path);
    data->execution_path = NULL;
  }

  if (data->subcontractor_name != NULL)
  {
    g_free(data->subcontractor_name);
    data->subcontractor_name = NULL;
  }

  if (data->subcontractor_transport != NULL)
  {
    transport_close(data->subcontractor_transport);
    data->subcontractor_transport = NULL;
  }

  if (data->subcontractor_transport_name != NULL)
  {
    debug_log("Cleaning up of possible left over end point required");
    if (clean_up_end_point_file_if_exists(data->subcontractor_transport_name) != 0)
    {
      warning_log("Couldn't clean up end point file. Files may still exist.");
    }
    g_free(data->subcontractor_transport_name);
  } else
  {
    //debug_log("Cleaning up not required");
  }

  volatile int local_pid = data->pid;

  if (local_pid != -1)
  {
    kill(local_pid, SIGTERM);
    data->pid = -1;
  }

  if (data->supported_types != NULL)
  {
    gchar *monkeys = g_array_free(data->supported_types, TRUE);

    if (monkeys == NULL)
    {
    }
    data->supported_types = NULL;
  }

  g_free(data);
  data = NULL;

}


/**
 * \brief Return the precedence array from the config
 *
 * \return An array of strings containing the subcontractor names in 
 * order of precedence
 */
gchar **get_precedence_array()
{

  // Load the precedence listing for subcontractors
  gchar *precedence_string = NULL;
  gchar **to_return = NULL;

  if ((config_get(NULL, CONFIG_SCON_PRECEDENCE_OPTION_NAME, &precedence_string) != 0) || precedence_string == NULL)
  {
    warning_log("Couldn't get the subcontractor precedence string! " "This is going to make it very difficult to determine the winning " "result.");

    if (precedence_string != NULL)
    {
      g_free(precedence_string);
    }
    return NULL;
  } else
  {
    to_return = g_strsplit(precedence_string, ",", -1);
  }

  int trimp = 0;

  for (trimp = 0; trimp < g_strv_length(to_return); trimp++)
  {
    g_strstrip(to_return[trimp]);
  }

  g_free(precedence_string);
  return to_return;
}


/**
 * \brief Sets up the subcontractors 
 *
 * \return 0 on success, -1 on failure
 *
 * This doesn't actually read the config, or spawn anything. It 
 * just sets up the structures, which are populated and spawned
 * as needed when contracts arrive. It also sets up the s
 *
 */
int setup_subcontractors(void)
{

  gchar **precedence_array = get_precedence_array();

  if (precedence_array != NULL)
  {
    debug_log("Loaded precedence array with %i elements", g_strv_length(precedence_array));
  }

  memset(unsupported_filetype_bitmap, 0xFF, sizeof(unsupported_filetype_bitmap));

  // All we do first is get a massive list of all the subcontractor
  // executables. 
  int type = 0;

  for (type = 0; type < 256; type++)
  {
    const gchar *magic_text = lightmagic_text_representation(type);

    if (g_strcmp0("MAGIC_UNKNOWN_TYPE", magic_text) == 0)
    {
      continue;
    }
    //debug_log("Requesting %s from config", lightmagic_text_representation(type));

    gchar *sub_contractors_this_type = NULL;

    if ((config_get(NULL, magic_text, &sub_contractors_this_type) != 0) || sub_contractors_this_type == NULL)
    {
      //debug_log("Couldn't lookup config. Assuming nothing exists");

      if (sub_contractors_this_type != NULL)
      {
        g_free(sub_contractors_this_type);
        sub_contractors_this_type = NULL;
      }
      //debug_log("Nothing found for %s", magic_text);
      continue;
    }
    // At this point, sub_contractors_this_type is a comma separated 
    // list of sub contractor executables that can handle this plugin 
    // type

    unsupported_filetype_bitmap[type / 8] = unsupported_filetype_bitmap[type / 8] & (~(0x01 << (type % 8)));

    //debug_log("Loading the following subcontractors for type %i (%s): %s", type, lightmagic_text_representation(type), sub_contractors_this_type);

    gchar **sub_contractors_this_type_array = g_strsplit(sub_contractors_this_type, ",", -1);

    //debug_log("Strsplit reported %u contractors to load on string %s", g_strv_length(sub_contractors_this_type_array), sub_contractors_this_type);

    if ((add_subcontractors(type, sub_contractors_this_type_array, precedence_array)) != 0)
    {
      severe_log("Couldn't add subcontractors to the subcontractors struct!");

      if (sub_contractors_this_type != NULL)
      {
        g_free(sub_contractors_this_type);
        sub_contractors_this_type = NULL;
      }

      if (sub_contractors_this_type_array != NULL)
      {
        g_strfreev(sub_contractors_this_type_array);
        sub_contractors_this_type_array = NULL;
      }

      continue;
    }

    if (sub_contractors_this_type != NULL)
    {
      g_free(sub_contractors_this_type);
      sub_contractors_this_type = NULL;
    }

    if (sub_contractors_this_type_array != NULL)
    {
      g_strfreev(sub_contractors_this_type_array);
      sub_contractors_this_type_array = NULL;
    }

  }

  if (precedence_array != NULL)
  {
    g_strfreev(precedence_array);
    precedence_array = NULL;
  }

  return 0;

}

/** 
 * \brief Setup signal handlers
 *
 * \return 0 on success, -1 on failure
 *
 */
int setup_sig_handlers(void)
{

  /* Setup sig handler */

  struct sigaction action;

  memset(&action, 0, sizeof(action));
  action.sa_sigaction = subcontractor_sigchld_handler;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGCHLD, &action, NULL))
  {
    severe_log("problem setting sub contractor sigchld handler (%s).", strerror(errno));
    return -1;
  }

  memset(&action, 0, sizeof(action));
  action.sa_sigaction = contractor_sigterm_handler;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGTERM, &action, NULL))
  {
    severe_log("problem setting contractor sigterm handler (%s).", strerror(errno));
    return -1;
  }

  return 0;

}

/** 
 * \brief Sends a blank (shutdown) message to all sub contractors 
 *
 * \return Returns zero on success, non zero on failure
 *
 * This sends a blank message to all subcontractors we know about 
 * in the subcontractors variable. 
 *
 */
int send_shutdown_message_to_subcontractors(void)
{

  debug_log("Sending a shutdown message to all sub contractors...");

  // While we send a shutdown message to all of the subcontractors, 
  // we block signals to avoid any odd race conditions.

  sigset_t x;

  sigemptyset(&x);
  sigaddset(&x, SIGCHLD);
  sigprocmask(SIG_BLOCK, &x, NULL);

  contract_t a_contract = contract_init(NULL, 0);

  contract_set_path(a_contract, "");
  unsigned int contract_serialised_size;
  char *contract_serialised = contract_serialise(a_contract, &contract_serialised_size);

  GSList *curr = subcontractor_list;

  while (curr != NULL)
  {
    struct subcontractor *to_shutdown = (struct subcontractor *) curr->data;

    if (to_shutdown->pid != -1 && to_shutdown->subcontractor_transport != NULL)
    {
      // This looks a live one! Send a shutdown message.
      if (transport_send(to_shutdown->subcontractor_transport, contract_serialised, &(to_shutdown->pid), contract_serialised_size) < 0)
      {
        severe_log("Error sending shutdown message!! (%s)", strerror(errno));
        contract_close(a_contract);
        continue;
      }
      // Now get a response
      debug_log("Sent a shutdown message to a sub contractors, waiting for junk back.");

      // We don't actually care what this is...
      unsigned int null_msg_size;
      const char *null_msg = transport_recv(to_shutdown->subcontractor_transport, &(to_shutdown->pid), &null_msg_size);

      if (null_msg == NULL)
      {
      }                         // Avoid compiler warnings
    }

    curr = g_slist_next(curr);
  }
  g_free(contract_serialised);

  // Let the handler get back to work
  sigprocmask(SIG_UNBLOCK, &x, NULL);

  // Done
  contract_close(a_contract);
  debug_log("Sent a shutdown message to all sub contractors.");
  return 0;
}


/**
 * \brief Clean up everything as best we can
 *
 * \param return_value What to return, allows calling 'return clean_up(0)' 
 * \param mcp_upstream_transport The MCP upstream transport that may need to be cleaned up
 * for a clean exit etc.
 * \return Simply returns whatever was passed to it
 *
 */
gint clean_up(int return_value, transport_t mcp_upstream_transport)
{

  debug_log("Cleaning up in contractor");
  sigset_t x;

  sigemptyset(&x);
  sigaddset(&x, SIGCHLD);

  sigprocmask(SIG_BLOCK, &x, NULL);

  if (mcp_upstream_transport != NULL)
  {
    transport_close(mcp_upstream_transport);
    mcp_upstream_transport = NULL;
  }

  if (subcontractor_list != NULL)
  {
    g_slist_free_full(subcontractor_list, subcontractor_gslist_free);
    subcontractor_list = NULL;
  }

  sigprocmask(SIG_UNBLOCK, &x, NULL);

  debug_log("Closing logger");

  logger_close();

  debug_log("Closing config");

  config_close();


  return return_value;
}


/**
 * \brief Set up the logging variable based on settings provided by the
 * config server
 *
 * \return 0 on success, -1 on failure
 *
 */
gint setup_logging(void)
{
  int ret = logger_config_init();

  if (ret != 0)
  {
    severe_log("Contractor %i failed to create log transport. Aborting\n", getpid());
    return -1;
  }

  debug_log("Setup logger OK, leaving setup function.");

  return 0;
}


/**
 * \brief Sets up the mcp transport based on settings in the
 * config file
 *
 * \return 0 on success, -1 on failure
 * \warning Requires a valid config global
 *
 */
int setup_mcp_transport(transport_t * mcp_upstream_transport)
{

  /* Work out the mcp transport port */
  gchar *mcp_endpoint = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_MCP_CONNECT_ENDPOINT, &mcp_endpoint) != 0) || (mcp_endpoint == NULL))
  {
    severe_log("Couldn't retrieve the upstream transport contractor needs to talk to MCP");
    if (mcp_endpoint != NULL)
    {
      g_free(mcp_endpoint);
    }

    return -1;

  }

  *mcp_upstream_transport = transport_init(TRANSPORT_TYPE_PUSHPULL, mcp_endpoint);

  g_free(mcp_endpoint);

  if (*mcp_upstream_transport == NULL)
  {
    severe_log("Failed to create upstream transport");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_CONTRACTOR_RECV_FROM_MCP_RETRIES, &contractor_to_mcp_retries) != 0)
  {
    warning_log("Couldn't get the retries option. Using default");
    contractor_to_mcp_retries = CONFIG_CONTRACTOR_RECV_FROM_MCP_RETRIES_DEFAULT;
  }

  long timeout = CONFIG_CONTRACTOR_RECV_FROM_MCP_TIMEOUT_DEFAULT;

  if (config_get_long_with_default_macro(NULL, CONFIG_CONTRACTOR_RECV_FROM_MCP_TIMEOUT, &timeout) != 0)
  {
    warning_log("Couldn't find out what timeout option to use for MCP <-> Contractor! (to set in contractors)");
  }

  transport_set_recv_timeout(*mcp_upstream_transport, timeout);

  return 0;

}

/**
 * \brief Kill a subcontractor (brutally)
 * 
 * \param kill_this The sub contractor to kill
 * \return 0 on success (or no action required), -1 on failure
 *
 * This kills subcontractors by sending a SIGKILL. The signal
 * handler should then take over.
 *
 */
gint kill_subcontractor(struct subcontractor * kill_this)
{
  if (kill_this == NULL)
  {
    warning_log("Asked to kill a NULL subcontractor!");
    return 0;
  }

  volatile int local_pid = kill_this->pid;

  if (local_pid == -1)
  {
    // Already dead
    warning_log("Asked to kill an already dead subcontractor!");
    return 0;
  }

  if (kill(local_pid, SIGKILL) != 0)
  {
    error_log("Error! Couldn't kill sub contractor.");
    return -1;
  }

  while (kill_this->pid != -1)
  {
    sleep(1);
  }

  return 0;
}


/** 
 * \brief Spawns an individual subcontractor based on the contents 
 * of the given struct
 *
 * \param spawn_this This struct contains the information required to 
 * spawn the subcontractor
 * \return Returns zero on success, non zero on failure
 * \warning If spawn_this->pid is NOT equal to -1, this function assumes the 
 * contractor is already running, does nothing and returns success (0).
 *
 * This spawns a subcontractor. Populated the spawn_this->pid member 
 * with the newly created pid. If spawn_this->pid != -1 then this 
 * function does nothing and returns success.
 *
 */
gint spawn_subcontractor(struct subcontractor * spawn_this)
{
  debug_log("Attempting to spawn a new sub contractor");

  /* Sanity Checking */

  if (spawn_this->execution_path == NULL)
  {
    severe_log("Couldn't spawn sub contractor, since the execution path was NULL! This doesn't make sense!");
    return -1;
  }

  prong_assert(spawn_this->subcontractor_name != NULL);

  if (spawn_this->pid != -1)
  {
    debug_log("Asked to spawn a sub contractor (%s) that already appeared to be alive", spawn_this->subcontractor_name);
    return 0;
  }

  if (spawn_this->subcontractor_transport != NULL)
  {
    warning_log("A dead sub contractor (%s) had a non dead transport. Attempting to close it. This probably means it crashed on the last run", spawn_this->subcontractor_name);

    transport_close(spawn_this->subcontractor_transport);

    if (spawn_this->subcontractor_transport_name != NULL)
    {
      if (clean_up_end_point_file_if_exists(spawn_this->subcontractor_transport_name) != 0)
      {
        warning_log("Couldn't clean up end point file. Files may still exist.");
      }
      g_free(spawn_this->subcontractor_transport_name);
    }
  }

  /* Check we have a config end point to pass on (we should at this stage) */

  gchar *config_endpoint = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_CONFIG_CONNECT_ENDPOINT, &config_endpoint) != 0) || (config_endpoint == NULL))
  {
    severe_log("Couldn't determine the config endpoint to pass to subs");
    if (config_endpoint != NULL)
    {
      g_free(config_endpoint);
    }
    return -1;

  }

  /* Setup transport */

  /* Note that we originally just set the option in the
   * config, and passed the config end point, but this is racy - the sub 
   * contractor might be up and ready to go, and reading the config
   * before the option is set. As such, we explicitly pass both the config
   * end point and the transport. It's not quite so elegant, but safer. 
   * It also means we need to setup the transport before we spawn the
   * child
   */

  transport_id++;

  gchar *working_dir = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_WORKING_DIRECTORY, &working_dir) != 0) || (working_dir == NULL))
  {
    severe_log("Couldn't determine the working directory (was going to use it for IPC paths");
    if (working_dir != NULL)
    {
      g_free(config_endpoint);
      g_free(working_dir);
    }
    return -1;

  }
  // Since this is stored reverse, we need to reverse it back...
  gchar *normal_order_exec_path = g_strdup(spawn_this->execution_path);

  normal_order_exec_path = g_strreverse(normal_order_exec_path);

  gchar *option_value = g_strdup_printf("ipc://%s/contractor_%i_%s_transport_%i", working_dir, getpid(), basename_safe(normal_order_exec_path), transport_id);

  g_free(working_dir);

  debug_log("Setting up transport for sub contractor, using %s", option_value);

  spawn_this->subcontractor_transport = transport_init(TRANSPORT_TYPE_PUSHPULL, option_value);

  if (spawn_this->subcontractor_transport == NULL)
  {
    severe_log("Something went wrong setting up sub contractors transport (in spawn_subcontractor). Error was: %s .Aborting.", strerror(errno));

    g_free(config_endpoint);
    g_free(option_value);
    g_free(normal_order_exec_path);
    return -1;
  }

  debug_log("Transport to contractor appeared to be setup OK!");

  // Save this to remove it later
  spawn_this->subcontractor_transport_name = g_strdup(option_value);


  const char *base_name = basename_safe(normal_order_exec_path);
  long timeout = CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_TIMEOUT_DEFAULT;

  if (config_get_long_group_or_general_with_default_macro(base_name, CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_TIMEOUT, &timeout) != 0)
  {
    warning_log("Couldn't find out what timeout option to use!!");
  }

  transport_set_recv_timeout(spawn_this->subcontractor_transport, timeout);
  debug_log("Using %li for timeout to %s", timeout, base_name);

  /* Now we can actually spawn the sub contractor */

  char *args_to_use[] = { normal_order_exec_path, config_endpoint, option_value, NULL, };

  debug_log("About to spawn sub contractor using \"%s\" \"%s\" \"%s\" ", args_to_use[0], args_to_use[1], args_to_use[2]);

  int ret = spawn_process(args_to_use, (sig_atomic_t *) & (spawn_this->pid));

  g_free(config_endpoint);
  g_free(normal_order_exec_path);
  g_free(option_value);

  if (ret != 0)
  {
    severe_log("Something went wrong spawning sub contractors (in spawn_subcontractor)! Aborting.");
    return -1;
  }

  /* 
   * This is no longer required, as we pass two arguments above to the sub contractor
   * 
   *
   *
   *
   * Transport setup complete, now save it in the config server 
   * (the sub contractor will probably never actually need it, 
   * but we may as well throw it in) 
   

  gchar *option_group = g_strdup_printf("%i", spawn_this->pid);

  if (config_set(option_group, CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_OPTION_NAME, option_value) != 0)
  {
    severe_log("Couldn't set the option for contractor <-> sub contractor transport");
    g_free(option_group);
    g_free(option_value);
    return -1;
  }

  g_free(option_group);

  */

  debug_log("Sub contractor setup OK, pid was %i", spawn_this->pid);

  // Spawn complete

  return 0;
}


/** 
 * \brief Processes a contract with a single sub contractor 
 *
 * \param to_process The contract to process
 * \param using_this_subcontractor The subcontractor to use
 * this function only processes it as a single type
 * \return A contract_completion_report containing a copy of 
 * all the results, NULL on error
 * \warning You are required to free the return struct when done. 
 *
 * This function takes a single contract, and passes it a subcontractor. 
 * Returns the result when done. If the specified subcontractor isn't alive, 
 * it will try and spawn a new one.
 *
 */
contract_completion_report_t process_with_single_subcontractor(struct subcontractor * using_this_subcontractor, contract_t to_process)
{

  // The first thing we need to do is check if the subcontractor is alive, 
  // otherwise we'll spawn it

  if (using_this_subcontractor->pid == -1)
  {

    sigset_t x;

    sigemptyset(&x);
    sigaddset(&x, SIGCHLD);
    sigprocmask(SIG_BLOCK, &x, NULL);

    int ret_val = spawn_subcontractor(using_this_subcontractor);

    sigprocmask(SIG_UNBLOCK, &x, NULL);

    if (ret_val != 0)
    {
      severe_log("There was an error spawning up subcontractor %s on demand!", using_this_subcontractor->execution_path);
      return NULL;
    }

  } else
  {
    debug_log("Appears I already have a valid contractor. No need to " "spawn on demand. ");
  }

  // Sub contractor is now expected to be alive; send to subcontractor!
  if (using_this_subcontractor->subcontractor_transport == NULL)
  {
    severe_log("Error - No valid transport was setup for a subcontractor!");
    return NULL;
  }
  // Create the new contract 
  contract_t single_scon_contract = contract_clone(to_process);

  contract_delete_types(single_scon_contract);

  // This is what we'll hope to get back
  contract_completion_report_t single_type_ccr = NULL;

  unsigned int contract_msg_to_send_size = 0;
  char *contract_msg_to_send = contract_msg_to_send = contract_serialise(single_scon_contract, &contract_msg_to_send_size);


  if (contract_msg_to_send == NULL)
  {
    severe_log("Error. Couldn't create the contract to send to subcontractor!");
    return NULL;
  }

  debug_log("Sending message to sub contractor for processing.");

  // At present. We don't need to really tidy anything up. 
  // This may change, in which case something need to be done below before
  // resetting these flags.
  unhandled_subcontractor_exit_signal = 0;
  unhandled_subcontractor_exit_normal = 0;

  unsigned int subcontractor_ccr_msg_size = 0;
  const char *subcontractor_ccr_msg =
    transport_sendrecv(using_this_subcontractor->subcontractor_transport, contract_msg_to_send, contract_msg_to_send_size, &(using_this_subcontractor->pid), &subcontractor_ccr_msg_size);
  g_free(contract_msg_to_send);

  if (subcontractor_ccr_msg == NULL)
  {
    severe_log("Failed to get back a sane message from subcontractor (%s) for contract %s (error: %i which means %s)", using_this_subcontractor->execution_path,
               contract_get_path(single_scon_contract), errno, strerror(errno));

    if (errno == 11 && unhandled_subcontractor_exit_signal != 1 && unhandled_subcontractor_exit_normal != 1)
    {
      // A sub contractor has timed out
      warning_log("A sub contractor (%s) appeared to time out for contract %s. Killing it.", using_this_subcontractor->execution_path, contract_get_path(single_scon_contract));

      if (kill_subcontractor(using_this_subcontractor) != 0)
      {
        error_log("Error killing a timed out subcontractor!");
      }
    }

    contract_close(single_scon_contract);
    return NULL;
  }

  single_type_ccr = contract_completion_report_init(subcontractor_ccr_msg, subcontractor_ccr_msg_size);

  contract_close(single_scon_contract);
  return single_type_ccr;
}


/**
 * \brief Assess a CCR for a single subcontractor. Returns the best result
 * above the subcontractor minimum threshold
 *
 * \param assess_me The CCR to assess
 * \return Returns NULL if no acceptable results were found, otherwise the 
 * CCR with the best result
 */
contract_completion_report_t assess_single_subcontractor_ccr(const contract_completion_report_t assess_me)
{

  if (assess_me == NULL)
  {
    return NULL;
  }

  unsigned int res_count = 0;
  const result_t *results = contract_completion_report_get_results(assess_me, &res_count);

  // Sanity
  if (res_count <= 0)
  {
    return NULL;
  }
  // Lookup the name of the first result which we presume is the same
  // name as all the results we are passed (we do check this later)
  const char *name = result_get_subcontractor_name(results[0]);
  const char *base_name = basename_safe(name);

  gchar *rev_name = g_strreverse(g_strdup(base_name));

  // Lookup its threshold
  struct subcontractor *scon = get_subcontractor_by_rev_name(rev_name);

  int thresh = CONFIG_SCON_MIN_CONF_THRESHOLD_DEFAULT;

  if (scon == NULL)
  {
    // Shouldn't happen. Assume default
    warning_log("Warning. The name set for an incoming result doesn't match any subcontractors I know about! Will assume default threshold value (%i)", CONFIG_SCON_MIN_CONF_THRESHOLD_DEFAULT);
  } else
  {
    thresh = scon->subcontractor_confidence_threshold;
  }

  debug_log("Threshold for %s calculated as %i", name, thresh);

  g_free(rev_name);

  // For each result, simply check if they are above the threshold,
  // and pick the highest in this set.

  const char *last_name = NULL;
  int res_num = 0;

  int highest_conf_this_sub = -2;
  result_t highest_result_this_sub = NULL;

  for (res_num = 0; res_num < res_count; res_num++)
  {
    name = result_get_subcontractor_name(results[res_num]);

    // Grab the name of the subcontractor
    if (res_num != 0 && name != last_name)
    {
      warning_log("When looking for the best result from a single sub contractor, I found results with different names. Will continue, but this is almost certainly not expected behaviour");
    }

    last_name = name;

    debug_log("Processing result %i from \"%s\"", res_num, name);

    int this_conf = result_get_confidence(results[res_num]);

    if (this_conf >= thresh)
    {
      // This result is above the minimum, check if it's the best
      // (or equal to the best) this sub has produced.

      if (this_conf >= highest_conf_this_sub)
      {
        // This is a result we want to include... 
        highest_conf_this_sub = this_conf;
        highest_result_this_sub = results[res_num];
      } else
      {
        debug_log("Discarding result %i from sub %s as it was not the best result returned by that sub (conf: %i best so far: %i)", res_num, name, this_conf, highest_conf_this_sub);
      }

    } else
    {
      debug_log("Discarding result %i from sub %s as it was below the required threshold (conf: %i thresh: %i)", res_num, name, this_conf, thresh);
    }
  }

  if (highest_result_this_sub != NULL)
  {
    contract_completion_report_t to_return = contract_completion_report_init(NULL, 0);

    contract_completion_report_add_result(to_return, highest_result_this_sub);
    contract_t orig = contract_completion_report_get_original_contract(assess_me);

    contract_completion_report_set_original_contract(to_return, orig);

    return to_return;
  }

  return NULL;
}

/** 
 * \brief Aggregates a GList of contract_completion_reports into a single one
 *
 * \param results A GList full of contract_completion_reports to aggregate
 * \param original_contract The original contract associated with the CCR
 * \return A contract_completion_report containing a copy of all the results, 
 * NULL on error.
 * \warning You are required to free the return struct when done. 
 *
 * This function takes a list of contract completion reports and aggregates
 * them into a single report, which is returned. It is the callers 
 * responsibility to free the returned struct.
 *
 */
contract_completion_report_t aggregate_results(GSList * results, contract_t original_contract)
{

  debug_log("Going to aggregate %i subcontractor results and return a single result", g_slist_length(results));

  int j = 0;

  contract_completion_report_t to_return = contract_completion_report_init(NULL, 0);

  GSList *curr = results;

  // For each incoming contract completion report
  while (curr != NULL)
  {
    contract_completion_report_t current_completion_report = (contract_completion_report_t) curr->data;

    // Collect the results and add them to our aggregated report ("to_return")
    unsigned int num_results;
    const result_t *results = contract_completion_report_get_results(current_completion_report, &num_results);

    for (j = 0; j < num_results; j++)
    {
      contract_completion_report_add_result(to_return, results[j]);
    }

    contract_completion_report_set_original_contract(to_return, original_contract);

    curr = g_slist_next(curr);
  }

  return to_return;
}

/**
 * \brief Does the specified subcontractor support the contract 
 * process_as_type(s)
 *
 * \param scon The subcontractor 
 * \param to_process The contract
 * \return TRUE is the subcontractor can support the contract, FALSE
 * if the subcontractor doesn't support it.
 */
gboolean subcontractor_supports_contract_type(struct subcontractor * scon, contract_t to_process)
{
  if (brute_force_mode == 1)
  {
    return TRUE;
  }

  unsigned int num_types = 0;

  const unsigned int *types = contract_get_types(to_process, &num_types);

  if (types == NULL || num_types == 0)
    return FALSE;

  int supp_i = 0;

  for (supp_i = 0; supp_i < scon->supported_types->len; supp_i++)
  {
    int type_i = 0;

    for (type_i = 0; type_i < num_types; type_i++)
    {
      if (types[type_i] == g_array_index(scon->supported_types, gint, supp_i))
      {
        return TRUE;
      }
    }
  }

  return FALSE;
}


/** 
 * \brief Add a result with a confidence of negative one to the CCR
 *
 * \param report The report to add the result to
 * \param type The type to add the -1 result for
 * \return 0 on success, -1 on error
 *
 * This simply appends a result of -1 confidence for the specified type
 * to the specified ccr. This is so that we can flag back up the chain 
 * the difference beween:\n
 * - A subcontractor inspecting a file/block and giving a low confidence 
 * (no result) and\n
 * - No subcontractors being able to inspect a certain type (conf = -1)
 *
 */
gint add_negative_one_result(contract_completion_report_t report, const int type)
{

  result_t new_res = result_init(NULL, 0);

  result_set_confidence(new_res, -1);
  result_set_subcontractor_name(new_res, "Contractor");
  result_set_brief_data_description(new_res, lightmagic_text_representation(type));
  result_set_data_description(new_res, lightmagic_human_friendly_descriptive_name(type));

  contract_completion_report_add_result(report, new_res);
  result_close(new_res);

  return 0;
}


/**
 * \brief Process a contract in brute force mode
 *
 * \param to_process The contract to process
 * \return The "brute forced" contract completion report  
 *
 */
contract_completion_report_t process_contract_brute_force(contract_t to_process)
{

  // Simply collect all the results for every sub contractor,
  // aggregate them and return them.
  GSList *all_results = NULL;

  GSList *curr = subcontractor_list;

  while (curr != NULL)
  {
    struct subcontractor *current = (struct subcontractor *) curr->data;
    contract_completion_report_t last_result = process_with_single_subcontractor(current, to_process);

    all_results = g_slist_prepend(all_results, last_result);

    curr = g_slist_next(curr);
  }

  contract_completion_report_t to_return = aggregate_results(all_results, to_process);

  // Close them all...

  curr = all_results;

  while (curr != NULL)
  {
    contract_completion_report_t to_free = (contract_completion_report_t) curr->data;

    contract_completion_report_close(to_free);

    curr = g_slist_next(curr);
  }

  return to_return;
}


/** 
 * \brief Processes a contract using all the sub contractors we can 
 * find that will accept this type of contract
 *
 * \param to_process The contract to process
 * \return A contract completion report with relevant results
 * \warning You are required to free the ccr returned using the
 * contract_completion_report_close method
 *
 */
contract_completion_report_t process_contract(contract_t to_process)
{
  debug_log("Processing a contract (%s). Will process with all available sub contractors", contract_get_path(to_process));

  if (brute_force_mode == 1)
  {
    return process_contract_brute_force(to_process);
  }

  GSList *next = subcontractor_list;

  while (next != NULL)
  {
    struct subcontractor *current = (struct subcontractor *) next->data;

    if (subcontractor_supports_contract_type(current, to_process))
    {
      contract_completion_report_t last_result = process_with_single_subcontractor(current, to_process);

      if (last_result == NULL)
      {
        warning_log("For some reason, I got back a NULL response from a single subcontractor.");
      }

      contract_completion_report_t subcontractor_assessed_result = assess_single_subcontractor_ccr(last_result);

      contract_completion_report_close(last_result);

      if (subcontractor_assessed_result != NULL)
      {
        // We have a winner. Return the CCR and break.
        debug_log("Found a satisfactory result, returning CCR");
        return subcontractor_assessed_result;
      } else
      {
        debug_log("Subcontractor %s supported this contract, however no satisfactory result was returned. Will continue processing", current->subcontractor_name);
      }

    } else
    {
      //debug_log("Subcontractor %s did not support this contract, will continue on.", current->subcontractor_name);
    }

    next = g_slist_next(next);
  }

  debug_log("Failed to process a contract (%s). Either no sub contractors that could handle it were available, or none returned a high enough confidence", contract_get_path(to_process));

  contract_completion_report_t to_return = contract_completion_report_init(NULL, 0);

  contract_completion_report_set_original_contract(to_return, to_process);

  // Checking for any data types that we don't support
  unsigned int requested_types_count = 0;

  const unsigned int *requested_types = contract_get_types(to_process, &requested_types_count);

  for (int i = 0; i < requested_types_count; i++)
  {
    if (unsupported_filetype_bitmap[requested_types[i] >> 3] & (0x01 << (requested_types[i] & 0x07)))
    {
      // This filetype wasn't supported!
      add_negative_one_result(to_return, requested_types[i]);
    }
  }

  return to_return;

}

/** 
 * \brief Prints out usage
 *
 */
void usage(void)
{
  fprintf(stderr, "Usage: contractor <config end point>\n\n" "If you aren't sure how you should be calling this, you should probably be using one of the shipped scripts to startup pronghorn");
}


/**
 * \brief Parse the command line arguments to the contractor
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
    severe_log("Wrong number of args passed. You only need to pass the " "config end point to the contractor.");
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

  debug_log("Config-init-ing using end point: %s", config_end_point);

  if (config_init(config_end_point) != 0)
  {
    severe_log("Problem setting up the configuration engine " "(endpoint: %s, " "error: %s). Aborting.", config_end_point, strerror(errno));

    return -1;
  }
  // Are we in "brute force" mode?
  brute_force_mode = 0;

  if (config_get_int_with_default_macro(CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_BRUTE_FORCE, &brute_force_mode) != 0)
  {
    brute_force_mode = 0;
  }

  return 0;
}


/**
 * \brief The main processing loop
 *
 * \param mcp_upstream_transport The transport to use
 * \return 0 on clean exit, -1 on failure
 *
 * The main processing loop that handles dispatching contracts 
 * as appropriate.
 */
int main_processing_loop(transport_t mcp_upstream_transport)
{
  /* Send empty "I'm ready" message */
  debug_log("About to send empty contract completion report");

  contract_completion_report_t ccr = contract_completion_report_init(NULL, 0);
  unsigned int empty_msg_size;
  char *empty_msg = contract_completion_report_serialise(ccr, &empty_msg_size);

  contract_completion_report_close(ccr);

  if (transport_send(mcp_upstream_transport, empty_msg, NULL, empty_msg_size) != 0)
  {
    severe_log("Couldn't send initial \"I'm ready\" message to MCP. Contractor can't start.");
    return -1;
  }

  debug_log("Empty contract completion report sent, commencing main contractor loop");

  /* Main processing loop */

  int finished = 0;
  int retries = 0;

  while (finished == 0 && sigterm_received == 0)
  {
    unsigned int msg_size;

    const char *msg = transport_recv(mcp_upstream_transport, NULL, &msg_size);

    if (msg == NULL && retries < contractor_to_mcp_retries)
    {

      info_log("Received a null message from the MCP. Not sure what to do. Will retry the recv...");
      retries++;
      continue;

    } else if (msg == NULL)
    {

      severe_log("Received a null message from the MCP again. Giving up retrying.");
      finished = 1;
      continue;

    }

    retries = 0;

    contract_t new_contract = contract_init(msg, msg_size);

    if (new_contract == NULL)
    {
      severe_log("Couldn't parse a message from the MCP.");

      contract_close(new_contract);

      // To preserve the req/resp model, we send an empty result back 
      // to the MCP. 
      // Eventually the MCP will time out if we don't do this, 
      // however this will keep things speedy.
      transport_send(mcp_upstream_transport, empty_msg, NULL, empty_msg_size);

      continue;
    }

    if (strcmp(contract_get_path(new_contract), "") == 0 && contract_get_sleep_time(new_contract) <= -1)
    {

      info_log("Received an empty contract from the MCP with sleep time set to -1. Assuming my work here is done.");
      finished = 1;
      contract_close(new_contract);
      continue;

    } else if (strcmp(contract_get_path(new_contract), "") == 0)
    {

      debug_log("Received an empty contract from the MCP with sleep time set to >= 0. Will sleep and try again.");
      sleep(contract_get_sleep_time(new_contract) / 1000);
      contract_close(new_contract);
      debug_log("Sleep done. Trying again.");

      if (transport_send(mcp_upstream_transport, empty_msg, NULL, empty_msg_size) != 0)
      {
        severe_log("Couldn't send wake up \"I'm ready\" message to MCP. Error.");
        return -1;
      }
      continue;
    }

    debug_log("Message from MCP parsed OK, processing %s using sub contractors", contract_get_path(new_contract));
    contract_completion_report_t contract_report = process_contract(new_contract);

    debug_log("Responding back to MCP with contract completion report");
    contract_close(new_contract);

    unsigned int msg_to_send_size;
    char *msg_to_send = contract_completion_report_serialise(contract_report, &msg_to_send_size);

    contract_completion_report_close(contract_report);

    if (transport_send(mcp_upstream_transport, msg_to_send, NULL, msg_to_send_size) != 0)
    {
      severe_log("Failed to send a message to the MCP.");
    }
    g_free(msg_to_send);

  }                             // End main while loop

  g_free(empty_msg);
  debug_log("Main while loop terminated in contractor.");

  // Tell every sub contractor we have to shutdown
  if (send_shutdown_message_to_subcontractors() != 0)
  {
    severe_log("Error sending shutdown messages to all sub contractors");
    // We could SIGTERM them here, however clean_up should do this anyway if it finds alive
    // sub contractors.

  } else
  {
    debug_log("Shutdown messages sent to all sub contractors");
  }

  while (sleep(1) != 0);

  return 0;
}


/** 
 * \brief Contractor main. Performs setup then commences the main run loop
 *
 * \param argc Argument count on startup
 * \param argv Value of arguments provided on startup
 */
int main(int argc, char **argv)
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];
  // Stop buffering on stdout and stderr
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  gchar *config_end_point = NULL;

  debug_log("Contractor has started up. Will try and find configuration" " server and connect to it.");

  if ((parse_command_args(argc, argv, &config_end_point) != 0) || (config_end_point == NULL))
  {

    severe_log("Couldn't get the configuration end point I need " "to connect to.");
    return clean_up(-1, NULL);
  }

  if (setup_config(config_end_point) != 0)
  {
    severe_log("Couldn't setup the connection to the configuration " "server");
    return clean_up(-1, NULL);
  }

  g_free(config_end_point);

  debug_log("Setup config OK, setting up logging");

  if (setup_logging() != 0)
  {
    severe_log("Couldn't setup logging!\n");
    return clean_up(-1, NULL);
  }

  debug_log("Setup logging OK, setting up mcp transport");

  transport_t mcp_upstream_transport;

  if (setup_mcp_transport(&mcp_upstream_transport) != 0)
  {
    severe_log("Config OK. Logging OK. But couldn't setup MCP transport!\n");
    return clean_up(-1, mcp_upstream_transport);
  }

  debug_log("Setup transport OK, setting up subcontractor struct and sig handlers");

  if (setup_subcontractors() != 0)
  {
    severe_log("Error setting up the sub contractors! I can't work without my subcontractors!");
    return clean_up(-1, mcp_upstream_transport);
  }

  debug_log("Setup sub contractors... will setup sig handlers");

  if (setup_sig_handlers() != 0)
  {
    severe_log("Error setting up signal handlers! Aborting.");
    return clean_up(-1, mcp_upstream_transport);
  }

  debug_log("Setup sig handlers. Contractor entering main processing loop");

  if (main_processing_loop(mcp_upstream_transport) != 0)
  {
    return clean_up(-1, mcp_upstream_transport);
  }

  debug_log("Contractor made clean exit, about to clean up");

  return clean_up(0, mcp_upstream_transport);

}
