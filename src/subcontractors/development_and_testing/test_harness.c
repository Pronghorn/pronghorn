/* libpronghorn test_harness
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
 */

/**
 * \file test_harness.c
 * \brief This is a simple test harness for a plugin.
 *
 * Modify the file and recompile to enable/disable features
 *
 * - PRINT_BLOCK_ARRAY. Prints the array of blocks returned by the subcontractor
 *
 * - SIMPLE_CONTRACT_ENUMERATION. List out number of contracts with no detail. (If 0 lists each contract in detail)
 *
 * - SORT_CONTRACT_ARRAY. Sorts the contract array.
 *
 * - PRINT_CONTRACT_ARRAY. Prints the contract array.
 *
 * - NUM_EXERCISE_LOOPS. Calls the subcontractor an extra N times (discarding results) to exercise it. Ensure that the subcontractor will function if passed the same file multiple times (in particular consider mounting limitations)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <glib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include <lprocess.h>
#include <transport.h>
#include <contract.h>
#include <report.h>
#include <logger.h>
#include <config.h>
#include <lightmagic.h>
#include <basename_safe.h>

/** The test comms socket to talk to the subcontractor. */
#define TEST_SOCKET "ipc:///tmp/test_socket"
#define IPC_PREFIX "ipc://"

/** If 1 it will cause the block array to be printed */
#define PRINT_BLOCK_ARRAY 1
/**
 * If 0 it will only list the number of contracts received, otherwise it
 * will list each contract in detail.
 */
#define SIMPLE_CONTRACT_ENUMERATION 0
/** If 1 will cause the contract array to be sorted */
#define SORT_CONTRACT_ARRAY 0
/** If 1 will cause the contract array to be printed */
#define PRINT_CONTRACT_ARRAY 1

/**
 * Defines the number of extra times the subcontractor will be called
 * to exercise it. Before setting this to a nonzero value ensure that
 * it will not automatically mount - otherwise you could have problems
 */
#define NUM_EXERCISE_LOOPS 0

/** Holds the PID of the subcontractor child, or 0 if one doesn't exist */
static volatile sig_atomic_t child_pid = -1;

/** Contains the executable name */
const char *SHORT_PROCESS_NAME = NULL;

/** Contains the executable name */
const char *PROCESS_NAME = NULL;

static void print_md5(const char *path);

/** A signal handler to handle child death */
static void sigchld_handler(int sig, siginfo_t * sig_info, void *ucontext)
{
  int status;
  pid_t cp;

  while ((cp = waitpid(-1, &status, WNOHANG)) > 0)
  {
    if (cp == child_pid)
    {
      if (WIFEXITED(status) == TRUE)
      {
        child_pid = -1;
        // This isn't safe, but the only consequence is a corrupt stderr stream... right?
        fprintf(stderr, "Test-harness: Child exited with return code %d\n", WEXITSTATUS(status));
        return;
      }

      if (WIFSIGNALED(status) == TRUE)
      {
        child_pid = -1;
        // This isn't safe, but the only consequence is a corrupt stderr stream... right?
        fprintf(stderr, "Test-harness: Child exited due to signal %d\n", WTERMSIG(status));
        return;
      }

      return;
    }
    // This isn't safe, but the only consequence is a corrupt stderr stream... right?
    fprintf(stderr, "Test-harness: Received a sigchld that wasn't handled. Either the pid was for a different child(?) or the child didn't die - just changed state\n");
    fprintf(stderr, "child_pid = %d, this pid = %d\n", child_pid, cp);
  }
}

int spawn_subcontractor(const char *config_endpoint, char *contractor_endpoint)
{
  struct sigaction action;

  memset(&action, 0, sizeof(action));
  action.sa_sigaction = sigchld_handler;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGCHLD, &action, NULL))
  {
    perror("problem setting sigaction");
    return -1;
  }

  char **args = (char **) g_malloc(sizeof(char *) * 4);

  char *subcontractor;

  if ((config_get(NULL, CONFIG_TEST_HARNESS_SUBCONTRACTOR_TO_TEST_OPTION_NAME, &subcontractor) != 0) || (subcontractor == NULL))
  {
    g_free(args);
    debug_log("%s", CONFIG_TEST_HARNESS_SUBCONTRACTOR_TO_TEST_OPTION_NAME);
    error_log("Unable to get the name of the subcontractor to test!");
    return -1;
  }

  args[0] = subcontractor;
  args[1] = g_strdup(config_endpoint);
  args[2] = contractor_endpoint;
  args[3] = NULL;
  int ret = spawn_process(args, (sig_atomic_t *) & child_pid);

  g_free(args[1]);
  g_free(args[0]);
  g_free(args);

  if (ret != 0)
  {
    error_log("Could not spawn subcontractor");
    return -1;
  } else
  {
    debug_log("Subcontractor spawned");
  }

  return 0;
}

/**
 * Prints the usage statement to screen.
 */
static void print_usage(void)
{
  error_log("Usage: %s <configserver endpoint>", PROCESS_NAME);
  error_log("This is a Pronghorn test harness");
}

static void cleanup(transport_t t)
{

  transport_close(t);

  // If something went wrong like a subcontractor crashed, it's possible files will be left behind.
  // Double check it here

  char *test_harness_listen_endpoint = g_strdup_printf("%s-%d", TEST_SOCKET, getpid());
  char *file = strstr(test_harness_listen_endpoint, IPC_PREFIX);

  if (file != NULL && (strlen(test_harness_listen_endpoint) > (strlen(IPC_PREFIX) + 1)))
  {
    file = test_harness_listen_endpoint + strlen(IPC_PREFIX);

    struct stat info;

    if (stat(file, &info) != 0)
    {
      debug_log("Couldn't stat %s, not cleaning up.", file);
    } else
    {
      if (unlink(file) != 0)
      {
        warning_log("Couldn't delete endpoint %s, may still exist. Error was %i (%s)", file, errno, strerror(errno));
      } else
      {
        debug_log("Deleted left over IPC end point %s", file);
      }
    }

  } else
  {
    debug_log("End point doesn't appear to be ipc. Not removing file: %s ", file);
  }

  g_free(test_harness_listen_endpoint);

  logger_close();
  config_close();
}

/**
 * Starts the harness.
 *
 * \param argc Num of args
 * \param argv The args
 * \returns 0 on success, -1 on error
 */
int main(int argc, char *argv[])
{
  SHORT_PROCESS_NAME = basename_safe(argv[0]);
  PROCESS_NAME = argv[0];

  // We accept only one argument, namely the transport address of the
  // global configuration server
  if (argc != 2)
  {
    print_usage();
    return -1;
  }

  if (config_init(argv[1]) != 0)
  {
    error_log("Unable to setup test harness. Is there a problem with the endpoint syntax? %s", argv[1]);
    return -1;
  }

  int ret = 0;

  ret = logger_config_init();

  if (ret != 0)
  {
    error_log("Failed to create log transport");
    cleanup(NULL);
    return -1;
  }

  char *test_harness_listen_endpoint = g_strdup_printf("%s-%d", TEST_SOCKET, getpid());

  debug_log("Test harness is listening on %s", test_harness_listen_endpoint);
  transport_t transport = transport_init(TRANSPORT_TYPE_PUSHPULL, test_harness_listen_endpoint);

  if (transport == NULL)
  {
    error_log("Unable to create transport");
    g_free(test_harness_listen_endpoint);
    cleanup(NULL);
    return -1;
  }

  if (spawn_subcontractor(argv[1], test_harness_listen_endpoint) != 0)
  {
    error_log("Unable to spawn subcontractor");
    g_free(test_harness_listen_endpoint);
    cleanup(transport);
    return -1;
  }
  g_free(test_harness_listen_endpoint);
  test_harness_listen_endpoint = NULL;

  char *input_file;

  if ((config_get(NULL, CONFIG_INPUT_FILE_OPTION_NAME, &input_file) != 0) || (input_file == NULL))
  {
    error_log("Could not get input file name");
    cleanup(transport);
    return -1;
  }

  char *subcontractor;

  if ((config_get(NULL, CONFIG_TEST_HARNESS_SUBCONTRACTOR_TO_TEST_OPTION_NAME, &subcontractor) != 0) || (subcontractor == NULL))
  {
    error_log("Unable to get the name of the subcontractor which means I couldn't calculate the timeout!");
    return -1;
  }

  const char *sub_name = basename_safe(subcontractor);

  long timeout = CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_TIMEOUT_DEFAULT;

  if (config_get_long_group_or_general_with_default_macro(sub_name, CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_TIMEOUT, &timeout) != 0)
  {
    info_log("Couldn't find out what timeout option to use, using default");
  }

  transport_set_recv_timeout(transport, timeout);
  debug_log("Using %li for timeout to subcontractor", timeout);

  unsigned int contract_string_size;
  contract_t c = contract_init(NULL, 0);

  contract_set_path(c, input_file);
  contract_set_contiguous(c, 1);
  contract_set_absolute_offset(c, 0);
  char *contract_string = contract_serialise(c, &contract_string_size);

  contract_close(c);
  g_free(input_file);
  if (contract_string == NULL)
  {
    perror("Failed to create contract_string");
    g_free(contract_string);
    g_free(subcontractor);
    cleanup(transport);
    return -1;
  }

  info_log("Sending message");

  unsigned int subcontractor_result_msg_size;
  const char *subcontractor_result_msg = transport_sendrecv(transport, contract_string, contract_string_size, &child_pid, &subcontractor_result_msg_size);

  if (subcontractor_result_msg == NULL)
  {

    if (errno == EAGAIN)
    {
      // Timeout.
      error_log
        ("Timeout in receiving message from subcontractor! Either your subcontractor hung (it will be killed when running in pronghorn) or it didn't compelete in time. You need to make sure that the timeout is long enough, by setting subcontractor_timeout (specifcally for your sub contractor or the general case). In pronghorn, this would be via the config file. Using the test harness, you can specificy this using \"-o %s.subcontractor_timeout=<timeout in milliseconds>\" or \"-o general.subcontractor_timeout=<timeout in milliseconds>\" at the end of the command line",
         sub_name);

    } else if (errno == EINTR)
    {
      // Interupted.
      error_log("Something when wrong waiting for your subcontractor to return. Did it crash?! You might like to try adding \"-o %s.valgrind_opts=<path to valgrind>\" when testing.", sub_name);
    }

    cleanup(transport);
    g_free(contract_string);
    g_free(subcontractor);
    return -1;
  }

  g_free(subcontractor);

  contract_completion_report_t report = contract_completion_report_init(subcontractor_result_msg, subcontractor_result_msg_size);

  if (report == NULL)
  {
    perror("Recreating contract_completion_report");
    g_free(contract_string);
    cleanup(transport);
    return -1;
  } else
  {
    info_log("Reconstructed message");
  }

  info_log("=====================");
  info_log("Results: ");
  unsigned int results_count;
  const result_t *results = contract_completion_report_get_results(report, &results_count);

  c = contract_completion_report_get_original_contract(report);;

  for (int i = 0; i < results_count; i++)
  {
    const result_t r = results[i];

    info_log("Path=%s. Type=(%s) %s. Confidence=%d", contract_get_path(c), result_get_brief_data_description(r), result_get_data_description(r), result_get_confidence(r));

#if PRINT_BLOCK_ARRAY
    unsigned int block_range_size;
    const block_range_t *ranges = result_get_block_ranges(r, &block_range_size);

    if (block_range_size > 0)
    {
      int j;

      info_log("Blocks:");

      // This is inefficient. But it works and this function is rarely used
      char *big_s = g_strdup("");

      for (j = 0; j < block_range_size; j++)
      {
        unsigned long long pos;
        unsigned long long len;

        block_range_get_range(ranges[j], &pos, &len);
        char *new_s = g_strdup_printf("%s %llu-%llu", big_s, pos, pos + len - 1);

        g_free(big_s);
        big_s = new_s;
      }
      info_log("%s", big_s);
      g_free(big_s);
    }
#endif // PRINT_BLOCK_ARRAY

    unsigned int new_contracts_count;

#if SIMPLE_CONTRACT_ENUMERATION
    result_get_new_contracts(r, &new_contracts_count);

    info_log("\t- With %d new contracts!", new_contracts_count);
#else // SIMPLE_CONTRACT_ENUMERATION
    // Yes, this looks dodgy, but it's fine until r gets destroyed (which is after we destroy our copy)
    const contract_t *new_contracts_const = result_get_new_contracts(r, &new_contracts_count);
    contract_t *new_contracts = (contract_t *) g_malloc(sizeof(contract_t) * new_contracts_count);

    memcpy(new_contracts, new_contracts_const, sizeof(contract_t) * new_contracts_count);

    if (new_contracts_count > 0)
    {
      // Sorting the array
#if SORT_CONTRACT_ARRAY
      {
        int j;

        for (j = 0; j < new_contracts_count - 1; j++)
        {
          int k;

          for (k = 0; k < new_contracts_count - j - 1; k++)
          {
            int a = atoi(contract_get_path(new_contracts[k]));
            int b = atoi(contract_get_path(new_contracts[k + 1]));

            if (a > b)
            {
              contract_t temp = new_contracts[k];

              new_contracts[k] = new_contracts[k + 1];
              new_contracts[k + 1] = temp;
            } else if (a == b)
            {
              warning_log("Duplicate entry found! %s", contract_get_path(new_contracts[k]));
            }
          }
        }
      }
#endif // SORT_CONTRACT_ARRAY
#if PRINT_CONTRACT_ARRAY
      {
        info_log("New contracts: ");
        int j;

        for (j = new_contracts_count - 1; j >= 0; j--)
        {
          const char *path = contract_get_path(new_contracts[j]);

          if (access(path, R_OK) == 0)
          {
            info_log("OK %s", path);
            print_md5(path);
          } else
          {
            info_log("Couldn't access advertised new path %s", path);
          }
        }
      }
#endif // PRINT_CONTRACT_ARRAY
    }
    g_free(new_contracts);
#endif // SIMPLE_CONTRACT_ENUMERATION
  }
  contract_completion_report_close(report);


  if (NUM_EXERCISE_LOOPS != 0)
  {
    info_log("=====================");
    info_log("Exercising the plugin");
    for (int i = 0; i < NUM_EXERCISE_LOOPS; i++)
    {
      subcontractor_result_msg = transport_sendrecv(transport, (char *) contract_string, contract_string_size, &child_pid, &subcontractor_result_msg_size);
    }

    info_log("Finished exercising the plugin");
  }

  info_log("=====================");

  info_log("Telling subcontractor to close nicely");

  g_free(contract_string);

  // Send empty contract to tell child to close
  c = contract_init(NULL, 0);
  contract_set_path(c, "");
  contract_string = contract_serialise(c, &contract_string_size);
  contract_close(c);
  subcontractor_result_msg = transport_sendrecv(transport, (char *) contract_string, contract_string_size, &child_pid, &subcontractor_result_msg_size);
  g_free(contract_string);

  if (child_pid != -1)
  {
    sleep(100);
  }

  volatile int local_child_pid = child_pid;

  if (local_child_pid != -1)
  {
    warning_log("Process hasn't died automatically. Sending SIGTERM");
    kill(local_child_pid, SIGTERM);
    sleep(10);
    local_child_pid = child_pid;
    if (local_child_pid != -1)
    {
      warning_log("Process STILL hasn't died... Killing it");
      kill(local_child_pid, SIGKILL);
    }
  }

  cleanup(transport);

  return 0;
}

static void print_md5(const char *path)
{
  FILE *file = fopen(path, "r");

  if (file == NULL)
  {
    error_log("Couldn't open %s. Error was %s", path, strerror(errno));
    return;
  }
  // Get the size and other information
  struct stat info;

  if (stat(path, &info) != 0)
  {
    error_log("Couldn't open file %s; %s", path, strerror(errno));
    return;
  }

  size_t size = info.st_size;

  if (size == 0)
  {
    unsigned char empty[512];

    if (fread(empty, 512, 1, file) != 0 || feof(file) == 0)
    {
      error_log("ERROR reading %s! (It was reported as a zero size file but it didn't appear to be empty!", path);
      return;
    }

    info_log("Empty file OK.");

  } else
  {
    char *data = (char *) g_malloc(size);

    if (fread(data, size, 1, file) != 1)
    {
      error_log("ERROR reading %s (%s)!", path, strerror(errno));
      g_free(data);
      fclose(file);
      return;
    }

    gchar *checksum = g_compute_checksum_for_data(G_CHECKSUM_MD5, (guchar *) data, size);

    info_log("md5: %s %s", path, checksum);
    g_free(checksum);
    g_free(data);
  }

  fclose(file);
  return;
}
