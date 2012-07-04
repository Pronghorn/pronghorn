/* libpronghorn Data Source Helper
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
 * \file data_source.c
 * \brief A helper to manage the data source including incoming 
 * completion reports etc.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>

#include <lightmagic.h>
#include <lprocess.h>
#include <config.h>
#include <defaults.h>
#include <prong_assert.h>

#include "data_source.h"
#include "block_storage.h"
#include "file_manager.h"
#include "job_node.h"
#include "print_manager.h"

//#define CONFIG_DATA_SOURCE_EXTENDED_OUTPUT_FILE_OPTION_NAME "extended_output_file"

/* Defines */

#define WINDOW_SIZE 2048

/* Globals */

/** Magic bytes used to try and identify memory corruption */
const static int DATA_SOURCE_MAGIC = 0xBAAABAAA;

/* Structs */

/**
 * The structure that holds all the information relevant for a particular data
 * source.
 */
struct data_source
{

  /** The raw data source we have opened / are reading */
  pronghorn_file_t the_file;

  /** The block size we are using to process this data source with */
  unsigned long long block_size;

  /** A magic flag to help us detect any memory corruption */
  int magic;

  /** A store representing which blocks are done in our raw source */
  block_store_t block_store;

  /** The file name of the file we are processing */
  char *file_name;

  /** A flag showing whether the data source is mounted using fuse */
  int is_mounted;

  /** The path to the mounted directory */
  char *mounted_directory;

  /** The root of our job tree which stores contracts to be processed
   * (or those that have been and need their results printed) */
  GNode *job_tree;

  /** A flag indicating whether brute force mode is active */
  int brute_force_mode;

  /** At the moment this is only really used for tracking stuff when we print it out */
  unsigned long long next_job_id;
  unsigned long long next_result_id;

  /** Development use */
  FILE *extended_output_file;

  /** Print manager */
  print_manager_t print_manager;

  /** Maximum size of the tree */
  int max_tree_size;

  /** Default wait time for contractors when a tree gets full */
  int contractor_wait_time;

};


/** A small structure for convenience. When we are searching for a specific
 * node, we are often searching by contract. This saves us having to find
 * it every time, and gives us somewhere to put the matching node into when
 * we find it.
 */
struct job_node_match_data
{

  /** The path we are looking for */
  char *contract_path;

  /** The abs offset we are looking for */
  long long abs_off;

  /** The node we found the contract it, or NULL if we couldn't find it */
  GNode *matching_node;
};


/* Actual definitions below */

/**
 * \brief Is a node in incomplete (is it still to be processed?)
 * \param node The node in question
 * \param data User data, in this case a gboolean pointer, the value of which is set to TRUE if a node is incomplete
 *
 * \returns TRUE if the node is incomplete, FALSE if it's complete
 *
 */
static gboolean is_node_incomplete(GNode * node, gpointer data)
{

  prong_assert(data != NULL);
  prong_assert(node != NULL);

  gboolean *completed = (gboolean *) data;
  struct job_node_data *ndata = (struct job_node_data *) node->data;

  if (ndata->node_report != NULL)
  {
    // We are done. Keep searching.
    return FALSE;
  }
  // This node is NOT completed. Stop traversal
  *completed = TRUE;

  return TRUE;

}


/**
 * \brief Does the node specified have a "not yet issued" contract?
 * \param node The node in question
 * \param data If the contract is available (i.e. not yet issued), this is
 * set to be a pointer to node.
 * \return Returns TRUE if the node does, FALSE if it doesn't 
 *
 * Designed to be used as a GNodeTraverseFunc function. 
 *
 */
static gboolean does_node_have_contract(GNode * node, gpointer data)
{
  struct job_node_data *ndata = (struct job_node_data *) node->data;

  if (G_NODE_IS_ROOT(node) == TRUE)
  {
    return FALSE;
  }

  prong_assert(ndata->node_contract != NULL);

  if (ndata->contract_issued == FALSE)
  {
    // We are available!
    GNode **to_set = (GNode **) data;

    *to_set = node;

    return TRUE;
  }

  return FALSE;
}


/**
 * \brief Mark blocks in the given node completed
 *
 * \param ds The data source in which the blocks are contained
 * \param this_node The node we want to mark off on the raw data source as being complete
 *
 * \return 0 on success, -1 on failure
 *
 */
static int mark_node_blocks_complete(struct data_source *ds, GNode * this_node)
{

  prong_assert(ds != NULL);
  prong_assert(this_node != NULL);

  struct job_node_data *jdata = (struct job_node_data *) this_node->data;
  contract_completion_report_t ccr = jdata->node_report;

  prong_assert(ccr != NULL);

  unsigned int num_results = 0;
  const result_t *results = contract_completion_report_get_results(ccr, &num_results);

  // If num_results == 0 it means we don't have any actual results => UNIDENTIFIED BLOCK
  // If num_results > 1 it means we are either in brute force mode OR we have unsupported types (with conf = -1)

  prong_assert(num_results > 0);

  if (result_get_confidence(results[0]) == -1)
  {
    return 0;
  }

  // NB This is potentially different to how we handle this case elsewhere. It doesn't matter in the 
  // current model, but if it becomes valid for a CCR to have multiple results, it does and this
  // should be changed
  prong_assert(num_results == 1);
  if (num_results != 1)
  {
    return 0;
  }

  unsigned int num_ranges;
  block_range_t *ranges = result_get_block_ranges(results[0], &num_ranges);

/*
for(int i=0; i<num_ranges; i++)
{
unsigned long long pos = 0;
unsigned long long len = 0;
block_range_get_range(ranges[i], &pos, &len);
printf("Storing block range %i is %llu -> %llu\n", i, pos, len);
}
*/

  return store_blocks(ds->block_store, ranges, num_ranges);

}


/**
 * \brief Compute the magic of a new contract, and update the contract
 * accordingly
 *
 * \param ds The data source we are operating on
 * \param contract The contract whose magic needs calculating
 * \return 0 on success, -1 on error
 *
 * This is done differently to the raw data source - the 
 * raw data source we keep open and just seek around.
 * This is actually opening a new file every time.
 *
 */
static int compute_magic_of_new_contract(struct data_source *ds, contract_t contract)
{

  prong_assert(contract != NULL);
  prong_assert(ds != NULL);

  const gchar *file_name = contract_get_path(contract);
  unsigned int buff_size = 0;

  pronghorn_file_t contract_file = prong_file_init(file_name, ds->block_size, WINDOW_SIZE);

  if (contract_file == NULL)
  {
    error_log("Couldn't open file %s using prong file store! (%s)", file_name, strerror(errno));
    return -1;
  }

  const unsigned char *buff = prong_file_read_offset(contract_file, 0, &buff_size);

  if (buff_size == 0)
  {
    warning_log("File %s had zero size during light magic computation.", file_name);
    prong_file_close(contract_file);
    return -1;
  }
  // Magic Calculation

  GArray *magic_types = lightmagic_detect(buff, ds->block_size, buff_size);

  prong_file_close(contract_file);

  for (int typei = 0; typei < magic_types->len; typei++)
  {
    if (contract_add_type(contract, g_array_index(magic_types, int, typei)) == -1)
    {
      severe_log("Error adding contract type to contract!!");
    } else
    {
      debug_log("Added type %i (%s) to contract based on lightmagic", g_array_index(magic_types, int, typei), lightmagic_text_representation(g_array_index(magic_types, int, typei)));
    }
  }

  g_array_free(magic_types, TRUE);
  return 0;
}


/**
 * \brief Build a constant contract completion report
 * \param num_constant_blocks The number of constant blocks we are claiming
 * \param original_contract The contract we are generating the result for
 * \return A newly created contract_completion_report_t containing the constant results
 * \warning It is the callers responsibility to contract_completion_report_close the returned result
 */
static contract_completion_report_t build_const_ccr(unsigned long long num_constant_blocks, const contract_t original_contract, unsigned long long block_size)
{

  prong_assert(original_contract != NULL);
  prong_assert(num_constant_blocks > 0);

  contract_completion_report_t new_ccr = contract_completion_report_init(NULL, 0);

  if (new_ccr == NULL)
  {
    return NULL;
  }

  result_t new_res = result_init(NULL, 0);

  if (new_res == NULL)
  {
    contract_completion_report_close(new_ccr);
    return NULL;
  }
  // Constant nodes have a confidence of -1 (other things rely on this)
  result_set_confidence(new_res, -1);
  result_set_subcontractor_name(new_res, "MCP");
  result_set_brief_data_description(new_res, lightmagic_text_representation(MAGIC_TYPE_CONSTANT));
  result_set_data_description(new_res, lightmagic_human_friendly_descriptive_name(MAGIC_TYPE_CONSTANT));

  block_range_t range = block_range_init(NULL, 0);

  int ret = block_range_set_range(range, (contract_get_absolute_offset(original_contract) / block_size), num_constant_blocks);
  prong_assert(ret == 0);
  result_set_block_ranges(new_res, &range, 1);
  block_range_close(range);

  contract_completion_report_add_result(new_ccr, new_res);
  contract_completion_report_set_original_contract(new_ccr, original_contract);

  result_close(new_res);

  return new_ccr;
}

contract_t build_wait_contract(int wait_time)
{

  contract_t a_contract = contract_init(NULL, 0);

  contract_set_path(a_contract, "");
  contract_set_sleep_time(a_contract, wait_time);

  return a_contract;

}


// Documented in header file
data_source_t data_source_init(const char *file_name, unsigned long long block_size)
{
  if (block_size <= 0)
  {
    return NULL;
  }

  if (file_name == NULL)
  {
    return NULL;
  }

  struct data_source *ds = (struct data_source *) g_malloc(sizeof(struct data_source));

  ds->block_size = block_size;
  ds->file_name = g_strdup(file_name);
  ds->the_file = NULL;
  ds->block_store = NULL;
  ds->magic = DATA_SOURCE_MAGIC;
  ds->is_mounted = 0;
  ds->mounted_directory = NULL;
  ds->next_job_id = 0;
  ds->next_result_id = 0;
  ds->extended_output_file = NULL;
  ds->print_manager = NULL;
	ds->max_tree_size = CONFIG_MCP_MAX_NODES_IN_TREE_DEFAULT;
	ds->contractor_wait_time = CONFIG_MCP_FULL_TREE_WAIT_TIME_DEFAULT;

  if (config_get_int_with_default_macro(CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_BRUTE_FORCE, &(ds->brute_force_mode)) != 0)
  {
    ds->brute_force_mode = 0;
  }

  ds->the_file = prong_file_init(ds->file_name, ds->block_size, WINDOW_SIZE);
  if (ds->the_file == NULL)
  {
    severe_log("Couldn't setup the input file!");
    g_free(ds->file_name);
    g_free(ds);
    return NULL;
  }

  ds->block_store = block_store_init();
  if (ds->block_store == NULL)
  {
    severe_log("Couldn't setup the block store!");
    g_free(ds->file_name);
    g_free(ds);
    return NULL;
  }

  long long int starting_block = 0;

  if (config_get_long_long_with_default_macro(CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_START_AT_BLOCK_NUMBER, &starting_block) != 0)
  {
    starting_block = 0;
  }

  // Thresholds for tree size

  if (config_get_int_with_default_macro(CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_MCP_MAX_NODES_IN_TREE, &ds->max_tree_size) != 0)
  {
    warning_log("Couldn't get the maximum tree node size from the config options");
    ds->max_tree_size = CONFIG_MCP_MAX_NODES_IN_TREE_DEFAULT;
  }
  debug_log("Max tree size set to %i", ds->max_tree_size);
  
  if (config_get_int_with_default_macro(CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_MCP_FULL_TREE_WAIT_TIME, &ds->contractor_wait_time) != 0)
  {
    warning_log("Couldn't get the contractor wait time from the config options");
    ds->contractor_wait_time = CONFIG_MCP_FULL_TREE_WAIT_TIME_DEFAULT;
  }
  debug_log("Contractor wait time set to %i", ds->contractor_wait_time);

  // Setup print manager
  if (starting_block > 0)
  {
    block_range_t dont_process_range = block_range_init(NULL, 0);

    int ret = block_range_set_range(dont_process_range, 0, starting_block);
    prong_assert(ret == 0);
    if (store_blocks(ds->block_store, &dont_process_range, 1) != 0)
    {
      severe_log("Couldn't store initial blocks!");
      return NULL;
    }
    info_log("Starting at block %lli, NOT the start of the file", starting_block);
    ds->print_manager = print_manager_init(ds->block_size, (unsigned long long) starting_block);
  } else
  {
    ds->print_manager = print_manager_init(ds->block_size, 0);
  }

  // Setup the contract tree, free-d in data_source_close
  struct job_node_data *root_node = job_node_data_init();

  root_node->job_id = ds->next_job_id++;

  ds->job_tree = g_node_new(root_node);

  return ds;
}


/**
 * \brief A helper function to help validate a data_source reference.
 *
 * \param _ds The data source to be validated
 * It takes a transport_t reference and converts it into a struct transport*
 * if it is valid.
 *
 * It returns a struct transport* on success or NULL on error.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EINVAL - The transport reference is invalid.
 */
inline static struct data_source *data_source_validate(data_source_t _ds)
{
#ifndef DEBUG
  return (struct data_source *) _ds;
#endif

  if (_ds == NULL)
  {
    errno = EINVAL;
    return NULL;
  }

  struct data_source *ds = (struct data_source *) _ds;

  if (ds->magic != DATA_SOURCE_MAGIC)
  {
    errno = EINVAL;
    return NULL;
  }

  return ds;
}


// Documented in header file
int data_source_close(data_source_t source)
{
  struct data_source *ds = data_source_validate(source);

  if (ds == NULL)
  {
    return -1;
  }

  int return_val = 0;

  if (ds->block_store != NULL)
  {
    if (block_store_close(ds->block_store) != 0)
    {
      warning_log("Couldn't close block store. Resources may not have been freed correctly");
    }
  }

  if (ds->the_file != NULL)
  {
    prong_file_close(ds->the_file);
    ds->the_file = NULL;
  }

  g_free(ds->file_name);
  ds->file_name = NULL;

  if (ds->is_mounted)
  {
    // The default behaviour is not to unmount. If we want the
    // MCP to do this (and not a bash script), then we need to
    // first check all the child mounts are unmounted.
    // For the moment, we'll leave this as is.
    //
    // Changed. Everything now dynamically unmounts including raw mount.
    return_val = data_source_unmount(source);

    // If we don't call unmount, we must do this:
    //g_free(ds->mounted_directory);
  }

  if (ds->job_tree != NULL)
  {
    g_node_traverse(ds->job_tree, G_POST_ORDER, G_TRAVERSE_ALL, -1, free_job_node, NULL);
    g_node_destroy(ds->job_tree);
    ds->job_tree = NULL;
  }

  if (ds->print_manager != NULL)
  {
    print_manager_close(ds->print_manager);
    ds->print_manager = NULL;
  }

  g_free(ds);
  ds = NULL;

  return return_val;
}


// Documented in header file
int data_source_unmount(data_source_t source)
{
  struct data_source *ds = data_source_validate(source);

  if (ds == NULL)
  {
    return -1;
  }

  if (ds->is_mounted == 0)
  {
    return 0;
  }

  int return_val = unmount_everything_below_path(ds->mounted_directory, TRUE);

  g_free(ds->mounted_directory);

  ds->mounted_directory = NULL;
  ds->is_mounted = 0;

  if (return_val != 0)
  {
    warning_log("Couldn't unmount the fuse mount!");
  }

  return return_val;
}


// Documented in header file
int data_source_mount(data_source_t source, const char *mount_directory)
{

  struct data_source *ds = data_source_validate(source);

  if (ds == NULL)
  {
    severe_log("Couldn't validate the data source passed to data_source_mount!!");
    return -1;
  }

  struct stat info;

  if (stat(mount_directory, &info) != 0)
  {
    warning_log("The mount directory (%s) doesn't appear to exist!", mount_directory);
    return -1;
  }

  if (!S_ISDIR(info.st_mode))
  {
    warning_log("The directory to mount (%s) doesn't appear to be a directory!", mount_directory);
    return -1;
  }

  gchar *exe_path = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_RAW_MOUNT_EXECUTABLE, &exe_path) != 0) || (exe_path == NULL))
  {
    severe_log("Couldn't get raw mount exe!");
    if (exe_path != NULL)
    {
      g_free(exe_path);
      exe_path = NULL;
    }
    return -1;
  }

  gchar *mount_options = g_strdup_printf("file=%s,allow_other", ds->file_name);

  char *o_option = g_strdup("-o");
  char *mnt_dir_cpy = g_strdup(mount_directory);

  char *spawn_args[5] = { exe_path, o_option, mount_options, mnt_dir_cpy, NULL };

  int ret = unmount_everything_below_path(mnt_dir_cpy, FALSE);
  if(ret != 0)
  {
    debug_log("Unable to unmount %s", mount_directory);
  }

  debug_log("Trying to raw mount using %s -o %s %s", exe_path, mount_options, mount_directory);

  int return_val = spawn_process_and_wait(spawn_args);

  g_free(mnt_dir_cpy);
  g_free(o_option);
  g_free(mount_options);
  g_free(exe_path);

  if (return_val != 0)
  {
    warning_log("Error mounting!");
    return -1;
  }

  gchar *zero_file = g_strdup_printf("%s/0", mount_directory);

  struct stat zero_file_info;

  if (stat(zero_file, &zero_file_info) != 0)
  {
    severe_log("Couldn't stat file %s", zero_file);
    g_free(zero_file);
    return -1;
  }

  if (zero_file_info.st_size == 0)
  {
    severe_log("Error with file (%s) size (size is 0)!", zero_file);
    g_free(zero_file);
    return -1;
  }

  ds->is_mounted = 1;
  ds->mounted_directory = g_strdup(mount_directory);

  g_free(zero_file);
  return 0;
}


/**
 * \brief Prints directed graph (dia format) info to stdout for the tree
 * \param node The node to start from (children are also printed)
 * \param data Not used
 *
 * Note you would normally call printf_dirgraph_of_tree if you wanted the whole tree
 * as it adds header information
 */
/*
static void printf_node_and_children_dirgraph(GNode* node, gpointer data)
{

  struct job_node_data* job_data = (struct job_node_data*) node->data;
  unsigned long long* parent_id = (unsigned long long*) data;

  gchar* ccr = NULL;
  gchar* issued = NULL;
  
  if (job_data->node_report != NULL)
  {
    ccr = g_strdup_printf("CCR Received");
  } else
  {
    ccr = g_strdup_printf("No CCR");
  }

  if (job_data->contract_issued == TRUE)
  {
    issued = g_strdup_printf("Contract ISSUED\\n  (path: %s abs_offset: %lli)", contract_get_path(job_data->node_contract), contract_get_absolute_offset(job_data->node_contract));
  } else
  {
    issued = g_strdup_printf("Contract NOT ISSUED\\n  (path: %s abs_offset: %lli)", contract_get_path(job_data->node_contract), contract_get_absolute_offset(job_data->node_contract));
  }

  printf("n%llu [label = \"%s\\n%s\\n%s\"]\n",job_data->job_id, contract_get_path(job_data->node_contract), issued, ccr);

  printf("n%llu->n%llu;\n", *parent_id, job_data->job_id);

  // Previous:
  #define PRINT_SIB 0
  if (g_node_prev_sibling(node) != NULL && PRINT_SIB)
  {
    GNode* prev = g_node_prev_sibling(node);
    struct job_node_data* prev_job_data = (struct job_node_data*) prev->data;

    printf("n%llu->n%llu [label=\"prev\"];\n", job_data->job_id, prev_job_data->job_id);
  }

  if (g_node_next_sibling(node) != NULL && PRINT_SIB)
  {
    GNode* next = g_node_next_sibling(node);
    struct job_node_data* next_job_data = (struct job_node_data*) next->data;

    printf("n%llu->n%llu [label=\"next\"];\n", job_data->job_id, next_job_data->job_id);
  }


  g_free(ccr);
  g_free(issued);

  g_node_children_foreach (node, G_TRAVERSE_ALL, printf_node_and_children_dirgraph , (gpointer) &job_data->job_id);
}
*/

/**
 * \brief Print job node information to stdout
 * \param node The node to print
 * \param data Not used
 */
static gboolean debug_print_job_node(GNode * node, gpointer data)
{

  if (node == NULL)
  {
    debug_log("Requested printing of NULL NODE!");
    return FALSE;
  }

  if (node->data == NULL)
  {
    debug_log("Requested printing of node with NULL data!");
    return FALSE;
  }

  struct job_node_data *job_data = (struct job_node_data *) node->data;

  if (job_data->node_contract == NULL && job_data->node_report == NULL)
  {
    debug_log("** Root Node **");
    return FALSE;
  }

  debug_log("---");

  if (job_data->node_contract == NULL)
  {
    debug_log("Contract: NULL");
  } else
  {
    if (job_data->contract_issued == TRUE)
    {
      debug_log("Contract: %s (abs: %lli) (ISSUED)", contract_get_path(job_data->node_contract), contract_get_absolute_offset(job_data->node_contract));
    } else
    {
      debug_log("Contract: %s (abs: %lli) (Not Issued)", contract_get_path(job_data->node_contract), contract_get_absolute_offset(job_data->node_contract));
    }
  }

  if (job_data->node_report == NULL)
  {
    debug_log("Report NULL");
  } else
  {
    debug_log("Report Obtained");
  }

  debug_log("---");
  return FALSE;
}


/**
 * \brief Print to stdout (in dia format) a digraph of the tree for debugging
 * \param source The data source to print
 */
/*
static void data_source_printf_dirgraph_of_tree(data_source_t source) 
{

  struct data_source* ds = data_source_validate(source);
  if (ds == NULL)
  {
    return;
  }

  static int graphnum = 0;
  printf("digraph %i\n", graphnum++);
  printf("{\n");
  unsigned long long root_id = 0;

  if (g_node_n_children(ds->job_tree) > 0)
  {
    printf("n0 [label = \"Root Node\"]\n");
    // .dot
    g_node_children_foreach (ds->job_tree, G_TRAVERSE_ALL, printf_node_and_children_dirgraph , (gpointer) &root_id);

    // printed
    // g_node_traverse(ds->job_tree, G_POST_ORDER, G_TRAVERSE_ALL, -1, print_job_node, NULL);
  }

  printf("}\n");
}
*/

static const char *data_source_mounted_path(data_source_t source)
{
  struct data_source *ds = data_source_validate(source);

  if (ds == NULL)
  {
    return NULL;
  }

  if (ds->is_mounted != 1)
  {
    return NULL;
  }

  return ds->mounted_directory;
}


/**
 * \brief Does this node match the data provided in data
 * \param node The node we are testing
 * \param data A job_node_match_data struct containing absolute offset and path
 * \return TRUE If the provided data matches the contract in the node, FALSE otherwise
 */
static gboolean does_node_match_contract(GNode * node, gpointer data)
{
  struct job_node_match_data *jdata = (struct job_node_match_data *) data;

  if (jdata->contract_path == NULL)
  {
    return FALSE;
  }

  struct job_node_data *ndata = (struct job_node_data *) node->data;

  if (ndata->node_contract == NULL)
  {
    debug_log("Contract was NULL when searching for a matching contract. Assuming ROOT node");
    return FALSE;
  }

  if (jdata->abs_off != contract_get_absolute_offset(ndata->node_contract))
  {
    return FALSE;
  }

  if (g_strcmp0(jdata->contract_path, contract_get_path(ndata->node_contract)) == 0)
  {
    // We have a match
    jdata->matching_node = node;
    return TRUE;
  }

  return FALSE;

}


/**
 * \brief Given a data source and a contract, find which node in the job tree
 * it refers to
 *
 * \param ds The data source whose job tree we wish to search
 * \param original_contract The contract we are looking for
 * \return The matching GNode, or NULL if not found
 *
 */
static GNode *find_job_node(struct data_source *ds, const contract_t original_contract)
{

  prong_assert(ds != NULL);

  struct job_node_match_data *mdata = (struct job_node_match_data *) g_malloc(sizeof(struct job_node_match_data));

  mdata->matching_node = NULL;
  mdata->contract_path = g_strdup(contract_get_path(original_contract));
  mdata->abs_off = contract_get_absolute_offset(original_contract);

  g_node_traverse(ds->job_tree, G_POST_ORDER, G_TRAVERSE_ALL, -1, does_node_match_contract, mdata);

  if (mdata->matching_node == NULL)
  {
    // Couldn't find a matching node!
    debug_log("Traveresed the tree but failed to find any matching node for %s", mdata->contract_path);

    g_free(mdata->contract_path);
    g_free(mdata);
    return NULL;
  }
  // We have a matching node.
  GNode *to_return = mdata->matching_node;

  g_free(mdata->contract_path);
  g_free(mdata);

  return to_return;

}


/** 
 * \brief Compare which of two contracts come first (as determined by absolute offset)
 * \param one The first contract
 * \param two The second contract
 * \return 0 if they are equal, -1 if the first comes before the second, 1 if the second before the first
 */
static int compare_contract_order(const contract_t one, const contract_t two)
{
  long long int pos1 = contract_get_absolute_offset(one);
  long long int pos2 = contract_get_absolute_offset(two);

  if (pos1 < pos2)
    return -1;
  if (pos1 > pos2)
    return 1;

  return 0;
}


/**
 * \brief Adds a contract to the job tree under the specified parent
 *
 * \param ds The data source we are operating on
 * \param parent The node under which this contract should be added
 * \param to_add The contract to add
 * \return The node containing the newly added contract
 *
 */
static GNode *add_contract_to_job_tree(struct data_source *ds, GNode * parent, const contract_t to_add)
{

  prong_assert(ds != NULL);

  // Take a copy and add it to the tree

  struct job_node_data *new_job = job_node_data_init();
  contract_t our_copy = contract_clone(to_add);

  new_job->node_contract = our_copy;
  new_job->job_id = ds->next_job_id++;

  debug_log("Inserted new contract into the tree.");

  // Insert sorted with siblings:

  // In general, we expect to receive contracts in increasing order, so
  // it makes sense to try and insert it at the end of the children.

  GNode *inserted_node = NULL;
  GNode *last_child = g_node_last_child(parent);

  if (last_child == NULL)
  {
    //debug_log("No siblings, inserting the first child with abs %lli", contract_get_absolute_offset(our_copy)); 
    inserted_node = g_node_insert_data(parent, -1, new_job);
  } else
  {
    GNode *current_pos_child = last_child;
    struct job_node_data *the_data = (struct job_node_data *) current_pos_child->data;

    while (current_pos_child != NULL && compare_contract_order(to_add, the_data->node_contract) < 0)
    {
      //debug_log("searchign....");
      current_pos_child = g_node_prev_sibling(current_pos_child);
      if (current_pos_child != NULL)
        the_data = (struct job_node_data *) current_pos_child->data;
    }

    if (current_pos_child == NULL)
    {

      // We are at the start
      inserted_node = g_node_insert_data(parent, 0, new_job);
      //debug_log("Inserting as the first child with abs %lli", contract_get_absolute_offset(our_copy));

    } else
    {
      // We aren't at the start, insert after the relevant sibling
      inserted_node = g_node_insert_data_after(parent, current_pos_child, new_job);

      //debug_log("Inserting abs: %lli", contract_get_absolute_offset(our_copy));
      //debug_log("After:");
      //print_job_node(current_pos_child, NULL);

    }
  }


  return inserted_node;
}


// This is not efficient
gboolean range_in_range(block_range_t this_one, block_range_t inside_this)
{

  unsigned long long this_pos;
  unsigned long long this_len;

  block_range_get_range(this_one, &this_pos, &this_len);

  unsigned long long inside_this_pos;
  unsigned long long inside_this_len;

  block_range_get_range(inside_this, &inside_this_pos, &inside_this_len);

  if (this_pos >= inside_this_pos && ((this_pos + this_len) < (inside_this_pos + inside_this_len)))
  {
    return TRUE;
  }

  return FALSE;
}

gboolean block_in_node_ranges(long long int block, GNode * node)
{
  unsigned int num_results = 0;

  struct job_node_data *jdata = (struct job_node_data *) node->data;

  prong_assert(jdata != NULL);
  const result_t *results = contract_completion_report_get_results(jdata->node_report, &num_results);

  prong_assert(results != NULL);
  for (int i = 0; i < num_results; i++)
  {
    unsigned int num_ranges = 0;
    block_range_t *ranges = result_get_block_ranges(results[i], &num_ranges);

    if (is_offset_within_ranges(block, ranges, num_ranges) == 1)
    {
      return TRUE;
    }
  }

  return FALSE;
}


// This is not efficient
gboolean range_in_node_ranges(block_range_t the_range, GNode * node)
{

  struct job_node_data *jdata = (struct job_node_data *) node->data;

  unsigned int num_results = 0;
  const result_t *results = contract_completion_report_get_results(jdata->node_report, &num_results);

  for (int i = 0; i < num_results; i++)
  {
    unsigned int num_ranges = 0;

    block_range_t *ranges = result_get_block_ranges(results[i], &num_ranges);

    for (int j = 0; j < num_ranges; j++)
    {
      if (range_in_range(the_range, ranges[j]) == TRUE)
      {
        return TRUE;
      }
    }
  }

  return FALSE;
}

// Returns -1 if the block cannot be safely converted, otherwise returns the abs_offset as a block position
long long safely_make_block_absolute_offset(GNode* node, unsigned long long block_size)
{
  struct job_node_data *jdata = (struct job_node_data *) node->data;
  long long int absoff = contract_get_absolute_offset(jdata->node_contract);

  // We need to conver to a block absolute offset safely
  if ((absoff % block_size) == 0)
  {
    return absoff / block_size;
  }

  // We need to safely convert - we can only do this if this node has claimed blocks
  unsigned int num_results = 0;
  const result_t* results = contract_completion_report_get_results(jdata->node_report, &num_results);
  if (num_results == 0)
  {
    return -1;
  }

  // This assumes there is only one result (not safe for brute force)
  unsigned int num_ranges;
  block_range_t* ranges = result_get_block_ranges(results[0], &num_ranges);
  if (num_ranges == 0)
  {
    // We can't convert
    return -1;
  }

  long long block_abs_off = (absoff / block_size) + 1;
  if (is_offset_within_ranges(block_abs_off, ranges, num_ranges) == 0)
  {
    // It's not within our block range. We can't call it valid.
    return -1;
  }

  // It's within our block range. Let's call it valid.
  return block_abs_off;
}

// This is not efficient
gboolean node_within_parents_range(GNode * node, unsigned long long block_size)
{
  if (G_NODE_IS_ROOT(node) == TRUE)
  {
    return TRUE;
  }

  if (node->parent == NULL)
  {
    return TRUE;
  }

  if (G_NODE_IS_ROOT(node->parent))
  {
    return TRUE;
  }

  struct job_node_data *jdata = (struct job_node_data *) node->data;

  long long int absoff = contract_get_absolute_offset(jdata->node_contract);
  if (absoff != -1)
  {
    long long block_abs_off = safely_make_block_absolute_offset(node, block_size);

    if (block_abs_off != -1)
    {
      if (block_in_node_ranges(block_abs_off, node->parent) == FALSE)
      {
        return FALSE;
      }
    }
  }

  if (jdata->node_report == NULL)
  {
    return TRUE;
  }

  unsigned int num_results = 0;
  const result_t *results = contract_completion_report_get_results(jdata->node_report, &num_results);

  if (num_results == 0)
  {
    return TRUE;
  }

  for (int i = 0; i < num_results; i++)
  {
    unsigned int num_ranges = 0;
    block_range_t *ranges = result_get_block_ranges(results[i], &num_ranges);

    for (int j = 0; i < num_ranges; j++)
    {
      if (range_in_node_ranges(ranges[j], node->parent) == FALSE)
      {
        return FALSE;
      }
    }
  }

  return node_within_parents_range(node->parent, block_size);
}



/** 
 * \brief Adds a contract_completion_report to the tree. Doesn't do any 
 * processing, just adds it.
 * 
 * \param ds The data source to which we are adding the CCR
 * \param to_add The CCR to add
 * \return The node to which the CCR was added, or NULL if it wasn't inserted
 *
 */
static GNode *add_ccr_to_job_tree(struct data_source *ds, GNode * parent, contract_completion_report_t to_add)
{

  prong_assert(ds != NULL);

  if (to_add == NULL)
  {
    error_log("Can't add a NULL ccr to job tree!");
    return NULL;
  }
  // Find the original contract in the tree

  const contract_t original_contract = contract_completion_report_get_original_contract(to_add);

  if (original_contract == NULL)
  {
    error_log("No original contract specified in the CCR. This is not valid");
    return NULL;
  }

  GNode *matching_job_node = find_job_node(ds, original_contract);

  if (matching_job_node == NULL)
  {
    debug_log("No matching contract was found for the CCR provided. Ignoring contract \"%s\"", contract_get_path(original_contract));
    return NULL;
  }

  struct job_node_data *matching_job_node_data = (struct job_node_data *) matching_job_node->data;


  // Add the CCR in the right spot 

  debug_log("Matched the CCR to the corresponding contract (%s). Will add to tree", contract_get_path(matching_job_node_data->node_contract));
  matching_job_node_data->node_report = contract_completion_report_clone(to_add);

  prong_assert(node_within_parents_range(matching_job_node, ds->block_size) == TRUE);

  if (matching_job_node_data->node_report == NULL)
  {
    warning_log("Clone of CCR failed.");
  }
  // Now create child nodes for each of the new contracts

  unsigned int num_results = 0;
  const result_t *results = contract_completion_report_get_results(to_add, &num_results);

  int res_i = 0;
  int contracts_in_which_result = -1;

  for (res_i = 0; res_i < num_results; res_i++)
  {
    const result_t current_result = results[res_i];

    // Add new contracts
    unsigned int num_contracts = 0;
    const contract_t *new_contracts = result_get_new_contracts(current_result, &num_contracts);

    int cont_i = 0;

    for (cont_i = 0; cont_i < num_contracts; cont_i++)
    {

      // There should only be one result that contains contracts
      prong_assert(contracts_in_which_result == -1 || contracts_in_which_result == res_i);

      debug_log("Adding contact \"%s\" to tree", contract_get_path(new_contracts[cont_i]));
      add_contract_to_job_tree(ds, matching_job_node, new_contracts[cont_i]);
      contracts_in_which_result = res_i;
    }

  }

  return matching_job_node;

}

/**
 * \brief Unmount all the contracts contained in a ccr
 * \param cr The contract completion report containing the new contracts to unmount
 * \return 0 on success, -1 on failure
 */
static gint unmount_contracts_in_orphan_ccr(contract_completion_report_t cr)
{

  prong_assert(cr != NULL);

  if (cr == NULL)
  {
    error_log("Can't unmount a NULL contract completion report!");
    return -1;
  }

  int num_contracts = 0;

  unsigned int num_results = 0;
  const result_t *the_results = contract_completion_report_get_results(cr, &num_results);

  if (num_results == 0)
  {
    return 0;
  }

  for (int i = 0; i < num_results; i++)
  {
    unsigned int num_new_contracts = 0;
    const contract_t *new_contracts = result_get_new_contracts(the_results[i], &num_new_contracts);

    if (new_contracts != NULL)
    {
      num_contracts += num_new_contracts;
    }
  }

  if (num_contracts > 0)
  {
    const contract_t unmount_below_me = contract_completion_report_get_original_contract(cr);
    int ret_val = unmount_everything_below_path(contract_get_path(unmount_below_me), TRUE);

    return ret_val;
  }

  return 0;

}

static gboolean can_print_node(GNode * node, unsigned int *num_children_found)
{

  gboolean temp = FALSE;

  // We can't print ourselves if we aren't finished
  if (is_node_incomplete(node, &temp) == TRUE)
  {
    return FALSE;
  }
  // We can't print ourselves if we have siblings to our left
  if (g_node_prev_sibling(node) != NULL)
  {
    return FALSE;
  }

  gboolean found_incomplete_node = FALSE;
  guint num_children = g_node_n_children(node);

  if (num_children > 0)
  {
    *num_children_found = num_children;

    g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1, is_node_incomplete, &found_incomplete_node);

    if (found_incomplete_node == TRUE)
    {
      // If some of our children are not done, then there is no way we can print anything. 
      return FALSE;
    }
  }

  return TRUE;

}

/**
 * \brief Unmounts everything below a node
 * \param node The node to unmount
 * \warning Will only work on raw blocks (root -1 nodes)
 * \return 0 on success, -1 on failure
 *
 */
static int unmount_everything_below_raw_node(GNode * node)
{
  // Root node
  if (node->parent == NULL)
  {
    // Shouldn't happen. You should call data_source_unmount
    warning_log("Refusing to unmount root node.");
    return -1;
  }
  // Not a root node or a raw node
  if (G_NODE_IS_ROOT(node->parent) != TRUE)
  {
    warning_log("Refusing to unmount something that isn't a raw block node");
    return -1;
  }
  // We are a raw node, calculate the path and unmount

  struct job_node_data *data = (struct job_node_data *) node->data;
  const char *path = contract_get_path(data->node_contract);
  gchar *to_unmount = g_strdup_printf("%s:", path);

  debug_log("Going to try and unmount %s", to_unmount);
  int return_val = unmount_everything_below_path(to_unmount, TRUE);

  g_free(to_unmount);

  if (return_val != 0)
  {
    warning_log("Couldn't unmount the fuse mount!");
  }

  return return_val;
}

static unsigned long long get_max_block_number_in_ranges(block_range_t * ranges, unsigned int num_ranges)
{
  unsigned long long pos;
  unsigned long long len;

  int retval = block_range_get_range(ranges[num_ranges - 1], &pos, &len);

  prong_assert(retval == 0);

  return pos + len - 1;
}

/**
 * \brief Given a node and a collection of block_ranges, find if the node is within any of the ranges, and if it is, return the maximum value of 
 * the range in which it is contained
 * \param the_node The node containing the contract we want to check
 * \param ranges The ranges we are checking
 * \param num_ranges The number of ranges in ranges
 * \param block_size The block size we are classifying at
 * \return 0 If it wasn't found in any ranges, otherwise the upper bounds of range (in blocks) in which it was found
 */
static unsigned int max_block_of_range_for_node(GNode * the_node, block_range_t * ranges, unsigned int num_ranges, unsigned long long block_size)
{
  prong_assert(the_node != NULL);

  // Obtain the absolute offset of this contract. 
  struct job_node_data *jdata = (struct job_node_data *) the_node->data;
  contract_t the_contract = jdata->node_contract;
  long long contract_abs_off = contract_get_absolute_offset(the_contract);

  if (contract_abs_off == -1)
  {
    debug_log("Returning false to node_contained_in_ranges = abs off == -1");
    return 0;
  }

  prong_assert(contract_abs_off >= 0);
  prong_assert(contract_abs_off % block_size == 0);

  unsigned long long contract_abs_off_block = ((unsigned long long) contract_abs_off / block_size);

  for (unsigned int i = 0; i < num_ranges; i++)
  {
    unsigned long long pos;
    unsigned long long len;

    int retval = block_range_get_range(ranges[i], &pos, &len);

    prong_assert(retval == 0);

    debug_log("Checking if %llu is contained in %llu (+%llu)", contract_abs_off_block, pos, len);

    if (contract_abs_off_block < pos)
    {
      // Since offset array should be sorted, we can stop looking now
      debug_log("Returning false to node_contained_in_ranges, abs off lower than start");
      break;
    }

    prong_assert(len != 0);

    if (contract_abs_off_block < (pos + len))
    {
      // Inside the range
      return pos + len;
    }
  }

  return 0;
}

/**
 * \brief Does the node contain a constant result
 * \param node The node in question
 * \return TRUE if the node contains a constant result, FALSE if it doesn't
 */
static gboolean node_contains_constant_result(GNode * node)
{
  struct job_node_data *jdata = (struct job_node_data *) node->data;

  if (jdata->node_report == NULL)
  {
    return FALSE;
  }

  unsigned int result_count = 0;

  contract_completion_report_get_results(jdata->node_report, &result_count);

  if (result_count != 1)
  {
    // Must be "unknown" or not be a "pure" constant block?
    return FALSE;
  }

  const contract_t orig_contract = contract_completion_report_get_original_contract(jdata->node_report);

  unsigned int num_types = 0;
  const unsigned int *contract_types = contract_get_types(orig_contract, &num_types);

  if (num_types != 1)
  {
    return FALSE;
  }

  if (contract_types[0] == MAGIC_TYPE_CONSTANT)
  {
    return TRUE;
  }

  return FALSE;
}

/**
 * \brief Walk the tree "right and up", starting from the given node
 *
 * \param node The node to start at
 * \return The node "right and up" from node, or NULL if there are none.
 *
 */
/*
static GNode* walk_tree_right_get_next(GNode* node)
{
  if (node == NULL) return NULL;

  //print_job_node(node, NULL);

  if (g_node_next_sibling(node) != NULL)
  {
    //debug_log("Node has next siblings");
    //print_job_node(g_node_next_sibling(node), NULL);
    return g_node_next_sibling(node);
  } else{
    //debug_log("No next sibling");
  }

  //debug_log("Moving up towards my parent..");

  if (node->parent == NULL)
  {
    //debug_log("No parent. Need to return NULL");
    return NULL;
  }

  return walk_tree_right_get_next(node->parent);
}
*/

/**
 * \brief Destoy a node
 * \param node The node to destroy
 * \param data Not used
 */
static gboolean destroy_node(GNode * node, gpointer data)
{
  // Now clean up - free contents
  free_job_node(node, NULL);

  // And the node itself
  g_node_destroy(node);

  return FALSE;
}

/**
 * \brief Destroy a node and all its children
 * \param node The node to destroy
 * \param data Not used
 */
static void destroy_node_and_children(GNode * node, gpointer data)
{
  debug_log("Destroying:");
  debug_print_job_node(node, NULL);

  g_node_traverse(node, G_POST_ORDER, G_TRAVERSE_ALL, -1, destroy_node, NULL);
}

/**
 * \brief Prunes a constant node. This might involve just pruning it, or if possible splitting it
 * \param node The node to be pruned or split
 * \param max_block The maximum block of the range we are inside (hence the prune)
 * \param block_size The block size we are currently operating on
 * \return The resulting node to the right of us following the split
 *
 * \note The max_block must have already been computed, and node must represent a constant block before you call this
 */
static GNode *split_and_prune_constant_node(GNode * node, unsigned long long max_block, unsigned long long block_size)
{
  // Collect information about the node to split
  struct job_node_data *jdata = (struct job_node_data *) node->data;

  contract_completion_report_t ccr = jdata->node_report;

  prong_assert(ccr != NULL);

  unsigned int num_results = 0;
  const result_t *the_results = contract_completion_report_get_results(ccr, &num_results);

  // A constant node should only have one result
  prong_assert(num_results == 1);

  unsigned int num_ranges = 0;
  block_range_t *the_ranges = result_get_block_ranges(the_results[0], &num_ranges);

  // A constant node should only have one range
  prong_assert(num_ranges == 1);

  unsigned long long node_start = 0;
  unsigned long long node_len = 0;

  int retval = block_range_get_range(the_ranges[0], &node_start, &node_len);

  prong_assert(retval == 0);

  if (node_start + node_len <= (max_block))
  {
    // The entire constant block is contained in the range => entire node needs to be pruned.
    debug_log("The entire node was contained within the range, so deleting it...");

    GNode *to_return = node->next;      // walk_tree_right_get_next(node);

    if (g_node_n_children(node) > 0)
    {
      unmount_everything_below_raw_node(node);
    }

    destroy_node_and_children(node, NULL);

    return to_return;
  }
  // Otherwise, we need to split it
  unsigned long long new_start_offset = max_block * block_size;
  unsigned long long new_num_blocks = (node_len - (max_block - node_start));

  debug_log("New start offset is: %llu number of new blocks is: %llu", new_start_offset, new_num_blocks);

  // Need to change: 
  // - The results
  // - The job_node offset data
  // - The absolute offset of the original contract...

  GNode *to_return = node->next;        // walk_tree_right_get_next(node);

  // Fix the contract
  contract_t new_contract = contract_clone(jdata->node_contract);

  contract_set_absolute_offset(new_contract, new_start_offset);

  contract_close(jdata->node_contract);
  jdata->node_contract = new_contract;

  // Fix the CCR
  contract_completion_report_t new_ccr = build_const_ccr(new_num_blocks, new_contract, block_size);

  contract_completion_report_close(jdata->node_report);
  jdata->node_report = new_ccr;

  return to_return;
}

// Given a CCR (which is the next to be printed out) we need to prune any nodes to its right that
// are now consumed by the CCR's block ranges
// Starting node is guaranteed to be Root-1 level
static int prune_completed_ranges(GNode * starting_node, unsigned long long block_size) G_GNUC_WARN_UNUSED_RESULT;
static int prune_completed_ranges(GNode * starting_node, unsigned long long block_size)
{
  prong_assert(starting_node != NULL);
  prong_assert(starting_node->data != NULL);

  struct job_node_data *data = (struct job_node_data *) starting_node->data;

  unsigned int num_results;
  const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

  prong_assert(num_results > 0);

  unsigned int num_ranges;
  block_range_t *ranges = result_get_block_ranges(results[0], &num_ranges);

  // Get the starting point
  GNode *raw_block_node = g_node_next_sibling(starting_node);

  if (raw_block_node == NULL)
  {
    debug_log("Nothing to prune - nothing on our right!");
    return 0;
  }
  // Find the highest value contained in the offset_ranges
  unsigned long long max_offset_range_value = get_max_block_number_in_ranges(ranges, num_ranges) * block_size;

  while (raw_block_node != NULL)
  {
    // Check if the current raw block node is greater than the greatest range value
    struct job_node_data *jdata = (struct job_node_data *) raw_block_node->data;

    prong_assert(contract_get_absolute_offset(jdata->node_contract) > 0);

    if ((unsigned long long) contract_get_absolute_offset(jdata->node_contract) > max_offset_range_value)
    {
      // There is no way any raw nodes to our right will match
      debug_log("Aborting prune traverse since it seems we are done! (max offset was %llu and the absolute offset was %llu)", (unsigned long long) contract_get_absolute_offset(jdata->node_contract),
                max_offset_range_value);
      break;
    }

    debug_log("Pruning completed ranges. raw_block_node is not null, it's abs off is %lli, and we haven't aborted the walk.", contract_get_absolute_offset(jdata->node_contract));

    unsigned long long max_block = max_block_of_range_for_node(raw_block_node, ranges, num_ranges, block_size);

    debug_log("Pruning completed ranges. Found the max block for this raw block as %lli.", max_block);

    if (max_block != 0)
    {
      // Then prune
      debug_log("Node prude required since a node was found using a block we just claimed.");
      // Check if this is a CONSTANT Result
      if (node_contains_constant_result(raw_block_node))
      {
        // It is, handle it differently
        raw_block_node = split_and_prune_constant_node(raw_block_node, max_block, block_size);
      } else
      {
        // This is just the normal case
        GNode *next = raw_block_node->next;     //walk_tree_right_get_next(raw_block_node);

//        GNode* next = raw_block_node->next;//Here

        if (g_node_n_children(raw_block_node) > 0)
        {
          unmount_everything_below_raw_node(raw_block_node);
        }

        destroy_node_and_children(raw_block_node, NULL);
        raw_block_node = next;
      }
    } else
    {
      // Don't prune
      debug_log("No prune required based on range...");
      //raw_block_node = raw_block_node->next;
      raw_block_node = raw_block_node->next;    //walk_tree_right_get_next(raw_block_node);
    }
  }

  return 0;
}

// Only gets called on root -1 nodes
static int prune_tree_based_on_new_ccr(struct data_source *ds, GNode * node_containing_new_ccr, int in_brute_force_mode)
{
  if (in_brute_force_mode)
  {
    error_log("Sorry, brute force mode NYI!!");
    return -1;
  }

  prong_assert(ds != NULL);
  prong_assert(node_containing_new_ccr != NULL);

  // Setup some vars for convenience
  struct job_node_data *node_data = ((struct job_node_data *) node_containing_new_ccr->data);

  unsigned int num_results;
  const result_t *results = contract_completion_report_get_results(node_data->node_report, &num_results);

  prong_assert(num_results > 0);

  unsigned int num_ranges;

  result_get_block_ranges(results[0], &num_ranges);
  if (num_ranges > 0)
  {
    debug_log("About to prune incoming ccr for %s (it has %u ranges)", contract_get_path(node_data->node_contract), num_ranges);
    if (prune_completed_ranges(node_containing_new_ccr, ds->block_size) != 0)
    {
      severe_log("Couldn't prune completed ranges for new ccr. Tree state may not be consistent!!");
      return -1;
    }
  }

  return 0;
}

static int print_and_prune_from_node(struct data_source *ds, GNode * node)
{
  prong_assert(node != NULL);
  prong_assert(ds != NULL);

  struct job_node_data *job_data = (struct job_node_data *) node->data;

  unsigned int res_count = 0;
  const result_t *results = contract_completion_report_get_results(job_data->node_report, &res_count);

  prong_assert(res_count > 0 && results != NULL);

  if (res_count <= 0 || results == NULL)
  {
    severe_log("Asked to prune from a node that has no results!");
    return -1;
  }

  g_node_unlink(node);

  print_manager_add_node(ds->print_manager, node);

  return 0;
}

/** 
 * \brief Walk up the tree until we find the raw block node, and return it
 * \param node The node to start at
 * \return The raw node, or NULL if it couldn't be found above node
 */
static GNode *walk_up_until_raw_block_node(GNode * node)
{
  if (node == NULL)
  {
    return NULL;
  }

  prong_assert(node->parent != NULL);
/*
  if (node->parent == NULL)
  {
    // Hrm. Odd.
    return NULL;
  }
*/
  if (G_NODE_IS_ROOT(node->parent))
  {
    // I am the raw block node!
    return node;
  }

  return walk_up_until_raw_block_node(node->parent);
}

/**
 * \brief Process a tree based on a new CCR
 * \param ds The data source we are operating on
 * \node node The node containing the newly added CCR
 * \in_brute_force_mode Are we operating in brute force mode (NYI)
 * \return 0 on success, -1 on failure
 *
 * We have to take a few steps based on a new CCR being put into the tree. 
 * We basically need to decide if we should print ourselves first. We can
 * only do this if:\n
 * - We are ready to be printed\n
 * - We are a raw node (root node -1)\n
 * - All our children are done\n
 * - We have nothing to our left that might be still be printed\n
 * \nOnce we've checked all that. We can print ourselves, prune stuff to our right that
 * we claim, and then check if anyone to our right needs to be printed. The process then repeats.
 */
static int process_tree_based_on_new_ccr(struct data_source *ds, GNode * node, int in_brute_force_mode)
{
  prong_assert(ds != NULL);

  if (node->parent == NULL)
  {
    // Must be the root, ignore.
    return 0;
  }

  if (in_brute_force_mode)
  {
    error_log("Sorry, brute force mode NYI!!");
    return -1;
  }

  debug_log("Processing tree based on new CCR");

  if (G_NODE_IS_ROOT(node->parent) == TRUE)
  {
    debug_log("Root -1 node processing");

    GNode *next_node = NULL;
    GNode *current_node = node;

    while (current_node != NULL)
    {
      unsigned int num_children = 0;

      if (can_print_node(current_node, &num_children) == FALSE)
      {
        return 0;
      }

      debug_log("\"Root -1\" node found. All kids are done (or we don't have any) OK to print.");

      if (num_children > 0)
      {
        debug_log("Root -1 node had %u children, will request unmount", num_children);

        if (unmount_everything_below_raw_node(current_node) != 0)
        {
          warning_log("Failed to unmount before printing. Mounts may still exist");
        }
      }

      debug_log("Result found we can act on (Mark complete, prune, print).");
      debug_log("Marking blocks complete for node.");

      // Mark the blocks off as complete
      mark_node_blocks_complete(ds, current_node);

      debug_log("Node blocks marked complete, pruning tree based on new ccr");

      // Prune eveything to our right
      prune_tree_based_on_new_ccr(ds, current_node, in_brute_force_mode);

      debug_log("Pruned tree based on new ccr, getting next sibling");

      // Need to do this AFTER the line above. Else things go boom if we trim our sibling
      next_node = g_node_next_sibling(current_node);

      debug_log("Tree pruned to our right. About to print and prune.");

      // Ok, actually print ourselves and delete ourselves.
      print_and_prune_from_node(ds, current_node);
      debug_log("Printed and pruned.");
      current_node = next_node;
    }

    debug_log("No more root -1 nodes left.");
    return 0;
  }

  debug_log("Not root -1, traversing to see if everything under us is done");

  // We are not the root - 1 node. Is everything under us done?
  gboolean found_incomplete_node = FALSE;

  g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1, is_node_incomplete, &found_incomplete_node);

  if (found_incomplete_node == TRUE)
  {
    debug_log("Not root -1, not everything under us is done ");
    // If some of our children are not done, then there is no way we can print anything. 
    return 0;
  }

  debug_log("Not root -1, everything under us IS done ");
  // Everything under us is done, check if we can now print 
  return process_tree_based_on_new_ccr(ds, walk_up_until_raw_block_node(node), in_brute_force_mode);
}

/**
 * \brief Handles an incoming contract completion report
 *
 * \param cr The contract completion report to handle
 * \param source The data source we are using
 * \return 0 on success, -1 on failure
 */
static int data_source_handle_incoming_contract_completion_report(data_source_t source, contract_completion_report_t cr)
{
//printf("DS START HANDLE INCOMING\n");

  // Basic Sanity checking
  if (cr == NULL)
  {
    severe_log("Got a malformed result from a contractor (handle_incoming_contract received a NULL completion report)");
    return -1;
  }

  struct data_source *ds = data_source_validate(source);

  if (ds == NULL)
  {
    error_log("Invalid data_source passed to handle_incoming ccr check!");
    return -1;
  }
  // Now check if either this is a do nothing event, or an error 

  const contract_t original_contract = contract_completion_report_get_original_contract(cr);

  unsigned int results_count;
  const result_t *results = contract_completion_report_get_results(cr, &results_count);

  if ((original_contract == NULL) && (results_count == 0))
  {
    // This state occurs for example when a contractor first starts up. 
    // It's not an error per se, we just don't have to actually do anything
    // to "handle" it, we're done.
    debug_log("Found a contract completion report without an original contract. and without any results. Ignoring");
    return 0;
  } else if (original_contract == NULL)
  {
    // This is invalid. You can't report on a non existent contract
    error_log("Received results but they were missing the original contract or had malformed results");
    return -1;
  } else if ((results == NULL) && (results_count > 0))
  {
    // This is invalid. You can't have null results if count > 0
    error_log("Received results but they were malformed.");
    return -1;
  }

  debug_log("Handling incoming CCR for %s", contract_get_path(original_contract));

  // Add it to the job tree
  GNode *added_to = add_ccr_to_job_tree(ds, ds->job_tree, cr);

  if (added_to == NULL)
  {
    debug_log("Couldn't add the CCR to the job tree. Maybe this processing is no longer required. Will attempt to unmount any new contracts.");

    if (unmount_contracts_in_orphan_ccr(cr) != 0)
    {
      error_log("Failed to unmount a CCR we didn't need. FUSE mounts may exist on exit!");
      return -1;
    }
    return 0;
  }

  debug_log("Added CCR for %s to job tree. About to try and print.", contract_get_path(original_contract));

  // Now we need to walk to the tree, and potentially print out results, and prune any leaves that are waiting to be printed. 
  if (process_tree_based_on_new_ccr(ds, added_to, ds->brute_force_mode) == 0)
  {
    //debug_log("Printing completed OK based on new CCR");
  } else
  {
    warning_log("Something went wrong when printing based on new CCR for %s, continuing though.", contract_get_path(original_contract));
  }

  debug_log("Following handling the incoming CCR (for %s), the tree has %u children", contract_get_path(original_contract), g_node_n_children(ds->job_tree));

  //May be useful for debugging:
  //data_source_print_tree_status(source);

  return 0;
}

/**
 * \brief Handle a slab of constant data blocks found in the source
 * \param ds The data source in which they have been found
 * \param next_offset The offset at which they start
 * \return 0 on success, -1 on failure
 */
static int handle_constant_data_blocks(struct data_source *ds, unsigned long long next_offset)
{
  //debug_log("Handling constant data blocks...");

  unsigned long long num_constant_blocks = prong_file_discover_num_constant_blocks(ds->the_file, next_offset);

  prong_assert(num_constant_blocks > 0);

  debug_log("Found %llu constant data blocks, starting at %llu", num_constant_blocks, next_offset);

  // We don't move the current offset along here. This happens when a contract is printed

  gchar *contract_path = g_strdup_printf("%s/%llu", ds->mounted_directory, next_offset);

  contract_t a_contract = contract_init(NULL, 0);

  contract_set_path(a_contract, contract_path);
  contract_set_absolute_offset(a_contract, next_offset);
  contract_set_contiguous(a_contract, 1);
  contract_add_type(a_contract, MAGIC_TYPE_CONSTANT);

  //debug_log("Built the contract of path %s, abs %lli contig %i", contract_path, next_offset, 1);

  g_free(contract_path);

  // Add the contract to the tree

  GNode *added_node = add_contract_to_job_tree(ds, ds->job_tree, a_contract);

  struct job_node_data *added = (struct job_node_data *) added_node->data;

  added->contract_issued = TRUE;

  // Mark these blocks as complete. Normally, we'd do this when we print, but this is safe here and 
  // prevents an edge case where we get constant runs of decreasing length
  block_range_t range = block_range_init(NULL, 0);

  int ret = block_range_set_range(range, next_offset / ds->block_size, num_constant_blocks);
  prong_assert(ret == 0);

  if (store_blocks(ds->block_store, &range, 1) != 0)
  {
    severe_log("Couldn't store the block range for a constant run. It's likely the same data will be processed multiple times!");
    return -1;
  }
  block_range_close(range);

  // Now also complete the result and add it a CCR
  contract_completion_report_t new_ccr = build_const_ccr(num_constant_blocks, a_contract, ds->block_size);

  if (new_ccr == NULL)
  {
    severe_log("Failed to build constant CCR!");
    contract_close(a_contract);
    contract_completion_report_close(new_ccr);
    return -1;
  }

  int retval = data_source_handle_incoming_contract_completion_report(ds, new_ccr);

  contract_close(a_contract);
  contract_completion_report_close(new_ccr);
  return retval;
}

/**
 * \brief Given a node in the tree containing a ready to issue contract, prepare the contract
 * \param node The node containing the contract to issue
 * \warning This assumes you have found a node that has a contract waiting to be issued
 * 
 * errno May be set to EAGAIN if something went wrong but you should try again
 *
 */
static contract_t prepare_contract_from_tree(struct data_source *ds, GNode * next_contract_node)
{
  prong_assert(next_contract_node != NULL);
  prong_assert(ds != NULL);

  struct job_node_data *the_data = (struct job_node_data *) next_contract_node->data;

  // The next thing we check is whether we have any contracts
  // in our tree that need processing...
  prong_assert(the_data->contract_issued == FALSE);
  the_data->contract_issued = TRUE;

  // We return a copy so that the behaviour (always freeing it) is consistent...
  contract_t to_return = contract_clone(the_data->node_contract);

  if (to_return == NULL)
  {
    severe_log("Couldn't clone contract properly!!");
    errno = ENOMEM;
    return NULL;
  }

  if (compute_magic_of_new_contract(ds, to_return) != 0)
  {
    // Something went wrong with LIGHTMAGIC calculation. This means we couldn't read it
    // In this case, we handle this.
    contract_completion_report_t zero_size_ccr = contract_completion_report_init(NULL, 0);

    contract_completion_report_set_original_contract(zero_size_ccr, to_return);
    contract_close(to_return);

    result_t new_res = result_init(NULL, 0);

    result_set_confidence(new_res, -1);
    result_set_subcontractor_name(new_res, "MCP");
    result_set_brief_data_description(new_res, "Unidentified");
    result_set_data_description(new_res, "File contained no readable data");

    contract_completion_report_add_result(zero_size_ccr, new_res);
    result_close(new_res);

    if (data_source_handle_incoming_contract_completion_report(ds, zero_size_ccr) != 0)
    {
      warning_log("Couldn't handle \"no data\" CCR!!");
    }

    contract_completion_report_close(zero_size_ccr);
    errno = EAGAIN;

    return NULL;
  }

  return to_return;
}

/** 
 * \brief Prepare a contract from the raw source
 * \param ds The data source
 */
static contract_t prepare_contract_from_raw_source(struct data_source *ds)
{
  unsigned long long next_block = next_missing_block(ds->block_store);
  unsigned long long next_offset = next_block * ds->block_size;
  unsigned int buff_size = 0;

  const unsigned char *next_block_data = prong_file_read_offset(ds->the_file, next_offset, &buff_size);

  if (buff_size == 0)
  {
    debug_log("The returned buffer size was 0 for requested offset (reported as %llu).", next_offset);
    errno = EIO;
    return NULL;
  }

  GArray *magic_types;

  if (ds->brute_force_mode)
  {
    // If brute force mode is enabled, just add MAGIC_TYPE_ALL to the  magic_types array 
    magic_types = g_array_new(FALSE, TRUE, sizeof(int));
    g_array_append(magic_types, MAGIC_TYPE_ALL);
  } else
  {
    // Magic Calculation
    magic_types = lightmagic_detect(next_block_data, ds->block_size, buff_size);
  }

  debug_log("METRIC: LM Types: %i", magic_types->len);

  // Can we "cheat"?
  if ((magic_types->len == 1) && (g_array_index(magic_types, int, 0) == MAGIC_TYPE_CONSTANT))
  {
    // Yes.
    g_array_free(magic_types, TRUE);

    debug_log("About to look for a constant run starting at %llu", next_offset);
    if (handle_constant_data_blocks(ds, next_offset) != 0)
    {
      error_log("Couldn't handle a constant stream!! Something went wrong!");
    }
    errno = EAGAIN;
    return NULL;
  }
  // Setup the contract
  const char *mounted_path = data_source_mounted_path(ds);
  if (mounted_path == NULL)
  {
    severe_log("It doesn't appear like the data source is currently mounted. This is a problem.");
    g_array_free(magic_types, TRUE);
    errno = EIO;
    return NULL;
  }

  contract_t a_contract = contract_init(NULL, 0);
  if (a_contract == NULL)
  {
    g_array_free(magic_types, TRUE);
    errno = ENOMEM;
    return NULL;
  }

  gchar *contract_path = g_strdup_printf("%s/%llu", mounted_path, next_offset);
  contract_set_path(a_contract, contract_path);
  contract_set_absolute_offset(a_contract, next_offset);
  contract_set_contiguous(a_contract, 1);

  debug_log("Built the contract of path %s, abs %lli contig %i", contract_path, next_offset, 1);

  g_free(contract_path);

  for (int i = 0; i < magic_types->len; i++)
  {
    if (contract_add_type(a_contract, g_array_index(magic_types, int, i)) == -1)
    {
      severe_log("Error adding contract type to contract!!");
    } else
    {
      debug_log("Added type %i (%s) to contract based on lightmagic", g_array_index(magic_types, int, i), lightmagic_text_representation(g_array_index(magic_types, int, i)));
    }
  }

  g_array_free(magic_types, TRUE);

  GNode *added_node = add_contract_to_job_tree(ds, ds->job_tree, a_contract);

  struct job_node_data *added = (struct job_node_data *) added_node->data;

  added->contract_issued = TRUE;

  return a_contract;
}

/**
 * \brief Returns the next contract for this data source.
 *
 * \param source The data source the next block is requested for
 * \return Returns a new contract, or NULL on error
 *
 * \warning It is the caller's job to free the returned contract when done.
 *
 * This function may return the next sequential block to process, or contracts
 * that have been discovered as a part of previous processing. In some instances
 * it may actually handle the contract it discovers internally. In this case
 * it will return EAGAIN, which means the caller should try again. 
 * On NULL return value, errno will be set to one of:\n
 * - EINVAL -> Invalid data source was passed\n 
 * - EBUSY -> The data source isn't ready yet (not mounted)\n
 * - EAGAIN -> Data source could handle the contract itself, try again\n
 * - ENOMEM -> Something pretty catastrophic went wrong \n
 * - EIO -> There is no data left to process\n
 */
static contract_t data_source_next_contract_to_process(data_source_t source)
{
  static int tree_full_warning = 0;

//printf("DS START NEXT CONTRACT\n");
  struct data_source *ds = data_source_validate(source);

  if (ds == NULL)
  {
    error_log("Invalid data_source passed to next_offset check!");
    errno = EINVAL;
    return NULL;
  }

  if (ds->is_mounted != 1)
  {
    error_log("Cowardly refusing to supply contracts when I don't have a mounted data source.");
    errno = EBUSY;
    return NULL;
  }
  // The first thing we check is whether we have any contracts
  // in our tree that need processing...

  GNode *next_contract_node = NULL;

  debug_log("Traversing to look for non issued contracts...");

  g_node_traverse(ds->job_tree, G_POST_ORDER, G_TRAVERSE_LEAVES, -1, does_node_have_contract, &next_contract_node);

  if (next_contract_node != NULL)
  {
    return prepare_contract_from_tree(ds, next_contract_node);
  }

  // The next thing we do if check if our tree is too big - if it is we need to tell the contractor
  // to wait a second...
  if (g_node_n_children(ds->job_tree) > ds->max_tree_size)
  {
    if (tree_full_warning == 0)
    {
      info_log("The MCP tree has got quite large. This normally means a contractor is taking a long time to return. I will tell the other contractors to sleep for a while. Do not be alarmed by an apparent lack of activity.");
      tree_full_warning = 1;
    }

    debug_log("Returning a wait contract - too many children in the tree (%u)", g_node_n_children(ds->job_tree));
    contract_t wait_contract = build_wait_contract(ds->contractor_wait_time);
    return wait_contract;
  }

  debug_log("None found, will try and create a new one from the raw source");

  // If not, then we press on to carving the raw source

  return prepare_contract_from_raw_source(ds);

}

// Documented in header file
int unmount_everything_below_path(const char *path, const gboolean lazy)
{

  // We shell out to do the hard work here. While shelling out isn't all that 
  // "nice", it's the simplest way to do this. In addition, we need to be 
  // root to unmount file systems. fusermount has the setuid flag set on 
  // most systems, so this isn't an issue. For a lot of reasons we don't 
  // want pronghorn to be setuid, so doing this programatically may be tricky.
  // FIXME There may be a slightly more elegant way to do this? Note that if it 
  // is changed to a new method, it still must be a lazy unmount.

  gchar *unmount_script = NULL;

  if (config_get_with_default_macro(NULL, CONFIG_UNMOUNT_ALL_FUSE_SCRIPT, &unmount_script) != 0)
  {
    severe_log("Couldn't find the unmount script! Can't unmount!");
    return -1;
  }

  char *path_dup = g_strdup(path);

  char *spawn_args[3] = { unmount_script, path_dup, NULL };

  debug_log("Unmounting using \"%s %s\"", unmount_script, path);

  pid_t pid;
  int return_val;
  if (lazy == TRUE)
  {
    return_val = spawn_process(spawn_args, &pid);
  }
  else
  {
    return_val = spawn_process_and_wait(spawn_args);
  }

  g_free(unmount_script);
  g_free(path_dup);

  if (return_val == -1)
  {
    warning_log("Couldn't unmount the fuse mount!");
    return -1;
  }

  return 0;
}

contract_t data_source_get_next_contract(data_source_t source, contract_completion_report_t cr)
{
  if (data_source_handle_incoming_contract_completion_report(source, cr) != 0)
  {
    info_log("Data source reported it couldn't handle incoming contract completion report.");
  }

  contract_t next_contract = data_source_next_contract_to_process(source);

  while (next_contract == NULL && errno == EAGAIN)
  {
    next_contract = data_source_next_contract_to_process(source);
  }

  return next_contract;
}
