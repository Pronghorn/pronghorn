/* MCP Print Management library
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
 * \file print_manager.h
 * \brief Provides a mechanism for the MCP to print results in a consistent manner.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>

#include <config.h>
#include <defaults.h>
#include <logger.h>
#include <prong_assert.h>
#include <lightmagic.h>
#include "job_node.h"
#include "print_manager.h"

#include "basic_print.h"
#include "dfrws_print.h"

/** Used to positively identify a print_manager struct. Four random bytes from /dev/urandom */
const unsigned int PRINT_MANAGER_MAGIC = 0xD7C073BB;

/** Maintains the current state of the print manager */
struct print_manager
{
  /** Magic bytes used to detect memory corruption */
  unsigned int magic;

  /** Block size in use */
  unsigned int block_size;

  /** Our current offset we are printing */
  long long current_offset;

  /** A binary tree containing node subtrees sorted by absolute offset */
  GTree *abs_tree;

  /** A binary tree containing block ranges and who owns them */
  GTree *continuation_tree;

  struct print_handler *print_handler;

  long long lookup_offset;
  block_range_t lookup_range;
  GArray *destroy_array;
  GArray *print_array;
};

struct continuation_node
{
  long long owner_offset;
  char *brief_description;
  int is_constant;
  char* path;
};

/**
 * A debug function to print out all of the 
 */
static gboolean debug_print_node(GNode * node, gpointer p_first)
{
  prong_assert(node != NULL);
  prong_assert(node->data != NULL);

  const char *prefix = "\t";

  if (*(int *) p_first == 1)
  {
    prefix = "";
    *(int *) p_first = 0;
  }

  struct job_node_data *data = (struct job_node_data *) node->data;

  printf("%sNode %p\n", prefix, (void *) node);
  printf("%s - Data = %p\n", prefix, (void *) data);
  printf("%s - Absolute Offset = %lld\n", prefix, contract_get_absolute_offset(data->node_contract));
  printf("%s - Path = %s\n", prefix, contract_get_path(data->node_contract));
  printf("%s - Parent = %lld\n", prefix, data->parent_absolute_offset);

  unsigned int num_results = 0;
  const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

  prong_assert(num_results > 0);

  printf("%s - Data Type = %s\n", prefix, result_get_brief_data_description(results[0]));
  printf("%s - Data Range (Blocks) = ", prefix);

  unsigned int num_ranges;
  block_range_t *ranges = result_get_block_ranges(results[0], &num_ranges);

  for (int i = 0; i < num_ranges; i++)
  {
    unsigned long long pos;
    unsigned long long len;

    block_range_get_range(ranges[i], &pos, &len);
    printf("%llu-%llu ", pos, pos + len - 1);
  }

  printf("\n");

  return FALSE;
}

static gboolean traverse_abs_tree(long long *abs_offset, GNode * node, gpointer data)
{
  int first = 1;

  g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1, (GNodeTraverseFunc) debug_print_node, &first);

  return FALSE;
}

static gboolean traverse_continuation_tree(block_range_t range, long long *owner_pos, gpointer data)
{
  unsigned long long pos;
  unsigned long long len;

  block_range_get_range(range, &pos, &len);

  printf("%llu-%llu (Continuation of %lld)\n", pos, pos + len - 1, *owner_pos);

  return FALSE;
}

void debug_print_state_of_play(struct print_manager *pm)
{
  printf("State of play\n");
  printf("Current Offset: %llu\n", pm->current_offset);

  g_tree_foreach(pm->abs_tree, (GTraverseFunc) traverse_abs_tree, NULL);

  g_tree_foreach(pm->continuation_tree, (GTraverseFunc) traverse_continuation_tree, NULL);

  printf("Finished printing state of play\n\n");
}

void g_node_safe_destroy(GNode * node)
{
//printf("Destroying node\n");
  prong_assert(node != NULL);
  g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1, (GNodeTraverseFunc) free_job_node, NULL);

  // Free nodes themselves
  g_node_destroy(node);
//printf("Finished destroying node\n");
}

static gint abs_tree_compare(long long *abs_a, long long *abs_b, gpointer data)
{
  prong_assert(abs_a != NULL);
  prong_assert(abs_b != NULL);

  if (*abs_a < *abs_b)
  {
    return -1;
  }
  if (*abs_a > *abs_b)
  {
    return 1;
  }
  return 0;
}

static gint continuation_tree_compare(block_range_t a, block_range_t b, gpointer data)
{
  prong_assert(a != NULL);
  prong_assert(b != NULL);

  unsigned long long pos_a;
  unsigned long long len_a;
  unsigned long long pos_b;
  unsigned long long len_b;

  block_range_get_range(a, &pos_a, &len_a);
  block_range_get_range(b, &pos_b, &len_b);

  if (pos_b >= (pos_a + len_a))
  {
    return -1;
  }

  if (pos_a >= (pos_b + len_b))
  {
    return 1;
  }

  return 0;
}

static void continuation_node_free(struct continuation_node *node)
{
  prong_assert(node != NULL);
  g_free(node->brief_description);
  g_free(node->path);
  g_free(node);
}

print_manager_t print_manager_init(unsigned int block_size, unsigned long long start_block)
{
  struct print_manager *pm = (struct print_manager *) g_malloc(sizeof(struct print_manager));

  pm->magic = PRINT_MANAGER_MAGIC;
  pm->block_size = block_size;
  pm->current_offset = start_block;
  pm->abs_tree = g_tree_new_full((GCompareDataFunc) abs_tree_compare, NULL, (GDestroyNotify) g_free, (GDestroyNotify) g_node_safe_destroy);
  pm->continuation_tree = g_tree_new_full((GCompareDataFunc) continuation_tree_compare, NULL, (GDestroyNotify) block_range_close, (GDestroyNotify) continuation_node_free);
  pm->print_array = NULL;
  pm->destroy_array = NULL;
  pm->lookup_offset = 0;
  pm->lookup_range = block_range_init(NULL, 0);

  // Work out which output format to use
  int print_style = 0;

  if (config_get_int_with_default_macro(NULL, CONFIG_OUTPUT_STYLE, &print_style) != 0)
  {
    print_style = CONFIG_OUTPUT_STYLE_DEFAULT;
  }

  switch (print_style)
  {
    case CONFIG_DFRWS_OUTPUT_STYLE:
      pm->print_handler = get_dfrws_print_handler();
      break;
    case CONFIG_PATH_OUTPUT_STYLE:
      pm->print_handler = get_basic_print_handler();
      break;
    default:
      warning_log("Unknown print style selected!!");
      pm->print_handler = get_dfrws_print_handler();
  }

  // Print out the header
  pm->print_handler->print_header();

  return (print_manager_t) pm;
}

static void save_children(struct print_manager *pm, GNode * node)
{
  prong_assert(node != NULL);
  prong_assert(node->data != NULL);

  struct job_node_data *data = (struct job_node_data *) node->data;
  long long parent_abs_off = contract_get_absolute_offset(data->node_contract);

  // This should never be called on nodes with offsets of -1
  prong_assert(parent_abs_off != -1);

  GNode *child = node->children;

  while (child != NULL)
  {
    GNode *next = child->next;

    g_node_unlink(child);

    data = (struct job_node_data *) child->data;

    // We only care if the children are on abs_offsets in the future
    long long abs_off = contract_get_absolute_offset(data->node_contract);

    if (abs_off > pm->current_offset)
    {
      if (g_tree_lookup(pm->abs_tree, &abs_off) == NULL)
      {
//printf("Inserting %lld into abs_tree\n", abs_off);
        data->parent_absolute_offset = parent_abs_off;
        long long *p_abs_off = (long long *) g_malloc(sizeof(long long));

        *p_abs_off = abs_off;
        g_tree_insert(pm->abs_tree, p_abs_off, child);
      } else
      {
        // A child is already in the tree at this address???
        g_node_safe_destroy(child);
      }
    } else
    {
      // Child has an offset in the past (or -1)
      g_node_safe_destroy(child);
    }

    child = next;
  }

//printf("Tree altered.\n");
//debug_print_state_of_play(pm);
}

static void print_and_process_tree(struct print_manager *pm, GNode * node)
{
//printf("Printing tree\n");
  prong_assert(node != NULL);
  prong_assert(node->data != NULL);

  struct job_node_data *data = (struct job_node_data *) node->data;

  unsigned int num_results;
  const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

  prong_assert(num_results > 0);
  unsigned int num_ranges;
  block_range_t *ranges = result_get_block_ranges(results[0], &num_ranges);

  int is_valid = 1;

  if ((contract_get_absolute_offset(data->node_contract) != pm->current_offset) && (is_offset_within_ranges(pm->current_offset, ranges, num_ranges) != 1))
  {
    is_valid = 0;
  }

  if (is_valid == 0)
  {
    printf("WARNING MCP passed me a node that is out of sequence!\n");
    printf("Print manager has printed up to offset %lld, but the node passed has offset %lld\n", pm->current_offset * pm->block_size,
           contract_get_absolute_offset(data->node_contract) * pm->block_size);
    printf("I *should* assert and blow up, but it's commented out for now\n");
    unsigned int num_results = 0;
    const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

    prong_assert(num_results > 0);
    printf("The data type of the node was %s\n", result_get_brief_data_description(results[0]));
    return;
  }

  prong_assert(is_valid != 0);

  pm->print_handler->print_node(pm->current_offset, pm->block_size, node);

  save_children(pm, node);

//printf("Incremented current offset\n");
  pm->current_offset++;
}

static gboolean abs_tree_check(long long *abs_off, GNode * node, struct print_manager *pm)
{
  if (pm->lookup_offset > *abs_off)
  {
    if (pm->destroy_array == NULL)
    {
      pm->destroy_array = g_array_new(FALSE, FALSE, sizeof(long long));
    }
    g_array_append_val(pm->destroy_array, *abs_off);
    pm->lookup_offset++;
    return FALSE;
  }

  if (pm->lookup_offset == *abs_off)
  {
    if (pm->print_array == NULL)
    {
      pm->print_array = g_array_new(FALSE, FALSE, sizeof(long long));
    }
    g_array_append_val(pm->print_array, *abs_off);
    pm->lookup_offset++;
    return FALSE;
  }
  // abs_off must be greater than our current position. We're finished here
  return TRUE;
}

static gboolean continuation_tree_check(block_range_t range, struct continuation_node *node, struct print_manager *pm)
{
  if (is_offset_after_ranges(pm->current_offset, &range, 1) == 1)
  {
    if (pm->destroy_array == NULL)
    {
      pm->destroy_array = g_array_new(FALSE, FALSE, sizeof(block_range_t));
    }
    block_range_t br = block_range_clone(range);

    g_array_append_val(pm->destroy_array, br);
    return FALSE;
  }

  if (is_offset_within_ranges(pm->current_offset, &range, 1) == 1)
  {
    if (pm->print_array == NULL)
    {
      pm->print_array = g_array_new(FALSE, FALSE, sizeof(block_range_t));
    }
    block_range_t br = block_range_clone(range);

    g_array_append_val(pm->print_array, br);
    return TRUE;
  }

  return TRUE;
}

static int do_tree_check(struct print_manager *pm)
{
//printf("Checking abs_off tree\n");
  pm->lookup_offset = pm->current_offset;
  g_tree_foreach(pm->abs_tree, (GTraverseFunc) abs_tree_check, pm);
  if (pm->destroy_array != NULL)
  {
    for (int i = 0; i < pm->destroy_array->len; i++)
    {
      long long off = g_array_index(pm->destroy_array, long long, i);
      GNode *node = (GNode *) g_tree_lookup(pm->abs_tree, &off);

      save_children(pm, node);
      g_tree_remove(pm->abs_tree, &off);
    }
    g_array_free(pm->destroy_array, TRUE);
    pm->destroy_array = NULL;
  }

  if (pm->print_array != NULL)
  {
    for (int i = 0; i < pm->print_array->len; i++)
    {
      long long off = g_array_index(pm->print_array, long long, i);
      GNode *node = (GNode *) g_tree_lookup(pm->abs_tree, &off);

      print_and_process_tree(pm, node);
      g_tree_remove(pm->abs_tree, &off);
    }
    g_array_free(pm->print_array, TRUE);
    pm->print_array = NULL;
  }
//printf("Checking continuation tree\n");
  g_tree_foreach(pm->continuation_tree, (GTraverseFunc) continuation_tree_check, pm);
  if (pm->destroy_array != NULL)
  {
    for (int i = 0; i < pm->destroy_array->len; i++)
    {
      block_range_t br = g_array_index(pm->destroy_array, block_range_t, i);

      gboolean ret = g_tree_remove(pm->continuation_tree, br);

      prong_assert(ret == TRUE);
      block_range_close(br);
    }
    g_array_free(pm->destroy_array, TRUE);
    pm->destroy_array = NULL;
  }

  if (pm->print_array != NULL)
  {
    for (int i = 0; i < pm->print_array->len; i++)
    {
      block_range_t br = g_array_index(pm->print_array, block_range_t, i);
      struct continuation_node *node = (struct continuation_node *) g_tree_lookup(pm->continuation_tree, br);

      prong_assert(node != NULL);
      if (node->is_constant == 1)
      {
        pm->print_handler->print_const_continuation((unsigned long long) pm->current_offset * pm->block_size, (unsigned long long) node->owner_offset * pm->block_size, node->path);
        //printf("%13lld %13lld   Constant\n", pm->current_offset * pm->block_size, node->owner_offset * pm->block_size);
      } else
      {
        pm->print_handler->print_continuation((unsigned long long) pm->current_offset * pm->block_size, (unsigned long long) node->owner_offset * pm->block_size, node->brief_description);
        //printf("%13lld %13lld   (Continuation of %s)\n", pm->current_offset * pm->block_size, node->owner_offset * pm->block_size, node->brief_description);
      }
//printf("Incremented current offset\n");
      pm->current_offset++;
      block_range_close(br);
    }
    g_array_free(pm->print_array, TRUE);
    pm->print_array = NULL;
    return 1;
  }

  return 0;
}

// We need node for the information about itself for the ownership details
static void record_block_range(struct print_manager *pm, GNode * node, block_range_t range)
{
/*
unsigned long long p;
unsigned long long l;
block_range_get_range(range, &p, &l);
printf("Claiming range %llu-%llu\n", p, l);
*/
  prong_assert(node != NULL);
  prong_assert(node->data != NULL);
  struct job_node_data *data = (struct job_node_data *) node->data;

  block_range_t existing_range;
  long long *owner;

  if (g_tree_lookup_extended(pm->continuation_tree, range, (gpointer *) & existing_range, (gpointer *) & owner) == TRUE)
  {
    unsigned long long pos_new;
    unsigned long long len_new;

    block_range_get_range(range, &pos_new, &len_new);
    unsigned long long pos_old;
    unsigned long long len_old;

    block_range_get_range(existing_range, &pos_old, &len_old);

    if (pos_new >= pos_old)
    {
      if ((pos_old + len_old) >= (pos_new + len_new))
      {
        // Old has completely consumed new, therefore there is no work to do
      } else
      {
        // Old stops before completing consuming new. Add the remainder
        unsigned long long fragment_pos = pos_old + len_old;
        unsigned long long fragment_len = pos_new + len_new - fragment_pos;
        block_range_t br = block_range_init(NULL, 0);

        int ret = block_range_set_range(br, fragment_pos, fragment_len);
        prong_assert(ret == 0);
        record_block_range(pm, node, br);
        block_range_close(br);
      }
    } else
    {
      // We know that the new address starts before the old address
      unsigned long long fragment_pos = pos_new;
      unsigned long long fragment_len = pos_old - pos_new;
      block_range_t br = block_range_init(NULL, 0);

      int ret = block_range_set_range(br, fragment_pos, fragment_len);
      prong_assert(ret == 0);
      record_block_range(pm, node, br);
      block_range_close(br);

      if ((pos_new + len_new) >= (pos_old + len_old))
      {
        // And now we know it also extends AFTER the end of the old address
        unsigned long long fragment_pos = pos_old + len_old;
        unsigned long long fragment_len = pos_new + len_new - fragment_pos;
        block_range_t br = block_range_init(NULL, 0);

        ret = block_range_set_range(br, fragment_pos, fragment_len);
        prong_assert(ret == 0);
        record_block_range(pm, node, br);
        block_range_close(br);
      }
    }
  } else
  {
    struct continuation_node *cont_node = (struct continuation_node *) g_malloc(sizeof(struct continuation_node));

    cont_node->owner_offset = contract_get_absolute_offset(data->node_contract);

    unsigned int num_results;
    const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

    prong_assert(results != NULL);
    prong_assert(num_results > 0);

    cont_node->brief_description = g_strdup(result_get_brief_data_description(results[0]));
    cont_node->path = g_strdup(contract_get_path(data->node_contract));
    cont_node->is_constant = is_constant_node(node);

    existing_range = block_range_clone(range);
    g_tree_insert(pm->continuation_tree, existing_range, cont_node);
  }
}

static gboolean divide_abs_off_and_record_block_ranges(GNode * node, struct print_manager *pm)
{
  prong_assert(node != NULL);
  prong_assert(node->data != NULL);
  struct job_node_data *data = (struct job_node_data *) node->data;

  long long abs_off = contract_get_absolute_offset(data->node_contract);

  if (abs_off != -1)
  {
    abs_off = abs_off / pm->block_size;
    contract_set_absolute_offset(data->node_contract, abs_off);

    unsigned int num_results;
    const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

    prong_assert(results != NULL);
    prong_assert(num_results > 0);

    unsigned int num_ranges;
    block_range_t *ranges = result_get_block_ranges(results[0], &num_ranges);

    for (int i = 0; i < num_ranges; i++)
    {
      record_block_range(pm, node, ranges[i]);
    }
  }

  return FALSE;
}

int print_manager_add_node(print_manager_t _pm, GNode * node)
{
  prong_assert(_pm != NULL);
  prong_assert(node != NULL);
  struct print_manager *pm = (struct print_manager *) _pm;

  prong_assert(pm->magic == PRINT_MANAGER_MAGIC);

  // Traversing through all nodes, dividing the abs_offset to be a block offset
  // and recording their block ranges
  g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1, (GNodeTraverseFunc) divide_abs_off_and_record_block_ranges, pm);

  // Setting the nodes 'parent' to be itself
  struct job_node_data *data = (struct job_node_data *) node->data;

  data->parent_absolute_offset = contract_get_absolute_offset(data->node_contract);

//debug_print_state_of_play(pm);
  print_and_process_tree(pm, node);
  // Because this isn't part of the abs_tree we need to destroy it manually
  g_node_safe_destroy(node);

  while (do_tree_check(pm) > 0)
  {
    // Do nothing
  }

  return 0;
}

void print_manager_close(print_manager_t _pm)
{
  prong_assert(_pm != NULL);
  struct print_manager *pm = (struct print_manager *) _pm;

  prong_assert(pm->magic == PRINT_MANAGER_MAGIC);

  // If we're here we should have printed everything - unless a subcontractor
  // went crazy and added in children with invalid absolute offsets
  if ((g_tree_nnodes(pm->abs_tree) != 0) || (g_tree_nnodes(pm->continuation_tree) != 0))
  {
    severe_log("The print manager has been asked to exit but some nodes weren't printed!");
//    printf("*****************************\n");
//    printf("These nodes are unclaimed at closing time\n");
//    debug_print_state_of_play(pm);
  }

  g_tree_destroy(pm->abs_tree);
  g_tree_destroy(pm->continuation_tree);

  block_range_close(pm->lookup_range);

  g_free(pm);
}

char* get_node_filename(const char* path)
{
  if (path == NULL)
  {
    return NULL;
  }

  char* filename_path = g_strdup_printf("%s:filename", path);
  FILE* filename_file = fopen(filename_path, "rb");
  g_free(filename_path);

  if (filename_file == NULL)
  {
    return NULL;
  }

  // Max filename we support is 2048 characters
  char* filename = (char*)g_malloc(2048);
  memset(filename, 0, 2048);
  if (fread(filename, 1, 2047, filename_file) < 1)
  {
    fclose(filename_file);
    g_free(filename);
    return NULL;
  }
  fclose(filename_file);

  // Make sure it's all ascii printable
  char* ptr = filename;
  while (*ptr != '\0')
  {
    if (isgraph(*ptr) == 0)
    {
      *ptr = '.';
    }
    ptr++;
  }

  return filename;
}

