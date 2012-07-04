/* MCP DFRWS 2012 Style Printer
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
 * \file dfrws_print.c
 * \brief Provides a simple printer for producing output based on the requirements of the DFRWS 2012 challenge
 */

#include <stdio.h>

#include <contract.h>
#include <result.h>
#include <report.h>
#include <prong_assert.h>

#include "job_node.h"
#include "dfrws_print.h"

struct print_handler global_ph;
int global_init = 0;

struct print_handler *get_dfrws_print_handler(void)
{
  if (global_init == 0)
  {
    global_ph.print_node = dfrws_print;
    global_ph.print_header = dfrws_header;
    global_ph.print_continuation = dfrws_continued;
    global_ph.print_const_continuation = dfrws_const_continued;
    global_init = 1;
  }

  return &global_ph;
}

void dfrws_header(void)
{
  printf("Pronghorn - here to BLOCK YOUR WORLD!\n");
  printf("%13s %s\n", "Offset", "Description");
}


void dfrws_const_continued(unsigned long long current_offset, unsigned long long continued_from, const char* path)
{
//  printf("%13llu Constant # Extra info: Continuation of const starting at block %llu\n", current_offset, continued_from);
  printf("%13llu %-12s # Path:%s\n", current_offset, "Constant", path);
  char* filename = get_node_filename(path);
  if (filename != NULL)
  {
    printf("(%s) ", filename);
    g_free(filename);
  }
 }

void dfrws_continued(unsigned long long current_offset, unsigned long long continued_from, const char *brief_desc)
{
  printf("%13llu %-12s # Continuation of data starting at block %llu\n", current_offset, brief_desc, continued_from);
}

/* Doesn't do de-duplication, but is almost certainly a lot faster
static void dfrws_print_child_data(GNode* node)
{
  if (node == NULL)
  {
    return;
  }

  GNode* child = node->children;
  if (child == NULL)
  {
    return;
  }

  int has_printed = 0;
  while (child != NULL)
  {
    prong_assert(child->data != NULL);
    struct job_node_data* data = (struct job_node_data*) child->data;
    int num_results = 0;
    const result_t* results = contract_completion_report_get_results(data->node_report, &num_results);
    prong_assert(num_results > 0);

    if (result_get_confidence(results[0]) > 0)
    {
      if (has_printed == 0)
      {
        printf("(");
        has_printed = 1;
      } else
      {
        printf(" ");
      }
      printf("%s", result_get_brief_data_description(results[0]));
      dfrws_print_child_data(child);
    }

    child = child->next;
  }

  if (has_printed == 1)
  {
    printf(")");
  }

}
*/

void dfrws_collect_child_data(GNode * node, GNode * print_tree)
{

  if (node == NULL)
  {
    return;
  }

  GNode *child = node->children;

  if (child == NULL)
  {
    return;
  }

  while (child != NULL)
  {
    prong_assert(child->data != NULL);
    struct job_node_data *data = (struct job_node_data *) child->data;
    unsigned int num_results = 0;
    const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

    prong_assert(num_results > 0);

    if (result_get_confidence(results[0]) > 0)
    {
      GNode *new_print_node = g_node_new((gpointer) result_get_brief_data_description(results[0]));

      g_node_insert(print_tree, -1, new_print_node);

      dfrws_collect_child_data(child, new_print_node);
    }

    child = child->next;
  }

}

gboolean print_tree_equal(GNode * a, GNode * b)
{
  prong_assert(a != NULL);
  prong_assert(b != NULL);

  if (g_node_n_nodes(a, G_TRAVERSE_ALL) != g_node_n_nodes(b, G_TRAVERSE_ALL))
    return FALSE;

  if (g_strcmp0((char *) a->data, (char *) b->data) != 0)
    return FALSE;

  GNode *childa = a->children;
  GNode *childb = b->children;

  while (childa != NULL && childb != NULL)
  {
    if (print_tree_equal(childa, childb) == FALSE)
      return FALSE;

    childa = childa->next;
    childb = childb->next;
  }

  return TRUE;
}

void collapse_print_tree(GNode * print_tree)
{

  if (print_tree == NULL)
    return;

  GNode *child = print_tree->children;

  while (child != NULL)
  {
    GNode *next = child->next;

    while (next != NULL)
    {

      if (print_tree_equal(child, next) == TRUE)
      {
        // Prune
        GNode *after_prune = next->next;

        g_node_destroy(next);
        next = after_prune;
      } else
      {
        next = next->next;
      }
    }

    child = child->next;
  }

  child = print_tree->children;

  // Now do the same for all our children
  while (child != NULL)
  {
    collapse_print_tree(child);
    child = child->next;
  }

}

gboolean debug_print_print_node(GNode * node, gpointer data)
{

  if (node->data != NULL)
  {
    printf("Node: %s\n", (char *) node->data);
  }

  if (node->parent != NULL && node->parent->data != NULL)
  {
    printf("  Node Parent: %s\n", (char *) node->parent->data);
  } else if (node->parent != NULL)
  {
    printf("  Node parent: ROOT\n");
  }

  return FALSE;

}

void debug_print_print_tree(GNode * node)
{

  g_node_traverse(node, G_IN_ORDER, G_TRAVERSE_ALL, -1, debug_print_print_node, NULL);

}

void dfrws_print_tree(GNode * node)
{

  if (node == NULL)
  {
    return;
  }

  GNode *child = node->children;

  if (child == NULL)
  {
    return;
  }

  int has_printed = 0;

  while (child != NULL)
  {
    prong_assert(child->data != NULL);

    if (has_printed == 0)
    {
      printf("-(");
      has_printed = 1;
    } else
    {
      printf(" ");
    }

    printf("%s", (char *) child->data);
    dfrws_print_tree(child);
    child = child->next;

  }

  if (has_printed == 1)
  {
    printf(")");
  }

}


void dfrws_print(unsigned long long current_offset, unsigned int block_size, GNode * node)
{
  struct job_node_data *data = (struct job_node_data *) node->data;
  GNode *print_tree;

  // Abs Offset:
  printf("%13llu ", current_offset * block_size);

  if (is_constant_node(node) == 1)
  {
    printf("%-12s # Path:%s\n", "Constant", contract_get_path(data->node_contract));
    char* filename = get_node_filename(contract_get_path(data->node_contract));
    if (filename != NULL)
    {
      printf("(%s) ", filename);
      g_free(filename);
    }
    return;
  }

  unsigned int num_results = 0;
  const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

  prong_assert(num_results > 0);

  if (contract_get_absolute_offset(data->node_contract) == current_offset)
  {
    if (result_get_confidence(results[0]) > 0)
    {
      print_tree = g_node_new(NULL);
      dfrws_collect_child_data(node, print_tree);
      collapse_print_tree(print_tree);
      
      // Only pad out the brief description if no child descriptions
      // are following.
      if(g_node_first_child(print_tree) == NULL)
      {
        printf("%-12s", result_get_brief_data_description(results[0]));
      }
      else
      {
        printf("%s", result_get_brief_data_description(results[0]));
      }
      dfrws_print_tree(print_tree);
      g_node_destroy(print_tree);

      printf(" # %s Path:%s ", result_get_data_description(results[0]), contract_get_path(data->node_contract));
      char* filename = get_node_filename(contract_get_path(data->node_contract));
      if (filename != NULL)
      {
        printf("(%s) ", filename);
        g_free(filename);
      }
      
    } else
    {
      printf("Unidentified # Path:%s ", contract_get_path(data->node_contract));
      char* filename = get_node_filename(contract_get_path(data->node_contract));
      if (filename != NULL)
      {
        printf("(%s) ", filename);
        g_free(filename);
      }
    }

  } else
  {
    printf("(continuation) ?? %lld!=%lld", contract_get_absolute_offset(data->node_contract) * block_size, current_offset * block_size);
    printf(" Path:%s ", contract_get_path(data->node_contract));
    char* filename = get_node_filename(contract_get_path(data->node_contract));
    if (filename != NULL)
    {
      printf("(%s) ", filename);
      g_free(filename);
    }
  }

  printf("\n");
/*


  if (is_constant_node(node) == 1)
  {
    printf("%13llu   ", current_offset * block_size);
    printf("Constant\n");
  } else
  {
    printf("%13llu   ", data->parent_absolute_offset * block_size);


    if (contract_get_absolute_offset(data->node_contract) == current_offset)
    {
      if (result_get_confidence(results[0]) > 0)
      {
        printf("%s", result_get_brief_data_description(results[0]));

        print_tree = g_node_new(NULL);
        dfrws_collect_child_data(node, print_tree);
        collapse_print_tree(print_tree);
        //debug_print_print_tree(print_tree);
        //if (g_node_n_nodes(print_tree, G_TRAVERSE_ALL) > 1) printf("  Contains children: %s", result_get_brief_data_description(results[0]));
        dfrws_print_tree(print_tree);
        g_node_destroy(print_tree);

        printf(" # Extra info: %s ", result_get_data_description(results[0]));
        //dfrws_print_child_data(node);

      } else
      {
        printf("Unidentified");
        //printf(" %s", contract_get_path(data->node_contract));
      }
    } else
    {
      printf("(continuation) ?? %lld!=%lld", contract_get_absolute_offset(data->node_contract) * block_size, current_offset * block_size);
      printf(" %s", contract_get_path(data->node_contract));
    }

    printf("\n");
  }
*/

}
