/* MCP Basic Printer
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
 * \file basic_print.c
 * \brief Provides a simple printer for producing output
 */

#include <stdio.h>

#include <contract.h>
#include <result.h>
#include <report.h>
#include <prong_assert.h>

#include "job_node.h"
#include "basic_print.h"
#include "print_manager.h"

struct print_handler global_basic_ph;
int global_basic_init = 0;

struct print_handler *get_basic_print_handler(void)
{
  if (global_basic_init == 0)
  {
    global_basic_ph.print_node = basic_print;
    global_basic_ph.print_header = basic_header;
    global_basic_ph.print_continuation = basic_continued;
    global_basic_ph.print_const_continuation = basic_const_continued;
    global_basic_init = 1;
  }

  return &global_basic_ph;
}

void basic_header(void)
{
  printf("Pronghorn - here to BLOCK YOUR WORLD!\n");
}


void basic_const_continued(unsigned long long current_offset, unsigned long long continued_from, const char* path)
{
  //printf("%13llu Constant # Extra info: Continuation of const starting at block %llu\n", current_offset, continued_from);
}

void basic_continued(unsigned long long current_offset, unsigned long long continued_from, const char *brief_desc)
{
  //printf("%13llu %s # Extra info: Continuation of data starting at block %llu\n", current_offset, brief_desc, continued_from);
}


static void node_destroy_wrapper(GNode* node, gpointer data)
{
  g_node_safe_destroy(node);
}

void basic_print(unsigned long long current_offset, unsigned int block_size, GNode * node)
{
  struct job_node_data *data = (struct job_node_data *) node->data;
  int num_results = 0;
  const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

  prong_assert(num_results > 0);

  if (result_get_confidence(results[0]) > 0)
  {
    if (contract_get_absolute_offset(data->node_contract) != -1)
    {
      printf("%13llu ", contract_get_absolute_offset(data->node_contract) * block_size);
    } else
    {
      printf("%13i ", -1);
    }

    printf("%s ", contract_get_path(data->node_contract));

    char* filename = get_node_filename(contract_get_path(data->node_contract));
    if (filename != NULL)
    {
      printf("(%s) ", filename);
      g_free(filename);
    }

    printf("%s : %s\n", result_get_brief_data_description(results[0]), result_get_data_description(results[0]));

    GNode *child = node->children;

    if (child == NULL)
    {
      return;
    }

    while (child != NULL)
    {
      basic_print(current_offset, block_size, child);
      child = child->next;
    }
  }

  // This is nasty, and prevents print_manager tracking children.
  // But I think it works?
  g_node_children_foreach(node, G_TRAVERSE_ALL, node_destroy_wrapper, NULL);

  /*
  if ((contract_get_absolute_offset(data->node_contract) == current_offset) || (contract_get_absolute_offset(data->node_contract) == -1))
  {
    if (result_get_confidence(results[0]) > 0)
    {
      if (contract_get_absolute_offset(data->node_contract) != -1)
      {
        printf("%13llu ", current_offset * block_size);
      } else
      {
        printf("%13i ", -1);
      }

      printf("%s ", contract_get_path(data->node_contract));

      printf("%s : %s\n", result_get_brief_data_description(results[0]), result_get_data_description(results[0]));

      GNode *child = node->children;

      if (child == NULL)
      {
        return;
      }

      while (child != NULL)
      {
        basic_print(current_offset, block_size, child);
        child = child->next;
      }
    } else
    {
      //printf("Unidentified\n");
    }
  }*/
}

