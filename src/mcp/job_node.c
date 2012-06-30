/* Libpronghorn Job Node
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
 * \file job_node.c
 * \brief Libpronghorn job node
 *
 */
#include <block_range.h>
#include <lightmagic.h>
#include <prong_assert.h>

#include "job_node.h"

struct job_node_data *job_node_data_init(void)
{
  struct job_node_data *new_job = (struct job_node_data *) g_malloc(sizeof(struct job_node_data));

  new_job->contract_issued = FALSE;
  new_job->job_id = 0;
  new_job->node_contract = NULL;
  new_job->node_report = NULL;
  new_job->parent_absolute_offset = -1;

  return new_job;
}

void job_node_data_close(struct job_node_data *jn)
{
  if (jn->node_contract != NULL)
  {
    contract_close(jn->node_contract);
    jn->node_contract = NULL;
  }
  if (jn->node_report != NULL)
  {
    contract_completion_report_close(jn->node_report);
    jn->node_report = NULL;
  }

  g_free(jn);
}


gboolean free_job_node(GNode * node, gpointer data)
{
  struct job_node_data *node_to_free = (struct job_node_data *) node->data;

  job_node_data_close(node_to_free);

  return FALSE;
}

int is_constant_node(GNode * node)
{
  prong_assert(node != NULL);
  prong_assert(node->data != NULL);
  struct job_node_data *data = (struct job_node_data *) node->data;

  int num_results = 0;
  const result_t *results = contract_completion_report_get_results(data->node_report, &num_results);

  prong_assert(num_results > 0);

  // Constant nodes have a confidence of -1
  if (result_get_confidence(results[0]) > 0)
  {
    return 0;
  }

  int num_types;
  const int *types = contract_get_types(data->node_contract, &num_types);

  for (int i = 0; i < num_types; i++)
  {
    if (types[i] == MAGIC_TYPE_CONSTANT)
    {
      return 1;
    }
  }
  return 0;
}

int is_offset_before_ranges(long long int offset, block_range_t * ranges, unsigned int num_ranges)
{
  if (ranges == NULL)
  {
    return -1;
  }

  for (int i = 0; i < num_ranges; i++)
  {
    unsigned long long pos;
    unsigned long long len;

    block_range_get_range(ranges[i], &pos, &len);
    if (offset >= pos)
    {
      return 0;
    }
  }
  return 1;
}

int is_offset_within_ranges(long long int offset, block_range_t * ranges, unsigned int num_ranges)
{
  if (ranges == NULL)
  {
    return -1;
  }

  for (int i = 0; i < num_ranges; i++)
  {
    unsigned long long pos;
    unsigned long long len;

    block_range_get_range(ranges[i], &pos, &len);
    if (offset < (pos + len))
    {
      if (offset >= pos)
      {
        return 1;
      }
    }
  }
  return 0;
}

int is_offset_after_ranges(long long int offset, block_range_t * ranges, unsigned int num_ranges)
{
  if (ranges == NULL)
  {
    return -1;
  }

  for (int i = 0; i < num_ranges; i++)
  {
    unsigned long long pos;
    unsigned long long len;

    block_range_get_range(ranges[i], &pos, &len);
    if (offset < (pos + len))
    {
      return 0;
    }
  }
  return 1;
}
