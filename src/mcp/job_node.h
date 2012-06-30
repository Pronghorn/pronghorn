/* libpronghorn Job Node
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

#ifndef JOB_NODE_H
#define JOB_NODE_H

#include <glib.h>

#include <contract.h>
#include <report.h>


/**
 * A structure that holds contracts and their CCRs if they have been 
 * processed. We store all of these in a tree like structure, the root
 * of which is stored in the data_source struct (called job_tree). 
 * This tree represents where we found data within the data source. 
 *
 * A node may either have a CCR set AND a completion report set (in which 
 * case it is just waiting before the data is printed out) or it may JUST 
 * have a contract set (this means that it is either BEING process or 
 * HAS BEEN processed - this info is stored by the data source struct).
 */
struct job_node_data
{
	/** The contract that either needs to be processed or has been processed */
	contract_t node_contract;

	/** The report (either NULL if we haven't processed it yet or filled out 
 	 * if it's ready to be printed). */
	contract_completion_report_t node_report;

	/** Has this node been issued (to be processed?) */
	gboolean contract_issued;

	/** A unique ID for this element in the node */
	unsigned long long job_id;

  /** The absolute_offset of the parent */
  long long parent_absolute_offset;
};


/** A range of offsets */
//struct offset_range
//{
	/** The starting offset */
//	unsigned long long offset;

	/** The length of this range */
//	unsigned long long length;
//};

struct job_node_data* job_node_data_init(void);
void job_node_data_close(struct job_node_data* jn);

/**
 * \brief Frees a job node 
 *
 * \param node The node to free
 * \param data User data. This is ignore but present to ensure this matches 
 * the GNodeTraverseFunc specification.
 *
 * \return Always returns FALSE to match the GNodeTraverseFunc specification
 *
 */
gboolean free_job_node(GNode* node, gpointer data);

int is_constant_node(GNode* node);

int is_offset_before_ranges(long long int offset, block_range_t* ranges, unsigned int num_ranges);
int is_offset_within_ranges(long long int offset, block_range_t* ranges, unsigned int num_ranges);
int is_offset_after_ranges(long long int offset, block_range_t* ranges, unsigned int num_ranges);

#endif
