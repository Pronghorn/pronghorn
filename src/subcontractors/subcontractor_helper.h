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

#ifndef SUBCONTRACTOR_HELPER_H
#define SUBCONTRACTOR_HELPER_H

#include <lightmagic.h>
#include <logger.h>
#include <config.h>
#include <contract.h>
#include <report.h>
#include <glib.h>

// For the subcontractors to complete

/**
 * An array of supported MAGIC_TYPE* entries. Must be 0 terminated.
 */
extern unsigned int supported_file_types[];
int subcontractor_init(void) G_GNUC_WARN_UNUSED_RESULT;
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr) G_GNUC_WARN_UNUSED_RESULT;
int subcontractor_close(void) G_GNUC_WARN_UNUSED_RESULT;

/*
 * \brief Populates a result.
 *
 * \param brief_description A brief description of the data
 * \param description A description of the data
 * \param confidence The confidence (0-100) with which the data is believed to
 * be a certain type
 * \param result The result to populate
 * \return Returns a 0 on success, -1 on error. 
 *
 * This is a convience method to make adding results to a ccr simpler.
 */
int populate_result(result_t result, const gchar * brief_description, const gchar * description, int confidence);

/*
 * \brief Populates a result.
 *
 * \param brief_description A brief description of the data
 * \param description A description of the data
 * \param confidence The confidence (0-100) with which the data is believed to
 * be a certain type
 * \param result The result to populate
 * \param ranges An array of block ranges to be added
 * \param num_ranges The size of the block range array
 * \return Returns a 0 on success, -1 on error. 
 *
 * This is a convience method to make adding results to a ccr simpler.
 */
int populate_result_blocks(result_t result, const gchar * brief_description, const gchar * description, int confidence, block_range_t* ranges, int num_ranges);


/*
 * \brief Populates a result, claiming a certain amount of data
 *
 * \param brief_description A brief description of the data
 * \param description A description of the data
 * \param confidence The confidence (0-100) with which the data is believed to
 * be a certain type
 * \param result The result to populate
 * \param abs_off The absolute offset of the contract
 * \param length The length of the file to claim (in bytes)
 * \param is_contiguous 1 if the file space is contiguous, 0 otherwise
 * \return Returns a 0 on success, -1 on error. 
 *
 * This is a convience method to make adding results to a ccr simpler.
 */
int populate_result_with_length(result_t result, const gchar * brief_description, const gchar * description, int confidence, long long int abs_offset, unsigned long long length, int is_contiguous);
#endif // SUBCONTRACTOR_HELPER_H
