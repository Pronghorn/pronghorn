/* Pronghorn texthelper header
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

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <logger.h>
#include <blocks.h>
#include <report.h>

//returns the length of uninterrupted ascii characters in buff starting from buff[0]
int length_of_text(char *buff, int buff_len) G_GNUC_WARN_UNUSED_RESULT;

//smart read will load an ascii text file that of a unknown length up the max_size
//smart read will only ever read the bits from disk once but may copy them around in memory
//this is a tradeoff to try and keep the memory allocation close to the (unkown) file size
//returns the number of bytes loaded into memory
//modifies pointer dst to point at those bytes
int smart_read_text(char **dst, FILE * file, int block_size, int max_size) G_GNUC_WARN_UNUSED_RESULT;

/*
 * \brief Submit a result to the ccr passed
 *
 * \param brief_description The brief description of the data
 * \param description A description of the data
 * \param confidence The confidence (0-100) with which the data is believed to
 * be a certain type
 * \param ccr The ccr to add the result to
 *
 * This is a convience method to make adding results to a ccr simpler.
 */
void submit_result(gchar * brief_description, gchar * description, int confidence, contract_completion_report_t ccr);

//returns a pointer to an array counting the number of times each regex matched
//ALLOCATES HEAP MEMORY THAT MUST BE FREED EXTERNALLY
int *regexen_match_counts(char *buff, int buff_size, const gchar ** regex_strings, int regex_count, GRegexCompileFlags compile_flags) G_GNUC_WARN_UNUSED_RESULT;

//returns the number of regex that matched at least once
int regexen_matched_count(char *buff, int buff_size, const gchar ** regex_strings, int regex_count, GRegexCompileFlags compile_flags) G_GNUC_WARN_UNUSED_RESULT;

//returns the number of times a single regex matched
int regex_match_count(char *buff, int buff_size, const gchar * regex_string, GRegexCompileFlags compile_flags) G_GNUC_WARN_UNUSED_RESULT;
