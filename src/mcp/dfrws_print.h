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

#ifndef DFRWS_PRINT_H
#define DFRWS_PRINT_H

#include <glib.h>
#include "print_manager.h"

struct print_handler* get_dfrws_print_handler(void);

void dfrws_header(void);
void dfrws_const_continued(unsigned long long current_offset, unsigned long long continued_from, const char* path);
void dfrws_continued(unsigned long long current_offset, unsigned long long continued_from, const char* brief_desc);
void dfrws_print(unsigned long long current_offset, unsigned int block_size, GNode* node);

#endif

