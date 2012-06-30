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

#ifndef PRINT_MANAGER_H
#define PRINT_MANAGER_H

/**
 * The print manager reference.
 */
typedef struct print_manager* print_manager_t;

/**
 * Typdef for a function that can actually print out a node
 */
typedef void (*print_node_function_t)(unsigned long long current_offset, unsigned int block_size, GNode* node);

/**
 * Typedef for a function that can just print out the header / preamble for output
 */
typedef void (*print_header_function_t)(void);

/** 
 * Typdef for a function that is called when a block that is a continuation of another block needs to be printed out
 */
typedef void (*print_continuation_function_t)(unsigned long long current_offset, unsigned long long continued_from, const char* brief_desc);

/** 
 * Typedef for a function that is called when a constant block that is a continuation of another const block needs to be printed out
 */
typedef void (*print_constant_continuation_function_t)(unsigned long long current_offset, unsigned long long continued_from, const char* path);

/**
 * Structure containing all the functions needed to be able to print out pronghorn output
 */
struct print_handler
{
	print_node_function_t print_node;
  print_header_function_t print_header;
  print_continuation_function_t print_continuation;
	print_constant_continuation_function_t print_const_continuation;
};


/**
 * \brief Init a print manager 
 * \param block_size The block size we are using
 * \return A reference to a newly created print_manager reference
 * \warning It is the callers job to close the returned reference using print_manager_close
 *
 */
print_manager_t print_manager_init(unsigned int block_size, unsigned long long start_block);

/**
 * \brief Add a tree (and print when appropriate) to the print manager
 * \param _pm The print manager we are adding the tree to
 * \param node The node to add
 * \return 0 on success, -1 on failure
 *
 */
int print_manager_add_node(print_manager_t _pm, GNode* node);

/*
 * Safely destroys an internally generated node
 */
void g_node_safe_destroy(GNode * node);

/** 
 * \brief Close the print manager, free its resources
 * \param _pm The print manager to close
 */
void print_manager_close(print_manager_t _pm);

/**
 * Returns the associated filename for the node, if it's known.
 *
 * \warning The caller must free this pointer using g_free.
 *
 * \param node The node to query
 * \returns The filename, or NULL if it cannot be determined
 */
char* get_node_filename(const char* path);

#endif

