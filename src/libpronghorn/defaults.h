/* Libpronghorn defaults
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
 * \file defaults.h
 * \brief Libpronghorn default options
 *
 * This defines some of the configuration option naming and defaults
 * where appropriate.
 */

#ifndef DEFAULTS_H
#define DEFAULTS_H

//
// Section Names
//

/** Name of the general section in config / cmd line options */
#define CONFIG_GENERAL_GROUP_OPTION_NAME "general"

//
// Basic Options
//

/** The name of the option specifying pronghorns config directory */
#define CONFIG_CONFIG_DIRECTORY_OPTION_NAME "config_directory"
/** The default pronghorn conf directory location */
#define CONFIG_CONFIG_DIRECTORY_DEFAULT "/etc/pronghorn"

/** The name of the option that provides the input file to process*/
#define CONFIG_INPUT_FILE_OPTION_NAME "input_file"

/** The name of the option that specifies how many cores to use when running pronghorn */
#define CONFIG_CONCURRENCY_OPTION_NAME "number_cores"
/** The default value for the number of cores to use */
#define CONFIG_CONCURRENCY_DEFAULT 1

/** The name of the option to set block size */
#define CONFIG_BLOCK_SIZE_OPTION_NAME "block_size"
/** The default value of the block size */
#define CONFIG_BLOCK_SIZE_DEFAULT 512

/** The name of the option for setting the starting block */
#define CONFIG_START_AT_BLOCK_NUMBER_OPTION_NAME "starting_block"
/** The default value of the starting block option */
#define CONFIG_START_AT_BLOCK_NUMBER_DEFAULT 0

/** The name of the option that sets log verbosity */
#define CONFIG_LOG_VERBOSITY_OPTION_NAME "log_verbosity"
/** The default value for log verbosity */
#define CONFIG_LOG_VERBOSITY_DEFAULT "INFO"

/** The name of the option to disable a security warning. The user must set this to "OK" or "ok" to disable */
#define CONFIG_WARN_ABOUT_SECURITY_OPTION_NAME "security_warning"

//
// MCP Options
//

/** The name of the option for the maximum number of nodes that the MCP will allow in its job tracking tree and continue to give out new raw contracts. If the number of nodes grows greater than this number, the MCP will tell contractors to wait before checking in again */
#define CONFIG_MCP_MAX_NODES_IN_TREE_OPTION_NAME "mcp_max_tree_nodes"
/** The default value for the maximum number of nodes the MCP will have in its jobs tracking tree while continuing to give out new raw contracts */
#define CONFIG_MCP_MAX_NODES_IN_TREE_DEFAULT 10000

/** The name of the option that sets how long the MCP should tell contractors to wait when the MCP tree starts becoming too full */
#define CONFIG_MCP_FULL_TREE_WAIT_TIME_OPTION_NAME "mcp_full_tree_wait"
/** The default value for the amount of time the MCP should tell a contractor to wait when its tree becomes full */
#define CONFIG_MCP_FULL_TREE_WAIT_TIME_DEFAULT 5000 // 5s

/** DFRWS output style is set to be that requested by the DFRWS 2012 challenge */
#define CONFIG_DFRWS_OUTPUT_STYLE 0
/** An output style that is slightly more concise */
#define CONFIG_PATH_OUTPUT_STYLE 1

/** The name of the option that sets the output style */
#define CONFIG_OUTPUT_STYLE_OPTION_NAME "output_style"
/** The default value of output style */
#define CONFIG_OUTPUT_STYLE_DEFAULT CONFIG_DFRWS_OUTPUT_STYLE


// Sub-Contractor Processing Options

/** The name of the option that specifies brute force mode. Note that
 * this is NYI. */
#define CONFIG_BRUTE_FORCE_OPTION_NAME "brute_force_mode"
/** The default value for brute force mode. This is NYI at present. */
#define CONFIG_BRUTE_FORCE_DEFAULT 0

/** The name of the option to set the subcontractor precedence */
#define CONFIG_SCON_PRECEDENCE_OPTION_NAME "subcontractor_precedence"

/** The name of the option that sets the subcontractor minimum confidence threshold */
#define CONFIG_SCON_MIN_CONF_THRESHOLD_OPTION_NAME "subcontractor_confidence_threshold"
/** The default value for the subcontractor confidence threshold */
#define CONFIG_SCON_MIN_CONF_THRESHOLD_DEFAULT 50

/** The name of the option that sets the subcontractor directories */
#define CONFIG_SUBCONTRACTOR_DIRECTORIES "subcontractor_directories"

// Directories and paths

/** The name of the option for the working directory */
#define CONFIG_WORKING_DIRECTORY_OPTION_NAME "working_dir"
/** The default value of the workding directory */
#define CONFIG_WORKING_DIRECTORY_DEFAULT "/tmp"

/** The name of the option that sets the fuse sub directory */
#define CONFIG_FUSE_SUB_DIR_OPTION_NAME "fuse_sub_dir"
/** The default value for the fuse mount sub directory */
#define CONFIG_FUSE_SUB_DIR_DEFAULT "fuse_mount"

/** The name of the option that sets the log server executable */
#define CONFIG_LOGSERVER_EXECUTABLE_NAME_OPTION_NAME "logserver_executable"
/** The default value of the log server executable */
#define CONFIG_LOGSERVER_EXECUTABLE_NAME_DEFAULT "logserver"

/** The name of the option that sets the mcp executable */
#define CONFIG_MCP_EXECUTABLE_NAME_OPTION_NAME "mcp_executable"
/** The default value for the mcp executable option */
#define CONFIG_MCP_EXECUTABLE_NAME_DEFAULT "mcp"

/** The name of the option that sets the raw mount executable */
#define CONFIG_RAW_MOUNT_EXECUTABLE_OPTION_NAME "rawmount_executable"
/** The default value of the rawmount executable option */
#define CONFIG_RAW_MOUNT_EXECUTABLE_DEFAULT "rawmount"

/** The name of the option that sets the contractor executable option */
#define CONFIG_CONTRACTOR_EXECUTABLE_NAME_OPTION_NAME "contractor_executable"
/** The default value of the contractor executable */
#define CONFIG_CONTRACTOR_EXECUTABLE_NAME_DEFAULT "contractor"

/** The name of the option that sets the unmount all script */
#define CONFIG_UNMOUNT_ALL_FUSE_SCRIPT_OPTION_NAME "unmount_all_script"
/** The default value of the unmount all script path option */
#define CONFIG_UNMOUNT_ALL_FUSE_SCRIPT_DEFAULT "unmount_all"

// MCP <-> Contractor transport

// This needs to be low so the MCP doesn't wait around for dead contractors too long. The MCP will retry 
// indefinitely, so this value is more about how often the MCP will retry recvs. If you want to change the "system"
// timeout, you should set the contractor time out below.
#define CONFIG_MCP_RECV_FROM_CONTRACTOR_TIMEOUT_OPTION_NAME "mcp_contractor_timeout"
/** The default value of the mcp recv timeout */
#define CONFIG_MCP_RECV_FROM_CONTRACTOR_TIMEOUT_DEFAULT 1000

/** The name of the option that sets that transport listen option */
#define CONFIG_MCP_LISTEN_ENDPOINT_OPTION_NAME "mcp_transport_listen"
/** The default value of the mcp transport listen address */
#define CONFIG_MCP_LISTEN_ENDPOINT_DEFAULT "tcp://127.0.0.1:4444"

/** The name of the option that sets the mcp transport connect address */
#define CONFIG_MCP_CONNECT_ENDPOINT_OPTION_NAME "mcp_transport_connect"
/** The default value of the mcp connect address */
#define CONFIG_MCP_CONNECT_ENDPOINT_DEFAULT "tcp://127.0.0.1:4444"

// These next two options define how long a contractor will wait (retries * timeout) before giving up talking to the MCP
/** The name of the option that sets how long a contractor waits for a response from the mcp */
#define CONFIG_CONTRACTOR_RECV_FROM_MCP_TIMEOUT_OPTION_NAME "contractor_mcp_timeout"
/** The default value for how long a contractor will wait for a response from the mcp */
#define CONFIG_CONTRACTOR_RECV_FROM_MCP_TIMEOUT_DEFAULT -1

/** The name of the option that sets how many times a contractor will retry a recieve from the mcp */
#define CONFIG_CONTRACTOR_RECV_FROM_MCP_RETRIES_OPTION_NAME "contractor_mcp_recv_retries"
/** The default value of how many times a contractor will retry a receive from the mcp */
#define CONFIG_CONTRACTOR_RECV_FROM_MCP_RETRIES_DEFAULT 50

// Config transport

/** The name of the option that sets the transport timeout of the config server */
#define CONFIG_CONFIG_TIMEOUT_OPTION_NAME "config_timeout"
/** The default value for the config server transport timeout */
#define CONFIG_CONFIG_TIMEOUT_DEFAULT 15000

/** THe name of the option that sets the config server listen endpoint */
#define CONFIG_CONFIG_LISTEN_ENDPOINT_OPTION_NAME "config_listen"
/** The default value for the config server endpoint */
#define CONFIG_CONFIG_LISTEN_ENDPOINT_DEFAULT "tcp://127.0.0.1:6666"

/** The name of the option that sets the endpoint the config clients will connect to */
#define CONFIG_CONFIG_CONNECT_ENDPOINT_OPTION_NAME "config_connect"
/** The default value for the address that the config clients will connect to */
#define CONFIG_CONFIG_CONNECT_ENDPOINT_DEFAULT "tcp://localhost:6666"

// Log transport

/** The name of the option that sets the log send timeout */
#define CONFIG_LOG_TIMEOUT_OPTION_NAME "log_send_timeout"
/** The default value for the log send timeout */
#define CONFIG_LOG_TIMEOUT_DEFAULT 15000

/** The name of the option that sets the address the log server should listen on */
#define CONFIG_LOG_LISTEN_ENDPOINT_OPTION_NAME "log_listen"
/** The default value for the address the config server should listen on */
#define CONFIG_LOG_LISTEN_ENDPOINT_DEFAULT "tcp://0.0.0.0:5555"

/** The name of the option that specifies the endpoint the log clients should connect to */
#define CONFIG_LOG_CONNECT_ENDPOINT_OPTION_NAME "log_connect"
/** The default value for the end point to connect to for the log server */
#define CONFIG_LOG_CONNECT_ENDPOINT_DEFAULT "tcp://127.0.0.1:5555"

// Contractor <-> Sub contractor transport

/* NO LONGER REQUIRED The name of the option that sets the the contractor to sub contractor transport 
   #define CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_OPTION_NAME "contractor_subcontractor_transport" */

/** The name of the option that sets the subcontractor time out */
#define CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_TIMEOUT_OPTION_NAME "subcontractor_timeout"
#define CONFIG_CONTRACTOR_SUBCONTRACTOR_TRANSPORT_TIMEOUT_DEFAULT 60000

// Log server specific

/** The name of the option that sets whether or not logs should be appended to or overwritten */
#define CONFIG_LOG_SERVER_OUTPUT_FILE_APPEND_OPTION_NAME "log_file_append"
#define CONFIG_LOG_SERVER_OUTPUT_FILE_APPEND_DEFAULT 0

/** The name of the option that sets the name for the output file */
#define CONFIG_LOG_SERVER_GENERAL_OUTPUT_FILE_OPTION_NAME "log_general_output_file"
/** The name of the option that sets the file name for the dbeug file */
#define CONFIG_LOG_SERVER_DEBUG_OUTPUT_FILE_OPTION_NAME "log_debug_output_file"
/** The name of the option that sets the file name for the output file */
#define CONFIG_LOG_SERVER_INFO_OUTPUT_FILE_OPTION_NAME "log_info_output_file"
/** The name of the option that sets the file name for the warning output file */
#define CONFIG_LOG_SERVER_WARNING_OUTPUT_FILE_OPTION_NAME "log_warning_output_file"
/** The name of the option that sets the file name for the error output file */
#define CONFIG_LOG_SERVER_ERROR_OUTPUT_FILE_OPTION_NAME "log_error_output_file"
/** The name of the option that sets the file name for the severe log output file */
#define CONFIG_LOG_SERVER_SEVERE_OUTPUT_FILE_OPTION_NAME "log_severe_output_file"

// Test harness specific

/** The name of the option that specifies which subcontractor will be run by the test harness */
#define CONFIG_TEST_HARNESS_SUBCONTRACTOR_TO_TEST_OPTION_NAME "test_harness_subcontractor"

// Misc

#define CONFIG_VALGRIND_OPTION_NAME "valgrind_opts"

#define CONFIG_SPAWN_MEMORY_LIMIT "mem_limit"
#define CONFIG_SPAWN_DISK_LIMIT "disk_limit"
#define CONFIG_SPAWN_PROC_LIMIT "proc_limit"

#define CONFIG_FORCE_STDERR_LOGGING "force_stderr_logging"

#define CONFIG_FUSE_NO_DIRECTORY_LISTINGS "fuse_no_dir_listing"
#define CONFIG_FUSE_OUTPUT_DEBUG_FILE "fuse_debug_file"

#endif
