#!/bin/bash

die () {
    #echo >&2 "$@"
		echo "At least one argument (input file) required"
		echo "Usage:"
		echo "`basename $0` file [-o group.option=value -o group2.option2=value2 ... ]" 
		echo ""
		echo "Example:"
		echo "`basename $0` ./file_to_classify.dd -o general.log_verbosity=DEBUG"
		echo ""
    exit 1
}

[ "$#" -gt 0 ] || die 


input_file=$1
shift

./src/scripts/unmount_all /tmp/

export G_SLICE=always-malloc
export G_DEBUG=gc-friendly,resident-modules valgrind

ERROR_FILE=pronghorn.log

echo "A log file will be created at '$ERROR_FILE'"

./src/pronghorn/pronghorn -o general.install_dir=`pwd` -o general.config_directory=./config -o general.logserver_executable=./src/logserver/logserver -o general.mcp_executable=./src/mcp/mcp -o general.log_verbosity=DEBUG -o general.input_file=$input_file -o general.fuse_sub_dir=fuse_mp -o general.rawmount_executable=./src/rawmount/rawmount -o general.contractor_executable=./src/contractor/contractor -o general.unmount_all_script=./src/scripts/unmount_all -o general.subcontractor_directories=\$\{install_dir\}/src/subcontractors -o general.security_warning=OK $@ 2>$ERROR_FILE

