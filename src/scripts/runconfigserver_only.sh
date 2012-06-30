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

installdir=`pwd`

./src/scripts/unmount_all /tmp/

export G_SLICE=always-malloc
export G_DEBUG=gc-friendly,resident-modules valgrind

./src/pronghorn/pronghorn -o general.install_dir=$installdir -o general.config_directory=./config/ -o general.logserver_executable=./src/logserver/logserver -o general.mcp_executable=./src/scripts/donothing.sh -o general.log_verbosity=DEBUG -o general.fuse_sub_dir=fuse_mp -o general.rawmount_executable=./src/rawmount/rawmount -o general.contractor_executable=./src/contractor/contractor -o general.fusermount_executable=/bin/fusermount -o general.unmount_all_script=./src/scripts/unmount_all $@

