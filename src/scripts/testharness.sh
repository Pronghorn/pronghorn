#!/bin/bash

cd `dirname $0`
scriptdir=`pwd`
cd ../..
installdir=`pwd`

echo "Install dir is $installdir"
echo "Script dir is $scriptdir"

die () {
    #echo >&2 "$@"
		echo "At least two arguments (input_file sub_contractor_to_use) required"
		echo "Usage:"
		echo "`basename $0` input_file subcontractor_to_use [-o group.option=value -o group2.option2=value2 ... ]" 
		echo ""
		echo "Example:"
		echo "`basename $0` ./tmp/somefile.dd ./src/subcontractors/development_and_testing/subcontractor_template -o general.log_verbosity=DEBUG"
		echo ""
    exit 1
}

[ "$#" -gt 0 ] || die 

input_file=$1
sub=$2
shift
shift


$scriptdir/unmount_all /tmp

export G_SLICE=always-malloc
export G_DEBUG=gc-friendly,resident-modules valgrind

$installdir/src/pronghorn/pronghorn -o general.install_dir=$installdir -o general.config_directory=$installdir/config/ -o general.logserver_executable=$installdir/src/logserver/logserver -o general.mcp_executable=$installdir/src/subcontractors/development_and_testing/test_harness -o general.test_harness_subcontractor=$sub -o general.log_verbosity=DEBUG -o general.input_file=$input_file -o general.fuse_sub_dir=fuse_mp -o general.rawmount_executable=$installdir/src/rawmount/rawmount -o general.contractor_executable=$installdir/src/contractor/contractor $@

