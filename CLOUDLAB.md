# Cloudlab setup instructions

 - instantiate 1 note with `cloudlab_profile.py` (or just get 1 host installed with ubuntu 18.04)
 - upload `cloudlab_setup.sh` and run it; this will install necessary software, including building current bcc from github.com/iovisor/bcc.  This will take a little while.  It is expected that the `cloudlab_setup.sh` script will be run from the home directory, but that isn't strictly necessary.
 - clone ebpf (this) repo
 - upload `run_tests_cloudlab.sh` and edit constants at the top of the script.  It is expected that this script will be in the parent directory for wherever the `someta_testapi` code exists.

You should be able to execute `./run_tests_cloudlab.sh`.  It will launch a series of ndt streams and collect inband hop-by-hop measurements using ebpf.

# Analyzing data

Run `print_table.py` on the resulting `.csv` file.
