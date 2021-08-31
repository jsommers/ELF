# Cloudlab setup instructions

 - instantiate 1 note with `exptscripts/cloudlab_profile.py` (or just get 1 host installed with ubuntu 18.04)
 - upload `exptscripts/cloudlab_setup.sh` and run it; this will install necessary software, including building current bcc from github.com/iovisor/bcc.  This will take a little while.  It is expected that the `cloudlab_setup.sh` script will be run from the home directory, but that isn't strictly necessary.
 - clone ELF (this) repo
 - upload `exptscripts/run_tests_cloudlab.sh` and edit constants at the top of the script appropriately.  It is expected that this script will be in the parent directory for wherever the `someta` code exists.  Note that `someta` isn't strictly necessary to use; we used it to capture ambient system performance measures to better assess tool performance, etc.

>> You should be able to execute `./run_tests_cloudlab.sh`.  It will launch a series of ndt streams and collect inband hop-by-hop measurements using ebpf.

**NOTE:** the command-line `ndt` client has changed behavior somewhat, so the `run_tests_cloudlab.sh` script will likely _not_ work out of the box anymore.  We will update as time permits.

# Analyzing data

Run `print_table.py` on the resulting `.csv` file.
