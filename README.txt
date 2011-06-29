dklab_logreplica: gathers logs from multiple machines into one place in realtime
(C) Dmitry Koterov, http://en.dklab.ru/lib/dklab_logreplica/
License: GPL

This simple, but very handy and powerful tool allows you to pull logs
from the whole cluster to a single logging server in realtime. These
logs may be used for monitoring, aggregation or analyzing.


SYNOPSIS
--------

1. Choose your logging server: it is a machine with root account and
   /opt/dklab_logreplica/ directory holding dklab_logreplica scripts.

2. Copy dklab_logreplica.init into /etc/init.d/dklab_logreplica and
   setup its automatical startup at server boot time.

3. Copy default config file dklab_logreplica.conf.sample to
   /etc/dklab_logreplica.conf and modify it according to your needs:
   - specify which host you want to pull the logs from,
   - what files to replicate (you may specify wildcards freely)
   - what destination directory is used to put the logs to.

4. Create SSH private-public key pair using "ssh-keygen -t rsa".
   Put public key to each of logs source machines using
   "ssh-copy-id root@machine-to-be-pulled" - you should have 
   access to all these machines from the log server without
   entering a password.

5. Now run /etc/init.d/dklab_logreplica
   After all that steps logs from source machines will be automatically
   and continuosly replicated to the log server in the background (with 
   support of reconnects and resumes if the connection is not stable). 
   You may monitor the activity at standard /var/log/messages file.
   No need to configure source machines - the single configuration
   point is dklab_logreplica.conf at your logging server.


THE PROBLEM WHICH IS SOLVED
---------------------------

If you have many machines in your cluster which performs different tasks 
(e.g. SQL server, web-frontend, balancer, mail server etc.), you may want 
to aggregate logs from all these machines in a single place to monitor them 
or preform various statistics collection. Of course you may configure 
syslog or syslog-ng to pass all the data over the network, but if you do
so, you are face to face with the following problems:

1. Due to network problems pieces of logs may not be correctly transfered,
   so you may loose data.
2. It is quite hard to keep the syslog configuration in sync with real
   world (which is changing time to time).
3. Not all services supports priting into syslog (e.g. apache supports
   only file-based logs writing). So you have to use named pipe, and your 
   configs grow.
4. Quite oftenly you want to replicate logs filenames by their wildcards
   specified. Syslog cannot do that.
5. At least, it is good to hold all logs at the machines at which they
   are produced (with e.g. weekly rotation) in addition to send them
   into a logging server. So your configs are growing again...

Dklab_logreplica solves all that problems.
