clearcutter
===========

A Log Manipulation and Parsing tool for SIEM users

Clearcutter is designed to automate some of the more common SIEM and log analysis tasks encountered when dealing with previously unseen log files or samples.

* Identifying unique message types (syntax) within a log sample
** Identifying common data fields (IP addresses, hostnames) within a particular log message syntax

As a tool primarily written to support the development of log parser plugins for OSSIM, it also supports

* Syntax checking and identifying of common typos in OSSIM plugins
* Profiling and dry-run testing of a plugin against a log sample to identify matches
* Performance profiling of a plugin's regular expressions (both on a per-rule basis, and on 'real world' performance testing against log samples
 
