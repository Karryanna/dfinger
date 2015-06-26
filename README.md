Distributed finger (dfinger)
============================

Name
----

Distributed finger -- finger-like utility designed to share data among several machines

Description
-----------

Distributed finger is a utility designed to share info about logged users among several
machines connected via network. It has server part and client part (though both run via
the same command).

Server part logs information about all user login sessions while client part feeds the
server with information about sessions on specific machine.

Server part can then provide clients with information about those sessions, including
queries concerning specific user or specific host machine. Those information are provided
via protocol heavily based on finger protocol (RFC 1288).

Information protocol
--------------------

As stated above, the information protocol which server uses to provide information
about current and past login sessions is heavily based on finger protocol (RFC 1288).
However please keep in mind that this implementation is NOT compliant with finger protocol,
not even conditionally.

The most notable difference is handling of {Q2} queries, that is queries with hostname
specified. If just one at-sign (@) is found in query, the query is understood as query
about logins (either of all users or user specified before that sign) and is served by
the server itself, without forwarding the query to specified host.

Options
-------

Dfinger program doesn't accept much options, it's mostly configured by editing
configuration file. The only supported option is name of configuration file which
should be used.

Exit status
-----------

Dfinger may return one of several error codes if it encounters problems.

* 0	No problem, dfinger exited normally.
* 1	Generic error code
* 2	Error while parsing configuration file
* 47	Could not allocate memory

Files
-----

* config	Default name of configuration file

Bugs
----

There are no known bugs yet which probably means the program still hasn't been tested
extensively enough.

Bug submissions are welcome at e-mail <karry@karryanna.cz>

Author
------

Written by Karryanna <karry@karryanna.cz>, based on idea of Martin Mareš <mj@ucw.cz>.
