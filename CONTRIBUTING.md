CONTRIBUTING
------------
The TIFAnet dev team welcomes contributions! Patches need to:

- WORK
- be well thought out
- adhere to the same coding style as the rest of TIFAnet, so including
  but not limited to:
  * tab to indent
  * use a space after control flow operators such as if, switch, return
  * use correctly typed iterator variables in e.g. 'for' loops, so NO int
  * do NOT use a space before or after parentheses for function calls
  * do use spaces after commas in a function call's argument list
  * always use parentheses around return values

And now for some other general considerations.

Don't integrate configure/autoconf. Submitting patches to do so will
result in a perma-ban for you. TIFAnet really is simple enough to be
handled with just the Makefile . Configure was somewhat useful back when
the unix world was much more diverse than now (but not really since even back
in 1999 it suffered from breakage when using it on non-Linux platforms).
Being smart about the variable types you use and how you use them negates the
need for all that minutes-long useless probing configure does for you.
Also, if you edit the Makefile, make sure it works with BSD make as well as
GNU make. By the way: this is really easy for a project this size.

Don't use C++ . If you're afraid of C for loops or malloc and free, you had
better contribute to another project. In C++, some things are simpler. Other
things more difficult. Binary size definately larger. For this project,
code might be marginally simpler if implemented with C++, but not enough
to warrant the added complexity of the language.

Really, really, really think through adding one or more library dependencies.
Will the code really benefit from it? How many lines will it save, i.e. will
code complexity really go down enough?
Example: libsodium provides convenient functions for both hashing and
encryption, both of which, but especially encryption are very specialized
fields where one trivial mistake can break encryption security entirely.
It was better to link to it than roll our own.
Example: libuv provides a wrapper around asynchronous I/O for several systems.
But one still has to handle reading and writing blocks from and to the
sockets, and handle any kind of unexpected state in the client/server state
machine. Code size in event.c and network.c would have been reduced using
libuv, but the project wouldn't have really benefitted much more than reduced
debugging time to get the asynchronous communication stable. Besides, any
project which stems from getting JavaScript to run on a wider variety of
environments is simply bad taste and should be avoided.
