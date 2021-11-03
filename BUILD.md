PREREQUISITES
-------------
TIFAnet is designed to take the least amount of dependencies necessary.
This is not so much NIH syndrome as it is to keep the code simple and
maintainable.

There is just one library - except from the usual suspects - required
by TIFAnet: libsodium >= 1.0.16.

For e.g. Debian and Ubuntu, this means
	apt install libsodium23 libsodium-dev

For e.g. RedHat,  tihs means
	yum install libsodium-devel

For e.g. FreeBSD, this means
	pkg install libsodium

BUILD
-----
When the dependencies are installed, issue a

	make

in the TIFAnet source directory. Export the CC and LD environment variables
if you want to use some compiler other than cc. Export CFLAGS or LDFLAGS
to specify compiler and linker options.
Export DESTDIR to install to some other base directory than /usr/local .

INSTALL
-------
Install TIFAnet using

	make install

This will install the tifa command line tool, the tifanetd daemon and
the manual pages.
