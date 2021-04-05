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

Some linux package managers install 1.0.8 libsodium headers even though
the package libsodium23 (1.0.16) is selected. In this case, either placing
the correct headers in /usr/include/sodium or building your own libsodium
1.0.16 is required to build TIFAnet.

BUILD
-----
When the dependencies are installed, issue a

	make

in the TIFAnet source directory. Export the CC and LD environment variables
if you want to use some compiler other than cc. Export CFLAGS or LDFLAGS
to specify compiler and linker options. For BSD, it is necessary to set
-I/usr/local/include and -L/usr/local/lib for the CFLAGS and LDFLAGS
variables respectively. Export DESTDIR to install to some other base directory
than /usr/local .

INSTALL
-------
Install TIFAnet using

	make install

This will install the tifa command line tool, the tifanetd daemon and
the manual pages.

On Linux, the base directory to install to usually is /usr , so this would
be appropriate:

	DESTDIR=/usr make install
