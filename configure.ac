AC_INIT(py-blkid, 1.0)

AC_LANG(C)
AC_PROG_CC


define(SECTION_TITLE,
[
	echo >& AS_MESSAGE_FD
	echo '   $1   ' | sed -e's/./-/g' >&AS_MESSAGE_FD
	echo '   $1' >& AS_MESSAGE_FD
	echo '   $1   ' | sed -e's/./-/g' >&AS_MESSAGE_FD
])


dnl works for checking define statements in c
m4_include([m4/AX_CHECK_DEFINE.m4])

LDFLAGS="-l :libblkid.so.1"



blkid_source="/usr/include/blkid"

if [[ ! -d $blkid_source ]]; then
	AC_MSG_NOTICE([Unable to locate $blkid_source directory])
else
	CFLAGS="${CFLAGS} -I$blkid_source"
fi

SECTION_TITLE([RUNNING TESTS ON blkid.h HEADER])
AC_CHECK_HEADERS([sys/types.h], [], [AC_ERROR([A working sys/types header is required])])
AC_CHECK_HEADERS([stdint.h], [], [AC_ERROR([A working stdint header is required])])
AC_CHECK_HEADERS([blkid.h], [], [AC_ERROR([A working blkid header is required])],[
	#include <stdint.h>
	#include <sys/types.h>
])

SECTION_TITLE([GENERATING config.py])

AC_CONFIG_FILES([config.py])
AC_MSG_NOTICE([GENERATED config.py])

dnl Process Makefile.in to create Makefile
AC_OUTPUT(Makefile)
