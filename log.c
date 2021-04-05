/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2018, Mitsumete Ishikawa
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdarg.h>
#ifdef __linux__
#  include <time.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include "config.h"
#include "log.h"

static FILE *__logfile = NULL;
uint8_t loglevel = 1;

void
openlog()
{
	char file[MAXPATHLEN + 1];

	if (!__logfile)
		__logfile = fopen(config_path(file, "tifanetd.log"), "a+");
}

void
lprintf(const char *fmt, ...)
{
	FILE *l;
	va_list args;
	struct tm *info;
	struct timeval tv;
	char tmbuf[30];

	if (!loglevel)
		return;

	l = __logfile ? __logfile : stderr;

	gettimeofday(&tv, NULL);
	info = localtime(&tv.tv_sec);
	strftime(tmbuf, 30, "%Y-%m-%d %H:%M:%S", info);
	fprintf(l, "[%s.%03ld] ", tmbuf, tv.tv_usec / 1000);

	va_start(args, fmt);

	vfprintf(l, fmt, args);

	va_end(args);

	fprintf(l, "\n");
	fflush(l);
}
