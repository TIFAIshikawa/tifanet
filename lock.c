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
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

#include "config.h"
#include "lock.h"
#include "log.h"

static int __lockfile_fd = -1;

int
lockfile_create(void)
{
	char file[MAXPATHLEN + 1];

	if (__lockfile_fd != -1)
		return (TRUE);

	if ((__lockfile_fd = open(config_path_r(file, ".lock"),
		O_CREAT | O_RDWR,
		0600)) == -1) {
		if (errno == EACCES)
			return (FALSE);

		FAIL(EX_TEMPFAIL, "open_lockfile: %s: %s", file,
			strerror(errno));
	}

	return (TRUE);
}

int
daemon_lock(void)
{
	return (lockf(__lockfile_fd, F_LOCK, 0) == 0 ? TRUE : FALSE);
}

int
daemon_unlock(void)
{
	return (lockf(__lockfile_fd, F_ULOCK, 0) == 0 ? TRUE : FALSE);
}

int
lockfile_is_locked(void)
{
	if (lockf(__lockfile_fd, F_TEST, 0) == -1)
		if (errno == EAGAIN || errno == EACCES)
			return (TRUE);

	return (FALSE);
}
