
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>

/*
* To change the process title in Linux and Solaris we have to set argv[1]
* to NULL and to copy the title to the same place where the argv[0] points to.
* However, argv[0] may be too small to hold a new title.  Fortunately, Linux
* and Solaris store argv[] and environ[] one after another.  So we should
* ensure that is the continuous memory and then we allocate the new memory
* for environ[] and copy it.  After this we could use the memory starting
* from argv[0] for our process title.
*
* The Solaris's standard /bin/ps does not show the changed process title.
* You have to use "/usr/ucb/ps -w" instead.  Besides, the UCB ps does not
* show a new title if its length less than the origin command line length.
* To avoid it we append to a new title the origin command line in the
* parenthesis.
*/

extern char **environ;

static char *ngx_os_argv_last;

static std::vector<unsigned char> alloc_new_env_block;

static char** ngx_os_argv;

void ngx_init_setproctitle(char* _ngx_os_argv[])
{
	unsigned char *p;
	size_t        size;
	unsigned int  i;

	size = 0;

	for (i = 0; environ[i]; i++)
	{
		size += std::strlen(environ[i]) + 1;
	}

	ngx_os_argv = _ngx_os_argv;
	alloc_new_env_block.resize(size);
	p = &alloc_new_env_block[0];

	ngx_os_argv_last = ngx_os_argv[0];

	for (i = 0; ngx_os_argv[i]; i++)
	{
		if (ngx_os_argv_last == ngx_os_argv[i])
		{
			ngx_os_argv_last = ngx_os_argv[i] + std::strlen(ngx_os_argv[i]) + 1;
		}
	}

	for (i = 0; environ[i]; i++)
	{
		if (ngx_os_argv_last == environ[i])
		{

			size = std::strlen(environ[i]) + 1;
			ngx_os_argv_last = environ[i] + size;

			std::memmove(p, (unsigned char *)environ[i], size);
			environ[i] = (char *)p;
			p += size;
		}
	}

	ngx_os_argv_last--;

}

void ngx_setproctitle(const char *title)
{
	unsigned char     *p;

#ifdef NGX_SOLARIS

	ngx_int_t   i;
	size_t      size;

#endif

	ngx_os_argv[1] = NULL;

	p = (decltype(p)) std::memmove((unsigned char *)ngx_os_argv[0], (unsigned char *)title,
		ngx_os_argv_last - ngx_os_argv[0]);

#ifdef NGX_SOLARIS

	size = 0;

	for (i = 0; i < ngx_argc; i++) {
		size += ngx_strlen(ngx_argv[i]) + 1;
	}

	if (size >(size_t) ((char *)p - ngx_os_argv[0])) {

		/*
		* ngx_setproctitle() is too rare operation so we use
		* the non-optimized copies
		*/

		p = ngx_cpystrn(p, (unsigned char *) " (", ngx_os_argv_last - (char *)p);

		for (i = 0; i < ngx_argc; i++) {
			p = ngx_cpystrn(p, (unsigned char *)ngx_argv[i],
				ngx_os_argv_last - (char *)p);
			p = ngx_cpystrn(p, (unsigned char *) " ", ngx_os_argv_last - (char *)p);
		}

		if (*(p - 1) == ' ') {
			*(p - 1) = ')';
		}
	}

#endif

	if (ngx_os_argv_last - (char *)p) {
		std::memset(p, ' ', ngx_os_argv_last - (char *)p);
	}

// 	ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
// 		"setproctitle: \"%s\"", ngx_os_argv[0]);
}
