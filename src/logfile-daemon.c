#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/param.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

/* parse buffer - ie, length of longest expected line */
#define	LOGFILE_BUF_LEN		65536

int do_flush = 0;

static void
signal_alarm(int unused)
{
    do_flush = 1;
}

static void
rotate(const char *path, int rotate_count)
{
#ifdef S_ISREG
    struct stat sb;
#endif
    int i;
    char from[MAXPATHLEN];
    char to[MAXPATHLEN];
    assert(path);
#ifdef S_ISREG
    if (stat(path, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif
    /* Rotate numbers 0 through N up one */
    for (i = rotate_count; i > 1;) {
	i--;
	snprintf(from, MAXPATHLEN, "%s.%d", path, i - 1);
	snprintf(to, MAXPATHLEN, "%s.%d", path, i);
	rename(from, to);
    }
    if (rotate_count > 0) {
	snprintf(to, MAXPATHLEN, "%s.%d", path, 0);
	rename(path, to);
    }
}

/*
 * The commands:
 *
 * L<data>\n - logfile data
 * R\n - rotate file
 * T\n - truncate file
 * O\n - repoen file
 * r<n>\n - set rotate count to <n>
 * b<n>\n - 1 = buffer output, 0 = don't buffer output
 */
int
main(int argc, char *argv[])
{
    int t;
    FILE *fp;
    char buf[LOGFILE_BUF_LEN];
    int rotate_count = 10;
    int do_buffer = 0;

    /* Try flushing to disk every second */
    signal(SIGALRM, signal_alarm);
    ualarm(1000000, 1000000);

    if (argc < 2) {
	printf("Error: usage: %s <logfile>\n", argv[0]);
	exit(1);
    }
    fp = fopen(argv[1], "a");
    if (fp == NULL) {
	perror("fopen");
	exit(1);
    }
    setbuf(stdout, NULL);
    close(2);
    t = open("/dev/null", O_RDWR);
    assert(t > -1);
    dup2(t, 2);

    while (fgets(buf, LOGFILE_BUF_LEN, stdin)) {
	/* First byte indicates what we're logging! */
	switch (buf[0]) {
	case 'L':
	    if (buf[1] != '\0') {
		fprintf(fp, "%s", buf + 1);
	    }
	    break;
	case 'R':
	    fclose(fp);
	    rotate(argv[1], rotate_count);
	    fp = fopen(argv[1], "a");
	    if (fp == NULL) {
		perror("fopen");
		exit(1);
	    }
	    break;
	case 'T':
	    break;
	case 'O':
	    break;
	case 'r':
	    //fprintf(fp, "SET ROTATE: %s\n", buf + 1);
	    rotate_count = atoi(buf + 1);
	    break;
	case 'b':
	    //fprintf(fp, "SET BUFFERED: %s\n", buf + 1);
	    do_buffer = (buf[1] == '1');
	    break;
	default:
	    /* Just in case .. */
	    fprintf(fp, "%s", buf);
	    break;
	}

	if (do_flush) {
	    do_flush = 0;
	    if (do_buffer == 0)
		fflush(fp);
	}
    }
    fclose(fp);
    fp = NULL;
    exit(0);
}
