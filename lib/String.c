
#include "config.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#include "util.h"

String *
stringCreate(size_t len)
{
	String *s = xcalloc(1, sizeof(String));
	s->buf = xcalloc(1, s->len = len);
	return s;
}

void
stringAppend(String *s, const char *buf, size_t len)
{
	assert(s->buf != NULL);
	if (len + s->off >= s->len) {
		char *old = s->buf;
		do {
			assert(s->len != 0);
			s->len <<= 1;
	        } while (len + s->off >= s->len);
		s->buf = xcalloc(1, s->len);
		xstrncpy(s->buf, old, s->len);
		xfree(old);
	}
	xstrncpy(s->buf + s->off, buf, s->len - s->off);
	s->off += len;
}

void
stringFree(String *s)
{
	xfree(s->buf);
	xfree(s);
}
