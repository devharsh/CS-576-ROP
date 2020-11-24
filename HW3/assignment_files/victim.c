#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

struct sockaddr_un *local;

static void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static int socket_create()
{
	int sd;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0)
		die("cannot create socket");

	local->sun_family = AF_UNIX;
	strcpy(local->sun_path, getenv("HOME"));
	strcat(local->sun_path, "/victim.sock");
	unlink(local->sun_path);
	if (bind(sd, (struct sockaddr *)local, 
				sizeof(struct sockaddr_un)) != 0) 
		die("bind failed");

	if (listen(sd, 5) != 0)
		die("listen failed");
	return sd;
}

static void socket_destroy(int sd)
{
	close(sd);
	unlink(local->sun_path);
}

static void heartbeat_respond(int sd, char *str, int len)
{
	char heartbeat[16], *c, *h;

	for (c = str, h = heartbeat; *c != '\n'; h++, c++)
		*h = *c;
	write(sd, heartbeat, len);
}

static void do_client(int sd)
{
	int len;
	char sbuf[512], *str, lbuf[32], *len_s;
	FILE *fl;

	fl = fdopen(sd, "rb+");
	if (!fl) {
		perror("opening FILE interface for socket failed");
		return;
	}

	while (1) {
		if ((str = fgets(sbuf, sizeof(sbuf), fl)) == NULL)
			break;
		if ((len_s = fgets(lbuf, sizeof(lbuf), fl)) == NULL)
			break;

		len = atoi(len_s);
		heartbeat_respond(sd, str, len);
	}
}

int main(int argc, const char **argv)
{
	int serv_sd, cli_sd;
	socklen_t slen;
	struct sockaddr_un remote;

	local = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (local == MAP_FAILED)
		die("mmap failed");
	
	serv_sd  = socket_create();

	if (mprotect(local, 4096, PROT_READ) != 0)
		die("mprotect failed");

	while (1) {
		cli_sd = accept(serv_sd, (struct sockaddr *)&remote, &slen);
		if (cli_sd < 0) {
			perror("accepting socket failed");
			break;
		}
		do_client(cli_sd);
		close(cli_sd);
	}

	socket_destroy(serv_sd);
	return 0xc35a; /* A gift */
}
