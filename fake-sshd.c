/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *       $Id: fake-sshd.c,v 1.9 2012/01/25 09:07:44 james.stevenson Exp $
 *
 * Author:
 *       NAME:   James Stevenson
 *       WWW:    http://www.stev.org
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <time.h>

int use_syslog = 0;
int verbose = 0;

void logger(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	printf("\n");

	if (use_syslog)
		vsyslog(LOG_NOTICE, fmt, ap);
 
	va_end(ap);
}

void handle_sigchild(int signum) {
	int status = -1;
	int pid = 0;

	do {
		int pid = waitpid(-1, &status, WNOHANG);
		if (verbose > 0)
			logger("Process %d Exited", pid);
	} while(pid > 0);
}

void print_help(FILE *fp, char *app) {

	fprintf(fp, "Usage: %s [<options>]\n", app);
	fprintf(fp, "\n");
	fprintf(fp, "\t-a	<secs>	Failed Auth delay\n");
	fprintf(fp, "\t-b	<str>	Set the banner\n");
	fprintf(fp, "\t-h		Print this help and exit\n");
	fprintf(fp, "\t-m	<n>		Max attempts per connection\n");
	fprintf(fp, "\t-p	<port>	Port to listen on\n");
	fprintf(fp, "\t-r	<file>	Path to rsa key\n");
	fprintf(fp, "\t-d	<file>	Path to dsa key\n");
	fprintf(fp, "\t-s		Log to syslog\n");
	fprintf(fp, "\t-t	<secs>	Timeout\n");
	fprintf(fp, "\t-v		Verbose. Repeat for more info\n");
	fprintf(fp, "\t-w	<secs>	Delay after connection\n");
	fprintf(fp, "\t-z		Multiple Delay by 2 each failure\n");
	fprintf(fp, "\n");
}

int main(int argc, char **argv) {
	ssh_bind sshbind;
	ssh_session session;
	int r = -1;
	int auth = 0;
	int c;
	int delay = 0;
	char *port = "22";
	char *dsakey = "/home/james/etc/ssh/ssh_host_dsa_key";
	char *rsakey = "/home/james/etc/ssh/ssh_host_rsa_key";
	char *banner = 0;
	int timeout = 0;
	int authdelay = 0;
	int doubledelay = 0;
	int maxfail = 0;

	while( (c = getopt(argc, argv, "a:b:hm:p:r:d:st:vw:z")) != -1) {
		switch(c) {
			case 'a':
				authdelay = atoi(optarg);
				break;
			case 'b':
				banner = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'h':
				print_help(stdout, argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case 'm':
				maxfail = atoi(optarg);
				break;
			case 'r':
				rsakey = optarg;
				break;
			case 'd':
				dsakey = optarg;
				break;
			case 's':
				use_syslog = 1;
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			case 'v':
				verbose++;
				break;
			case 'w':
				delay = atoi(optarg);
				break;
			case 'z':
				doubledelay = 1;
				break;
			default:
				break;
		}
	}

	if (dsakey == NULL) {
		if (access("/etc/ssh/ssh_host_rsa_key", R_OK) == 0)
			rsakey = "/etc/ssh/ssh_host_rsa_key";
	}

	if (rsakey == NULL) {
		if (access("/etc/ssh/ssh_host_dsa_key", R_OK) == 0)
			dsakey = "/etc/ssh/ssh_host_dsa_key";
	}

	if (rsakey == NULL || dsakey == NULL) {
		print_help(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	sshbind = ssh_bind_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, port);

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, dsakey);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, rsakey);

	if (banner != NULL)
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, banner);

	if (ssh_bind_listen(sshbind) < 0) {
		logger("Error listening to socket: %s", ssh_get_error(sshbind));
		exit(EXIT_FAILURE);
	}

	signal(SIGCHLD, &handle_sigchild);

restart:
	session = ssh_new();

	if (timeout > 0)
		ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

	r = ssh_bind_accept(sshbind, session);

	if (r == SSH_ERROR) {
		logger("Error accepting connection: %s", ssh_get_error(sshbind));
		goto restart;
	}

	int ret = fork();

	if (fork < 0) {
		logger("fork: %s", strerror(errno));
		logger("exiting ...");
		exit(EXIT_FAILURE);
	}
	
	int sockfd = ssh_get_fd(session); 
	struct sockaddr_in peer;
	socklen_t peer_len = sizeof(peer);
	char *peername = 0;
	int attempts = 0;

	if (ret > 0) {
		if (verbose > 0)
			logger("Started Process %d", ret);
		ssh_free(session);
		goto restart;
	}

	ret = getpeername(sockfd, (struct sockaddr *) &peer, &peer_len);
	peername = inet_ntoa(peer.sin_addr);
	logger("Connection From %s:%d", peername, peer.sin_port);

	if (ssh_handle_key_exchange(session)) {
		logger("ssh_handle_key_exchange: %s", ssh_get_error(session));
		goto error;
	}

	do {
		ssh_message message = ssh_message_get(session);
		if (message == NULL)
			break;

		switch(ssh_message_type(message)) {
			case SSH_REQUEST_AUTH:
				switch(ssh_message_subtype(message)) {
					case SSH_AUTH_METHOD_PASSWORD:
						attempts++;
						time_t timer;
					    char t_buffer[26];
					    struct tm* tm_info;
					    time(&timer);
					    tm_info = localtime(&timer);
					    strftime(t_buffer, 26, "%Y-%m-%dT%H:%M:%S%z", tm_info);
						logger("TIME: %s, IP: %s USER: %s PASS: %s", t_buffer, peername, ssh_message_auth_user(message), ssh_message_auth_password(message));
						if (authdelay > 0)
							sleep(authdelay);
						if (doubledelay)
							authdelay *= 2;
						if (attempts > maxfail) {
							if (verbose > 1)
								logger("Max failures reached");
							ssh_message_free(message);
							goto error;
						}
					case SSH_AUTH_METHOD_NONE:
						if (verbose > 1)
							logger("AUTH_METHOD_NONE Requested");
						// break missing on purpose
					default:
						if (verbose > 1)
							logger("REQUEST_AUTH: %d", ssh_message_subtype(message));
						ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
						ssh_message_reply_default(message);
						break;
				}
				break;
			default:
				if (verbose > 0)
					logger("Message Type: %d", ssh_message_type(message));
				ssh_message_reply_default(message);
				break;
		}
		ssh_message_free(message);
	} while(auth == 0);

error:
	ssh_disconnect(session);
	ssh_free(session);
	ssh_bind_free(sshbind);
	logger("Connection Closed From %s", peername);

	return 0;
}

