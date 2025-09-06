/* Copyright (C) 2025 etaHEN / LightningMods

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include "common_utils.h"


// Start of Discord RPC server block
int sceSystemServiceGetAppIdOfRunningBigApp(void);
int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
// Function to write to socket
int writeToSocket(int client_socket, const char *message)
{
	return send(client_socket, message, strlen(message), MSG_NOSIGNAL);
}

void *startDiscordRpcServer(void* unused)
{
	(void)unused;
	int server_fd, client_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("[RPC] Socket failed");
		return NULL;
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
	{
		perror("[RPC] Setsockopt failed");
		return NULL;
	}
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(8000);

	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(server_fd, 3) < 0)
	{
		perror("[RPC] Bind or listen failed.");
		return NULL;
	}

	notify(true, "Discord RPC server listening on port: 8000");

	while (true)
	{
		struct pollfd fds[1];
		fds[0].fd = server_fd;
		fds[0].events = POLLIN;

		int activity = poll(fds, 1, 5000); // Wait for 5 seconds before timeout

		if (activity < 0)
		{
			perror("[RPC] Poll failed.");
			return NULL;
		}

		if (fds[0].revents & POLLIN)
		{
			if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
			{
				perror("[RPC] Accept failed.");
				break;
			}

			notify(true, "[RPC] New connection accepted\n");

			while (true)
			{
				char tid[255];
				int bigAppId = sceSystemServiceGetAppIdOfRunningBigApp();

				if (bigAppId < 0)
				{ // bigAppId < 0 means no bigApp is running.
					if (writeToSocket(client_socket, "No game running.\n") <= 0)
					{
						close(client_socket);
						break;
					}
					usleep(10000000); // Sleep for 10 seconds
					continue;
				}

				(void)memset(tid, 0, sizeof(tid));

				if (sceSystemServiceGetAppTitleId(bigAppId, &tid[0]) != 0)
				{
					if (writeToSocket(client_socket, "Failed to get title ID.\n") <= 0)
					{
						close(client_socket);
						break;
					}
					usleep(10000000); // Sleep for 10 seconds
					continue;
				}

				strcat(tid, "\n"); // Append newline to tid
				if (writeToSocket(client_socket, tid) <= 0)
				{
					close(client_socket);
					break;
				}

				usleep(10000000); // Sleep for 10 seconds
			}
		}
	}

	close(server_fd);
	return NULL;
}
