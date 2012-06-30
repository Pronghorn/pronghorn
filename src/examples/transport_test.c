/* Pronghorn Transport Test
 * Copyright (C) 2012 Department of Defence Australia
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <stdio.h>
#include <string.h>

#include <transport.h>

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    printf("Usage: %s <endpoint>\n", argv[0]);
    return -1;
  }

  transport_t transport = transport_init(TRANSPORT_TYPE_PUSHPULL, argv[1]);

  if (transport == NULL)
  {
    perror("Creating transport");
    return -1;
  }

  char input_string[80];

  while (fgets(input_string, 79, stdin) != NULL)
  {
    char *ptr = strchr(input_string, '\n');

    if (ptr != NULL)
    {
      *ptr = '\0';
    }
    printf("Txed: %s\n", input_string);

    int recvsize;
    const char *recv = transport_sendrecv(transport, input_string, strlen(input_string) + 1, NULL, &recvsize);

    printf("Recv: %s\n", recv);
  }

  transport_close(transport);

  return 0;
}
