/* Libpronghorn Transport Mechanism
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

/**
 * \file transport.h
 * \brief Libpronghorn transport mechanism
 *
 * This provides the transport we use in pronghorn to send and receive
 * messages between processes.
 */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <glib.h>

/** The transport reference. */
typedef struct transport* transport_t;

/** Specifies a send-then-receive type ZMQ socket */
#define TRANSPORT_TYPE_PUSHPULL 1
/** Specifies a receive-then-send type ZMQ socket */
#define TRANSPORT_TYPE_PULLPUSH 2
/** Specifies a one way send type ZMQ socket */
#define TRANSPORT_TYPE_PUSH 3
/** Specifies a one way receive type ZMQ socket */
#define TRANSPORT_TYPE_PULL 4

/**
 * Initializing the transport layer. Must be called once per transport layer.
 *
 * This must be called once per transport. 
 *
 * This is not thread safe!
 *
 * It returns a transport reference on success or NULL on error.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * ENOMEM - Insufficient memory to create the transport reference.
 * EINVAL - The provided transport type is invalid, or the provided server address is invalid.
 * EMFILE - The limit on the total number of sockets has been reached.
 * EPROTONOSUPPORT - The requested transport protocol is not supported.
 * ENOCOMPATPROTO - The requested transport protocol is not compatible with the socket type.
 * EADDRINUSE - The requested address is already in use.
 * EADDRNOTAVAIL - The requested address was not local.
 * ENODEV - The requested address specifies a nonexistent interface.
 * EMTHREAD - No I/O thread is available to accomplish the task.
 * 
 * \param type the transport type. One of TRANSPORT_TYPE_{PUSHPULL,PULLPUSH,PUSH,PULL}
 * \param endpoint_address the address used to connect to the server
 * \return a transport_t reference or NULL to indicate an error
 */
transport_t transport_init(unsigned int type, const char *const endpoint_address) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sets the transmission timeout for the socket.
 *
 * \param transport The transport reference
 * \param milliseconds The amount of time to attempt to deliver each message before giving up.
 * \returns 0 on success, -1 on error
 */
int transport_set_send_timeout(transport_t transport, int milliseconds);

/**
 * Sets the receive timeout for the socket.
 *
 * \param transport The transport reference
 * \param milliseconds The amount of time to wait for each message before giving up.
 * \returns 0 on success, -1 on error
 */
int transport_set_recv_timeout(transport_t transport, long milliseconds);

/**
 * Sends a message to a remote endpoint.
 *
 * The tx_data is a NULL terminated string. It is the responsibility of the 
 * caller to ensure memory is managed accordingly (it will not free tx_data)
 *
 * tx_data_size is the size of tx_data in bytes.
 *
 * It returns 0 on success or -1 on error.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EINVAL - The transport reference is invalid.
 * ENOMEM - Insufficient storate space is available.
 * ENOTSUP - The send operation is not supported by this socket type.
 * EFSM - The operation cannot be performed at the moment due to the socket not being in the appropriate state
 * EINTR - The operation was interrupted by a signal before the message was sent.
 *
 * \param transport the transport reference returned by transport_init
 * \param tx_data the message to send to the remote endpoint
 * \param pid An atomic int that represents whether the process is still alive. Is checked for >= 0. (May be null)
 * \param tx_data_size the size of tx_data in bytes
 * \return 0 on success, -1 on error. errno is set.
 * \todo This should probably be a G_GNUC_WARN_UNUSED_RESULT 
 */
int transport_send(transport_t transport, const char *const tx_data, volatile sig_atomic_t * pid, unsigned int tx_data_size);

/**
 * Receives a message from a remote endpoint.
 *
 * \warning DO NOT free the returned buffer.
 *
 * In the event of an error NULL is returned and errno is set to one of the following values.
 *
 * EINVAL - The transport reference is invalid.\n
 * ENOMEM - Insufficient storate space is available.\n
 * ENOSUP - The recv operation is not supported by this socket type.\n
 * EFSM - The operation cannot be performed at the moment due to the socket not being in the appropriate state\n
 * EINTR - The operation was interrupted by a signal before the message was sent.\n
 *
 * \param transport The transport reference returned by transport_init
 * \param pid An atomic int that represents whether the process is still alive. Is checked for >= 0. (May be null)
 * \param rx_data_size will be populated with the size of the buffer returned in bytes
 * \return The buffer received, or NULL on error.
 */
const char *transport_recv(transport_t transport, volatile sig_atomic_t * pid, unsigned int *rx_data_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sends and receives a message with a remote endpoint.
 *
 * \warning DO NOT free the returned buffer.
 *
 * In the event of an error NULL is returned and errno is set to one of the following values:
 *
 * - EINVAL - The transport reference is invalid.\n
 * - ENOMEM - Insufficient storate space is available.\n
 * - ENOSUP - The recv operation is not supported by this socket type.\n
 * - EFSM - The operation cannot be performed at the moment due to the socket 
 * not being in the appropriate state\n
 * - EINTR - The operation was interrupted by a signal before the message was sent.
 *
 * \param transport The transport reference
 * \param tx_data The message to send to the remote endpoint
 * \param tx_data_size The size of the buffer to send
 * \param pid An atomic int that represents whether the process is still alive. Is checked for >= 0. (May be null)
 * \param rx_data_size Returns the size of the received buffer
 * \return The buffer received, or NULL on error.
 */
const char *transport_sendrecv(transport_t transport, const char *const tx_data, unsigned int tx_data_size, volatile sig_atomic_t * pid, unsigned int *rx_data_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Closes the transport layer.
 *
 * This must be called once for every successful call of transport_init.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EINVAL - The transport reference is invalid.
 *
 * \param transport the transport reference to close
 * \return 0 on success, -1 on error. errno is set.
 */
int transport_close(transport_t transport);

#endif // TRANSPORT_H
