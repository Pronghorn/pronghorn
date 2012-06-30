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
 * \file transport.c
 * \brief Libpronghorn transport mechanism
 *
 * This provides the transport we use in pronghorn to send and receive
 * messages between processes.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <zmq.h>
#include <glib.h>

#include <prong_assert.h>

#include "transport.h"

/** The default timeout in seconds */
#define RECV_TIMEOUT_DEFAULT 10

/**
 * Holds the single open context for ZMQ.
 */
static void *context = NULL;

/**
 * Holds the number of open references to the ZMQ context.
 */
static unsigned int context_cnt = 0;

/**
 * A unique ID to identify a transport structure.
 * It's just four bytes taken from /dev/urandom
 */
static const int TRANSPORT_MAGIC = 0xCB22E9E4;

/**
 * The transport structure used to retain state.
 */
struct transport
{
        /** This magic value is used to correctly identify a transport structure. */
  int magic;
        /** Itentifies the type of socket created */
  int type;
        /** The ZMQ socket handle */
  void *socket;

        /** The input buffer */
  char *buf;
        /** The size of the input buffer */
  unsigned int buf_size;

        /** Holds the currently set receive timeout */
  unsigned int recv_timeout;

        /** Has the receieve timeout been explicity set by the user */
  unsigned long recv_timeout_isset;
};

/**
 * An internal helper function to help create a REQUEST socket.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EFAULT - The provided transport context is invalid.
 * EINVAL - The provided server address is invalid.
 * EMFILE - The limit on the total number of sockets has been reached.
 * ETERM - The transport context was closed.
 * EPROTONOSUPPORT - The requested transport protocol is not supported.
 * ENOCOMPATPROTO - The requested transport protocol is not compatible with the socket type.
 * EMTHREAD - No I/O thread is available to accomplish the task.
 *
 * \param t The transport structure.
 * \param server_address The ZMQ endpoint.
 * \returns 0 on success, -1 on error
 */
static int init_request(struct transport *t, const char *const server_address)
{
  t->socket = zmq_socket(context, ZMQ_REQ);
  if (t->socket == NULL)
  {
    prong_assert(errno != EINVAL);      // This should never occur.
    return -1;
  }

  if (zmq_connect(t->socket, server_address) < 0)
  {
    prong_assert(errno != ENOTSOCK);    // This should never occur.

    int olderrno = errno;

    zmq_close(t->socket);
    prong_assert(errno != ENOTSOCK);
    errno = olderrno;
    return -1;
  }

  return 0;
}

/**
 * An internal helper function to help create a REPLY socket.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EFAULT - The provided transport context is invalid.
 * EINVAL - The provided server address is invalid.
 * EMFILE - The limit on the total number of sockets has been reached.
 * ETERM - The transport context was closed.
 * EPROTONOSUPPORT - The requested transport protocol is not supported.
 * ENOCOMPATPROTO - The requested transport protocol is not compatible with the socket type.
 * EADDRINUSE - The requested address is already in use.
 * EADDRNOTAVAIL - The requested address was not local.
 * ENODEV - The requested address specifies a nonexistent interface.
 * EMTHREAD - No I/O thread is available to accomplish the task.
 *
 * \param t The transport structure.
 * \param server_address The ZMQ endpoint.
 * \returns 0 on success, -1 on error.
 */
static int init_reply(struct transport *t, const char *const server_address)
{
  t->socket = zmq_socket(context, ZMQ_REP);
  if (t->socket == NULL)
  {
    prong_assert(errno != EINVAL);      // This should never occur.
    return -1;
  }

  if (zmq_bind(t->socket, server_address) < 0)
  {
    prong_assert(errno != ENOTSOCK);    // This should never occur.

    int olderrno = errno;

    zmq_close(t->socket);
    prong_assert(errno != ENOTSOCK);
    errno = olderrno;
    return -1;
  }

  return 0;
}

/**
 * An internal helper function to help create a PUSH socket.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EFAULT - The provided transport context is invalid.
 * EINVAL - The provided server address is invalid.
 * EMFILE - The limit on the total number of sockets has been reached.
 * ETERM - The transport context was closed.
 * EPROTONOSUPPORT - The requested transport protocol is not supported.
 * ENOCOMPATPROTO - The requested transport protocol is not compatible with the socket type.
 * EADDRINUSE - The requested address is already in use.
 * EADDRNOTAVAIL - The requested address was not local.
 * ENODEV - The requested address specifies a nonexistent interface.
 * EMTHREAD - No I/O thread is available to accomplish the task.
 *
 * \param t The transport structure.
 * \param server_address The ZMQ endpoint.
 * \returns 0 on success, -1 on error.
 */
static int init_push(struct transport *t, const char *const server_address)
{
  t->socket = zmq_socket(context, ZMQ_PUSH);
  if (t->socket == NULL)
  {
    prong_assert(errno != EINVAL);      // This should never occur.
    return -1;
  }

  if (zmq_connect(t->socket, server_address) < 0)
  {
    prong_assert(errno != ENOTSOCK);    // This should never occur.

    int olderrno = errno;

    zmq_close(t->socket);
    prong_assert(errno != ENOTSOCK);
    errno = olderrno;
    return -1;
  }

  return 0;
}

/**
 * An internal helper function to help create a PULL socket.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EFAULT - The provided transport context is invalid.
 * EINVAL - The provided server address is invalid.
 * EMFILE - The limit on the total number of sockets has been reached.
 * ETERM - The transport context was closed.
 * EPROTONOSUPPORT - The requested transport protocol is not supported.
 * ENOCOMPATPROTO - The requested transport protocol is not compatible with the socket type.
 * EADDRINUSE - The requested address is already in use.
 * EADDRNOTAVAIL - The requested address was not local.
 * ENODEV - The requested address specifies a nonexistent interface.
 * EMTHREAD - No I/O thread is available to accomplish the task.
 *
 * \param t The transport structure.
 * \param server_address The ZMQ endpoint.
 * \returns 0 on success, -1 on error.
 */
static int init_pull(struct transport *t, const char *const server_address)
{
  t->socket = zmq_socket(context, ZMQ_PULL);
  if (t->socket == NULL)
  {
    prong_assert(errno != EINVAL);      // This should never occur.
    return -1;
  }

  if (zmq_bind(t->socket, server_address) < 0)
  {
    prong_assert(errno != ENOTSOCK);    // This should never occur.

    int olderrno = errno;

    zmq_close(t->socket);
    prong_assert(errno != ENOTSOCK);
    errno = olderrno;
    return -1;
  }

  return 0;
}

transport_t transport_init(const int type, const char *const server_address)
{
  struct transport *t = (struct transport *) g_malloc(sizeof(struct transport));

  t->magic = TRANSPORT_MAGIC;

  if (context_cnt == 0)
  {
    context = zmq_init(1);
    if (context == NULL)
    {
      prong_assert(errno != EINVAL);    // This should never happen
      g_free(t);
      return NULL;
    }
  }
  context_cnt++;

  int ret;

  switch (type)
  {
  case TRANSPORT_TYPE_PUSHPULL:
    ret = init_request(t, server_address);
    break;
  case TRANSPORT_TYPE_PULLPUSH:
    ret = init_reply(t, server_address);
    break;
  case TRANSPORT_TYPE_PULL:
    ret = init_pull(t, server_address);
    break;
  case TRANSPORT_TYPE_PUSH:
    ret = init_push(t, server_address);
    break;
  default:
    errno = EINVAL;
    ret = -1;
  }

  if (ret < 0)
  {
    prong_assert(errno != EFAULT);
    prong_assert(errno != ETERM);

    if (--context_cnt == 0)
    {
      int olderrno = errno;

      errno = 0;
      while ((zmq_term(context) < 0) && (errno == EINTR))
      {
        // Do nothing
      }
      prong_assert(errno != EFAULT);
      context = NULL;
      errno = olderrno;
    }

    g_free(t);
    return NULL;
  }

  t->type = type;
  t->buf = NULL;
  t->buf_size = 0;
  t->recv_timeout_isset = 0;
  t->recv_timeout = 0;
  return t;
}

/*
 * An internal helper function to help validate a transport reference.
 *
 * It takes a transport_t reference and converts it into a struct transport*
 * if it is valid.
 *
 * In the event of an error, errno is set to one of the following values.
 *
 * EINVAL - The transport reference is invalid.
 *
 * \param _t The transport reference
 * \returns a transport struct, or NULL on error
 */
inline static struct transport *validate(transport_t _t)
{
#ifndef DEBUG
  return (struct transport *) _t;
#endif

  if (_t == NULL)
  {
    errno = EINVAL;
    return NULL;
  }

  struct transport *t = (struct transport *) _t;

  if (t->magic != TRANSPORT_MAGIC)
  {
    errno = EINVAL;
    return NULL;
  }

  return t;
}


int transport_set_send_timeout(transport_t _t, int milliseconds)
{
  struct transport *t = validate(_t);

  if (t == NULL)
  {
    return -1;
  }

  if (zmq_setsockopt(t->socket, ZMQ_LINGER, &milliseconds, sizeof(milliseconds)) != 0)
  {
    fprintf(stderr, "zmq_setsockopt failed with error: %s\n", strerror(errno));
  }

  return 0;
}


int transport_set_recv_timeout(transport_t _t, long milliseconds)
{
  struct transport *t = validate(_t);

  if (t == NULL)
  {
    return -1;
  }

  t->recv_timeout_isset = 1;
  t->recv_timeout = milliseconds;

  return 0;
}

int transport_send(transport_t _t, const char *const tx_data, volatile sig_atomic_t * pid, const int tx_data_size)
{
  struct transport *t = validate(_t);

  if (t == NULL)
  {
    return -1;
  }
  // PULL types can never send
  if (t->type == TRANSPORT_TYPE_PULL)
  {
    errno = EINVAL;
    return -1;
  }

  zmq_msg_t message;

  if (zmq_msg_init_size(&message, tx_data_size) < 0)
  {
    return -1;
  }

  memcpy(zmq_msg_data(&message), tx_data, tx_data_size);

  int rc;

  do
  {
    rc = zmq_send(t->socket, &message, 0);
    // Retry if interrupted and pid is 'valid'
  }
  while ((rc == -1) && (errno == EINTR) && ((pid == NULL) || (*pid >= 0)));

  if (rc < 0)
  {
    prong_assert(errno != EAGAIN);
    prong_assert(errno != ETERM);
    prong_assert(errno != ENOTSOCK);
    prong_assert(errno != EFAULT);
  }
  int olderrno = errno;

  if (zmq_msg_close(&message) < 0)
  {
    prong_assert(errno != EFAULT);
  }

  errno = olderrno;

  return rc;
}

static int is_data_available(transport_t _t, long milliseconds)
{
  struct transport *t = validate(_t);

  if (t == NULL)
  {
    return -1;
  }

  zmq_pollitem_t item;

  item.socket = t->socket;
  item.events = ZMQ_POLLIN;

  int ret = zmq_poll(&item, 1, milliseconds * 1000);

  if (ret == -1)
  {
    return -1;
  }

  if (ret == 0)
  {
    // No items to read
    return 0;
  }

  return 1;
}

const char *transport_recv(transport_t _t, volatile sig_atomic_t * pid, int *rx_data_size)
{
  *rx_data_size = 0;

  struct transport *t = validate(_t);

  if (t == NULL)
  {
    return NULL;
  }
  // PUSH types can never recv
  if (t->type == TRANSPORT_TYPE_PUSH)
  {
    errno = EINVAL;
    return NULL;
  }
  // By default wait for RECV_TIMEOUT_DEFAULT seconds
  long timeout = (RECV_TIMEOUT_DEFAULT * 1000);

  if (t->recv_timeout_isset == 1)
  {
    timeout = t->recv_timeout;
  }

  int retval;

  do
  {
    retval = is_data_available(_t, timeout);
    // If we got interrupted, we retry. This should technically
    // only wait for the remainder of the timeout, but this should
    // be sufficient for our needs.
  }
  while ((retval == -1) && (errno == EINTR) && ((pid == NULL) || (*pid >= 0)));

  if (retval != 1)
  {
    if (errno == EINTR)
    {
      // Signal
    } else
    {
      errno = EAGAIN;
    }

    return NULL;
  }

  zmq_msg_t message;

  if (zmq_msg_init(&message) < 0)
  {
    // No errno values are defined??
    return NULL;
  }

  if (zmq_recv(t->socket, &message, 0) < 0)
  {
    prong_assert(errno != EAGAIN);
    prong_assert(errno != ETERM);
    prong_assert(errno != ENOTSOCK);
    prong_assert(errno != EFAULT);

    int olderrno = errno;

    if (zmq_msg_close(&message) < 0)
    {
      prong_assert(errno != ENOTSOCK);
    }
    errno = olderrno;
    return NULL;
  }
  int size = zmq_msg_size(&message);

  if ((size + 1) > t->buf_size)
  {
    g_free(t->buf);
    t->buf = (char *) g_malloc(size * 2);
    t->buf_size = size * 2;
  }
  memcpy(t->buf, zmq_msg_data(&message), size);
  if (zmq_msg_close(&message) < 0)
  {
    prong_assert(errno != ENOTSOCK);
  }
  *rx_data_size = size;
  t->buf[size] = 0;
  return t->buf;
}

const char *transport_sendrecv(transport_t _t, const char *const tx_data, const int tx_data_size, volatile sig_atomic_t * pid, int *rx_data_size)
{
  if (transport_send(_t, tx_data, pid, tx_data_size) < 0)
  {
    return NULL;
  }

  return transport_recv(_t, pid, rx_data_size);
}

int transport_close(transport_t _t)
{
  struct transport *t = validate(_t);

  if (t == NULL)
  {
    return -1;
  }

  if (zmq_close(t->socket) < 0)
  {
    prong_assert(errno != ENOTSOCK);
    return -1;
  }
  t->socket = NULL;

  prong_assert(context_cnt != 0);
  if (--context_cnt == 0)
  {
    while ((zmq_term(context) < 0) && (errno == EINTR))
    {
      // Do nothing
    }
    prong_assert(errno != EFAULT);
    context = NULL;
  }

  if (t->buf_size > 0)
  {
    g_free(t->buf);
    t->buf_size = 0;
    t->buf = NULL;
  }

  g_free(t);

  return 0;
}
