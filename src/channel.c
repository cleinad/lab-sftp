/**
 * @file channel.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH connection layer channel abstraction.
 * This file handles open, close, and data transfer on a virtual channel.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/channel.h"

#include "libsftp/error.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

/**
 * RFC4253 section 6.1
 * All implementations MUST be able to process packets with an
 * uncompressed payload length of 32768 bytes or less and a total packet
 * size of 35000 bytes or less
 *
 */

#define CHANNEL_MAX_PACKET 32768
#define CHANNEL_INITIAL_WINDOW 64000

/**
 * @brief Get a new channel id.
 * @todo Since we only support one channel per session, returning 1 meets the
 * need. This function needs to be updated if we want to support arbitrary
 * number of channels in the future.
 *
 * @param session
 * @return uint32_t
 */
static uint32_t channel_new_id(ssh_session session) { return 1; }

static int channel_add_remote_window(ssh_channel channel,
                                     uint32_t bytes_to_add) {
    if (UINT32_MAX - channel->remote_window < bytes_to_add) {
        LOG_ERROR("remote channel window overflow");
        return SSH_ERROR;
    }

    channel->remote_window += bytes_to_add;
    LOG_NOTICE("remote window adjust to %u", channel->remote_window);
    return SSH_OK;
}

static int channel_handle_global_request(ssh_session session) {
    char *request = NULL;
    uint8_t want_reply;
    int rc;

    rc = ssh_buffer_unpack(session->in_buffer, "sb", &request, &want_reply);
    if (rc != SSH_OK) {
        SAFE_FREE(request);
        return SSH_ERROR;
    }

    LOG_NOTICE("rejecting global request %s", request);
    SAFE_FREE(request);

    if (!want_reply) return SSH_OK;

    rc = ssh_buffer_pack(session->out_buffer, "b", SSH_MSG_REQUEST_FAILURE);
    if (rc != SSH_OK || ssh_packet_send(session) != SSH_OK) {
        ssh_buffer_reinit(session->out_buffer);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int channel_reject_open(ssh_session session) {
    char *type = NULL;
    uint32_t sender_channel;
    int rc;

    rc = ssh_buffer_unpack(session->in_buffer, "sd", &type, &sender_channel);
    if (rc != SSH_OK) {
        SAFE_FREE(type);
        return SSH_ERROR;
    }

    LOG_NOTICE("rejecting server channel open of type %s", type);
    SAFE_FREE(type);

    rc = ssh_buffer_pack(session->out_buffer, "bddss",
                         SSH_MSG_CHANNEL_OPEN_FAILURE, sender_channel,
                         SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                         "server-initiated channels are not supported", "");
    if (rc != SSH_OK || ssh_packet_send(session) != SSH_OK) {
        ssh_buffer_reinit(session->out_buffer);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int channel_reject_request(ssh_channel channel) {
    ssh_session session = channel->session;
    char *request = NULL;
    uint8_t want_reply;
    int rc;

    rc = ssh_buffer_unpack(session->in_buffer, "sb", &request, &want_reply);
    if (rc != SSH_OK) {
        SAFE_FREE(request);
        return SSH_ERROR;
    }

    LOG_NOTICE("ignoring channel request %s", request);
    SAFE_FREE(request);

    if (!want_reply) return SSH_OK;

    rc = ssh_buffer_pack(session->out_buffer, "bd", SSH_MSG_CHANNEL_FAILURE,
                         channel->remote_channel);
    if (rc != SSH_OK || ssh_packet_send(session) != SSH_OK) {
        ssh_buffer_reinit(session->out_buffer);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int channel_send_close(ssh_channel channel) {
    ssh_session session = channel->session;
    int rc;

    if (channel->local_eof == 2) return SSH_OK;

    rc = ssh_buffer_pack(session->out_buffer, "bd", SSH_MSG_CHANNEL_CLOSE,
                         channel->remote_channel);
    if (rc != SSH_OK || ssh_packet_send(session) != SSH_OK) {
        ssh_buffer_reinit(session->out_buffer);
        return SSH_ERROR;
    }

    channel->local_eof = 2;
    return SSH_OK;
}

/**
 * @brief Open a channel by sending a SSH_CHANNEL_OPEN message and
 *        wait for the reply.
 *
 * @param[in]  channel  The current channel.
 *
 * @param[in]  type   A C string describing the kind of channel (e.g. "exec").
 *
 * @param[in]  window   The receiving window of the channel. The window is the
 *                      maximum size of data that can stay in buffers and
 *                      network.
 *
 * @param[in]  maxpacket The maximum packet size allowed (like MTU).
 *
 * @param[in]  payload   The buffer containing additional payload for the query.
 *
 * @return             SSH_OK if successful; SSH_ERROR otherwise.
 */
static int channel_open(ssh_channel channel, const char *type, uint32_t window,
                        uint32_t maxpacket, ssh_buffer payload) {
    ssh_session session = channel->session;
    uint8_t reply_type;
    uint32_t recipient_channel;
    uint32_t reason_code;
    char *description = NULL;
    char *language = NULL;
    int rc;

    channel->local_channel = channel_new_id(session);
    channel->local_maxpacket = maxpacket;
    channel->local_window = window;

    rc = ssh_buffer_pack(session->out_buffer, "bsddd", SSH_MSG_CHANNEL_OPEN,
                         type, channel->local_channel, channel->local_window,
                         channel->local_maxpacket);
    if (rc != SSH_OK) {
        LOG_ERROR("can not create buffer");
        return SSH_ERROR;
    }

    if (payload != NULL) {
        if (ssh_buffer_add_buffer(session->out_buffer, payload) < 0) {
            return SSH_ERROR;
        }
    }

    if (ssh_packet_send(session) != SSH_OK) {
        return SSH_ERROR;
    }

    while (1) {
        /* wait until the channel is opened or an error occurs */
        rc = ssh_packet_receive_message(session);
        if (rc != SSH_OK) return SSH_ERROR;

        rc = ssh_buffer_get_u8(session->in_buffer, &reply_type);
        if (rc == 0) return SSH_ERROR;
        switch (reply_type) {
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                rc = ssh_buffer_unpack(
                    session->in_buffer, "dddd", &recipient_channel,
                    &channel->remote_channel, &channel->remote_window,
                    &channel->remote_maxpacket);
                if (rc != SSH_OK ||
                    recipient_channel != channel->local_channel ||
                    channel->remote_maxpacket == 0) {
                    LOG_ERROR("invalid channel open confirmation");
                    return SSH_ERROR;
                }

                LOG_INFO("local channel id %u, window %u",
                         channel->local_channel, channel->local_window);
                LOG_INFO("remote channel id %u, window %u",
                         channel->remote_channel, channel->remote_window);
                return SSH_OK;

            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                rc = ssh_buffer_unpack(session->in_buffer, "ddss",
                                       &recipient_channel, &reason_code,
                                       &description, &language);
                if (rc == SSH_OK &&
                    recipient_channel == channel->local_channel) {
                    ssh_set_error(SSH_REQUEST_DENIED,
                                  "channel open failed (%u): %s", reason_code,
                                  description);
                } else {
                    ssh_set_error(SSH_FATAL,
                                  "invalid channel open failure response");
                }
                SAFE_FREE(description);
                SAFE_FREE(language);
                return SSH_ERROR;

            case SSH_MSG_GLOBAL_REQUEST:
                /**
                 * RFC 4254 Section 4
                 * There are several kinds of requests that affect the state of
                 * the remote end globally, independent of any channels.  An
                 * example is a request to start TCP/IP forwarding for a
                 * specific port.  Note that both the client and server MAY send
                 * global requests at any time, and the receiver MUST respond
                 * appropriately.  All such requests use the following format.
                 *      byte      SSH_MSG_GLOBAL_REQUEST
                 *      string    request name in US-ASCII only
                 *      boolean   want reply
                 *      ....      request-specific data follows
                 *
                 * The value of 'request name' follows the DNS extensibility
                 * naming convention outlined in [SSH-ARCH].
                 *
                 */
                if (channel_handle_global_request(session) != SSH_OK)
                    return SSH_ERROR;
                break;

            case SSH_MSG_CHANNEL_OPEN:
                if (channel_reject_open(session) != SSH_OK) return SSH_ERROR;
                break;

            default:
                LOG_ERROR("received type %u during channel open", reply_type);
                return SSH_ERROR;
        }
    }
}

/**
 * @brief Send SSH channel request and wait for reply if `reply` is set to 1.
 *
 * @param channel
 * @param request
 * @param reply
 * @param req_spec
 * @return int
 */
static int channel_request(ssh_channel channel, const char *request, int reply,
                           ssh_buffer req_spec) {
    ssh_session session = channel->session;
    uint8_t type;
    uint32_t recipient_channel;
    uint32_t bytes_to_add;
    int rc;

    rc = ssh_buffer_pack(session->out_buffer, "bdsb", SSH_MSG_CHANNEL_REQUEST,
                         channel->remote_channel, request, reply == 0 ? 0 : 1);
    if (rc != SSH_OK) {
        LOG_ERROR("can not create buffer");
        goto error;
    }

    if (req_spec != NULL) {
        if (ssh_buffer_add_data(session->out_buffer, ssh_buffer_get(req_spec),
                                ssh_buffer_get_len(req_spec)) < 0) {
            LOG_ERROR("can not concat buffer");
            goto error;
        }
    }
    if (ssh_packet_send(session) != SSH_OK) {
        goto error;
    }

    if (reply == 0) return SSH_OK;

    while (1) {
        /* wait for reply or an error occurs */
        if (ssh_packet_receive_message(session) != SSH_OK) {
            return SSH_ERROR;
        }

        rc = ssh_buffer_get_u8(session->in_buffer, &type);
        if (rc == 0) return SSH_ERROR;

        if (type == SSH_MSG_GLOBAL_REQUEST) {
            if (channel_handle_global_request(session) != SSH_OK)
                return SSH_ERROR;
            continue;
        }
        if (type == SSH_MSG_CHANNEL_OPEN) {
            if (channel_reject_open(session) != SSH_OK) return SSH_ERROR;
            continue;
        }

        rc = ssh_buffer_unpack(session->in_buffer, "d", &recipient_channel);
        if (rc != SSH_OK) return SSH_ERROR;
        if (recipient_channel != channel->local_channel) {
            LOG_ERROR(
                "channel number in the reply does not match with the "
                "original");
            return SSH_ERROR;
        }

        switch (type) {
            case SSH_MSG_CHANNEL_SUCCESS:
                return SSH_OK;
            case SSH_MSG_CHANNEL_FAILURE:
                return SSH_ERROR;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                /* window adjust message could happen here */
                if (ssh_buffer_unpack(session->in_buffer, "d",
                                      &bytes_to_add) != SSH_OK ||
                    channel_add_remote_window(channel, bytes_to_add) != SSH_OK)
                    return SSH_ERROR;
                break;
            case SSH_MSG_CHANNEL_REQUEST:
                if (channel_reject_request(channel) != SSH_OK)
                    return SSH_ERROR;
                break;
            default:
                LOG_ERROR("received type %u during channel request", type);
                return SSH_ERROR;
        }
    }

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Grow local channel window to at least `minimum_size`.
 * This function sends SSH_MSG_CHANNEL_WINDOW_ADJUST.
 *
 * @param channel
 * @param minimum_size
 * @return int
 */
static int grow_window(ssh_channel channel, uint32_t minimum_size) {
    ssh_session session;
    int rc;

    if (channel == NULL) return SSH_ERROR;
    if (channel->local_eof == 2 || channel->remote_eof == 2) return SSH_OK;
    session = channel->session;

    if (channel->local_window >= minimum_size) return SSH_OK;

    rc = ssh_buffer_pack(session->out_buffer, "bdd",
                         SSH_MSG_CHANNEL_WINDOW_ADJUST, channel->remote_channel,
                         minimum_size - channel->local_window);
    if (rc != SSH_OK) {
        LOG_ERROR("can not pack buffer");
        goto error;
    }

    if (ssh_packet_send(session) != SSH_OK) goto error;

    channel->local_window = minimum_size;
    return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

static int channel_adjust_receive_window(ssh_channel channel) {
    uint32_t bytes_to_add;

    if (channel->local_eof == 2 || channel->remote_eof == 2 ||
        channel->local_window >= CHANNEL_INITIAL_WINDOW / 2) {
        return SSH_OK;
    }

    bytes_to_add = CHANNEL_INITIAL_WINDOW - channel->local_window;
    if (channel->local_consumed < bytes_to_add) return SSH_OK;
    if (grow_window(channel, CHANNEL_INITIAL_WINDOW) != SSH_OK)
        return SSH_ERROR;

    channel->local_consumed -= bytes_to_add;
    return SSH_OK;
}

/**
 * @brief Wait for WINDOW_ADJUST message to grow remote window.
 *
 * @param channel
 * @return int
 */
static int wait_window(ssh_channel channel) {
    ssh_session session;
    uint8_t type;
    uint32_t recipient_channel;
    uint32_t bytes_to_add;
    uint32_t data_type;
    ssh_string channel_data = NULL;
    size_t data_len;
    int rc;

    if (channel == NULL) return SSH_ERROR;
    session = channel->session;

    type = 0;
    while (type != SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        rc = ssh_packet_receive_message(session);
        if (rc != SSH_OK ||
            ssh_buffer_get_u8(session->in_buffer, &type) == 0)
            return SSH_ERROR;

        if (type == SSH_MSG_GLOBAL_REQUEST) {
            if (channel_handle_global_request(session) != SSH_OK)
                return SSH_ERROR;
            continue;
        }
        if (type == SSH_MSG_CHANNEL_OPEN) {
            if (channel_reject_open(session) != SSH_OK) return SSH_ERROR;
            continue;
        }

        if (ssh_buffer_unpack(session->in_buffer, "d", &recipient_channel) !=
            SSH_OK)
            return SSH_ERROR;
        if (recipient_channel != channel->local_channel) {
            LOG_ERROR(
                "channel number in the reply %d does not match with the "
                "original %d",
                recipient_channel, channel->local_channel);
            return SSH_ERROR;
        }

        switch (type) {
            case SSH_MSG_CHANNEL_DATA:
                if (ssh_buffer_unpack(session->in_buffer, "S",
                                      &channel_data) != SSH_OK ||
                    channel_data == NULL)
                    goto error;
                data_len = ssh_string_len(channel_data);
                if (data_len > channel->local_window ||
                    data_len > channel->local_maxpacket) {
                    LOG_ERROR("channel data exceeds receive limits");
                    goto error;
                }
                if (data_len > 0 &&
                    ssh_buffer_add_data(channel->out_buffer,
                                        ssh_string_data(channel_data),
                                        (uint32_t)data_len) != SSH_OK)
                    goto error;
                channel->local_window -= (uint32_t)data_len;
                SSH_STRING_FREE(channel_data);
                break;
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                if (ssh_buffer_unpack(session->in_buffer, "dS", &data_type,
                                      &channel_data) != SSH_OK ||
                    channel_data == NULL)
                    goto error;
                data_len = ssh_string_len(channel_data);
                if (data_len > channel->local_window ||
                    data_len > channel->local_maxpacket) {
                    LOG_ERROR("extended channel data exceeds receive limits");
                    goto error;
                }
                channel->local_window -= (uint32_t)data_len;
                channel->local_consumed += (uint32_t)data_len;
                LOG_WARNING("discarding extended channel data type %u",
                            data_type);
                SSH_STRING_FREE(channel_data);
                if (channel_adjust_receive_window(channel) != SSH_OK)
                    goto error;
                break;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                if (ssh_buffer_unpack(session->in_buffer, "d",
                                      &bytes_to_add) != SSH_OK)
                    return SSH_ERROR;
                return channel_add_remote_window(channel, bytes_to_add);
            case SSH_MSG_CHANNEL_REQUEST:
                if (channel_reject_request(channel) != SSH_OK)
                    return SSH_ERROR;
                break;
            case SSH_MSG_CHANNEL_EOF:
                LOG_ERROR("channel %d received EOF on window waiting",
                          channel->local_channel);
                return SSH_ERROR;
            case SSH_MSG_CHANNEL_CLOSE:
                channel->remote_eof = 2;
                channel_send_close(channel);
                LOG_ERROR("remote channel %d closed on window waiting",
                          channel->remote_channel);
                return SSH_ERROR;
            default:
                LOG_ERROR("unexpected message type %d on window waiting", type);
                return SSH_ERROR;
        }
    }

    return SSH_OK;

error:
    SSH_STRING_FREE(channel_data);
    return SSH_ERROR;
}

/**
 * @brief Create a new channel and attach it to the SSH session.
 *
 * @param session
 * @return ssh_channel
 */
ssh_channel ssh_channel_new(ssh_session session) {
    ssh_channel channel = NULL;

    if (session == NULL) {
        return NULL;
    }

    channel = calloc(1, sizeof(struct ssh_channel_struct));
    if (channel == NULL) {
        LOG_ERROR("can not create ssh channel");
        return NULL;
    }

    channel->out_buffer = ssh_buffer_new();
    if (channel->out_buffer == NULL) {
        LOG_ERROR("can not create buffer");
        SAFE_FREE(channel);
        return NULL;
    }

    channel->session = session;
    session->channel = channel;

    return channel;
}

/**
 * @brief Open a channel for `session` service
 * @see RFC4254 section 6.1
 *
 * @param channel
 * @return int
 */
int ssh_channel_open_session(ssh_channel channel) {
    if (channel == NULL) {
        return SSH_ERROR;
    }

    return channel_open(channel, "session", CHANNEL_INITIAL_WINDOW,
                        CHANNEL_MAX_PACKET, NULL);
}

/**
 * @brief Request SFTP subsystem service on an opened channel.
 *
 * @param channel
 * @return int
 */
int ssh_channel_request_sftp(ssh_channel channel) {
    ssh_buffer subsys = NULL;
    int rc;

    if (channel == NULL) {
        return SSH_ERROR;
    }

    subsys = ssh_buffer_new();
    if (subsys == NULL) {
        LOG_ERROR("can not create buffer");
        return SSH_ERROR;
    }

    rc = ssh_buffer_pack(subsys, "s", "sftp");
    if (rc != SSH_OK) {
        ssh_buffer_free(subsys);
        return SSH_ERROR;
    }

    rc = channel_request(channel, "subsystem", 1, subsys);
    ssh_buffer_free(subsys);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Write data to the channel. This function would block until `len` bytes
 * of data are written.
 *
 * @param channel
 * @param data
 * @param len
 * @return bytes written, SSH_ERR on error.
 */
int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len) {
    ssh_session session;
    uint32_t origlen = len;
    uint32_t effectivelen;
    uint32_t maxpacketlen;
    int rc;

    if (channel == NULL || data == NULL || len > INT_MAX) {
        LOG_ERROR("param error");
        ssh_set_error(SSH_FATAL, "invalid params");
        return SSH_ERROR;
    }

    if (channel->local_eof) {
        ssh_set_error(SSH_REQUEST_DENIED,
                      "Can't write to channel %d:%d  after EOF was sent",
                      channel->local_channel, channel->remote_channel);
        return SSH_ERROR;
    }

    session = channel->session;
    maxpacketlen = channel->remote_maxpacket;
    if (maxpacketlen == 0) {
        ssh_set_error(SSH_FATAL, "remote channel packet limit is zero");
        return SSH_ERROR;
    }

    while (len > 0) {
        while (channel->remote_window == 0) {
            /* can not send, wait for window adjust message */
            rc = wait_window(channel);
            if (rc != SSH_OK) goto error;
        }
        effectivelen = MIN(len, channel->remote_window);
        effectivelen = MIN(effectivelen, maxpacketlen);
        effectivelen = MIN(effectivelen, CHANNEL_MAX_PACKET);
        if (effectivelen == 0) continue;

        rc = ssh_buffer_pack(session->out_buffer, "bd", SSH_MSG_CHANNEL_DATA,
                             channel->remote_channel);
        if (rc != SSH_OK) goto error;

        rc = ssh_buffer_pack(session->out_buffer, "dP", effectivelen,
                             (size_t)effectivelen, data);
        if (rc != SSH_OK) goto error;

        rc = ssh_packet_send(session);
        if (rc != SSH_OK) goto error;

        channel->remote_window -= effectivelen;
        len -= effectivelen;
        data = ((uint8_t *)data + effectivelen);
    }

    return origlen;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Read data from channel. This function would block until `count` bytes
 * of data is read.
 *
 * @todo take care of static `buf`
 * @param channel
 * @param dest
 * @param count
 * @return bytes read, SSH_ERR on error.
 */
int ssh_channel_read(ssh_channel channel, void *dest, uint32_t count) {
    ssh_session session;
    ssh_buffer buf;
    ssh_string channel_data = NULL;
    uint8_t type;
    uint32_t recipient_channel;
    uint32_t bytes_to_add;
    uint32_t data_type;
    uint32_t effectivelen;
    uint32_t nread = 0;
    size_t data_len;
    int rc;

    if (channel == NULL || (dest == NULL && count > 0)) return SSH_ERROR;
    session = channel->session;
    buf = channel->out_buffer;

    if (count == 0) return 0;
    if (channel->remote_eof && ssh_buffer_get_len(buf) == 0) return SSH_EOF;

    if (buf == NULL) return SSH_ERROR;

    while (count > 0) {
        if (ssh_buffer_get_len(buf) > 0) {
            /* try to read channel data from static buffer first */
            effectivelen = MIN(count, ssh_buffer_get_len(buf));
            if (ssh_buffer_get_data(buf, (uint8_t *)dest + nread,
                                    effectivelen) != effectivelen)
                goto error;
            if (ssh_buffer_get_len(buf) == 0) ssh_buffer_reinit(buf);

            count -= effectivelen;
            nread += effectivelen;
            channel->local_consumed += effectivelen;
            if (channel_adjust_receive_window(channel) != SSH_OK)
                goto error;

        } else {
            if (channel->remote_eof) return nread > 0 ? (int)nread : SSH_EOF;

            /* static buffer has insufficient data, read another
             * SSH_MSG_CHANNEL_DATA packet */
            rc = ssh_packet_receive_message(session);
            if (rc != SSH_OK) goto error;

            rc = ssh_buffer_get_u8(session->in_buffer, &type);
            if (rc == 0) goto error;

            if (type == SSH_MSG_GLOBAL_REQUEST) {
                if (channel_handle_global_request(session) != SSH_OK)
                    goto error;
                continue;
            }
            if (type == SSH_MSG_CHANNEL_OPEN) {
                if (channel_reject_open(session) != SSH_OK) goto error;
                continue;
            }

            rc = ssh_buffer_unpack(session->in_buffer, "d",
                                   &recipient_channel);
            if (rc != SSH_OK) goto error;
            if (recipient_channel != channel->local_channel) {
                LOG_ERROR(
                    "channel number in the reply %d does not match with the "
                    "original %d",
                    recipient_channel, channel->local_channel);
                goto error;
            }
            switch (type) {
                case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    /* window adjust message could happen here */
                    if (ssh_buffer_unpack(session->in_buffer, "d",
                                          &bytes_to_add) != SSH_OK ||
                        channel_add_remote_window(channel, bytes_to_add) !=
                            SSH_OK)
                        goto error;
                    break;

                case SSH_MSG_CHANNEL_DATA:
                    if (ssh_buffer_unpack(session->in_buffer, "S",
                                          &channel_data) != SSH_OK ||
                        channel_data == NULL)
                        goto error;

                    data_len = ssh_string_len(channel_data);
                    if (data_len > channel->local_window ||
                        data_len > channel->local_maxpacket) {
                        LOG_ERROR("channel data exceeds receive limits");
                        goto error;
                    }

                    if (data_len > 0 &&
                        ssh_buffer_add_data(buf, ssh_string_data(channel_data),
                                            (uint32_t)data_len) != SSH_OK)
                        goto error;
                    channel->local_window -= (uint32_t)data_len;
                    SSH_STRING_FREE(channel_data);
                    break;

                case SSH_MSG_CHANNEL_EXTENDED_DATA:
                    if (ssh_buffer_unpack(session->in_buffer, "dS", &data_type,
                                          &channel_data) != SSH_OK ||
                        channel_data == NULL)
                        goto error;

                    data_len = ssh_string_len(channel_data);
                    if (data_len > channel->local_window ||
                        data_len > channel->local_maxpacket) {
                        LOG_ERROR("extended channel data exceeds receive limits");
                        goto error;
                    }
                    channel->local_window -= (uint32_t)data_len;
                    channel->local_consumed += (uint32_t)data_len;
                    LOG_WARNING("discarding extended channel data type %u",
                                data_type);
                    SSH_STRING_FREE(channel_data);
                    if (channel_adjust_receive_window(channel) != SSH_OK)
                        goto error;
                    break;

                case SSH_MSG_CHANNEL_EOF:
                    channel->remote_eof = 1;
                    return nread > 0 ? (int)nread : SSH_EOF;

                case SSH_MSG_CHANNEL_CLOSE:
                    channel->remote_eof = 2;
                    if (channel_send_close(channel) != SSH_OK) goto error;
                    return nread > 0 ? (int)nread : SSH_EOF;

                case SSH_MSG_CHANNEL_REQUEST:
                    if (channel_reject_request(channel) != SSH_OK) goto error;
                    break;

                case SSH_MSG_CHANNEL_SUCCESS:
                    LOG_NOTICE("received channel request success");
                    break;

                case SSH_MSG_CHANNEL_FAILURE:
                    LOG_ERROR("received channel request failure");
                    goto error;

                default:
                    LOG_ERROR("unexpected channel message type %u", type);
                    goto error;
            }
        }
    }

    return nread;

error:
    SSH_STRING_FREE(channel_data);
    return SSH_ERROR;
}

/**
 * @brief Send EOF to the channel.
 *
 * @param channel
 * @return int
 */
int ssh_channel_eof(ssh_channel channel) {
    ssh_session session;
    int rc;

    if (channel == NULL || channel->session == NULL) {
        return SSH_ERROR;
    }

    /* If the EOF has already been sent we're done here. */
    if (channel->local_eof != 0) {
        return SSH_OK;
    }

    session = channel->session;

    rc = ssh_buffer_pack(session->out_buffer, "bd", SSH_MSG_CHANNEL_EOF,
                         channel->remote_channel);
    if (rc != SSH_OK) {
        LOG_ERROR("can not create buffer");
        goto error;
    }

    if (ssh_packet_send(session) != SSH_OK) goto error;

    channel->local_eof = 1;
    return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/**
 * @brief Close a SSH channel. Send SSH_CHANNEL_CLOSE and wait for reply.
 *
 * RFC 4254 section 5.3
 * The channel is considered closed for a
 * party when it has both sent and received SSH_MSG_CHANNEL_CLOSE, and
 * the party may then reuse the channel number.  A party MAY send
 * SSH_MSG_CHANNEL_CLOSE without having sent or receive
 * SSH_MSG_CHANNEL_EOF.
 *
 */
int ssh_channel_close(ssh_channel channel) {
    ssh_session session;
    uint8_t type;
    uint32_t recipient_channel;
    uint32_t bytes_to_add;
    int rc;

    if (channel == NULL) {
        return SSH_ERROR;
    }

    session = channel->session;

    rc = ssh_channel_eof(channel);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = channel_send_close(channel);
    if (rc != SSH_OK) return SSH_ERROR;

    if (channel->remote_eof == 2) return SSH_OK;

    /* wait for SSH_MSG_CHANNEL_CLOSE reply */
    while (1) {
        rc = ssh_packet_receive_message(session);
        if (rc != SSH_OK ||
            ssh_buffer_get_u8(session->in_buffer, &type) == 0)
            return SSH_ERROR;

        if (type == SSH_MSG_GLOBAL_REQUEST) {
            if (channel_handle_global_request(session) != SSH_OK)
                return SSH_ERROR;
            continue;
        }
        if (type == SSH_MSG_CHANNEL_OPEN) {
            if (channel_reject_open(session) != SSH_OK) return SSH_ERROR;
            continue;
        }

        rc = ssh_buffer_unpack(session->in_buffer, "d", &recipient_channel);
        if (rc != SSH_OK) return SSH_ERROR;
        if (recipient_channel != channel->local_channel) {
            LOG_ERROR(
                "channel number in the reply %d does not match with the "
                "original %d",
                recipient_channel, channel->local_channel);
            return SSH_ERROR;
        }

        switch (type) {
            case SSH_MSG_CHANNEL_CLOSE:
                channel->remote_eof = 2;
                return SSH_OK;
            case SSH_MSG_CHANNEL_EOF:
                channel->remote_eof = 1;
                break;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                if (ssh_buffer_unpack(session->in_buffer, "d",
                                      &bytes_to_add) != SSH_OK ||
                    channel_add_remote_window(channel, bytes_to_add) != SSH_OK)
                    return SSH_ERROR;
                break;
            case SSH_MSG_CHANNEL_REQUEST:
                if (channel_reject_request(channel) != SSH_OK)
                    return SSH_ERROR;
                break;
            case SSH_MSG_CHANNEL_SUCCESS:
            case SSH_MSG_CHANNEL_FAILURE:
                break;
            default:
                LOG_ERROR("unexpected message type %u during channel close",
                          type);
                return SSH_ERROR;
        }
    }
}

/**
 * @brief Free the channel and deallocate its resource.
 *
 * @param channel
 */
void ssh_channel_free(ssh_channel channel) {
    ssh_buffer_free(channel->out_buffer);
    channel->session->channel = NULL;
    channel->session = NULL;
    SAFE_FREE(channel);
}
