/**
 * @file kex.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH transport layer key exchange functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "libsftp/kex.h"

#include <stdlib.h>
#include <string.h>

#include "libsftp/error.h"
#include "libsftp/libcrypto.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

/**
 * We only support one specific cipher suite,
 *
 */
const char *supported_methods[] = {
    "diffie-hellman-group1-sha1", /* key exchange */
    "ssh-rsa",                    /* public key algorithm */
    "aes256-cbc",                 /* cipher algorithm client to server */
    "aes256-cbc",                 /* cipher algorithm server to client */
    "hmac-sha1",                  /* MAC algorithm client to server */
    "hmac-sha1",                  /* MAC algorithm server to client */
    "none", /* compression algorithm client to server */
    "none", /* compression algorithm client to server */
    "",     /* languages client to server */
    ""};    /* languages server to client */

static int hashbufout_add_cookie(ssh_session session) {
    int rc;

    session->out_hashbuf = ssh_buffer_new();
    if (session->out_hashbuf == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_allocate_size(session->out_hashbuf, sizeof(uint8_t) + 16);
    if (rc < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return SSH_ERROR;
    }

    if (ssh_buffer_add_u8(session->out_hashbuf, SSH_MSG_KEXINIT) < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return SSH_ERROR;
    }

    if (ssh_buffer_add_data(session->out_hashbuf,
                            session->next_crypto->client_kex.cookie, 16) < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return SSH_ERROR;
    }

    return SSH_OK;
}

int ssh_set_client_kex(ssh_session session) {
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    int rc;

    rc = ssh_get_random(client->cookie, 16, 0);
    if (!rc) {
        LOG_ERROR("PRNG error");
        return SSH_ERROR;
    }

    memset(client->methods, 0, SSH_KEX_METHODS * sizeof(char **));

    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        client->methods[i] = strdup(supported_methods[i]);
        if (client->methods[i] == NULL) {
            for (int j = 0; j < i; j++) {
                SAFE_FREE(client->methods[j]);
            }
            return SSH_ERROR;
        }
    }
    return SSH_OK;
}

/**
 * @brief Send supported cipher suites for algorithm negotiation.
 * 
 * @param session 
 * @return int 
 */
int ssh_send_kex(ssh_session session) {
    struct ssh_kex_struct *kex = &session->next_crypto->client_kex;
    ssh_string str = NULL;
    int rc;

    rc = ssh_buffer_pack(session->out_buffer, "bP", SSH_MSG_KEXINIT, 16,
                         kex->cookie);
    if (rc != SSH_OK) goto error;

    if (hashbufout_add_cookie(session) < 0) goto error;

    for (int i = 0; i < SSH_KEX_METHODS; ++i) {
        str = ssh_string_from_char(kex->methods[i]);
        if (ssh_buffer_add_ssh_string(session->out_hashbuf, str) < 0) {
            goto error;
        }
        if (ssh_buffer_add_ssh_string(session->out_buffer, str) < 0) {
            goto error;
        }
        ssh_string_free(str);
    }

    rc = ssh_buffer_pack(session->out_buffer, "bd", 0, 0);
    rc |= ssh_buffer_pack(session->out_hashbuf, "bd", 0, 0);
    if (rc != SSH_OK) goto error;

    if (ssh_packet_send(session) != SSH_OK)
        return SSH_ERROR;  // TODO: or goto error
    return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    ssh_buffer_reinit(session->out_hashbuf);
    ssh_string_free(str);
    return SSH_ERROR;
}

/**
 * @brief Wait for algorithm negotiation reply.
 * 
 * @param session 
 * @return int 
 */
int ssh_receive_kex(ssh_session session) {
    uint8_t msg_type = 0;
    ssh_string str = NULL;
    char *strings[SSH_KEX_METHODS] = {0};
    int rc = SSH_ERROR;
    bool first_kex_follows;
    uint32_t reserved;
    size_t len;

    rc = ssh_packet_receive(session);
    if (rc != SSH_OK) goto error;

    /* I_S is the complete, unmodified SSH_MSG_KEXINIT payload. */
    session->in_hashbuf = ssh_buffer_new();
    if (session->in_hashbuf == NULL) goto error;
    rc = ssh_buffer_add_data(session->in_hashbuf,
                             ssh_buffer_get(session->in_buffer),
                             ssh_buffer_get_len(session->in_buffer));
    if (rc != SSH_OK) goto error;

    if (ssh_buffer_get_u8(session->in_buffer, &msg_type) != 1) goto error;
    if (msg_type != SSH_MSG_KEXINIT) {
        LOG_ERROR("wrong msg type: received %d expected %d", msg_type,
                  SSH_MSG_KEXINIT);
        goto error;
    }

    len = ssh_buffer_get_data(session->in_buffer,
                              session->next_crypto->server_kex.cookie, 16);
    if (len != 16) goto error;

    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        str = ssh_buffer_get_ssh_string(session->in_buffer);
        if (str == NULL) goto error;
        strings[i] = ssh_string_to_char(str);
        if (strings[i] == NULL || strlen(strings[i]) != ssh_string_len(str)) {
            goto error;
        }
        ssh_string_free(str);
        str = NULL;
    }

    rc = ssh_buffer_unpack(session->in_buffer, "bd", &first_kex_follows,
                           &reserved);
    if (rc != SSH_OK || reserved != 0 ||
        ssh_buffer_get_len(session->in_buffer) != 0) {
        goto error;
    }

    session->first_kex_follows_guess_wrong = first_kex_follows;

    /* copy the server kex info into the array of strings */
    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        session->next_crypto->server_kex.methods[i] = strings[i];
    }

    return SSH_OK;

error:
    ssh_string_free(str);
    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        session->next_crypto->server_kex.methods[i] = NULL;
        SAFE_FREE(strings[i]);
    }
    return SSH_ERROR;
}

static bool name_list_contains(const char *list, const char *name,
                               size_t name_len) {
    const char *start = list;

    if (name_len == 0) {
        return list[0] == '\0';
    }

    while (*start != '\0') {
        const char *end = strchr(start, ',');
        size_t len = end == NULL ? strlen(start) : (size_t)(end - start);

        if (len == name_len && memcmp(start, name, len) == 0) {
            return true;
        }
        if (end == NULL) {
            break;
        }
        start = end + 1;
    }
    return false;
}

static char *select_method(const char *client, const char *server) {
    const char *start = client;

    if (client[0] == '\0') {
        return server[0] == '\0' ? strdup("") : NULL;
    }

    while (*start != '\0') {
        const char *end = strchr(start, ',');
        size_t len = end == NULL ? strlen(start) : (size_t)(end - start);

        if (name_list_contains(server, start, len)) {
            char *selected = malloc(len + 1);
            if (selected == NULL) {
                return NULL;
            }
            memcpy(selected, start, len);
            selected[len] = '\0';
            return selected;
        }
        if (end == NULL) {
            break;
        }
        start = end + 1;
    }
    return NULL;
}

static bool first_method_is(const char *list, const char *method) {
    const char *comma = strchr(list, ',');
    size_t len = comma == NULL ? strlen(list) : (size_t)(comma - list);

    return strlen(method) == len && memcmp(list, method, len) == 0;
}

/**
 * @brief Select an agreed cipher suite based on both ends' negotiation messages.
 * 
 * @param session 
 * @return int 
 */
int ssh_select_kex(ssh_session session) {
    struct ssh_kex_struct *server = &session->next_crypto->server_kex;
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;

    for (int i = 0; i < SSH_KEX_METHODS; ++i) {
        session->next_crypto->kex_methods[i] =
            select_method(client->methods[i], server->methods[i]);
        if (session->next_crypto->kex_methods[i] == NULL) {
            LOG_ERROR("no mutually supported method for KEX field %d", i);
            goto error;
        }
    }

    LOG_INFO("negotiated algorithms: KEX=%s host-key=%s; "
             "client->server cipher=%s MAC=%s compression=%s; "
             "server->client cipher=%s MAC=%s compression=%s",
             session->next_crypto->kex_methods[SSH_KEX],
             session->next_crypto->kex_methods[SSH_HOSTKEYS],
             session->next_crypto->kex_methods[SSH_CRYPT_C_S],
             session->next_crypto->kex_methods[SSH_MAC_C_S],
             session->next_crypto->kex_methods[SSH_COMP_C_S],
             session->next_crypto->kex_methods[SSH_CRYPT_S_C],
             session->next_crypto->kex_methods[SSH_MAC_S_C],
             session->next_crypto->kex_methods[SSH_COMP_S_C]);

    if (session->first_kex_follows_guess_wrong &&
        (!first_method_is(server->methods[SSH_KEX],
                          session->next_crypto->kex_methods[SSH_KEX]) ||
         !first_method_is(server->methods[SSH_HOSTKEYS],
                          session->next_crypto->kex_methods[SSH_HOSTKEYS]))) {
        if (ssh_packet_receive(session) != SSH_OK) goto error;
    }
    session->first_kex_follows_guess_wrong = 0;

    session->next_crypto->kex_type = SSH_KEX_DH_GROUP1_SHA1;
    return SSH_OK;

error:
    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        SAFE_FREE(session->next_crypto->kex_methods[i]);
    }
    return SSH_ERROR;
}
