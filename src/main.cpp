// #include <iostream>
// #include <boost/asio.hpp>
// #include <quiche.h>
// #include <ev.h>

// #include <sys/types.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>

// int main() {
//   // Connection name and id
//   const char* server_name = "youtube.com";
//   const uint8_t scidbuf[16] = {0};
//   const uint8_t* scid = scidbuf;
//   const size_t scid_len = sizeof(scidbuf);
  
//   // Local address
//   struct sockaddr_in local_addr;
//   local_addr.sin_family = AF_INET;
//   local_addr.sin_addr.s_addr = INADDR_ANY;
//   local_addr.sin_port = 0;
//   const struct sockaddr* local = (struct sockaddr*)&local_addr; 
//   const socklen_t local_len = sizeof(local_addr);

//   // Connection address
//   struct sockaddr_in peer_addr;
//   peer_addr.sin_family = AF_INET;
//   peer_addr.sin_port = htons(443);
//   inet_pton(AF_INET, "172.217.0.174", &peer_addr.sin_addr);
//   const struct sockaddr* peer = (struct sockaddr*)&peer_addr;
//   const socklen_t peer_len = sizeof(peer_addr);

//   // Configuration
//   quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
//   quiche_conn *conn = quiche_connect(server_name, scid, scid_len, local, local_len, peer, peer_len, config);

//   std::cout << quiche_conn_is_established(conn) << std::endl;
//   return 0;
// }



// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <inttypes.h> // for PRIu64, PRId64 type
#include <stdio.h> // for standard io
#include <stdlib.h> // getenv(), malloc()

#include <fcntl.h> // fcntl(), open()
#include <errno.h> // errno identifiers

#include <netdb.h> // For network stuff

#include <ev.h> // For UDP async stuff

#include <quiche.h> // For quic, http3 stuff

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

// For connections
struct conn_io {
    ev_timer timer; // timeout timer

    const char *host; // server hostname

    int sock; // file descriptor for local UDP socket

    struct sockaddr_storage local_addr; // for socket IP storage
    socklen_t local_addr_len; // length of address

    quiche_conn *conn; // QUIC conection

    quiche_h3_conn *http3; // http3 connection
};

// Logs debug info via quiche callback
static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

// sends out pending QUIC packets requiring event loop and connection
static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE]; // outgoing packet buffer

    quiche_send_info send_info; // struct for packet where from, to, and what time to send

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out), // Writes packet size written bytes to out buffer
                                           &send_info);

        if (written == QUICHE_ERR_DONE) { // -1 nothing to write
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) { // other negative codes - error
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }
        
        ssize_t sent = sendto(conn_io->sock, out, written, 0, // sends packet to server
                              (struct sockaddr *) &send_info.to,
                              send_info.to_len);

        if (sent != written) { // sent bytes should equal written bytes
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %zd bytes\n", sent); // log
    }

    // Quiche tracks timeout but for actions, need to let libev know when timeout happens to callback timeout_cb()
    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f; // next timeout as seconds
    conn_io->timer.repeat = t; // udpates timer trigger time
    ev_timer_again(loop, &conn_io->timer); // restarts timer
}

// Callback for each HTTP/3 setting
static int for_each_setting(uint64_t identifier, uint64_t value,
                           void *argp) {
    fprintf(stderr, "got HTTP/3 SETTING: %" PRIu64 "=%" PRIu64 "\n",
            identifier, value);

    return 0;
}

// Callback for each HTTP/3 header
static int for_each_header(uint8_t *name, size_t name_len,
                           uint8_t *value, size_t value_len,
                           void *argp) {
    fprintf(stderr, "got HTTP header: %.*s=%.*s\n",
            (int) name_len, name, (int) value_len, value);

    return 0;
}

// Callback for receiving EV_P_ ev_io *w gets the event loop by macro and the watcher that triggered the callback. Revents is the events that triggered the callback
static void recv_cb(EV_P_ ev_io *w, int revents) {
    // makes sure request and settings handled only once
    static bool req_sent = false;
    static bool settings_received = false;

    struct conn_io *conn_io = (struct conn_io*)w->data; // get connection from socket watcher (multiple connections may be open)

    static uint8_t buf[65535]; // receive buffer

    while (1) {
        struct sockaddr_storage peer_addr; // prepares address storage
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conn_io->sock, buf, sizeof(buf), 0, // reads UDP packets into buf and sets peer_addr
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) { // Error reading
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        // Get packet address info
        quiche_recv_info recv_info = {
            (struct sockaddr *) &peer_addr,
            peer_addr_len,

            (struct sockaddr *) &conn_io->local_addr,
            conn_io->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info); // receive packet to quiche for processing

        if (done < 0) { // Error processing
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);
    }

    fprintf(stderr, "done reading\n");
    
    // Handles connection close
    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE); // end event loop
        return;
    }

    // For when connection is just established
    if (quiche_conn_is_established(conn_io->conn) && !req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len); // gets the IP protocol

        fprintf(stderr, "connection established: %.*s\n",
                (int) app_proto_len, app_proto);

        quiche_h3_config *config = quiche_h3_config_new(); // Create HTTP/3 configuration
        if (config == NULL) {
            fprintf(stderr, "failed to create HTTP/3 config\n");
            return;
        }

        conn_io->http3 = quiche_h3_conn_new_with_transport(conn_io->conn, config); // Create HTTP/3 Connection with configuration
        if (conn_io->http3 == NULL) {
            fprintf(stderr, "failed to create HTTP/3 connection\n");
            return;
        }

        quiche_h3_config_free(config); // Frees configuration

        // Prepare request headers
        quiche_h3_header headers[] = {
            {
                .name = (const uint8_t *) ":method",
                .name_len = sizeof(":method") - 1,

                .value = (const uint8_t *) "GET",
                .value_len = sizeof("GET") - 1,
            },

            {
                .name = (const uint8_t *) ":scheme",
                .name_len = sizeof(":scheme") - 1,

                .value = (const uint8_t *) "https",
                .value_len = sizeof("https") - 1,
            },

            {
                .name = (const uint8_t *) ":authority",
                .name_len = sizeof(":authority") - 1,

                .value = (const uint8_t *) conn_io->host,
                .value_len = strlen(conn_io->host),
            },

            { // Change this for different file path
                .name = (const uint8_t *) ":path",
                .name_len = sizeof(":path") - 1,

                .value = (const uint8_t *) "/",
                .value_len = sizeof("/") - 1,
            },

            {
                .name = (const uint8_t *) "user-agent",
                .name_len = sizeof("user-agent") - 1,

                .value = (const uint8_t *) "quiche",
                .value_len = sizeof("quiche") - 1,
            },
        };

        // Send HTTP/3 request
        int64_t stream_id = quiche_h3_send_request(conn_io->http3,
                                                   conn_io->conn,
                                                   headers, 5, true);

        fprintf(stderr, "sent HTTP request %" PRId64 "\n", stream_id);

        req_sent = true; // So this only gets called once
    }

    // For every other instance while connection active
    if (quiche_conn_is_established(conn_io->conn)) {
        quiche_h3_event *ev;

        while (1) {
            int64_t s = quiche_h3_conn_poll(conn_io->http3, // Detects if received packet is an HTTP/3 event and receives into ev and returns stream id
                                            conn_io->conn,
                                            &ev);

            if (s < 0) { // No more HTTP/3 events to parse
                break;
            }

            if (!settings_received) { // Receive HTTP/3 settings from server once
                int rc = quiche_h3_for_each_setting(conn_io->http3,
                                                    for_each_setting,
                                                    NULL);

                if (rc == 0) {
                    settings_received = true;
                }
            }

            switch (quiche_h3_event_type(ev)) { // processes possible HTTP/3 events received into ev
                case QUICHE_H3_EVENT_HEADERS: { // HTTP/3 headers have arrived -> receive headers
                    int rc = quiche_h3_event_for_each_header(ev, for_each_header,
                                                             NULL);

                    if (rc != 0) {
                        fprintf(stderr, "failed to process headers");
                    }

                    break;
                }

                case QUICHE_H3_EVENT_DATA: { // HTTP/3 body content received -> process body data
                    printf("%s", "\n\n\n\nI DO BE RECEIVING BODY NOW!!!\n\n");
                    while (1) {
                        ssize_t len = quiche_h3_recv_body(conn_io->http3, // Receives body
                                                          conn_io->conn, s,
                                                          buf, sizeof(buf));

                        if (len <= 0) { // Loop until received length is 0 (done)
                            break;
                        }

                        printf("%.*s", (int) len, buf); // Print body
                    }
                    printf("%s", "\n\nBODY FREAKING DONE!!!\n\n\n\n");

                    break;
                }

                case QUICHE_H3_EVENT_FINISHED: // Stream is done -> close connection
                    if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                    break;

                case QUICHE_H3_EVENT_RESET: // Stream aborted by peer -> close connection
                    fprintf(stderr, "request was reset\n");

                    if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                    break;

                case QUICHE_H3_EVENT_PRIORITY_UPDATE: // HTTP/3 stream priority change
                    break;

                case QUICHE_H3_EVENT_GOAWAY: { // Peer sent GOAWAY frame
                    fprintf(stderr, "got GOAWAY\n");
                    break;
                }
            }

            quiche_h3_event_free(ev); // Free ev
        }
    }

    flush_egress(loop, conn_io); // Send whatever else might need to be sent (ACK, retransmission, etc.)
}

// Callback for timeout events
static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = (struct conn_io*)w->data;
    quiche_conn_on_timeout(conn_io->conn); // Quiche timeout

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io); // Flush outgoing messages

    if (quiche_conn_is_closed(conn_io->conn)) { // Handle connection close
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns\n",
                stats.recv, stats.sent, stats.lost, path_stats.rtt);

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

int main(int argc, char *argv[]) {
    // 1. get host and port
    const char *host = argv[1];
    const char *port = argv[2];

    // 2. Set address/socket settings
    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    quiche_enable_debug_logging(debug_log, NULL);

    // 3. Parse host data
    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    // 4. Create socket to host
    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    // 5. Make socket non-blocking since UDP doesn't need to be ordered
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    // 6. Create quiche configuraiton
    quiche_config *config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_set_application_protos(config,
        (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL,
        sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);

    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true);

    if (getenv("SSLKEYLOGFILE")) {
      quiche_config_log_keys(config);
    }

    // Create random scid
    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return -1;
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return -1;
    }

    // allocate space for connection info
    struct conn_io *conn_io = (struct conn_io*)malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return -1;
    }

    // Get socket local address
    conn_io->local_addr_len = sizeof(conn_io->local_addr);
    if (getsockname(sock, (struct sockaddr *)&conn_io->local_addr,
                    &conn_io->local_addr_len) != 0)
    {
        perror("failed to get local address of socket");
        return -1;
    };

    // 7. Connect quiche on client side
    quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid, sizeof(scid),
                                       (struct sockaddr *) &conn_io->local_addr,
                                       conn_io->local_addr_len,
                                       peer->ai_addr, peer->ai_addrlen, config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return -1;
    }

    conn_io->sock = sock;
    conn_io->conn = conn;
    conn_io->host = host;

    // 8. Create ev watcher to watch for callback triggers
    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0); // Waits for watchers and calls callbacks

    // 9. Initialize watchers
    ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
    ev_io_start(loop, &watcher); // start receive watcher
    watcher.data = conn_io;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    // 10. Initialize communication
    flush_egress(loop, conn_io);

    // 11. start event loop to handle callbacks
    ev_loop(loop, 0);

    // 12. clean up
    freeaddrinfo(peer);
    quiche_h3_conn_free(conn_io->http3);
    quiche_conn_free(conn);
    quiche_config_free(config);

    return 0;
}