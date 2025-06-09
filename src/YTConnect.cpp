#include <iostream>
#include <netdb.h>
#include <fcntl.h>
#include <ev.h>
#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350

// Easily pass in connection data to function
struct conn_io {
  ev_timer timer;

  const char *host;

  int sock;

  sockaddr *local_addr;
  socklen_t local_addrlen;

  sockaddr *peer_addr;
  socklen_t peer_addrlen;

  quiche_conn *conn;
  quiche_h3_conn *http3;
};

/**
 * send()
 * Writes quiche egress data to a buffer and sends it to the peer address.
 * 
 * @param EV_P_ Event loop if ev settings allow more than one loop
 * @param conn_info Struct containing local connection info
 */
static void send(EV_P_ conn_io *conn_info) {
  static uint8_t buf[MAX_DATAGRAM_SIZE];

  quiche_send_info out_info;

  // Send until nothing left to write
  while(1) {
    ssize_t written = quiche_conn_send(conn_info->conn, buf, sizeof(buf), &out_info);

    if (written == QUICHE_ERR_DONE) {
      break;
    } else if (written < 0) {
      return;
    }

    ssize_t sent = sendto(conn_info->sock, buf, written, 0,
                          (sockaddr *)&out_info.to, out_info.to_len);

    fprintf(stderr, "sent %zd bytes\n", sent);
  }

  // Adjust ev timeout to match quic timeout
  double t = quiche_conn_timeout_as_nanos(conn_info->conn) / 1e9f;
  conn_info->timer.repeat = t;
  ev_timer_again(loop, &conn_info->timer);
}

/**
 * recv_cb()
 * Runs from an ev watcher that watches for if the socket has read data.
 * Initializes an HTTP/3 connection if not done so already and parses
 * received data from the peer.
 * 
 * @param EV_P_ Event loop if ev settings allow more than one loop
 * @param w The watcher
 * @param revents The event flag (EV_READ)
 */
static void recv_cb(EV_P_ ev_io *w, int revents) {
  static uint8_t buf[MAX_DATAGRAM_SIZE];

  // For first receive
  static bool request_sent = false;

  conn_io *conn_info = (conn_io *)w->data;

  // Receive data
  while(1) {
    ssize_t read = recvfrom(conn_info->sock, buf, sizeof(buf), 0,
              conn_info->peer_addr, &conn_info->peer_addrlen);

    if (read < 0) {
      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
        break;
      }
      return;
    }

    quiche_recv_info recv_info = {
      conn_info->peer_addr,
      conn_info->peer_addrlen,

      conn_info->local_addr,
      conn_info->local_addrlen,
    };

    ssize_t received = quiche_conn_recv(conn_info->conn, buf, read, &recv_info);

    fprintf(stderr, "recv %zd bytes\n", received);
  }

  // Handles connection close
  if (quiche_conn_is_closed(conn_info->conn)) {
    ev_break(EV_A_ EVBREAK_ONE);
    return;
  }
  
  if (quiche_conn_is_established(conn_info->conn) && !request_sent) {
    const uint8_t *app_proto;
    size_t app_proto_len;

    // Create http3 configuration
    quiche_conn_application_proto(conn_info->conn, &app_proto, &app_proto_len);

    fprintf(stderr, "connection established: %.*s\n",
                (int) app_proto_len, app_proto);
    quiche_h3_config *config = quiche_h3_config_new();
    conn_info->http3 = quiche_h3_conn_new_with_transport(conn_info->conn, config);
    quiche_h3_config_free(config);

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

        .value = (const uint8_t *) conn_info->host,
        .value_len = strlen(conn_info->host),
      },

      {
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

    int64_t stream_id = quiche_h3_send_request(conn_info->http3,
                                              conn_info->conn,
                                              headers,
                                              sizeof(headers)/sizeof(quiche_h3_header),
                                              true);

    request_sent = true;
  }

  if (quiche_conn_is_established(conn_info->conn)) {
    // Get the http3 event
    quiche_h3_event *ev;

    while (1) {
      int64_t status = quiche_h3_conn_poll(conn_info->http3, conn_info->conn, &ev);

      if (status < 0) {
        break;
      }

      std::cout << quiche_h3_event_type(ev) << std::endl;

      switch (quiche_h3_event_type(ev)) {
        case QUICHE_H3_EVENT_HEADERS: // HTTP/3 headers have arrived
          break;
        case QUICHE_H3_EVENT_DATA: // Data
            while (1) {
              ssize_t len = quiche_h3_recv_body(conn_info->http3,
                                                conn_info->conn, status,
                                                buf, sizeof(buf));

              if (len <= 0) {
                break;
              }

              printf("%.*s", (int) len, buf);
            }
            break;

        case QUICHE_H3_EVENT_FINISHED: // Stream is done
          quiche_conn_close(conn_info->conn, true, 0, NULL, 0) < 0;
          break;

        case QUICHE_H3_EVENT_RESET: // Stream aborted by peer
            if (quiche_conn_close(conn_info->conn, true, 0, NULL, 0) < 0) {
                fprintf(stderr, "failed to close connection\n");
            }
            break;

        case QUICHE_H3_EVENT_PRIORITY_UPDATE: // HTTP/3 stream priority change
            break;

        case QUICHE_H3_EVENT_GOAWAY: // Peer sent GOAWAY frame
            break;
      }

      quiche_h3_event_free(ev);
    }
  }

  send(loop, conn_info);
}

/**
 * timeout_cb()
 * Callback for when timeout occurs. Handles connection end
 * 
 * @param EV_P_ Event loop if ev settings allow more than one loop
 * @param w The watcher
 * @param revents The event flag
 */
static void timeout_cb(EV_P_ ev_timer *w, int revents) {
  conn_io *conn_info = (conn_io*)w->data;

  // Timeout and send remaining
  quiche_conn_on_timeout(conn_info->conn);
  send(loop, conn_info);

  // End if connection closed
  if (quiche_conn_is_closed(conn_info->conn)) {
    quiche_stats stats;
    quiche_path_stats path_stats;

    quiche_conn_stats(conn_info->conn, &stats);
    quiche_conn_path_stats(conn_info->conn, 0, &path_stats);

    fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%ins\n",
            stats.recv, stats.sent, stats.lost, path_stats.rtt);
    ev_break(EV_A_ EVBREAK_ONE);
    return;
  }
}

int main (int argc, char *argv[]) {
  // Get arguments
  const char *host = argv[1];
  const char *port = argv[2];

  // For getaddrinfo()
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_DGRAM,
    .ai_protocol = IPPROTO_UDP
  };

  // Get peer address info
  addrinfo *peer;
  getaddrinfo(host, port, &hints, &peer);

  // Create socket
  int sock = socket(peer->ai_family, peer->ai_socktype, peer->ai_protocol);
  fcntl(sock, F_SETFL, O_NONBLOCK);

  // Create quiche configuration
  quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  quiche_config_set_application_protos(config,
          (uint8_t *)QUICHE_H3_APPLICATION_PROTOCOL,
          sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);
  quiche_config_set_max_idle_timeout(config, 30000);
  quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_initial_max_streams_bidi(config, 100);
  quiche_config_set_initial_max_streams_uni(config, 100);
  quiche_config_set_initial_max_data(config, 10000000);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
  quiche_config_set_initial_max_stream_data_uni(config, 1000000);
  quiche_config_set_disable_active_migration(config, true);

  // Create scid
  uint8_t scid[LOCAL_CONN_ID_LEN];
  int rng = open("/dev/urandom", O_RDONLY);
  ssize_t scid_len = read(rng, &scid, LOCAL_CONN_ID_LEN);
  close(rng);

  // Get local connection info
  conn_io *conn_info = new conn_io;
  conn_info->local_addr = reinterpret_cast<sockaddr*>(new sockaddr_storage);
  conn_info->local_addrlen = sizeof(sockaddr_storage);
  getsockname(sock, conn_info->local_addr, &conn_info->local_addrlen);

  // Set peer connection info
  conn_info->peer_addr = peer->ai_addr;
  conn_info->peer_addrlen = peer->ai_addrlen;

  // Create quiche connection
  quiche_conn *conn = quiche_connect(host, scid, scid_len,
                  conn_info->local_addr, conn_info->local_addrlen,
                  conn_info->peer_addr, conn_info->peer_addrlen, config);

  conn_info->sock = sock;
  conn_info->conn = conn;
  conn_info->host = host;

  // Set up watchers and loop
  ev_io watcher;
  struct ev_loop *loop = ev_default_loop(0);

  ev_io_init(&watcher, recv_cb, conn_info->sock, EV_READ);
  ev_io_start(loop, &watcher);
  watcher.data = conn_info;

  ev_init(&conn_info->timer, timeout_cb);
  conn_info->timer.data = conn_info;

  // Start
  send(loop, conn_info);
  ev_loop(loop, 0);

  // Clean up
  freeaddrinfo(peer);
  quiche_h3_conn_free(conn_info->http3);
  quiche_conn_free(conn);
  quiche_config_free(config);
  delete reinterpret_cast<sockaddr_storage*>(conn_info->local_addr);
  delete conn_info;
  return 0;
}
