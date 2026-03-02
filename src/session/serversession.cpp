/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
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
 */

#include "serversession.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ServerSession::ServerSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context, Authenticator *auth, const string &plain_http_response) :
    Session(config, io_context),
    status(HANDSHAKE),
    in_socket(io_context, ssl_context),
    out_socket(io_context),
    udp_resolver(io_context),
    auth(auth),
    plain_http_response(plain_http_response) {}

tcp::socket& ServerSession::accept_socket() {
    return (tcp::socket&)in_socket.next_layer();
}

void ServerSession::start() {
    boost::system::error_code ec;
    start_time = time(nullptr);
    in_endpoint = in_socket.next_layer().remote_endpoint(ec);
    if (ec) {
        destroy();
        return;
    }
    auto self = shared_from_this();
    in_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
        if (error) {
            Log::log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
            if (error.message() == "http request" && !plain_http_response.empty()) {
                recv_len += plain_http_response.length();
                boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response), [this, self](const boost::system::error_code, size_t) {
                    destroy();
                });
                return;
            }
            destroy();
            return;
        }
        in_async_read();
    });
}

void ServerSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        in_recv(string((const char*)in_read_buf, length));
    });
}

void ServerSession::in_async_write(const string &data) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    boost::asio::async_write(in_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void ServerSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string((const char*)out_read_buf, length));
    });
}

void ServerSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void ServerSession::udp_async_read() {
    auto self = shared_from_this();
    udp_socket.async_receive_from(boost::asio::buffer(udp_read_buf, MAX_LENGTH), udp_recv_endpoint, [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        udp_recv(string((const char*)udp_read_buf, length), udp_recv_endpoint);
    });
}

void ServerSession::udp_async_write(const string &data, const udp::endpoint &endpoint) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    udp_socket.async_send_to(boost::asio::buffer(*data_copy), endpoint, [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        udp_sent();
    });
}

void ServerSession::in_recv(const string &data) {
    if (status == HANDSHAKE) {
        TrojanRequest req;
        bool valid = false;
        if (!config.forward_all_to_remote) {
            valid = req.parse(data) != -1;
            if (valid) {
                auto password_iterator = config.password.find(req.password);
                if (password_iterator == config.password.end()) {
                    valid = false;
                    if (auth && auth->auth(req.password)) {
                        valid = true;
                        auth_password = req.password;
                        Log::log_with_endpoint(in_endpoint, "authenticated by authenticator (" + req.password.substr(0, 7) + ')', Log::INFO);
                    }
                } else {
                    Log::log_with_endpoint(in_endpoint, "authenticated as " + password_iterator->second, Log::INFO);
                }
                if (!valid) {
                    Log::log_with_endpoint(in_endpoint, "valid trojan request structure but possibly incorrect password (" + req.password + ')', Log::WARN);
                }
            }
        }
        string query_addr = valid ? req.address.address : config.remote_addr;
        string query_port = to_string([&]() {
            if (valid) {
                return req.address.port;
            }
            const unsigned char *alpn_out;
            unsigned int alpn_len;
            SSL_get0_alpn_selected(in_socket.native_handle(), &alpn_out, &alpn_len);
            if (alpn_out == nullptr) {
                return config.remote_port;
            }
            auto it = config.ssl.alpn_port_override.find(string(alpn_out, alpn_out + alpn_len));
            return it == config.ssl.alpn_port_override.end() ? config.remote_port : it->second;
        }());
        if (valid) {
            out_write_buf = req.payload;
            if (req.command == TrojanRequest::UDP_ASSOCIATE) {
                Log::log_with_endpoint(in_endpoint, "requested UDP associate to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
                status = UDP_FORWARD;
                udp_data_buf = out_write_buf;
                udp_sent();
                return;
            } else {
                Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
            }
            // Store target address for SOCKS5 proxy
            target_addr = req.address.address;
            target_port = req.address.port;
        } else {
            if (config.forward_all_to_remote) {
                Log::log_with_endpoint(in_endpoint, "forward_all_to_remote is enabled, forwarding current connection to " + query_addr + ':' + query_port, Log::INFO);
            } else {
                Log::log_with_endpoint(in_endpoint, "not trojan request, connecting to " + query_addr + ':' + query_port, Log::WARN);
            }
            out_write_buf = data;
            // Store target address for SOCKS5 proxy
            target_addr = query_addr;
            target_port = static_cast<uint16_t>(stoi(query_port));
        }
        
        // If SOCKS5 proxy is enabled, connect to it instead of direct connection
        if (config.socks5.enabled) {
            Log::log_with_endpoint(in_endpoint, "using SOCKS5 proxy " + config.socks5.server_addr + ':' + to_string(config.socks5.server_port) + " to reach " + target_addr + ':' + to_string(target_port), Log::INFO);
            status = SOCKS5_CONNECT;
            sent_len += out_write_buf.length();
            auto self = shared_from_this();
            resolver.async_resolve(config.socks5.server_addr, to_string(config.socks5.server_port), [this, self](const boost::system::error_code error, const tcp::resolver::results_type& results) {
                if (error || results.empty()) {
                    Log::log_with_endpoint(in_endpoint, "cannot resolve SOCKS5 server hostname " + config.socks5.server_addr + ": " + error.message(), Log::ERROR);
                    destroy();
                    return;
                }
                auto iterator = results.begin();
                Log::log_with_endpoint(in_endpoint, config.socks5.server_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
                boost::system::error_code ec;
                out_socket.open(iterator->endpoint().protocol(), ec);
                if (ec) {
                    destroy();
                    return;
                }
                if (config.tcp.no_delay) {
                    out_socket.set_option(tcp::no_delay(true));
                }
                if (config.tcp.keep_alive) {
                    out_socket.set_option(boost::asio::socket_base::keep_alive(true));
                }
#ifdef TCP_FASTOPEN_CONNECT
                if (config.tcp.fast_open) {
                    using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
                    boost::system::error_code ec;
                    out_socket.set_option(fastopen_connect(true), ec);
                }
#endif // TCP_FASTOPEN_CONNECT
                out_socket.async_connect(*iterator, [this, self](const boost::system::error_code error) {
                    if (error) {
                        Log::log_with_endpoint(in_endpoint, "cannot establish connection to SOCKS5 server " + config.socks5.server_addr + ':' + to_string(config.socks5.server_port) + ": " + error.message(), Log::ERROR);
                        destroy();
                        return;
                    }
                    Log::log_with_endpoint(in_endpoint, "connected to SOCKS5 server");
                    // Start SOCKS5 handshake
                    socks5_connect();
                });
            });
        } else {
            // Direct connection to target (no SOCKS5)
            auto self = shared_from_this();
            resolver.async_resolve(query_addr, query_port, [this, self, query_addr, query_port](const boost::system::error_code error, const tcp::resolver::results_type& results) {
                if (error || results.empty()) {
                    Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + query_addr + ": " + error.message(), Log::ERROR);
                    destroy();
                    return;
                }
                auto iterator = results.begin();
                if (config.tcp.prefer_ipv4) {
                    for (auto it = results.begin(); it != results.end(); ++it) {
                        const auto &addr = it->endpoint().address();
                        if (addr.is_v4()) {
                            iterator = it;
                            break;
                        }
                    }
                }
                Log::log_with_endpoint(in_endpoint, query_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
                boost::system::error_code ec;
                out_socket.open(iterator->endpoint().protocol(), ec);
                if (ec) {
                    destroy();
                    return;
                }
                if (config.tcp.no_delay) {
                    out_socket.set_option(tcp::no_delay(true));
                }
                if (config.tcp.keep_alive) {
                    out_socket.set_option(boost::asio::socket_base::keep_alive(true));
                }
#ifdef TCP_FASTOPEN_CONNECT
                if (config.tcp.fast_open) {
                    using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
                    boost::system::error_code ec;
                    out_socket.set_option(fastopen_connect(true), ec);
                }
#endif // TCP_FASTOPEN_CONNECT
                out_socket.async_connect(*iterator, [this, self, query_addr, query_port](const boost::system::error_code error) {
                    if (error) {
                        Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + query_addr + ':' + query_port + ": " + error.message(), Log::ERROR);
                        destroy();
                        return;
                    }
                    Log::log_with_endpoint(in_endpoint, "tunnel established");
                    status = FORWARD;
                    out_async_read();
                    if (!out_write_buf.empty()) {
                        out_async_write(out_write_buf);
                    } else {
                        in_async_read();
                    }
                });
            });
        }
    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    } else if (status == UDP_FORWARD) {
        udp_data_buf += data;
        udp_sent();
    } else if (status == SOCKS5_CONNECT) {
        // Buffer data until SOCKS5 connection is established
        out_write_buf += data;
    }
}

void ServerSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    } else if (status == UDP_FORWARD) {
        udp_async_read();
    } else if (status == SOCKS5_CONNECT) {
        // Still connecting to SOCKS5 proxy, wait
    }
}

void ServerSession::out_recv(const string &data) {
    if (status == FORWARD) {
        recv_len += data.length();
        in_async_write(data);
    } else if (status == UDP_FORWARD) {
        // For UDP forward, we don't expect incoming data on the TCP connection
    }
}

void ServerSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    } else if (status == UDP_FORWARD) {
        // For UDP forward, after sending response to client, wait for more UDP data
        udp_async_read();
    } else if (status == SOCKS5_CONNECT) {
        // Still connecting to SOCKS5 proxy, wait
    }
}

void ServerSession::udp_recv(const string &data, const udp::endpoint &endpoint) {
    if (status == UDP_FORWARD) {
        size_t length = data.length();
        Log::log_with_endpoint(in_endpoint, "received a UDP packet of length " + to_string(length) + " bytes from " + endpoint.address().to_string() + ':' + to_string(endpoint.port()));
        recv_len += length;
        in_async_write(UDPPacket::generate(endpoint, data));
    }
}

void ServerSession::udp_sent() {
    if (status == UDP_FORWARD) {
        UDPPacket packet;
        size_t packet_len;
        bool is_packet_valid = packet.parse(udp_data_buf, packet_len);
        if (!is_packet_valid) {
            if (udp_data_buf.length() > MAX_LENGTH) {
                Log::log_with_endpoint(in_endpoint, "UDP packet too long", Log::ERROR);
                destroy();
                return;
            }
            in_async_read();
            return;
        }
        Log::log_with_endpoint(in_endpoint, "sent a UDP packet of length " + to_string(packet.length) + " bytes to " + packet.address.address + ':' + to_string(packet.address.port));
        udp_data_buf = udp_data_buf.substr(packet_len);
        string query_addr = packet.address.address;
        auto self = shared_from_this();
        udp_resolver.async_resolve(query_addr, to_string(packet.address.port), [this, self, packet, query_addr](const boost::system::error_code error, const udp::resolver::results_type& results) {
            if (error || results.empty()) {
                Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + query_addr + ": " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            auto iterator = results.begin();
            if (config.tcp.prefer_ipv4) {
                for (auto it = results.begin(); it != results.end(); ++it) {
                    const auto &addr = it->endpoint().address();
                    if (addr.is_v4()) {
                        iterator = it;
                        break;
                    }
                }
            }
            Log::log_with_endpoint(in_endpoint, query_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
            if (!udp_socket.is_open()) {
                auto protocol = iterator->endpoint().protocol();
                boost::system::error_code ec;
                udp_socket.open(protocol, ec);
                if (ec) {
                    destroy();
                    return;
                }
                udp_socket.bind(udp::endpoint(protocol, 0));
                udp_async_read();
            }
            sent_len += packet.length;
            udp_async_write(packet.payload, *iterator);
        });
    }
}
// SOCKS5 protocol implementation
void ServerSession::socks5_connect() {
    // Send SOCKS5 greeting: VER(1) + NMETHODS(1) + METHODS(2)
    // We support NO_AUTH(0x00) and USERPASS(0x02)
    string greeting;
    if (config.socks5.username.empty() && config.socks5.password.empty()) {
        // No authentication required
        greeting = {0x05, 0x01, 0x00};
    } else {
        // Username/password authentication
        greeting = {0x05, 0x02, 0x00, 0x02};
    }
    socks5_send_handshake(greeting);
}

void ServerSession::socks5_send_handshake(const string &data) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            Log::log_with_endpoint(in_endpoint, "SOCKS5 handshake send error: " + error.message(), Log::ERROR);
            destroy();
            return;
        }
        // Read server's method selection
        out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
            if (error) {
                Log::log_with_endpoint(in_endpoint, "SOCKS5 method selection recv error: " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            socks5_handshake_recv(string((const char*)out_read_buf, length));
        });
    });
}

void ServerSession::socks5_handshake_recv(const string &data) {
    if (data.length() < 2 || data[0] != 0x05) {
        Log::log_with_endpoint(in_endpoint, "invalid SOCKS5 version in method selection", Log::ERROR);
        destroy();
        return;
    }
    
    uint8_t method = static_cast<uint8_t>(data[1]);
    
    if (method == 0x00) {
        // No authentication required
        Log::log_with_endpoint(in_endpoint, "SOCKS5: no authentication required", Log::INFO);
        socks5_send_connect_request();
    } else if (method == 0x02) {
        // Username/password authentication
        Log::log_with_endpoint(in_endpoint, "SOCKS5: username/password authentication", Log::INFO);
        
        // Build username/password auth packet
        // VER(1) + ULEN(1) + USERNAME + PLEN(1) + PASSWORD
        string auth_packet;
        auth_packet += static_cast<char>(0x01);  // Version
        auth_packet += static_cast<char>(config.socks5.username.length());
        auth_packet += config.socks5.username;
        auth_packet += static_cast<char>(config.socks5.password.length());
        auth_packet += config.socks5.password;
        
        auto self = shared_from_this();
        auto data_copy = make_shared<string>(auth_packet);
        boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
            if (error) {
                Log::log_with_endpoint(in_endpoint, "SOCKS5 auth send error: " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            // Read auth response
            out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
                if (error) {
                    Log::log_with_endpoint(in_endpoint, "SOCKS5 auth response recv error: " + error.message(), Log::ERROR);
                    destroy();
                    return;
                }
                string resp((const char*)out_read_buf, length);
                if (resp.length() < 2 || resp[0] != 0x01 || resp[1] != 0x00) {
                    Log::log_with_endpoint(in_endpoint, "SOCKS5 authentication failed", Log::ERROR);
                    destroy();
                    return;
                }
                Log::log_with_endpoint(in_endpoint, "SOCKS5 authentication successful", Log::INFO);
                socks5_send_connect_request();
            });
        });
    } else if (method == 0xFF) {
        Log::log_with_endpoint(in_endpoint, "SOCKS5: no acceptable methods", Log::ERROR);
        destroy();
        return;
    } else {
        Log::log_with_endpoint(in_endpoint, "SOCKS5: unsupported auth method: " + to_string(method), Log::ERROR);
        destroy();
        return;
    }
}

void ServerSession::socks5_send_connect_request() {
    // Build CONNECT request: VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR + DST.PORT
    string request;
    request += static_cast<char>(0x05);  // SOCKS version
    request += static_cast<char>(0x01);  // CONNECT command
    request += static_cast<char>(0x00);  // Reserved
    
    // Determine address type and encode address
    boost::system::error_code ec;
    boost::asio::ip::address addr = boost::asio::ip::make_address(target_addr, ec);
    
    if (!ec && addr.is_v4()) {
        // IPv4 address
        request += static_cast<char>(0x01);  // ATYP: IPv4
        // Convert IPv4 to bytes manually
        auto bytes = addr.to_v4().to_bytes();
        request += string(reinterpret_cast<const char*>(bytes.data()), 4);
    } else if (!ec && addr.is_v6()) {
        // IPv6 address
        request += static_cast<char>(0x04);  // ATYP: IPv6
        // Convert IPv6 to bytes manually
        auto bytes = addr.to_v6().to_bytes();
        request += string(reinterpret_cast<const char*>(bytes.data()), 16);
    } else {
        // Domain name
        request += static_cast<char>(0x03);  // ATYP: Domain name
        request += static_cast<char>(target_addr.length());  // Domain length
        request += target_addr;              // Domain name
    }
    
    // Port (2 bytes, big endian)
    uint16_t port = target_port;
    request += static_cast<char>((port >> 8) & 0xFF);
    request += static_cast<char>(port & 0xFF);
    
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(request);
    boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            Log::log_with_endpoint(in_endpoint, "SOCKS5 connect request send error: " + error.message(), Log::ERROR);
            destroy();
            return;
        }
        // Read connect response
        out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
            if (error) {
                Log::log_with_endpoint(in_endpoint, "SOCKS5 connect response recv error: " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            socks5_connect_recv(string((const char*)out_read_buf, length));
        });
    });
}

void ServerSession::socks5_connect_recv(const string &data) {
    if (data.length() < 10 || data[0] != 0x05 || data[1] != 0x00) {
        Log::log_with_endpoint(in_endpoint, "invalid SOCKS5 connect response", Log::ERROR);
        destroy();
        return;
    }
    
    uint8_t reply_type = data[1];
    
    if (reply_type != 0x00) {
        string error_msg;
        switch (reply_type) {
            case 0x01: error_msg = "general SOCKS server failure"; break;
            case 0x02: error_msg = "connection not allowed by ruleset"; break;
            case 0x03: error_msg = "network unreachable"; break;
            case 0x04: error_msg = "host unreachable"; break;
            case 0x05: error_msg = "connection refused"; break;
            case 0x06: error_msg = "TTL expired"; break;
            case 0x07: error_msg = "command not supported"; break;
            case 0x08: error_msg = "address type not supported"; break;
            default: error_msg = "unknown error"; break;
        }
        Log::log_with_endpoint(in_endpoint, "SOCKS5 connection failed: " + error_msg + " (code=" + to_string(reply_type) + ')', Log::ERROR);
        destroy();
        return;
    }
    
    Log::log_with_endpoint(in_endpoint, "tunnel established via SOCKS5 proxy to " + target_addr + ':' + to_string(target_port), Log::INFO);
    
    status = FORWARD;
    
    // Send any buffered data first
    out_async_read();
    
    if (!out_write_buf.empty()) {
        out_async_write(out_write_buf);
    } else {
        in_async_read();
    }
}
void ServerSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    if (auth && !auth_password.empty()) {
        auth->record(auth_password, recv_len, sent_len);
    }
    boost::system::error_code ec;
    resolver.cancel();
    udp_resolver.cancel();
    if (out_socket.is_open()) {
        out_socket.cancel(ec);
        out_socket.shutdown(tcp::socket::shutdown_both, ec);
        out_socket.close(ec);
    }
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }
    if (in_socket.next_layer().is_open()) {
        auto self = shared_from_this();
        auto ssl_shutdown_cb = [this, self](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            ssl_shutdown_timer.cancel();
            in_socket.next_layer().cancel(ec);
            in_socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
            in_socket.next_layer().close(ec);
        };
        in_socket.next_layer().cancel(ec);
        in_socket.async_shutdown(ssl_shutdown_cb);
        ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
}
